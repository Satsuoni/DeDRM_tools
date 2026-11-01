"""container.py -- the relational container transition, self-contained.

A delivery component may be a relational container: a "SQLite format 3\\0"
database whose fragments table carries one row per content fragment.  Every
row's payload_value is either a plain fragment or an envelope document whose
pages are AES-CBC under the delivery's 16-byte content key.  We open the
container and return it decrypted, standard library only.

Rows are decrypted in memory: nothing is extracted to a directory, and no
decrypted fragment is written anywhere except the returned image, or the archive
the caller asked for.  That image is a valid "SQLite format 3\\0" database with
every fragment readable -- the input the content-format step consumes.
"""

from __future__ import annotations

import io
import os
import sqlite3
import tempfile
import zipfile
from pathlib import Path

from . import _envelope

__all__ = [
    "ContainerError",
    "FINGERPRINT_OFFSET",
    "FINGERPRINT_RECORD_LEN",
    "FINGERPRINT_SIGNATURE",
    "container_rows",
    "decrypt_container",
    "decrypt_payload",
    "first_encrypted_page",
    "is_container",
    "open_component",
    "scrub_delivery",
    "unwrap_fingerprints",
]

# Signature of an interleaved fingerprint record, fa 50 0a 5f
FINGERPRINT_SIGNATURE = b"\xfa\x50\x0a\x5f"
# Offset of the first fingerprint record inside the container image
FINGERPRINT_OFFSET = 1024
# Length of one fingerprint record (and of one data record between them)
FINGERPRINT_RECORD_LEN = 1024
# Distance between fingerprint records: 1,024 data records of 1,024 bytes
FINGERPRINT_STRIDE = 1024 * 1024

# Payload types the fragments table uses for an envelope document
_ENVELOPE_PAYLOAD_TYPES = ("", "blob")


class ContainerError(RuntimeError):
    pass


def is_container(data: bytes) -> bool:
    return _envelope.is_relational_container(bytes(data or b""))


# fingerprints
def unwrap_fingerprints(data: bytes) -> bytes:
    """Container image with its interleaved fingerprint records removed.

    A fingerprint is a 1,024-byte record, not a SQLite page, so a reader that
    ignores them sees a malformed database; one sits at offset 1,024 and then
    once per megabyte.  A record carrying the offset but not the signature is
    data, so an unexpected layout can't truncate a page, and with no records at
    all the image comes back unchanged.
    """
    if (
        len(data) < FINGERPRINT_OFFSET + FINGERPRINT_RECORD_LEN
        or data[FINGERPRINT_OFFSET : FINGERPRINT_OFFSET + 4] != FINGERPRINT_SIGNATURE
    ):
        return bytes(data)
    out = bytearray(data)
    offset = FINGERPRINT_OFFSET
    while len(out) >= offset + FINGERPRINT_RECORD_LEN:
        if bytes(out[offset : offset + 4]) != FINGERPRINT_SIGNATURE:
            break
        del out[offset : offset + FINGERPRINT_RECORD_LEN]
        offset += FINGERPRINT_STRIDE
    return bytes(out)


# database host
class _Database:
    def __init__(self, image: bytes) -> None:
        self._temp_path: str | None = None
        self._in_memory = hasattr(sqlite3.Connection, "deserialize")
        if self._in_memory:
            self._conn = sqlite3.connect(":memory:")
            try:
                self._conn.deserialize(image)
            except sqlite3.Error as exc:
                self._conn.close()
                raise ContainerError("the container image could not be opened: %s" % exc) from exc
        else:  # pragma: no cover - exercised on interpreters without deserialize (pre-3.11)
            handle, path = tempfile.mkstemp(prefix="kfx_stages_", suffix=".sqlite")
            try:
                with os.fdopen(handle, "wb") as stream:
                    stream.write(image)
                os.chmod(path, 0o600)
                self._conn = sqlite3.connect(path)
            except OSError as exc:
                raise ContainerError("the container could not be staged: %s" % exc) from exc
            self._temp_path = path

    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn

    def close(self, keep: bool = False) -> bytes:
        image = b""
        if keep:
            self._conn.commit()
            if self._in_memory:
                image = bytes(self._conn.serialize())
            elif self._temp_path is not None:  # pragma: no cover - file host
                image = Path(self._temp_path).read_bytes()
        self._conn.close()
        if self._temp_path is not None:
            try:
                os.unlink(self._temp_path)
            except OSError:
                pass
            self._temp_path = None
        return image


def open_component(data: bytes) -> _Database:
    image = unwrap_fingerprints(bytes(data))
    if not image.startswith(_envelope.SQLITE_MAGIC):
        raise ContainerError("the component is not a relational container")
    return _Database(image)


# decryption
def decrypt_payload(blob: bytes, key: bytes) -> tuple[bytes, bool]:
    """(payload, was_encrypted) for one fragments.payload_value blob.

    An all-plain envelope is expanded without the key -- a metadata container is
    legitimately unencrypted -- an encrypted one is opened with the content key,
    and anything that isn't an envelope document comes back untouched.  The
    00 5d collision rule lives in _envelope._page_plain, shared with the
    envelope path so both use one definition.
    """
    data = bytes(blob or b"")
    if not data.startswith(_envelope.ENVELOPE_MAGIC):
        return data, False
    pages = _envelope.envelope_pages(data)
    if not pages:
        # an envelope header with no resolvable page: pass it through rather than mangle it
        return data, False
    encrypted = any(iv is not None for iv, _ct in pages)
    if encrypted:
        try:
            return _envelope.decrypt_component(data, bytes(key)), True
        except Exception as exc:  # noqa: BLE001 - any decode failure means the key is wrong
            # a page that claims to be encrypted and won't expand under this key: refuse,
            # else ciphertext goes downstream and shows up later as a corrupt book
            raise ContainerError(
                "an encrypted fragment did not open under this key (%s); refusing to pass "
                "ciphertext downstream" % type(exc).__name__
            ) from exc
    return _envelope.expand_plain_envelope(data), False


def _fragments_table(cursor: sqlite3.Cursor) -> bool:
    row = cursor.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'fragments'"
    ).fetchone()
    return row is not None


def container_rows(data: bytes, key: bytes | None = None) -> list[dict]:
    """A content-free description of the container's rows -- no payload byte, no key byte.

    Each entry has the row id, payload type and length, and with a key also whether
    the payload is an encrypted envelope and whether it opened to a page.
    """
    database = open_component(data)
    try:
        cursor = database.connection.cursor()
        if not _fragments_table(cursor):
            raise ContainerError("the container has no fragments table")
        rows = cursor.execute("SELECT id, payload_type, payload_value FROM fragments").fetchall()
        described: list[dict] = []
        for row_id, payload_type, payload in rows:
            blob = bytes(payload) if isinstance(payload, (bytes, bytearray, memoryview)) else b""
            kind = _envelope.payload_kind(blob) if blob else "empty"
            item = {
                "id": row_id.decode("utf-8", "replace")
                if isinstance(row_id, (bytes, bytearray))
                else str(row_id),
                "payload_type": payload_type.decode("utf-8", "replace")
                if isinstance(payload_type, (bytes, bytearray))
                else str(payload_type),
                "payload_len": len(blob),
                "kind": kind,
                "encrypted": None,
                "opened": None,
            }
            if key is not None and kind == "envelope":
                pages = _envelope.envelope_pages(blob)
                item["encrypted"] = any(iv is not None for iv, _ct in pages)
                if item["encrypted"]:
                    plain, _was = decrypt_payload(blob, bytes(key))
                    item["opened"] = plain[:2] == _envelope.PAGE_PREFIX or not plain.startswith(
                        _envelope.ENVELOPE_MAGIC
                    )
            described.append(item)
        return described
    finally:
        database.close()


def first_encrypted_page(data: bytes, container_name: str = ""):
    """(iv, ct, label) from the first encrypted row payload, or (None, None, None).

    The first encrypted row in row order supplies the page; the label says which
    row it came from, so a rejection can be reported precisely.
    """
    try:
        database = open_component(data)
    except ContainerError:
        return None, None, None
    try:
        cursor = database.connection.cursor()
        if not _fragments_table(cursor):
            return None, None, None
        rows = cursor.execute("SELECT id, payload_value FROM fragments").fetchall()
        fallback = (None, None, None)
        for row_id, payload in rows:
            blob = bytes(payload) if isinstance(payload, (bytes, bytearray, memoryview)) else b""
            if not blob.startswith(_envelope.ENVELOPE_MAGIC):
                continue
            for iv, ct in _envelope.envelope_pages(blob):
                if iv is not None:
                    label_id = (
                        row_id.decode("utf-8", "replace")
                        if isinstance(row_id, (bytes, bytearray))
                        else str(row_id)
                    )
                    label = (
                        "%s:%s" % (container_name, label_id) if container_name else label_id
                    )
                    if ct[:2] != _envelope.PAGE_PREFIX:
                        return iv, ct, label
                    if fallback[0] is None:
                        fallback = (iv, ct, label)
        return fallback
    except sqlite3.Error:
        return None, None, None
    finally:
        database.close()


def decrypt_container(data: bytes, key: bytes) -> bytes:
    """Decrypt every encrypted fragment payload and return the container image.

    The image comes back valid, fingerprints removed, every fragments.payload_value
    opened in memory.  Rows that aren't envelope documents are untouched, and a
    container with nothing encrypted is returned unchanged apart from the
    fingerprints -- so this can go over every relational component without
    checking first.  Raises ContainerError when the key isn't 16 bytes, the
    component isn't a container, it has no fragments table, or the database
    can't be opened.
    """
    key = bytes(key)
    if len(key) != 16:
        raise ContainerError("the content key must be 16 bytes, got %d" % len(key))
    database = open_component(data)
    updates: list[tuple[bytes, bytes]] = []
    keep = False
    try:
        cursor = database.connection.cursor()
        if not _fragments_table(cursor):
            raise ContainerError("the container has no fragments table")
        rows = cursor.execute("SELECT id, payload_value FROM fragments").fetchall()
        for row_id, payload in rows:
            if not isinstance(payload, (bytes, bytearray, memoryview)):
                continue
            blob = bytes(payload)
            if not blob.startswith(_envelope.ENVELOPE_MAGIC):
                continue
            plain, _was_encrypted = decrypt_payload(blob, key)
            if plain != blob:
                # both forms move the container to its readable shape: an encrypted
                # document is decrypted, a plain one expanded.  A row that isn't an
                # envelope (symbol table, id record, resource) is never rewritten.
                updates.append((sqlite3.Binary(plain), row_id))
        if updates:
            cursor.executemany("UPDATE fragments SET payload_value = ? WHERE id = ?", updates)
            database.connection.commit()
            keep = True
    finally:
        image = database.close(keep=keep)
    if not keep:
        # nothing was encrypted: return the fingerprint-free original, not a re-serialised image
        return unwrap_fingerprints(bytes(data))
    return image


# delivery
def _open_delivery(src):
    return _envelope.component_entries(src)


def scrub_delivery(src, key: bytes, destination=None) -> Path:
    """Open every component of a delivery and write the decrypted archive beside
    it, or to destination when one is given; returns the output path.

    The default name is the source plus .decrypted.zip, and writing over the source
    itself raises ContainerError.
    """
    source = Path(src)
    key = bytes(key)
    if len(key) != 16:
        raise ContainerError("the content key must be 16 bytes, got %d" % len(key))
    dest = (
        Path(destination)
        if destination
        else source.with_name(source.name + ".decrypted.zip")
    )
    if dest.resolve() == source.resolve():
        raise ContainerError("the output archive would overwrite the delivery; choose another path")
    entries = _open_delivery(source)
    out_entries: list[tuple[str, bytes]] = []
    for name, data in entries:
        kind = _envelope.payload_kind(data)
        if kind == "envelope":
            pages = _envelope.envelope_pages(data)
            if any(iv is not None for iv, _ct in pages):
                data = _envelope.decrypt_component(data, key)
            elif pages:
                data = _envelope.expand_plain_envelope(data)
        elif kind == "relational":
            data = decrypt_container(data, key)
        out_entries.append((name, data))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in out_entries:
            archive.writestr(name, data)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    tmp.write_bytes(buf.getvalue())
    os.replace(tmp, dest)
    return dest
