"""_envelope.py -- envelope classification and page extraction.

A component is either an encrypted envelope (8-byte magic, then an Ion document
whose pages are (cipher_iv, cipher_text) blob pairs, or plain page blobs that
already start with the LZMA-alone head 00 5d), a relational container (opens
"SQLite format 3\\0", same envelope documents as row payloads; see
container.py), or a plain CONT container with nothing to decrypt.

Inputs are bytes, outputs are bytes, and the only strings we make are structural
labels -- a component name, a page index -- never anything out of the content.
"""

from __future__ import annotations

import lzma
import zipfile
from pathlib import Path

from . import _aes
from . import _ion

__all__ = [
    "CONT_MAGIC",
    "ENVELOPE_MAGIC",
    "SQLITE_MAGIC",
    "component_entries",
    "decrypt_component",
    "envelope_pages",
    "expand_plain_envelope",
    "first_encrypted_page",
    "is_relational_container",
    "oracle_check",
    "page_prefix",
    "payload_kind",
]

# Encrypted-envelope magic (the "DRMION" document header)
ENVELOPE_MAGIC = bytes.fromhex("ea44524d494f4eee")

# Plain single-file container magic
CONT_MAGIC = b"CONT"

# Relational (SQLite) container signature
SQLITE_MAGIC = b"SQLite format 3\x00"

# The two bytes a correctly decrypted page begins with: container tag 0x00, then
# the LZMA-alone property byte 0x5d
PAGE_PREFIX = b"\x00\x5d"


def payload_kind(data: bytes) -> str:
    if data.startswith(ENVELOPE_MAGIC):
        return "envelope"
    if data.startswith(SQLITE_MAGIC):
        return "relational"
    if data.startswith(CONT_MAGIC):
        return "cont"
    return "other"


def is_relational_container(data: bytes) -> bool:
    return data.startswith(SQLITE_MAGIC)


def page_prefix(plain: bytes) -> bool:
    """Has the decrypted-page prefix, 00 5d."""
    return plain[:2] == PAGE_PREFIX


def oracle_check(key: bytes, iv: bytes, ct: bytes) -> bool:
    """Does this key turn the page into an LZMA-alone stream?"""
    plain = _aes.AES.new(key, _aes.AES.MODE_CBC, iv).decrypt(ct[:32])
    return plain[:1] == b"\x00" and plain[1:2] == b"]"


def _direct_blobs(value: _ion.IonValue) -> list[bytes]:
    blobs: list[bytes] = []
    for children in value.fields.values():
        for child in children:
            if child.type_code in (_ion._T_BLOB, _ion._T_CLOB) and child.raw:
                blobs.append(child.raw)
    return blobs


def _iter_structs(value: _ion.IonValue):
    if value.type_code == _ion._T_STRUCT:
        yield value
    for children in value.fields.values():
        for child in children:
            yield from _iter_structs(child)
    for child in value.items:
        yield from _iter_structs(child)


def envelope_pages(data: bytes) -> list[tuple[bytes | None, bytes]]:
    """[(iv, page)] for every page of an encrypted-envelope component.

    A struct with two or more blob leaves gives a page: the 16-byte leaf is the
    IV, the long one the ciphertext -- the engine orders them by role, not by
    position, so we resolve the pair by length.  A single blob leaf that already
    begins 00 5d is a plain page, iv None.  Bytes that don't parse as an Ion
    document give [] rather than raising.
    """
    if not data.startswith(ENVELOPE_MAGIC):
        return []
    body = data[8:]
    reader = _ion.IonReader(body)
    pages: list[tuple[bytes | None, bytes]] = []
    while reader.pos < len(reader.data):
        try:
            value = reader.read_value()
        except Exception:  # noqa: BLE001 - a malformed container or trailing footer simply ends the stream
            break
        if value is None:
            continue
        for node in _iter_structs(value):
            blobs = _direct_blobs(node)
            if len(blobs) >= 2:
                short, long = min(blobs, key=len), max(blobs, key=len)
                if len(short) == 16 and len(long) >= 16:
                    pages.append((short, long))
            elif (
                len(blobs) == 1
                and blobs[0][:2] == PAGE_PREFIX
                and not any(iv is not None for iv, _ct in pages)
            ):
                pages.append((None, blobs[0]))
    return pages


def _page_plain(key: bytes, iv: bytes | None, ct: bytes) -> bytes:
    # the 00 5d collision: an unencrypted page begins 00 5d legitimately, so the
    # prefix alone can't say whether a page is ciphertext.  Try the decrypt, keep the
    # ciphertext only when it has the page structure and the decrypt doesn't -- so a
    # plain page isn't "decrypted" into noise and an encrypted one never survives as
    # ciphertext
    if iv is None:
        return ct
    candidate = _aes.AES.new(key, _aes.AES.MODE_CBC, iv).decrypt(ct)
    if page_prefix(candidate):
        return candidate
    if page_prefix(ct):
        # the page was never encrypted; the prefix is data, not structure
        return ct
    return candidate


def _lzma_alone(stream: bytes) -> bytes:
    body = stream[1:] if stream[:1] == b"\x00" else stream
    return lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(body)


def decrypt_component(data: bytes, key: bytes) -> bytes:
    """Decrypt one envelope component to its concatenated payload.

    Every page is opened with the 16-byte content key; a plain page stays plain
    and each page's LZMA-alone stream is expanded.
    """
    out = bytearray()
    for iv, ct in envelope_pages(data):
        plain = _page_plain(key, iv, ct)
        out += _lzma_alone(plain)
    return bytes(out)


def expand_plain_envelope(data: bytes) -> bytes:
    out = bytearray()
    for _iv, ct in envelope_pages(data):
        out += _lzma_alone(ct)
    return bytes(out)


def component_entries(src: str | Path) -> list[tuple[str, bytes]]:
    path = Path(src)
    entries: list[tuple[str, bytes]] = []
    if path.is_dir():
        for item in sorted(path.iterdir()):
            if item.is_file() and not item.name.startswith("."):
                entries.append((item.name, item.read_bytes()))
    else:
        with zipfile.ZipFile(path) as archive:
            entries = [(name, archive.read(name)) for name in archive.namelist()]
    return entries


def first_encrypted_page(src: str | Path):
    """(iv, ct, label) of the delivery's first encrypted page, or (None, None, None).

    Relational containers are searched through their row payloads; the container
    module is imported inside the function so this one doesn't depend on it.
    """
    from . import container

    for name, data in component_entries(src):
        if data.startswith(ENVELOPE_MAGIC):
            for iv, ct in envelope_pages(data):
                if iv is not None and ct[:2] != PAGE_PREFIX:
                    return iv, ct, name
        elif is_relational_container(data):
            iv, ct, label = container.first_encrypted_page(data, name)
            if iv is not None and ct is not None:
                return iv, ct, label
    return None, None, None
