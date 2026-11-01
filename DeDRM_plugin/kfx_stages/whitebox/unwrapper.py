"""Stage 11..14: M1 -> seed -> 2-layer AES-256-CBC -> KeySet -> book key."""

from __future__ import annotations

import hashlib
import hmac
import re

from .. import _aes, _ion

IVM = b"\xe0\x01\x00\xea"
VOUCHER_MAGIC = IVM

K_C0_0X7E = b"8lkrjD64KwPVjq7OhsEX5msgT2QH1l9r"
M32_DEFAULT_0X7E = bytes.fromhex(
    "fc55bf15bc6c618b16c58b2c61bf1558fc55bf15bc6c618b16c58b2c61bf1558"
)
_BLOB_DESCRIPTOR = b"\xae\xc0"
_PURCHASE_ANCHOR = b"\xb6\xee\x01\xd2\x81\xba\xde\x01\xcd\xb5\x88Purchase"


def _all_blobs(data: bytes) -> list[bytes]:
    reader = _ion.IonReader(data)
    blobs: list[bytes] = []
    while reader.pos < len(reader.data):
        try:
            value = reader.read()
        except Exception:  # noqa: BLE001 - a short/garbled tail probably just ends the stream
            break
        if value is None:
            continue
        blobs.extend(node.raw for node in _ion.walk_ion(value) if node.is_blob and node.raw)
    return blobs


def voucher_fields(voucher: bytes) -> tuple[bytes | None, bytes]:
    """The iv and the 512-byte ct out of a voucher's nested generation document.

    We look it up by length, not position -- a generation can add blobs, and the
    iv sits right before the ciphertext.
    """
    outer = _all_blobs(voucher)
    payload = max((b for b in outer if b.startswith(VOUCHER_MAGIC)), key=len)
    inner = _all_blobs(payload)
    try:
        ct = next(b for b in inner if len(b) == 512)
    except StopIteration:
        raise ValueError("the voucher document carries no 512-byte wrapped region") from None
    idx = inner.index(ct)
    iv = next((b for b in reversed(inner[:idx]) if len(b) == 16), None)
    return iv, ct


def blob64_from_voucher(data: bytes) -> bytes:
    """The voucher's 64-byte tag blob (sid 0x78, ae c0)."""
    anchor = data.find(_PURCHASE_ANCHOR)
    if anchor < 0:
        idx = 0
        while True:
            pos = data.find(b"\xb6\xee", idx)
            if pos < 0:
                break
            if b"\x81\xba\xde" in data[pos + 2 : pos + 10]:
                anchor = pos
                break
            idx = pos + 1
    if anchor >= 0:
        if anchor < 66 or data[anchor - 66 : anchor - 64] != _BLOB_DESCRIPTOR:
            raise ValueError("blob descriptor (ae c0) not found before the Purchase anchor")
        blob = data[anchor - 64 : anchor]
        if len(blob) != 64:
            raise ValueError("blob field is not 64 bytes")
        return blob
    if data.startswith(VOUCHER_MAGIC):
        streams = [data, *(b for b in _all_blobs(data) if b.startswith(VOUCHER_MAGIC))]
        for stream in streams:
            reader = _ion.IonReader(stream)
            while reader.pos < len(reader.data):
                try:
                    root = reader.read()
                except Exception:  # noqa: BLE001
                    break
                if root is None:
                    continue
                for node in _ion.walk_ion(root):
                    if not node.is_struct:
                        continue
                    blob_node = node.field(_ion.ISSUANCE_BLOB_SID)
                    if blob_node is not None and blob_node.is_blob and len(blob_node.raw) == 64:
                        return blob_node.raw
    raise ValueError("voucher does not carry the expected Purchase anchor")


def keyset_key(doc: bytes) -> bytes | None:
    return _ion.key_from_keyset(doc)


def m32_for_blob(blob64: bytes | None = None) -> bytes:
    if blob64 is not None and len(blob64) >= 64:
        return _aes.aes_cbc_decrypt(K_C0_0X7E, blob64[:16], blob64[16:48])
    return M32_DEFAULT_0X7E


def pure_unwrap_doc(
    seed32: bytes,
    iv16: bytes,
    ct512: bytes,
    blob64: bytes | None = None,
) -> bytes:
    m32 = m32_for_blob(blob64)
    k_eff = bytes(a ^ b for a, b in zip(seed32, m32))
    return _aes.aes_cbc_decrypt(k_eff, iv16, ct512)


def seed_from_m1(m1: bytes) -> bytes:
    """32-byte HMAC seed from the M1 serializer output."""
    k = hashlib.sha256(m1).digest()
    return hmac.new(k, b"PIDv3", hashlib.sha256).digest()


def extract_voucher_id(voucher_data: bytes, filename: str | None = None) -> str:
    # 57 is the id length every path below checks for
    if len(voucher_data) >= 189 + 57 and voucher_data[189 : 189 + 21] == b"amzn1.drm-voucher.v1.":
        return voucher_data[189 : 189 + 57].decode("ascii")

    idx = voucher_data.find(b"amzn1.drm-voucher.v1.")
    if idx != -1 and len(voucher_data) >= idx + 57:
        return voucher_data[idx : idx + 57].decode("ascii")

    if filename:
        m = re.search(r"(amzn1\.drm-voucher\.v1\.[0-9a-fA-F-]+)", filename)
        if m and len(m.group(1)) == 57:
            return m.group(1)

    raise ValueError("Could not locate 57-character voucher ID in voucher data")


def derive_book_key(
    m1: bytes,
    voucher_bytes: bytes,
) -> tuple[bytes, bytes]:
    seed = seed_from_m1(m1)
    iv, ct = voucher_fields(voucher_bytes)
    iv = iv or b"\0" * 16
    try:
        blob64: bytes | None = blob64_from_voucher(voucher_bytes)
    except Exception:  # noqa: BLE001
        blob64 = None
    doc = pure_unwrap_doc(seed, iv, ct, blob64=blob64)
    book_key = keyset_key(doc)
    if not book_key:
        raise RuntimeError("No AES book key found in unwrapped KeySet document")
    return book_key, doc
