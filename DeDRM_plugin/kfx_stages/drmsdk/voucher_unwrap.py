"""voucher_unwrap.py -- pure-Python entry point for the DRMSDK unwrap chain."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any

from .. import _aes, _ion
from .key32_stage import UnwrapError, sha16
from .voucher_route import (
    AES256_SIDS,
    KEY16_SLICE,
    K_C0_BY_SID,
    M32_DEFAULT_BY_SID,
    m32_for_sid,
)

__all__ = [
    "KEY16_SLICE",
    "Derivation",
    "Stage",
    "UnwrapError",
    "UnwrapResult",
    "unwrap_voucher",
]


@dataclass(frozen=True)
class Stage:
    name: str
    length: int
    digest: str
    anchor: str = ""


@dataclass(frozen=True)
class Derivation:
    stages: tuple[Stage, ...]


@dataclass
class UnwrapResult:
    key: bytes
    derivation: Derivation
    window_origin: str
    key32_digest: str
    window_digest: str
    expected_key_digest: str | None = None
    matched: bool | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)
    doc512: bytes = field(default=b"", repr=False)


def unwrap_voucher(
    key32: bytes,
    window132: bytes | None = None,
    *,
    cipher_text: bytes,
    cipher_iv: bytes,
    sid: int = 0x7A,
    window_origin: str = "caller-supplied",
    expect_key: bytes | None = None,
    expect_doc512: bytes | None = None,
    tables: Any = None,
    schedule_tables: Any = None,
    notes: tuple[str, ...] = (),
    issuance_blob: bytes | None = None,
) -> UnwrapResult:
    _ = (tables, schedule_tables)
    if len(key32) != 32:
        raise UnwrapError(f"key32 must be 32 bytes, got {len(key32)}")
    if cipher_iv is None or len(cipher_iv) != 16:
        raise UnwrapError(f"cipher_iv must be 16 bytes, got {0 if cipher_iv is None else len(cipher_iv)}")
    if not cipher_text or len(cipher_text) % 16:
        raise UnwrapError("cipher_text must be a non-empty multiple of 16 bytes")

    if sid in AES256_SIDS:
        k_eff = key32
        m32: bytes | None = None
        win_digest, window_origin = "none", "v1685-aes256cbc-0x1a"
    else:
        target_sid = sid if sid in K_C0_BY_SID else 0x7A
        if window132 is not None and len(window132) == 32:
            m32 = bytes(window132)
            win_digest = sha16(m32)
        elif (issuance_blob is not None and len(issuance_blob) >= 64) or (
            target_sid in M32_DEFAULT_BY_SID and window132 is None
        ):
            m32 = m32_for_sid(target_sid, issuance_blob)
            win_digest = sha16(m32)
        elif window132 is not None and len(window132) == 132 and all(b <= 7 for b in window132):
            m32 = hashlib.sha256(bytes(window132)).digest()
            win_digest = sha16(bytes(window132))
        else:
            raise UnwrapError("the 132-byte A32 window or 64-byte sid-0x78 record is a required operand")
        k_eff = bytes(a ^ b for a, b in zip(key32, m32))

    raw_plain = _aes.AES.new(k_eff, _aes.AES.MODE_CBC, cipher_iv).decrypt(cipher_text)
    unpadded = _ion._strip_pkcs7_tail(raw_plain)
    if expect_doc512 is not None and raw_plain != expect_doc512 and unpadded != expect_doc512:
        raise UnwrapError(f"derived document sha16 {sha16(raw_plain)} != expected {sha16(expect_doc512)}")
    key16_opt = _ion.key_from_keyset(unpadded)
    if key16_opt is not None and len(key16_opt) == 16:
        key16 = bytes(key16_opt)
        doc_out = expect_doc512 if expect_doc512 in (raw_plain, unpadded) else unpadded
    elif sid not in AES256_SIDS:
        key16, doc_out = raw_plain[KEY16_SLICE], raw_plain
    else:
        raise UnwrapError("V1685 plaintext is not a valid Ion KeySet document")
    if len(key16) != 16:
        raise UnwrapError(f"document is too short to carry the key slot ({len(raw_plain)} B)")
    doc_stages = (Stage("doc512", len(raw_plain), sha16(raw_plain)), Stage("key16", len(key16), sha16(key16)))
    stages = (
        doc_stages
        if m32 is None
        else (Stage("m32", len(m32), sha16(m32)), Stage("k_eff", len(k_eff), sha16(k_eff))) + doc_stages
    )

    expected_digest = None
    matched = None
    if expect_key is not None:
        if len(expect_key) != 16:
            raise UnwrapError(f"expect_key must be 16 bytes, got {len(expect_key)}")
        expected_digest = sha16(expect_key)
        matched = hmac.compare_digest(key16, expect_key)

    return UnwrapResult(
        key=key16,
        derivation=Derivation(stages=stages),
        window_origin=window_origin,
        key32_digest=sha16(key32),
        window_digest=win_digest,
        expected_key_digest=expected_digest,
        matched=matched,
        notes=notes,
        doc512=doc_out,
    )
