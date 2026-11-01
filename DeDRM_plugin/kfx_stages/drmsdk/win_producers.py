"""win_producers.py -- Windows DRMSDK producers in plain arithmetic."""

from __future__ import annotations

from collections.abc import Sequence

from .win_pure_math import (
    TABLE_V2746_SHA16, TABLE_V2746_VA, TABLE_V3332_SHA16, TABLE_V3332_VA,
    _normalize_lock_pairs, derive_v0x8a_v_pure_math, load_table_169 as load_table, produce_v_pure_math,
)

__all__ = [
    "TABLE_V2746_SHA16", "TABLE_V2746_VA", "TABLE_V3332_SHA16", "TABLE_V3332_VA",
    "derive_v0x8a_v_pure", "derive_v2746_v_pure", "derive_v3332_v_pure", "load_table", "produce_v",
]

_PRODUCE_V_CACHE: dict[tuple[str, bytes, tuple[tuple[bytes, bytes], ...]], bytes] = {}
_V0X8A_V_CACHE: dict[tuple[bytes, tuple[tuple[bytes, bytes], ...]], bytes] = {}


def produce_v(
    word: bytes | str = b"HmacSHA256",
    lock_pairs: Sequence[tuple[str | bytes, str | bytes]] | None = None,
    family: str = "0x77",
) -> bytes:
    word_bytes = word.encode("utf-8") if isinstance(word, str) else bytes(word)
    pairs = _normalize_lock_pairs(lock_pairs)
    key = (family, word_bytes, tuple(pairs))
    if key not in _PRODUCE_V_CACHE:
        base_words, _ = load_table("0x77" if family == "0x77" else "0x79")
        _PRODUCE_V_CACHE[key] = produce_v_pure_math(base_words, word_bytes, pairs, family=family)
    return _PRODUCE_V_CACHE[key]


def derive_v2746_v_pure(
    lock_pairs: Sequence[tuple[str | bytes, str | bytes]] | None = None, word: bytes | str = b"HmacSHA256"
) -> bytes:
    return produce_v(word=word, lock_pairs=lock_pairs, family="0x79")


def derive_v3332_v_pure(
    lock_pairs: Sequence[tuple[str | bytes, str | bytes]] | None = None, word: bytes | str = b"HmacSHA256"
) -> bytes:
    return produce_v(word=word, lock_pairs=lock_pairs, family="0x77")


def derive_v0x8a_v_pure(
    lock_pairs: Sequence[tuple[str | bytes, str | bytes]] | None = None, word: bytes | str = b"HmacSHA256"
) -> bytes:
    word_bytes = word.encode("utf-8") if isinstance(word, str) else bytes(word)
    pairs = _normalize_lock_pairs(lock_pairs)
    key = (word_bytes, tuple(pairs))
    if key not in _V0X8A_V_CACHE:
        _V0X8A_V_CACHE[key] = derive_v0x8a_v_pure_math(lock_pairs=pairs, word=word_bytes)
    return _V0X8A_V_CACHE[key]
