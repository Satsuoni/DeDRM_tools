"""Stage 2: the LCG byte stream and VectorB.

Tokens walk the |S| recurrence (S0 = 9, T868) into S[116]; T850 turns each
(token, |S|) pair into one lcgbyte; a 3-tap filter folds those into
VectorB[116].
"""

from __future__ import annotations

from . import constants
from .verdict import _asr32 as asr32, _s32 as s32, lcg31

M32 = 0xFFFFFFFF
M8 = 0xFF


def smull_hi(a: int, b: int) -> int:
    prod = s32(a) * s32(b)
    return (prod >> 32) & M32


def step_byte(b: int, s_abs: int, t850: list[int]) -> int:
    w24_sq = (b * b) & M32
    x = (b * 19 + (t850[s_abs % 1256] & M32)) & M32
    return (lcg31(x) + (w24_sq << 7)) & M8


def step_state(S: int, b: int, t868: list[int]) -> int:
    s_abs = abs(s32(S))
    idx_868 = s_abs % 1079
    t868_val = t868[idx_868] & M32

    sb = (S * b) & M32
    sb_sh = (sb << 3) & M32
    w8 = t868_val ^ sb_sh

    w9_const2 = 0xA00000DF
    hi = smull_hi(w8, w9_const2)
    w9 = (hi + w8) & M32
    w10_q = asr32(w9, 27)
    q = (w10_q + ((w9 >> 31) & 1)) & M32
    w10_mod = 0x0CCCCCBB

    S_next = (w8 - (q * w10_mod)) & M32
    return S_next


def tokens_to_lcgbytes(
    tokens: list[int] | bytes,
    S0: int = 9,
    t850: list[int] | None = None,
    t868: list[int] | None = None,
) -> list[int]:
    table850 = t850 if t850 is not None else constants.T850
    table868 = t868 if t868 is not None else constants.T868

    S = S0 & M32
    lcgbytes = []
    for b in tokens:
        s_abs = abs(s32(S))
        out_byte = step_byte(b & 0xFF, s_abs, table850)
        lcgbytes.append(out_byte)
        S = step_state(S, b & 0xFF, table868)
    return lcgbytes


def tap3(lcgbytes: list[int], L: int = 116) -> list[int]:
    """3-tap filter at 0x33bd090: VectorB[i] = |L[i+2]+L[i-1]+L[i-3]| & 0xFF."""
    return [
        abs(lcgbytes[(i + 2) % L] + lcgbytes[(i - 1) % L] + lcgbytes[(i - 3) % L]) & M8
        for i in range(L)
    ]


def tokens_to_vectorB(
    tokens: list[int] | bytes,
    S0: int = 9,
    t850: list[int] | None = None,
    t868: list[int] | None = None,
) -> list[int]:
    if len(tokens) != 116:
        raise ValueError(f"Expected 116 tokens for VectorB, got {len(tokens)}")
    lcg = tokens_to_lcgbytes(tokens, S0, t850=t850, t868=t868)
    return tap3(lcg)
