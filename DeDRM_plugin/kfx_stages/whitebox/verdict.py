"""Stage 3 (state), stage 5 (VectorA/VectorB mixing) and stage 6 (fills tensor).
"""

from __future__ import annotations

from . import constants

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF
MAGIC = 0x20C49BA5E353F7CF

MUL = 0x8FC1B
FMIX = 0x10B44EFF
DIV = 1079


def _s32(x: int) -> int:
    x &= M32
    return x - (1 << 32) if x >= (1 << 31) else x


def _s64(x: int) -> int:
    x &= M64
    return x - (1 << 64) if x >= (1 << 63) else x


def _asr32(x: int, n: int) -> int:
    return (_s32(x) >> n) & M32


def _fold32(a: int) -> int:
    a &= M32
    return ((a & 0x7FFFFFFF) + _asr32(a, 31)) & M32


def _srem(v: int, d: int) -> int:
    v = _s32(v)
    return v - int(v / d) * d


def lcg31(x24: int) -> int:
    w24_s = _s32(x24)
    w8 = w24_s >> 15
    w10 = x24 & 0x7FFF
    p9 = (w8 * 0x7E0D8000) & 0x7FFF8000
    m = (w10 * MUL + p9 + (_s32(w8 * MUL) >> 16)) & M32
    return _s32(_fold32(m))


def fn_c1810_pure(x: int) -> int:
    prod = (x * 0x30154F00) & M64
    neg = (-prod) & M64
    res = ((neg + 0x7FFFFFFF) if _s64(neg) <= 0 else neg) & 0x7FFFFFFF
    return 0x7FFFFFFF if res == 0 else res


# 256 words of 64 bits out of VectorB and the 57-char voucher ID
def compute_state(vecB: list[int] | bytes, voucher_id: str | bytes) -> list[int]:
    v_b = voucher_id.encode("ascii") if isinstance(voucher_id, str) else bytes(voucher_id)
    if len(v_b) != 57:
        raise ValueError(f"Expected 57-char voucher ID, got {len(v_b)}")

    x24 = 0x00987ABE
    w22 = 0
    for k in range(len(vecB)):
        val = vecB[k]
        val_s = _s32(val)
        prod = val_s * 0x55555556
        q_s = _s32((prod >> 32) + ((prod >> 63) & 1))
        rem_s = _s32(val_s - q_s * 3)
        if rem_s == 1:
            di = w22 % len(v_b)
            diff = ((val & 0x6AEFF) ^ v_b[di]) & M32
            x24 = (x24 + diff) & M64
        elif rem_s in (2, -1):
            idx = w22 % len(vecB)
            x24 = (x24 + _s32(vecB[idx] ^ val)) & M64
        else:
            di = (w22 ^ 0x929) % len(v_b)
            x0 = fn_c1810_pure(x24)
            x24 = (x24 + ((x0 ^ v_b[di]) & M64)) & M64
        x24_s = _s64(x24)
        prod64 = (x24_s * 0x1C71C71C71C71C72) >> 64
        q9_ws = _s32(prod64 + ((prod64 >> 63) & 1))
        rem9 = _s32(x24) - q9_ws * 9
        w22 = (w22 + rem9) & M32

    state = [0] * 256
    for i in range(256):
        if i % 5 == 4:
            x24_s = _s64(x24)
            q3 = x24_s // 3 if x24_s >= 0 else -((-x24_s) // 3)
            x8 = (state[(i >> 1) + 1] * 6 + q3) & M64
            x24 = (x8 + state[i - 1] * 2) & M64
        elif i % 3 == 1:
            x24 = (fn_c1810_pure(x24) * state[i - 1]) & M64
        elif i != 0:
            x11 = _s64(x24) >> 3
            x24 = ((x11 + lcg31(x24)) + state[i - 1]) & M64
        x24_s = _s64(x24)
        q7 = x24_s // 7 if x24_s >= 0 else -((-x24_s) // 7)
        rem7 = x24_s - q7 * 7
        word = (lcg31(x24) if rem7 <= 4 else fn_c1810_pure(x24)) & M64
        if i % 11 == 5:
            word = (-3 * word) & M64
        elif i % 5 == 1:
            word = (-word) & M64
        state[i] = word
    return state


# VectorA (60) and VectorB (116) -> VectorC (116)
def mix_vectorC(vecA: list[int], vecB: list[int]) -> list[int]:
    la, lb = len(vecA), len(vecB)
    return [
        ((vecA[i % la] + vecA[(la + i - 1) % la]) ^ (vecB[i % lb] ^ vecB[(lb + i - 1) % lb])) & M32
        for i in range(lb)
    ]


# non-linear transform, the 0..114 tail of the fills tensor
def transform(c: int) -> int:
    pre = _s32(c)
    rem = pre % 3
    if rem == 0:
        scaled = (pre * 2004) & M64
        prod = (scaled * MAGIC) >> 64
        w8 = (prod >> 7) + ((prod >> 63) & 1)
        return (w8 ^ ((pre % 100) << 1)) & M32
    if rem == 1:
        return (-((pre // 2) * ((pre % 1000) ^ (pre % 1526)))) & M32
    return pre % 19


def hash_law(z: int, tbl: list[int]) -> int:
    # fills tensor 116..161
    r = _fold32((z * MUL) & M32)
    k = abs(_srem(r, DIV))
    q = FMIX % (z + 2)
    w25 = (q * MUL) & M32
    val = (tbl[k] + _asr32(w25, 31) + (w25 & 0x7FFFFFFF)) & M32
    return val


# 162 ints: 0..n-2 transform, n-1 stays 0, n..161 hashlaw
def fills_tensor(vecC: list[int], t868: list[int] | None = None) -> list[int]:
    n = len(vecC)
    if n > 162:
        raise ValueError(f"vecC too wide for the fills tensor: {n}")
    tbl = t868 if t868 is not None else constants.T868
    t = [0] * 162
    for i in range(n - 1):
        t[i] = transform(vecC[i]) & M32
    if n > 0:
        t[n - 1] = 0
    for i in range(n, 162):
        t[i] = hash_law(i, tbl) & M32
    return t
