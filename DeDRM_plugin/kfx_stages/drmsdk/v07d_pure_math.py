"""Pure-Python law for the 64-bit mobile M5 selector 0x7d.

From the 64-bit mobile image (m5_pages, entry 0x33daaa4); ranges are native body
offsets.

1. 0x33dab08..0x33dc0f8: vec_w[0] = the 42-wchar seed from 0xa6dac4 (key
   0x6447c23f via 0x33decf8); vec_str = the lock_pairs values, then fallback
   0xa6dbd0 (41 B, 0 pairs) and 0xa6dba0 (22 B, <= 1 pair).
2. 0x33db914..0x33dbe84: per string, T850/T868/T880 lookups + pow(idx + ch, 3.0) +
   modexp 0x33c07f0(ch + 10, abs(T850[ch - 13]), 256,
   ceil(pow(idx + ch, 3.0)), abs(T850[10])) + log(abs(w26)).
3. 0x33dc10c..0x33dc658: the 5-word 31-bit PRNG 0x33b7724 swaps total_chars
   character pairs across adjacent vec_w entries; flatten to v_in, N = 42 + total_chars.
4. 0x33dc65c..0x33dcbbc: 0x8fc1b LCG + quadratic byte filter -> v_e0;
   v90[i] = c_srem32(v_e0[(i+2)%N] + v_e0[(i-1)%N] + v_e0[(i-3)%N], 256).
5. 0x33dcbc0..0x33dd358: v90 folds into x19 (seed 0x7abfedff); 0x33c1810 builds
   the 256-element int64 v60, issuance_blob mixes in over 256 steps (mod-5 switch
   0x33de84c / 0x36723ec / 0x33de954).
6. 0x33df34c, 0x33d5f0c, 0x33d8798: v60 -> v1 (evens) / v2 (odds), 128 doubles
   each; solve 0x33d5f0c(0.3, v1, v2) -> v3, then 0x33d8798 at 60 steps
   d8 = 0.07 .. 19.27 (step 0.32) -> int32 v48[60].
7. 0x33dd458..0x33dd524, 0x33e0600, 0x33e143c: v48 (mod 60) + v90 (mod N) ->
   v78[0..N-1]; recursive split/reverse/parity-merge 0x33e0600 -> v18[0..N-1].
8. 0x33dd528..0x33dd88c: 2 x 9 x 9 int32 tensor (w19 = 3, w20 = 9, w28 = 2);
   v18[0..N-2] into cells 0..N-2, cell N-1 stays 0; cells N..161 =
   T880[abs(c_srem32(lcg_8fc1b_signed(idx), 1079))] + rng.next().
9. 0x33dd88c..0x33de848: faces {'x':1,'r':2,'p':3,'z':4,'y':7,'q':9} + reserve
   [5, 8, 6]; w_bc from issuance_blob; 8-way cube-slice / cross-plane machine
   (0x33d96b0, 0x33cbc70, 0x33c741c, 0x33c9aac, 0x33d9e5c) until the 162 low
   bytes come out as V.
"""

from __future__ import annotations

import math
import struct
from collections.abc import Sequence
from typing import Final

from ..whitebox.constants import T850 as _T850, T868 as _T868, T880 as _T880, T898 as _T898

# Pre-decrypted static constants from m5_pages:
# - 0xa6dac4 (count=0x2b, key=0x6447c23f via 0x33decf8): 42-wchar initial seed
_V07D_SEED_WCHARS: Final[tuple[int, ...]] = tuple(
    b"Rk_N_Rl_witA^Sein#gat**@!JQVVa&lw\\M39Z#/\\/"
)
# - 0xa6dbd0 (count=11, key=0xef642b36 via 0x33decf8): 41-byte fallback when lock_pairs is empty
_V07D_FALLBACK_STR0: Final[bytes] = b"Abra#Ka&Dabra1!^JQVVa&lw\\M39Z#/\\87bHSqW\\/"
# - 0xa6dba0 (count=6, key=0xcce95406 via 0x33decf8): 22-byte fallback when len(lock_pairs) <= 1
_V07D_FALLBACK_STR1: Final[bytes] = b"He_#$MwQA(Ni*>?;k<QU\\/"

# Face keys at 0xa6dbb8 ('x', 'p', 'z', 'y', 'r', 'q')
_V07D_FACE_KEYS: Final[tuple[int, ...]] = (0x78, 0x70, 0x7A, 0x79, 0x72, 0x71)

# Pre-decrypted 3-character face-cycle suffixes (0xa66494..0xa664d0 via 0x33c929c)
_V07D_VEC6_C741C: Final[tuple[bytes, ...]] = (b"zqp", b"qpz", b"pzq", b"pqz", b"zqp", b"qpz")
_V07D_VEC6_C9AAC: Final[tuple[bytes, ...]] = (b"yzr", b"yrz", b"zyr", b"zry", b"ryz", b"rzy")
_V07D_VEC6_CBC70: Final[tuple[bytes, ...]] = (b"yqr", b"yrq", b"qyr", b"qry", b"ryq", b"rqy")

# IEEE-754 double constants from rodata (0x875c38..0x87acd8)
_D8_PARAM_030: Final[float] = struct.unpack("<d", struct.pack("<Q", 0x3FD3333333333333))[0]
_D_STEP_032: Final[float] = struct.unpack("<d", struct.pack("<Q", 0x3FD47AE147AE147B))[0]
_D_START_007: Final[float] = struct.unpack("<d", struct.pack("<Q", 0x3FB1EB851EB851EC))[0]
_D_LIMIT_1927: Final[float] = struct.unpack("<d", struct.pack("<Q", 0x4033451EB851EB85))[0]
_D_CLAMP_303: Final[float] = struct.unpack("<d", struct.pack("<Q", 0x40083D70A3D70A3D))[0]
_D_THRESH_002: Final[float] = struct.unpack("<d", struct.pack("<Q", 0x3F947AE147AE147B))[0]
_D_DIV_145: Final[float] = struct.unpack("<d", struct.pack("<Q", 0x3FF7333333333333))[0]


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def _s32(x: int) -> int:
    x &= 0xFFFFFFFF
    return x - 0x100000000 if (x & 0x80000000) else x


def _u64(x: int) -> int:
    return x & 0xFFFFFFFFFFFFFFFF


def _s64(x: int) -> int:
    x &= 0xFFFFFFFFFFFFFFFF
    return x - 0x10000000000000000 if (x & 0x8000000000000000) else x


def _c_sdiv32(a: int, b: int) -> int:
    a, b = _s32(a), _s32(b)
    if b == 0:
        return 0
    q = abs(a) // abs(b)
    return _s32(-q if (a < 0) ^ (b < 0) else q)


def _c_srem32(a: int, b: int) -> int:
    a, b = _s32(a), _s32(b)
    if b == 0:
        return 0
    return _s32(a - _c_sdiv32(a, b) * b)


def _c_sdiv64(a: int, b: int) -> int:
    a, b = _s64(a), _s64(b)
    if b == 0:
        return 0
    q = abs(a) // abs(b)
    return _s64(-q if (a < 0) ^ (b < 0) else q)


def _c_srem64(a: int, b: int) -> int:
    a, b = _s64(a), _s64(b)
    if b == 0:
        return 0
    return _s64(a - _c_sdiv64(a, b) * b)


def _fcvtps_s32(d: float) -> int:
    if math.isnan(d):
        return 0
    if d >= 2147483647.0:
        return 0x7FFFFFFF
    if d <= -2147483648.0:
        return -0x80000000
    return int(math.ceil(d))


def _frinta(d: float) -> float:
    if math.isnan(d) or math.isinf(d):
        return d
    return math.floor(d + 0.5) if d >= 0.0 else math.ceil(d - 0.5)


def _normalize_pairs(
    lock_pairs: Sequence[tuple[str | bytes, str | bytes]] | None,
) -> list[tuple[bytes, bytes]]:
    if not lock_pairs:
        return []
    out: list[tuple[bytes, bytes]] = []
    for k, v in lock_pairs:
        kb = k.encode("ascii") if isinstance(k, str) else bytes(k)
        vb = v.encode("ascii") if isinstance(v, str) else bytes(v)
        out.append((kb, vb))
    return out


def _fn_33c07f0(x0: int, x1: int, x2: int, x3: int, x4: int) -> int:
    x0, x1, x2, x3, x4 = _u64(x0), _u64(x1), _u64(x2), _u64(x3), _u64(x4)
    if x3 == 0:
        x3 = 0x1FFFFFFF
    q = _u64(_c_sdiv64(x0, x3))
    r = _u64(x0 - _u64(q * x3))
    x5 = _s64(_u64(r * x1) - _u64(q * x4))
    return _u64(x5) if x5 > 0 else _u64(x5 + x2)


def _fn_33c1810(x0: int) -> int:
    return _fn_33c07f0(x0, 0x4FEAB0FF, 0x7FFFFFFF, 1, 0x30154F00) & 0x7FFFFFFF


class _Rng33b7724:
    __slots__ = ("s0", "s1", "s2", "s3", "s4")

    def __init__(self) -> None:
        self.s0 = 0x4FEAB0FF
        self.s1 = 0x7FFFFFFF
        self.s2 = 1
        self.s3 = 0x30154F00
        self.s4 = 0x3797

    def next(self) -> int:
        self.s4 = _fn_33c07f0(self.s4, self.s0, self.s1, self.s2, self.s3) & 0x7FFFFFFF
        return self.s4


def _lcg_8fc1b_signed(w8: int) -> int:
    w8 = _s32(w8)
    w9 = w8 >> 15
    w8_low = w8 & 0x7FFF
    w11 = _u32(w9 * 0x7E0D8000) & 0x7FFF8000
    w9_m = _s32(w9 * 0x8FC1B)
    w8_new = _s32(w8_low * 0x8FC1B + w11 + (w9_m >> 16))
    return _s32((w8_new & 0x7FFFFFFF) + (w8_new >> 31))


def _lcg_8fc1b_signed_raw(w8: int) -> int:
    w8 = _s32(w8)
    w9 = w8 >> 15
    w8_low = w8 & 0x7FFF
    w10 = _u32(w9 * 0x7E0D8000) & 0x7FFF8000
    w9_mul = _s32(w9 * 0x8FC1B)
    return _s32(w8_low * 0x8FC1B + w10 + (w9_mul >> 16))


def _lcg_8fc1b_unsigned_raw(w10: int) -> int:
    w10 = _u32(w10)
    w11 = w10 >> 15
    w10_low = w10 & 0x7FFF
    w12 = _u32(w11 * 0x7E0D8000) & 0x7FFF8000
    w11_mul = _u32(w11 * 0x8FC1B)
    w8 = _u32(w10_low * 0x8FC1B + w12 + (w11_mul >> 16))
    return _u32((w8 & 0x7FFFFFFF) + (w8 >> 31))


def _phase1_and_2(
    norm_pairs: list[tuple[bytes, bytes]],
) -> tuple[list[list[int]], int]:
    vec_w: list[list[int]] = [list(_V07D_SEED_WCHARS)]
    vec_str: list[bytes] = [v for _k, v in norm_pairs]
    if len(norm_pairs) == 0:
        vec_str.append(_V07D_FALLBACK_STR0)
        vec_str.append(_V07D_FALLBACK_STR1)
    elif len(norm_pairs) == 1:
        vec_str.append(_V07D_FALLBACK_STR1)

    w4_const = _u32(abs(_T850[10]))
    for idx_s, s in enumerate(vec_str):
        w13 = idx_s + 1
        w108 = idx_s
        len_s = len(s)
        w24 = 0xD
        ws: list[int] = []
        for ch in s:
            w27 = ch
            w10 = ((w24 + (w27 << 2)) | w13) & 0x7FFFFFFF
            w8 = _s32(abs(_T880[w10 % 2743]) * len_s - w24)
            w9 = 0x7FFFFFFF if w8 == -0x80000000 else (_s32(-w8) if w8 < 0 else w8)
            w8_b = _T868[_u32(w9) % 1079]
            w9_c = _T850[w27 - 13] if w27 >= 13 else 0
            w19 = _u32(-w9_c) if w9_c < 0 else _u32(w9_c)
            w10_base = _s32(w108 + w27)
            w8_m = _s32(w8_b * w24 + w13)
            w26 = _s32(w8_m * w13 + _s32(w24 * w24))
            d0 = math.pow(float(w10_base), 3.0)
            w9_pow = _fcvtps_s32(d0)
            w0 = _fn_33c07f0(_u64(w27 + 10), w19, 0x100, _u64(w9_pow), w4_const)
            ws.append((w26 + w27 + w0) & 0xFF)

            d1 = float(_s32(w27))
            d0_add = float((_u32(w27) >> 1) & 0x38)
            w19_rem = _c_srem32(w24, 256)
            w8_abs26 = _s32(-w26) if w26 < 0 else w26
            w21 = _fcvtps_s32(d1 * 37.5 + d0_add)
            w8_log = _fcvtps_s32(math.log(float(w8_abs26)))
            w24 = _s32(w19_rem + w21 + w8_log + 1)
        vec_w.append(ws)

    total_chars = sum(len(s) for s in vec_str)
    return vec_w, total_chars


def _phase3_and_4(
    vec_w: list[list[int]], total_chars: int
) -> tuple[list[int], _Rng33b7724]:
    rng = _Rng33b7724()
    n_w = len(vec_w)
    for _ in range(total_chars):
        w19 = rng.next()
        w0 = rng.next()
        wa = vec_w[w19 % n_w]
        wb = vec_w[(w19 + 1) % n_w]
        pa = w0 % len(wa)
        pb = w0 % len(wb)
        wa[pa], wb[pb] = wb[pb], wa[pa]

    v_in = [ch for w in vec_w for ch in w]
    v_e0: list[int] = []
    w21 = 9
    for w10 in v_in:
        w24 = _s32(-w21) if w21 < 0 else w21
        w8 = _s32(w10 * 19 + _T850[_u32(w24) % 1256])
        w9 = w8 >> 15
        w8_low = w8 & 0x7FFF
        w11 = _u32(w9 * 0x7E0D8000) & 0x7FFF8000
        w9_m = _s32(w9 * 0x8FC1B)
        w8_new = _s32(w8_low * 0x8FC1B + w11 + (w9_m >> 16))
        w10_sign = w8_new >> 31
        w8_pos = w8_new & 0x7FFFFFFF
        w9_sq = _s32(w10 * w10)
        w10_sum = _s32(_s32(w10_sign + (w9_sq << 7)) + w8_pos)
        v_e0.append(_c_srem32(w10_sum, 256))

        w8_x = _s32(_T868[_u32(w24) % 1079] ^ _s32(_s32(w21 * w10) << 4))
        x9 = (w8_x << 30) + w8_x
        w9_hi = _s32((x9 >> 61) + (_u64(x9) >> 63))
        w9_hi = _s32(w9_hi + (w9_hi << 31))
        w21 = _s32(w8_x + w9_hi)

    n = len(v_e0)
    v90: list[int] = []
    for i in range(n):
        s_tap = _s32(v_e0[(i + 2) % n] + v_e0[(i + n - 1) % n] + v_e0[(i + n - 3) % n])
        v90.append(_c_srem32(s_tap, 256))

    return v90, rng


def _phase5(v90: list[int], blob: bytes) -> list[int]:
    blob_len = len(blob)
    blob_data = blob

    x19 = 0x7ABFEDFF
    x10 = 0
    for w14 in v90:
        w14_low = w14 & 0x7FFF
        rem = x10 if blob_len == 0 else (x10 % blob_len)
        b_val = blob_data[rem] if rem < len(blob_data) else 0
        w13 = _u32(w14_low ^ b_val)
        x19 = _u64(x19 + w13)
        x13 = x19 % 11
        x10 = _u64(x10 + x13)

    v60: list[int] = [0] * 256
    for k in range(256):
        rem7 = _c_srem32(k, 7)
        if rem7 < 4:
            rem3 = _c_srem32(k, 3)
            if rem3 == 1:
                w8 = _lcg_8fc1b_signed(_u32(x19))
                x19 = _u64((x19 << 2) + _s64(w8) + v60[k - 1])
            elif k > 0:
                x0 = _fn_33c1810(x19)
                x19 = _u64(x0 * _u64(v60[k - 1]))
        else:
            q3 = _c_sdiv64(x19, 3)
            x8 = v60[(k // 2) + 1]
            x9 = v60[k - 1]
            x19 = _u64(q3 + (x9 << 1) + ((x8 >> 2) * 3))

        rem5 = _s64(x19) - _c_sdiv64(x19, 5) * 5
        if rem5 > 2:
            val = _s64(_lcg_8fc1b_signed(_u32(x19)))
        else:
            val = _s64(_fn_33c1810(x19))
        if rem7 == 4:
            val = _s64(-val)
        v60[k] = val

    for b8 in range(256):
        rem5 = _c_srem32(_fn_33c1810(_u32((b8 + 1) ** 2)), 5)
        if rem5 == 0:
            w8 = _T898[b8]
            idx = abs(_c_srem32(w8, blob_len)) if blob_len else 0
        elif rem5 == 1:
            w8_2 = _T868[abs(_c_srem32(_T898[b8 + 5], 1079))]
            w10 = 0x7FFFFFFF if w8_2 == -0x80000000 else abs(w8_2)
            idx = (w10 % blob_len) if blob_len else 0
        elif rem5 in (2, 3) or ((v60[b8] & 1) != 0):
            w8 = _T868[b8 + 5]
            idx = abs(_c_srem32(w8, blob_len)) if blob_len else 0
        else:
            continue
        if idx < blob_len:
            v60[b8] ^= blob[idx]

    return v60


def _phase6(v60: list[int]) -> list[int]:
    v1 = [0.0] * 128
    v2 = [0.0] * 128
    w26 = 0
    w27 = 0
    for w24 in range(256):
        if (w24 & 1) == 0:
            if w24 == 0:
                v1[w26] = float(_s64(v60[0] + 1))
            else:
                w8 = _u32(v60[w24])
                v1[w26] = float((w8 * w8) & 0xFF)
            w26 += 1
        else:
            if w24 == 1:
                x8 = _s64(v60[1])
                v2[w27] = float(_s64(_u64(x8 << 1) | _u64(x8 >> 2)))
            elif _c_srem32(w24, 3) != 2:
                x8 = _s64(v60[w24] - v60[w24 - 1])
                v2[w27] = float(_c_srem64(x8, 255))
            else:
                x8 = _s64(_s64(v60[w24 - 2] + v60[w24 - 1]) * _s64(v60[w24]))
                v2[w27] = float(_c_srem64(x8, 257))
            w27 += 1

    A = [0.0] * 128
    B = [0.0] * 128
    C = [0.0] * 128
    D = [0.0] * 128
    A[0] = B[0] = C[0] = A[127] = B[127] = C[127] = 1.0
    D[0] = D[127] = 0.0

    for i in range(1, 127):
        A[i] = _frinta(v1[i] - v1[i - 1])
        B[i] = float(math.ceil((v1[i - 1] * -7.0) * v1[i] + v1[i + 1] * 7.0))
        C[i] = float(math.ceil(v1[i] * v2[i - 1] + v1[i + 1]))
        D[i] = float(math.ceil(v1[i - 1] * v1[i + 1] + v1[i] * (v1[i] * -2.0)))

    for k in range(1, 127):
        denom_b = B[k - 1] if B[k - 1] >= 3.0 else 3.0
        B[k] = B[k] + float(math.ceil(((A[k] + C[k]) * _D8_PARAM_030) / denom_b))
        denom_d = B[k - 1] if B[k - 1] >= 5.0 else 5.0
        D[k] = D[k] - float(math.ceil((D[k - 1] * _D8_PARAM_030) / denom_d))

    v3 = [0.0] * 128
    v3[127] = D[127] / (7.0 if B[127] == 0.0 else B[127])
    for k in range(126, -1, -1):
        v3[k] = (A[k] * v3[k + 1] + D[k]) / (5.0 if B[k] == 0.0 else B[k])

    d8 = _D_START_007
    v48 = [0] * 60
    k = 0
    while d8 < _D_LIMIT_1927:
        w25 = 0
        while w25 < 127 and v1[w25 + 1] < d8:
            w25 += 1
        d10 = v1[w25]
        d9 = v1[w25 + 1]
        diff = d9 - d10
        d11 = diff if diff >= 3.0 else 3.0
        d16 = v2[w25]
        d17 = v2[w25 + 1]
        d12 = v3[w25]
        d13 = v3[w25 + 1]
        d14 = d9 - d8
        d15 = d8 - d10
        term1 = ((d11 * d12) / -6.0 + (d16 / d11)) * d14
        term2 = (d13 / (d11 * _D_DIV_145)) * math.pow(d15, 3.0)
        v1_next = v1[(w25 + 1) % 128]
        term3 = (d12 / (d11 * d11)) * math.pow(d9 * v1_next - d8, 5.0)
        term4 = ((d17 / d11) + (d11 * d13) / -6.0) * d15
        d0 = (term1 + (term2 + term3)) + term4

        d9_val = _D_CLAMP_303 if d0 > _D_CLAMP_303 else d0
        w_sp0 = _fcvtps_s32((math.log(abs(d9_val)) * 100.0) * d8)
        w_sp8 = w_sp0 if w_sp0 > 0x51 else 0x51
        d1_sq = float(_s32(_s32(w_sp8 * w_sp8) * 100))
        w_sp4 = _fcvtps_s32((d8 * d8) * 99.0 + d1_sq)
        frac = d9_val - math.floor(d9_val)
        w_pick = w_sp8 if frac > _D_THRESH_002 else w_sp4
        rot = _c_srem32(k, 32)
        w9_rot = _s32(_u32(w_pick << rot) | _u32(_s32(w_pick) >> ((~rot) & 31)))
        v48[k] = _c_srem32(w9_rot, 256)
        k += 1
        d8 = d8 + _D_STEP_032
    return v48


def _fn_33e143c(a: list[int], b: list[int]) -> list[int]:
    a = list(a)
    b = list(b)
    out: list[int] = []
    while a and b:
        if ((len(a) | len(b)) & 1) == 0:
            out.append(b.pop(0))
        else:
            out.append(a.pop(0))
    out.extend(a)
    out.extend(b)
    return out


def _fn_33e0600(vec: list[int]) -> list[int]:
    n = len(vec)
    if n <= 1:
        return list(vec)
    mid = n // 2
    left = list(vec[:mid])
    right = list(vec[mid:])
    w14 = _s32(vec[mid])
    if (w14 & 1) != 0 and 16 <= n <= 25:
        right.reverse()
    if (mid & 1) == 0 and ((n * 4) & ~0xF) == 0x40:
        left.reverse()
    w8 = _lcg_8fc1b_signed(w14)
    rem25 = _c_srem32(w8, 25)
    if rem25 < 22:
        return _fn_33e143c(right, left)
    l_res = _fn_33e0600(left)
    r_res = _fn_33e0600(right)
    return _fn_33e143c(l_res, r_res)


def _phase7(v48: list[int], v90: list[int]) -> list[int]:
    n = len(v90)
    v78 = [0] * n
    v78[0] = _s32((v48[0] + v48[59]) ^ v90[0] ^ v90[n - 1])
    v78[1] = _s32((v48[1] + v48[0]) ^ v90[1] ^ v90[0])
    for i in range(2, n):
        a = v48[_c_srem32(i, 60)]
        b = v48[_c_srem32(59 + i, 60)]
        c = v90[_c_srem32(i, n)]
        d = v90[_c_srem32(i - 1 + n, n)]
        v78[i] = _s32(_s32(a + b) ^ c ^ d)
    return _fn_33e0600(v78)


def _phase8(
    v18: list[int], rng: _Rng33b7724
) -> tuple[list[list[list[int]]], int, int, int]:
    n = len(v18)
    d12 = float(n)
    w19 = _fcvtps_s32(math.exp(math.log(d12 / 18.0) * 0.5))
    w20 = 3 * w19
    w8_p = _fcvtps_s32(d12 / (float(w19) * 9.0 * float(w19)))
    w28 = w8_p if w8_p > 2 else 2
    total_cells = w28 * w20 * w20
    tensor = [[[0 for _ in range(w20)] for _ in range(w20)] for _ in range(w28)]

    for idx in range(n - 1):
        plane = _c_sdiv32(idx, w20 * w20)
        row = _c_srem32(_c_sdiv32(idx, w20), w20)
        col = _c_srem32(idx, w20)
        tensor[plane][row][col] = _s32(v18[idx])

    for idx in range(n, total_cells):
        w22 = abs(_c_srem32(_lcg_8fc1b_signed(idx), 1079))
        w0 = rng.next()
        plane = _c_sdiv32(idx, w20 * w20)
        row = _c_srem32(_c_sdiv32(idx, w20), w20)
        col = _c_srem32(idx, w20)
        tensor[plane][row][col] = _s32(_T880[w22] + w0)

    return tensor, w19, w20, w28


def _box_coords(face_idx: int, w19: int) -> tuple[int, int]:
    idx0 = face_idx - 1
    q = _s32((idx0 * 0x55555556) >> 32)
    q = _s32(q + (_u32(q) >> 31))
    r = _s32(idx0 - q * 3)
    return _s32(q * w19), _s32(r * w19)


# 90-degree sub-box rotation: cw=True (0x33d0fec = vertical flip 0x33cfa04 + transpose
# 0x33cedc4) or cw=False (0x33ce85c = horizontal flip 0x33d1700 + transpose 0x33cedc4)
def _rotate_box(
    tensor: list[list[list[int]]], w19: int, r_in: int, c_in: int, plane: int, cw: bool
) -> None:
    w28 = w19 * w19
    r_start = _c_sdiv32(_c_srem32(r_in, w28), w19) * w19
    c_start = _c_sdiv32(_c_srem32(c_in, w28), w19) * w19
    grid = tensor[plane]
    if cw:
        for i in range(w19 // 2):
            r1, r2 = r_start + i, r_start + w19 - 1 - i
            for j in range(w19):
                c = c_start + j
                grid[r1][c], grid[r2][c] = grid[r2][c], grid[r1][c]
    else:
        for i in range(w19):
            r = r_start + i
            for j in range(w19 // 2):
                c1, c2 = c_start + j, c_start + w19 - 1 - j
                grid[r][c1], grid[r][c2] = grid[r][c2], grid[r][c1]
    for i in range(w19):
        for j in range(i + 1, w19):
            r1, c1 = r_start + i, c_start + j
            r2, c2 = r_start + j, c_start + i
            grid[r1][c1], grid[r2][c2] = grid[r2][c2], grid[r1][c1]


def _select_cycle_str(vec6: tuple[bytes, ...], w4: int, w5: int) -> bytearray:
    w0 = _fn_33c1810(_lcg_8fc1b_unsigned_raw(_u32(w4 * w4 + 1)))
    rem6 = _c_srem32(w0, 6)
    s = bytearray(b"x" + vec6[-rem6 if rem6 < 0 else rem6])
    if (w5 & 1) != 0:
        s.reverse()
    return s


def _cycle_plane0(
    tensor: list[list[list[int]]],
    face_map: dict[int, int],
    w19: int,
    w4: int,
    w5: int,
    *,
    use_tbl: bool,
) -> None:
    s = _select_cycle_str(_V07D_VEC6_C9AAC if use_tbl else _V07D_VEC6_C741C, w4, w5)

    for k in range(w19):
        col_off = w19 - 1 - k
        r_last, c_last = _box_coords(face_map[s[-1]], w19)
        r_prev = r_last + w4
        c_prev = c_last + col_off
        saved_val = tensor[0][r_prev][c_prev]
        for i in range(len(s) - 2, -1, -1):
            r_i, c_i = _box_coords(face_map[s[i]], w19)
            w12 = tensor[0][r_i + w4][c_i + col_off]
            if use_tbl:
                w15 = tensor[0][r_prev][c_prev]
                abs_w15 = (
                    0x7FFFFFFF
                    if w15 == -0x80000000
                    else _u32(-w15 if w15 < 0 else w15)
                )
                w12 = _s32(_T868[abs_w15 % 1079] ^ w12)
            tensor[0][r_prev][c_prev] = w12
            r_prev = r_i + w4
            c_prev = c_i + col_off
        r_first, c_first = _box_coords(face_map[s[0]], w19)
        tensor[0][r_first + w4][c_first + col_off] = saved_val

    rem = _c_srem32(w4, w19)
    if rem == 0:
        r0, c0 = _box_coords(face_map[0x78 if use_tbl else 0x79], w19)
        _rotate_box(tensor, w19, r0, c0, 0, cw=use_tbl)
    elif rem == w19 - 1:
        rq, cq = _box_coords(face_map[0x71], w19)
        _rotate_box(tensor, w19, rq, cq, 0, cw=not use_tbl)


def _fn_33c741c(
    tensor: list[list[list[int]]],
    face_map: dict[int, int],
    w19: int,
    w4: int,
    w5: int,
) -> None:
    _cycle_plane0(tensor, face_map, w19, w4, w5, use_tbl=False)


def _fn_33c9aac(
    tensor: list[list[list[int]]],
    face_map: dict[int, int],
    w19: int,
    w4: int,
    w5: int,
) -> None:
    _cycle_plane0(tensor, face_map, w19, w4, w5, use_tbl=True)


def _fn_33cbc70(
    tensor: list[list[list[int]]],
    face_map: dict[int, int],
    w19: int,
    w4: int,
    w5: int,
) -> None:
    w_74 = _s32(w19 * w4 + w19)
    s = _select_cycle_str(_V07D_VEC6_CBC70, w4, w5)

    w8_init = _s32(w_74 * s[-1])
    lcg_init = _lcg_8fc1b_signed_raw(w8_init)
    plane = (lcg_init + (_u32(lcg_init) >> 31)) & 1
    plane_saved = plane

    for k in range(w19):
        row_off = w19 - 1 - k
        d8 = float(k * k + 1) / 2.0
        r_last, c_last = _box_coords(face_map[s[-1]], w19)
        r_prev = r_last + row_off
        c_prev = c_last + w4
        saved_val = tensor[plane][r_prev][c_prev]

        w8_exp = _s32(_s32(r_prev * r_prev) * c_prev + c_prev)
        try:
            exp_val = math.exp(float(w8_exp) * d8)
        except OverflowError:
            exp_val = math.inf
        w9_exp = _fcvtps_s32(exp_val)
        lcg_e = _lcg_8fc1b_signed_raw(w9_exp)
        plane_alt = (lcg_e + (_u32(lcg_e) >> 31)) & 1

        for i in range(len(s) - 2, -1, -1):
            r_i, c_i = _box_coords(face_map[s[i]], w19)
            v_prev = tensor[plane][r_prev][c_prev]
            idx1 = 0x7FFFFFFF if v_prev == -0x80000000 else _u32(-v_prev if v_prev < 0 else v_prev)
            t1 = _c_srem32(_s32(_T850[idx1 % 1256] ^ v_prev), 256)

            v_curr = tensor[plane][r_i + row_off][c_i + w4]
            v_add = _s32(v_curr + i)
            idx2 = 0x7FFFFFFF if v_add == -0x80000000 else _u32(-v_add if v_add < 0 else v_add)
            t2 = _c_srem32(_s32(_T868[idx2 % 1079] ^ v_curr), 256)

            tensor[plane_alt][r_prev][c_prev] = t2
            tensor[plane][r_i + row_off][c_i + w4] = t1
            r_prev = r_i + row_off
            c_prev = c_i + w4
            plane ^= 1
            plane_alt ^= 1

        r_first, c_first = _box_coords(face_map[s[0]], w19)
        tensor[plane_saved][r_first + row_off][c_first + w4] = saved_val

    rem = _c_srem32(w4, w19)
    if rem == 0:
        rp, cp = _box_coords(face_map[0x70], w19)
        _rotate_box(tensor, w19, rp, cp, plane, cw=False)
    elif rem == w19 - 1:
        rz, cz = _box_coords(face_map[0x7A], w19)
        _rotate_box(tensor, w19, rz, cz, plane, cw=True)


def _fn_33d96b0(tensor: list[list[list[int]]], w19: int, rng: _Rng33b7724) -> None:
    w28 = rng.next()
    w22 = rng.next()
    w20 = 3 * w19
    r0 = _c_srem32(w28, w20)
    r1 = _c_srem32(w22, w20)
    for c in range(w20):
        tensor[0][r0][c], tensor[1][r1][c] = tensor[1][r1][c], tensor[0][r0][c]


def _fn_33d9e5c(
    tensor: list[list[list[int]]],
    v60: list[int],
    w19: int,
    rng: _Rng33b7724,
) -> None:
    w9 = tensor[0][0][0]
    w10 = tensor[0][w19][w19 + 3]
    w8 = tensor[1][w19 + 1][w19 + 2]
    w28 = _lcg_8fc1b_signed(_s32(w9 * w10 + w8))
    b1 = _c_srem32(w28, 9) + 1
    w0 = rng.next()
    b2 = _c_srem32(w0, 9) + 1
    r_a, c_a = _box_coords(b1, w19)
    r_b, c_b = _box_coords(b2, w19)

    for w12 in range(w19):
        w16 = tensor[1][r_a][c_b]
        w13 = tensor[0][r_a + w12][c_a]
        idx = abs(_c_srem32(w16, 2743))
        w_sp8 = _s32(_lcg_8fc1b_signed(_T880[idx]) ^ w13)

        w14 = tensor[1][w19 - 1 - w12 + r_b][c_b]
        w15 = _u32(v60[w12])
        w15 = _s32(w15 - _s32(w15 << 2))
        tensor[0][r_a + w12][c_a] = _s32(_s32(w14 * w14) + w15)
        tensor[1][w19 - 1 - w12 + r_b][c_b] = w_sp8


def _phase9(
    tensor: list[list[list[int]]],
    v60: list[int],
    rng: _Rng33b7724,
    w19: int,
    w20: int,
    w28: int,
    blob: bytes,
) -> bytes:
    blob_len = len(blob)
    blob_data = blob

    face_map = {
        0x78: 1,  # 'x'
        0x72: 2,  # 'r'
        0x70: 3,  # 'p'
        0x7A: 4,  # 'z'
        0x79: 7,  # 'y'
        0x71: 9,  # 'q'
    }
    arr3 = [5, 8, 6]

    acc_88 = 0
    for idx_b in range(blob_len):
        w20_b = blob_data[idx_b] if idx_b < len(blob_data) else 0
        w0 = rng.next()
        r6 = _c_srem32(w0, 6) + 1
        acc_88 = _s32(acc_88 + (2 if (r6 & w20_b) == 0 else 5))

    w8_5 = _s32(acc_88 * 5)
    w9_sh = _s32(w8_5 << 3)
    x9_m = (w9_sh * _s32(0x824A4E61)) >> 32
    w8_s = _s32(_s32(x9_m) + w9_sh)
    w_bc = _s32((w8_s >> 8) + (_u32(w8_s) >> 31) + 60)

    w_e0 = 1
    w_e4 = 0
    w10_74 = w19 & 0x7FFF

    while w_e4 < w_bc:
        sw = _c_srem32(w_e0, 8)
        if sw < 0:
            sw = -sw

        if sw == 0:
            _fn_33d96b0(tensor, w19, rng)
            w_bc = (w_bc if w_bc < 99 else 99) + 1
        elif sw == 1:
            w8 = _lcg_8fc1b_signed(_s32(w_e0 * w_e4 + w_e0))
            w4 = _c_srem32(w8, w19)
            _fn_33cbc70(tensor, face_map, w19, w4, 0)
            w_bc = (w_bc if w_bc > 61 else 61) - 1
        elif sw == 2:
            w8 = _lcg_8fc1b_signed(_s32(_s32(w_e0 + 2) * _s32(w_e4 + 5)))
            w4 = _c_srem32(w8, w19)
            _fn_33c741c(tensor, face_map, w19, w4, 0)
        elif sw == 3:
            w8 = _lcg_8fc1b_signed(_s32(_s32(w_e4 + 3) * w_e0 + _s32(w_e4 + 3)))
            w4 = _c_srem32(w8, w19)
            _fn_33c9aac(tensor, face_map, w19, w4, 0)
            w_bc = (w_bc if w_bc < 99 else 99) + 1
        elif sw == 4:
            w8 = _lcg_8fc1b_signed(_s32(w_e0 * w_e4 + w_e0))
            w4 = _c_srem32(w8, w19)
            _fn_33cbc70(tensor, face_map, w19, w4, 1)
        elif sw == 5:
            w8 = _lcg_8fc1b_signed(_s32(_s32(w_e0 + 9) * _s32(w_e4 + 5)))
            w4 = _c_srem32(w8, w19)
            _fn_33c741c(tensor, face_map, w19, w4, 1)
            w_bc = (w_bc if w_bc < 99 else 99) + 1
        elif sw == 6:
            w8 = _lcg_8fc1b_signed(_s32(_s32(_s32(w_e4 + 4) * _s32(w_e4 + 3)) * _s32(w_e0 + 6)))
            w4 = _c_srem32(w8, w19)
            _fn_33c9aac(tensor, face_map, w19, w4, 1)
        elif sw == 7:
            _fn_33d9e5c(tensor, v60, w19, rng)

        w8_m = _s32(_s32(w_e4 * w19) * _s32(w10_74 ^ _s32(w_e0 << 3)))
        w9_orr = _s32(9 | _s32(w_e4 << 6))
        d0 = math.log(float(w9_orr)) * 4.0 + float(w8_m)
        w8_ceil = _fcvtps_s32(d0)
        w8_lcg = _lcg_8fc1b_signed(w8_ceil)
        idx6 = _c_srem32(w8_lcg, 6)
        w11 = _s32(w_e4 * w_e4 + 3)
        w9_m2 = _s32(_s32(w11 * w19) * idx6 + tensor[0][0][0] + 1)
        w9_lcg2 = _lcg_8fc1b_signed(w9_m2)
        w22 = _c_srem32(w9_lcg2, 3)
        face_ch = _V07D_FACE_KEYS[idx6]
        w20_old = arr3[w22]
        arr3[w22] = face_map[face_ch]
        face_map[face_ch] = w20_old

        _ = rng.next()
        w0_2 = rng.next()
        rem256 = w0_2 % 256
        w_e0 = _s32(w_e0 + _u32(v60[rem256]) + 5)
        w_e4 += 1

    out = bytearray()
    for p in range(w28):
        for r in range(w20):
            for c in range(w20):
                out.append(tensor[p][r][c] & 0xFF)
    return bytes(out)


def derive_v07d_v_pure_math(
    lock_pairs: Sequence[tuple[str | bytes, str | bytes]] | None = (),
    issuance_blob: bytes | None = None,
) -> bytes:
    norm_pairs = _normalize_pairs(lock_pairs)
    blob = bytes(issuance_blob) if issuance_blob is not None else bytes(range(64))
    vec_w, total_chars = _phase1_and_2(norm_pairs)
    v90, rng = _phase3_and_4(vec_w, total_chars)
    v60 = _phase5(v90, blob)
    v48 = _phase6(v60)
    v18 = _phase7(v48, v90)
    tensor, w19, w20, w28 = _phase8(v18, rng)
    return _phase9(tensor, v60, rng, w19, w20, w28, blob)
