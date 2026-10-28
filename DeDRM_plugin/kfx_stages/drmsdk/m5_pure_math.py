"""Pure-Python rewrites of two M5 selectors, 0x74 and 0x71.

Closed-form copies of two routines in the 64-bit mobile image (m5_pages):
0x74 (V074 @ 0x33b4258) and 0x71 (V071 @ 0x33a93bc).  Same output as the
native code, no VM.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Final

# 0x74 consts, decrypted by 0x33b5d44 from 0xa59064 (seed), 0xa59074 (digit
# accumulator s78), 0xa59078 (fallback)
_V074_INIT_SEED_BYTES: Final[bytes] = b"#@kunaM@8ata!"
_V074_FALLBACK_DIGIT_STR: Final[bytes] = b"2869"
_V074_ZERO_SEED_FALLBACK: Final[int] = 0x61E7
_V074_RDP_THRESHOLD_I32: Final[int] = 0x0E087BBB


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def _u64(x: int) -> int:
    return x & 0xFFFFFFFFFFFFFFFF


def _s8(x: int) -> int:
    x &= 0xFF
    return x - 0x100 if x & 0x80 else x


def _s32(x: int) -> int:
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x & 0x80000000 else x


def _s64(x: int) -> int:
    x &= 0xFFFFFFFFFFFFFFFF
    return x - 0x10000000000000000 if x & 0x8000000000000000 else x


def _c_div32(a: int, b: int) -> int:
    sa, sb = _s32(a), _s32(b)
    if sb == 0:
        return 0
    q = abs(sa) // abs(sb)
    return _s32(-q if (sa < 0) ^ (sb < 0) else q)


def _c_rem32(a: int, b: int) -> int:
    sa, sb = _s32(a), _s32(b)
    if sb == 0:
        return 0
    return _s32(sa - _c_div32(sa, sb) * sb)


def _c_div64(a: int, b: int) -> int:
    sa, sb = _s64(a), _s64(b)
    if sb == 0:
        return 0
    q = abs(sa) // abs(sb)
    return _s64(-q if (sa < 0) ^ (sb < 0) else q)


def _c_rem64(a: int, b: int) -> int:
    sa, sb = _s64(a), _s64(b)
    if sb == 0:
        return 0
    return _s64(sa - _c_div64(sa, sb) * sb)


def _c_atoi32(raw: bytes) -> int:
    s = raw.decode("latin1", errors="ignore").lstrip()
    if not s:
        return 0
    sign = 1
    idx = 0
    if s[0] in "+-":
        if s[0] == "-":
            sign = -1
        idx += 1
    val = 0
    while idx < len(s) and "0" <= s[idx] <= "9":
        val = val * 10 + (ord(s[idx]) - 0x30)
        idx += 1
    return _u32(sign * val)


# selector 0x74 (V074 @ 0x33b4258)


def _v074_xorshift32_asr17(w: int) -> int:  # 0x33b4d38, asr 17
    w = _u32(w ^ _u32(w << 13))
    w = _u32(w ^ (_s32(w) >> 17))
    return _u32(w ^ _u32(w << 5))


def _v074_xorshift_39bd2_double(w: int) -> int:  # 0x33b56d4 / 0x33b5950
    w8 = _u32(_u32(w ^ _u32(w << 13)) + 0x39BD2)
    w8 = _u32(w8 ^ (_s32(w8) >> 17))
    w11 = _u32(w ^ _u32(w8 << 5) ^ _u32(w << 13))
    w8 = _u32(w11 ^ w8)
    w8 = _u32(w8 ^ (_s32(w8) >> 17))
    w11 = _u32(w8 ^ _u32(w8 << 13))
    w8 = _u32(w8 << 13)
    w12 = _u32(w11 ^ (_s32(w11) >> 17))
    w8 = _u32(w8 ^ _u32(w12 << 5))
    w8 = _u32(w8 ^ (_s32(w11) >> 17))
    return _u32(w8 ^ _u32(w8 << 5))


def _v074_rho_poly(v: int, n: int) -> int:  # 0x7fffffff modulus, 0x33b50f0..0x33b5118
    v2 = _u32(v * v)
    x12 = _u64(v2 + (v2 << 30)) >> 0x3D
    w12 = _u32(x12 | (x12 << 31))
    w11 = _u32(v2 + w12 + 1)
    return _c_rem32(w11, n)


# 0x33b50c8..0x33b5214 / 0x33b5350..0x33b54a0.  Gives up after 0x15 attempts on
# the same n and falls back to x ^ n -- probably fine for the n this sees, but I
# never found where 0x15 comes from.
def _v074_pollard_rho(n_u32: int) -> int:
    n_u32 = _u32(n_u32)
    if n_u32 < 2:
        return 0x7FFE
    attempts = 0
    y = 2
    x = 2
    while True:
        y = _v074_rho_poly(y, n_u32)
        x = _v074_rho_poly(x, n_u32)
        y = _v074_rho_poly(y, n_u32)
        w13 = _s32(n_u32)
        w12 = _s32(x - y)
        if w12 < 0:
            w12 = _s32(-w12)
        while True:
            w23 = w13
            w13 = _c_rem32(w12, w23)
            w12 = w23
            if w13 <= 0:
                break
        if w23 == 1:
            continue
        if w23 != _s32(n_u32):
            return _u32(w23)
        if attempts == 0x15:
            return _u32(x ^ n_u32)
        x = _s32(x + 1)
        y = _s32(y + 1)
        attempts = _s32(attempts + 1)


# 0x33b3494
def _v074_dist_3494(pt: tuple[int, int], p0: tuple[int, int], p1: tuple[int, int]) -> float:
    px, py = pt
    x0, y0 = p0
    x1, y1 = p1
    dx01 = float(_s32(x0 - x1))
    dy01 = float(_s32(y0 - y1))
    if int(dx01 * dx01 + dy01 * dy01) == 0:
        dx = float(_s32(px - x0))
        dy = float(_s32(py - y0))
        return dx * dx + dy * dy
    w12 = _u32(px - x0)
    w15 = _u32(x1 - x0)
    w16 = _u32(y1 - y0)
    w12 = _u32(w15 * w12)
    w15 = _u32(py - y0)
    w12 = _u32(w16 * w15 + w12)
    rx, ry = (x1, y1) if _s32(w12) > 0 else (x0, y0)
    dx = float(_s32(px - rx))
    dy = float(_s32(py - ry))
    return math.sqrt(float(int(dx * dx + dy * dy)))


# 0x33b36e8
def _v074_rdp_36e8(
    pts: list[tuple[int, int]], count: int, threshold_i32: int
) -> list[tuple[int, int]]:
    d9 = float(_s32(threshold_i32))
    p0 = pts[0]
    p1 = pts[count - 1]
    d10 = 0.0
    max_idx = 0
    for i in range(1, count - 1):
        d = _v074_dist_3494(pts[i], p0, p1)
        if d > d10:
            max_idx = i
            d10 = d
    if d10 > d9:
        left = _v074_rdp_36e8(pts, max_idx + 1, threshold_i32)
        right = _v074_rdp_36e8(pts[max_idx:], count - max_idx, threshold_i32)
        return left + right[1:]
    return [p0, p1]


# 13..59+ bytes of V, longer with more lock pairs
def derive_v074_v_pure(
    lock_pairs: Sequence[tuple[str | bytes, str | bytes]] = (),
) -> bytes:
    norm_pairs = [
        (
            k.encode("ascii") if isinstance(k, str) else bytes(k),
            v.encode("ascii") if isinstance(v, str) else bytes(v),
        )
        for k, v in lock_pairs
    ]

    vec_48: list[int] = list(_V074_INIT_SEED_BYTES)
    s78 = bytearray()

    for first_b, second_b in norm_pairs:
        limit = min(len(first_b), len(second_b))
        # s78 takes ASCII digits off both sides while it's under 8 bytes; every
        # pair byte (unsigned) lands in vec_48 either way
        for idx in range(limit):
            c94 = first_b[idx]
            c90 = second_b[idx]
            if len(s78) < 8:
                if 0x30 <= c94 <= 0x39:
                    s78.append(c94)
                if 0x30 <= c90 <= 0x39:
                    s78.append(c90)
            vec_48.append(c94)
            vec_48.append(c90)
        # native rotates vec_48 once per k in 0..n-1 by (k + n // 3) % n, which
        # composes to one net rotation mod n
        n = len(vec_48)
        if n > 0:
            total_rot = sum((k + n // 3) % n for k in range(n)) % n
            if total_rot:
                vec_48 = vec_48[total_rot:] + vec_48[:total_rot]

    if not s78:
        s78.extend(_V074_FALLBACK_DIGIT_STR)

    w28 = _c_atoi32(bytes(s78))
    if w28 == 0:
        w28 = _V074_ZERO_SEED_FALLBACK  # 0x61e7 = 25063

    num_pts = 3 * len(vec_48)
    vec_b0: list[tuple[int, int]] = []
    # 3 * len(vec_48) points (px, py) off the signed-asr17 xorshift32, each
    # coordinate mod 0x7fff
    for _ in range(num_pts):
        w8 = _v074_xorshift32_asr17(w28)
        w28 = _v074_xorshift32_asr17(w8)
        px = _c_rem32(w8, 0x7FFF)
        py = _c_rem32(w28, 0x7FFF)
        vec_b0.append((px, py))

    # polyline reduction (0x33b36e8, metric 0x33b3494); threshold 0x0e087bbb is
    # 235436987.0 read as i32 and cast to float
    vec_c8 = _v074_rdp_36e8(vec_b0, num_pts, _V074_RDP_THRESHOLD_I32)
    half = len(vec_c8) >> 1

    vec_f8: list[int] = []
    # first half of the simplified points goes through Pollard rho (0x33b50e4 /
    # 0x33b5370)
    for pt_x, pt_y in vec_c8[:half]:
        vec_f8.append(_v074_pollard_rho(pt_x))
        vec_f8.append(_v074_pollard_rho(pt_y))

    w28_xor = 0x42021
    n_f8 = len(vec_f8)
    # w28 steps from 0x42021 by the double-xorshift (+0x39bd2); each element
    # gets XORed with vec_f8[abs(w28) % len(vec_f8)] and the low byte is V
    for i in range(len(vec_48)):
        w28_xor = _v074_xorshift_39bd2_double(w28_xor)
        s_val = _s32(w28_xor)
        w8_abs = _u32(-s_val) if s_val < 0 else w28_xor
        f8_idx = w8_abs % n_f8
        vec_48[i] = _u32(vec_48[i] ^ vec_f8[f8_idx])

    return bytes(x & 0xFF for x in vec_48)


# selector 0x71 (V071 @ 0x33a93bc)

# 32 x int64 tables at 0xa58dc8 and 0xa58ec8
_V071_SEED_32_I64: Final[tuple[int, ...]] = (
    -184, 156, -97, 84, -145, 113, 197, -38,
    72, -77, 126, -173, -68, 29, -170, -53,
    167, -50, 91, -136, 7, -162, 138, -16,
    188, 47, -105, 10, 181, -19, 62, -110,
)
_V071_TAB_32_I64: Final[tuple[int, ...]] = (
    -132, 183, -95, 70, -158, 102, 194, -24,
    56, -86, 119, -165, -81, 37, -178, -42,
    153, -63, 88, -141, 11, -199, 130, -9,
    175, 66, -120, 28, 193, -76, 49, -112,
)
# empty vec2f8 fallback: 827509261 (0x3152ca0d) divided by 10, repeatedly
_V071_EMPTY_FALLBACK_VEC2F8: Final[tuple[int, ...]] = (
    827509261, 82750926, 8275092, 827509, 82750, 8275, 827, 82, 8,
)
_V071_HASH_MULT_U64: Final[int] = 0xF1BBCDD800
_V071_HASH_XOR_U64: Final[int] = 0x7FFFFFFA


def _v071_gcd_s64(a: int, b: int) -> int:  # 0x33a9b70..0x33a9b88 / 0x33a9f0c..0x33a9f20
    if b == 0:
        return a
    x3, x4 = a, b
    while True:
        x17 = x4
        x4 = _c_rem64(x3, x4)
        x3 = x17
        if x4 == 0:
            return x17


# 4-word state step, used by 3A (0x33aa318), 3B (0x33aab54) and 3F (0x33aae10)
def _v071_prng1_step(s0: int, s1: int, s2: int, s3: int) -> tuple[int, int, int, int, int]:
    x9 = _u64(s0 + s1)
    x16 = _u64(s1 ^ s3)
    x12 = x9 >> 2
    w17 = _u32(s0 ^ x16)
    s3_new = _u64(x16 | (_s64(x16) >> 17))
    w9 = _u32(x12 | _u32(x9 << 11)) ^ 5
    x12_2 = _u64(s0 ^ s2)
    x14 = _u64(x12_2 ^ s1)
    x15 = (s0 & 0x3FFFFF) << 9
    w9 = _u32((w9 << 3) - w9)
    s2_new = _u64(x15 ^ x12_2)
    out_val = _u32(~w9) & 0x7FFFFFFF
    x12_3 = _u64(0x5A2CE2A9 + _u64(x14 << 23))
    w10 = _u32(x12_3 + w17)
    s1_new = x12_3 & 0x7FACE2A9
    s0_new = w10 & 0x7FFFFFFF
    return out_val, s0_new, s1_new, s2_new, s3_new


# emits sp_a0; 0x33ab2d0..0x33ab3ec / 0x33aba6c..0x33abb0c
def _v071_stage3d_step_pair(x25: int, x22: int) -> tuple[int, int, int]:
    x14 = _u64(x25 * _V071_HASH_MULT_U64)
    w12 = _u32(((x14 >> 17) & 0x1FFFFFF) | _u32(x14))
    w12 = _u32(w12 + _u32(w12 << 3))
    x11_hash = w12 & 0x7FFFFFFF
    sp_a0 = _u64(x11_hash ^ _V071_HASH_XOR_U64)

    x10_xor = _u64(x25 ^ x22)
    w10 = _u32((x10_xor >> 7) | _u32(x10_xor << 16))
    w10 = _u32(w10 ^ _u32(x22 << 11) ^ _u32(x22))
    x25_new = w10 & 0x7FFFFFFF

    x13_eon = _u64(x25_new ^ (~_u64(x22 << 17)))
    w12_2 = _u32((x13_eon >> 21) | _u32(x13_eon))
    x22_new = w12_2 & 0x7FFFFFFF
    return sp_a0, x25_new, x22_new


# 256 bytes of V
def derive_v071_v_pure(
    lock_pairs: Sequence[tuple[str | bytes, str | bytes]] = (),
) -> bytes:
    norm_pairs = [
        (
            k.encode("ascii") if isinstance(k, str) else bytes(k),
            v.encode("ascii") if isinstance(v, str) else bytes(v),
        )
        for k, v in lock_pairs
    ]

    # stage 1 (0x33ac364 .. 0x33ac890 & 0x33ace64 .. 0x33ad218): vec2f8
    vec2f8: list[int] = []
    for _k, second_b in norm_pairs:
        for b in second_b:
            t = b ^ 0x2A
            t = _u32((t << 3) | (t >> 4))
            vec2f8.append(0x7F & (~t))
    if not vec2f8:
        vec2f8 = list(_V071_EMPTY_FALLBACK_VEC2F8)

    # stage 2 (0x33a99e4 .. 0x33aa1dc): sp240 (32 x int64) -> sp7d0 (16 x uint64)
    sp240: list[int] = list(_V071_SEED_32_I64)
    for _k, second_b in norm_pairs:
        ln = len(second_b)
        if ln == 0:
            continue
        limit = max(ln, 32)
        for i in range(limit):
            b = second_b[i % ln]
            idx = i & 0x1F
            x15 = sp240[idx]
            g = _v071_gcd_s64(x15, b)
            prod = _s64(x15 * b)
            q = _c_div64(x15, b)
            lcm = _c_div64(prod, g)
            sp240[idx] = _s64((prod + q) - g + lcm)

    for k in range(32):
        x11 = sp240[k]
        x12 = _V071_TAB_32_I64[(5 * k) & 0x1F]
        g = _v071_gcd_s64(x11, x12)
        lcm = _c_div64(_s64(x12 * x11), g)
        sp240[k] = _s64(lcm + g)

    sp7d0 = [0] * 16
    for k in range(32):
        sp7d0[k >> 1] = _u64((sp7d0[k >> 1] << 8) | (sp240[k] & 0xFF))

    # stage 3A (0x33aa1e0 .. 0x33aa6d8): mat1[16][16]
    s0, s1, s2, s3 = sp7d0[0], sp7d0[1], sp7d0[2], sp7d0[3]
    mat1 = [[0] * 16 for _ in range(16)]
    for r in range(16):
        for c in range(16):
            flat = (r << 4) + c
            if flat < len(vec2f8):
                mat1[r][c] = _u64(_s32(vec2f8[flat]))
            else:
                val, s0, s1, s2, s3 = _v071_prng1_step(s0, s1, s2, s3)
                mat1[r][c] = val

    # stage 3B (0x33aa6e4 .. 0x33aac30 & 0x33abf48): mat2[16][16]
    x25, x22, x_c0, x_148 = sp7d0[1], sp7d0[3], sp7d0[4], sp7d0[7]
    mat2 = [[0] * 16 for _ in range(16)]
    for r in range(16):
        for c in range(16):
            val, x25, x22, x_c0, x_148 = _v071_prng1_step(x25, x22, x_c0, x_148)
            sp28 = val & 0xFF
            sp40 = _u64(x25 ^ x22)
            sp20 = _u64(x_c0 ^ x_148)
            for _ in range(10):
                w12 = _u32((sp40 >> 19) ^ _u32(sp40 << 13))
                w11 = _u32((sp20 >> 15) ^ _u32(sp20 << 17))
                x10 = _u32(w12 * 0x3F6EAF6B) & 0x7FFFFFFF
                x11 = _u32(w11 * 0x6A2A123A) & 0x7FFFFFFE
                sp20 = x11
                sp40 = _u64(x10 + x11)
            w8 = _u32((sp40 >> 11) ^ sp40)
            w8 = _u32(w8 * 0x67B5185B)
            w9 = (w8 >> 13) & 0x3FFFF
            w8 = _u32(w9 ^ w8)
            w8 = _u32(w8 * 0x31F1E2A1)
            x8 = w8 & 0x7FFFFFFF
            x10 = _u64(x8 ^ (x8 >> 15))
            x8 = _u64(x10 - 0x7FFFFFFF) if x10 >= 0x7FFFFFFF else x10
            x8 = _u64(x8 ^ sp28)
            mat2[r][c] = mat1[(x8 >> 4) & 0xF][x8 & 0xF]

    # stage 3C (0x33ad8dc quadrant split, 0x33ad5e8 submatrix product, 0x33ad788
    # elementwise max): recursive combine -> mat3[16][16]
    mat3 = [[0] * 16 for _ in range(16)]

    def _fill_mat3(r0: int, c0: int, h: int, w: int) -> None:
        if h <= 2 and w <= 2:
            for dr in range(h):
                for dc in range(w):
                    x3 = mat1[r0 + dr][c0 + dc]
                    x4 = mat2[r0 + dr][c0 + dc]
                    m3 = _u32(_c_rem64(x3, 17))
                    m4 = _u32(_c_rem64(x4, 17))
                    w5 = _u32(_u32(x3 * x3) + m3 + _u32(m4 * 17))
                    w3_diff = _u32(x4 - x3)
                    mat3[r0 + dr][c0 + dc] = _u32(_u32(w3_diff * _u32(x4)) + w5) & 0x7FFFFFFF
            return
        hh = h >> 1
        hw = w >> 1
        _fill_mat3(r0, c0, hh, hw)
        _fill_mat3(r0, c0 + hw, hh, hw)
        _fill_mat3(r0 + hh, c0, hh, hw)
        _fill_mat3(r0 + hh, c0 + hw, hh, hw)
        for dr in range(hh):
            for dc in range(hw):
                acc = 0
                for k in range(hw):
                    prod = _u32(_u32(mat1[r0 + dr][c0 + k]) * _u32(mat2[r0 + k][c0 + dc])) & 0x7FFFFFFF
                    acc = _u64(acc + prod)
                c1 = acc & 0x7FFFFFFF
                a_cell = mat1[r0 + dr][c0 + dc]
                b_cell = mat2[r0 + dr][c0 + dc]
                c2 = a_cell if _s64(a_cell) > _s64(b_cell) else b_cell
                mat3[r0 + dr][c0 + dc] = _u64(mat3[r0 + dr][c0 + dc] + _u64(c1 - c2))

    _fill_mat3(0, 0, 16, 16)

    # stage 3D (0x33aaef8 .. 0x33abb38): fold sp7d0[8..11] and the lock pairs into
    # mat_final[16][16], arithmetic right shift by (row + col)
    x25, x22, x_c0, x_148 = sp7d0[8], sp7d0[9], sp7d0[10], sp7d0[11]
    mat_final = [[0] * 16 for _ in range(16)]
    for x16 in range(16):
        for w15 in range(16):
            x8 = sp7d0[x16] ^ sp7d0[w15] ^ x_148 ^ x22 ^ mat3[x16][w15] ^ (x_c0 ^ x25)
            x8 = _u64(x8 | mat_final[x16][w15])
            shift = (x16 + w15) & 0x3F
            x8 = (_s64(x8) >> shift) & 0x7FFFFFFF
            mat_final[w15][x16] = _u64(mat_final[w15][x16] ^ x8)

            sp_a0, x25, x22 = _v071_stage3d_step_pair(x25, x22)
            if norm_pairs:
                p_idx = _s8(sp_a0 % len(norm_pairs))
                vb = norm_pairs[p_idx][1]
                ch_hash, x25, x22 = _v071_stage3d_step_pair(x25, x22)
                if len(vb) > 0:
                    b = vb[ch_hash % len(vb)]
                    mat_final[w15][x16] = _u64(mat_final[w15][x16] | b)

    # stage 3E (0x33ab634 .. 0x33ab86c): 3x3 block transpose-XOR with vec2f8
    n_2f8 = len(vec2f8)
    for w9_blk in range(0, 16, 3):
        for w10_blk in range(0, 16, 3):
            for w0 in range(w9_blk, min(w9_blk + 3, 16)):
                for w17 in range(w10_blk, min(w10_blk + 3, 16)):
                    w8 = _u32(w0 + (w17 << 4) + _u32(w10_blk + w9_blk))
                    idx = _u64(_s64(_s32(w8))) % n_2f8
                    v_val = _u64(_s32(vec2f8[idx]))
                    mat_final[w0][w17] = _u64(mat_final[w17][w0] ^ v_val)

    # stage 3F (0x33aaecc .. 0x33abde0): pull V out
    out_v = bytearray()
    for _ in range(256):
        val, x25, x22, x_c0, x_148 = _v071_prng1_step(x25, x22, x_c0, x_148)
        idx8 = val & 0xFF
        out_v.append(mat_final[(idx8 >> 4) & 0xF][idx8 & 0xF] & 0xFF)

    return bytes(out_v)
