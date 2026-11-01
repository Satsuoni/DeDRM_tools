"""Pure-Python lifts of the Windows key derivation producers. Plain math only,
no instruction decoding, no interpreter stepping.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
import hashlib
import math
import struct

M64 = 0xFFFFFFFFFFFFFFFF
M32 = 0xFFFFFFFF

TABLE_V2746_VA = 0x180A8C6B0
TABLE_V3332_VA = 0x180A8C400
TABLE_V2746_SHA16 = "9f75e1ae09acca97"
TABLE_V3332_SHA16 = "2f3bc6f0c98f6e9b"

# 169 signed 32-bit words, 676 bytes each (1,352 both), out of 0x180a8c400 (V3332,
# producer 2) and 0x180a8c6b0 (V2746, producer 1).
TABLE_V3332_WORDS: tuple[int, ...] = (
    829926615, -1630652, 268393, 740274147, -2310771, 302335, 719885386, -2694800, 368425, 215278653, -2135126, 300971, 783368690,
    -3266965, 207331, 18788390, -1090892, 271042, 304089172, -1040354, 336667, 521595368, -842829, 312205, 336465782, -1209704,
    244014, 233665123, -1086349, 300959, 27, -30, 22545, 51, -27, 28119, 54, -154, 19505,
    53, -262, 1123, 54, -189, 2499, 22, -348, 15714, 40, -164, 10611, 8,
    -177, 1293, 14, -186, 14518, 55, -77, 2487, 1061, 282853, -45828602, 845, 259799,
    -31630933, 2366, 12546, -7605546, 1655, 7037, -41798687, 2145, 26821, -16426186, 1222, 309879, -35388385,
    1309, 278245, -35005211, 1449, 26955, -25657687, 1914, 220358, -16984594, 702, 66256, -10661166, -98562,
    33, 16708, -137638, 21, 59055, -82362, 62, 68641, -93127, 53, 41707, -128767, 18,
    72290, -118555, 64, 28311, -102958, 15, 53704, -50393, 52, 48998, -122492, 41, 84687,
    -69741, 26, 49956, 1804289383, -7450, 599599848, 1714636915, -3281, 424238335, 719885386, -7608, 596516649, 1189641421,
    -7226, 268397098, 783368690, -3787, 962804834, 1967513926, -4020, 458290497, 304089172, -6040, 35005211, 521595368, -4971,
    644863500, 336465782, -2930, 278722862, 233665123, -4327, 468703135, 206455, 70, -49593, 175231, 67, -17450,
    922, 58, -5398, 520525, 71, -45799, 93590, 37, -88047, 218326, 21, -85251, 251296,
)

TABLE_V2746_WORDS: tuple[int, ...] = (
    60577497, 7792270, -2317426, 35005211, 27767198, -175557, 829926615, -1630652, 268393, 740274147, -2310771, 302335, 719885386,
    -2694800, 368425, 215278653, -2135126, 300971, 783368690, -3266965, 207331, 18788390, -1090892, 271042, 304089172, -1040354,
    336667, 521595368, -842829, 312205, 336465782, -1209704, 244014, 233665123, -1086349, 300959, -1352, 297, -474495,
    -93, -543, 2, 109, -38, 29, 4071436, -392, -19, 41, -108, 157, 73,
    -107, -876, 297, 721, -284, 7, 13, -175, 38, 523, -97, 8739, -298,
    36, 74, -19, 1945, 4713, 469713, -5120245, 2382618, -469713, 498828, 4234600, 4738322, 3012283,
    3289097, 5653822, 3516855, 67, 3248926, -2031080, 4601003, 4848292, -3826460, -70125, 3483979, 4534964, -1489775,
    -4115709, 1859517, 986941, -3642892, 5720305, 1552230, 958, 4783483, -2912949, 3785412, 5664036, 549970, -2352699,
    -539874, 2275107, -4181453, 2516098, -2050557, 11620189, 966, -445953, 220745920, -7249, 701731, 122328988, 6380,
    -985485, -293306824, 6330, -332731, 185812292, 7931, 312431, -174844732, -124, -1032114, 5310973, 2040, 606299,
    222817169, -3559, 561033, -37687583, 1370, -306668, 233665123, 563, 17959, 26507971, -631756, 201886848, 35621137,
    -448043, 424238335, 28525948, -1900512, 103248006, 4453813, -3678302, 363952741, 42626435, -2704009, 71823191, 41584063, -663000,
    60577497, 7792270, -2317426, 35005211, 27767198, -175557, 247150500, 40168880, -3537830, 278722862, 36133855, -1464817, 468703135,
)


def load_table_169(family: str = "0x77") -> tuple[list[int], str]:
    """Mutable copy of the 169-word table; it's checked against the sha16 here."""
    if family in ("0x77", "0x83", "V3332", "2f3bc6f0c98f6e9b"):
        words = list(TABLE_V3332_WORDS)
        want_sha = TABLE_V3332_SHA16
    elif family in ("0x79", "0x84", "0x87", "0x89", "V2746", "9f75e1ae09acca97"):
        words = list(TABLE_V2746_WORDS)
        want_sha = TABLE_V2746_SHA16
    else:
        raise ValueError(f"unknown family {family!r}")
    raw = struct.pack("<169i", *words)
    h = hashlib.sha256(raw).hexdigest()[:16]
    if h != want_sha:
        raise RuntimeError(f"table sha16 mismatch {h} != {want_sha}")
    return words, h

_K_ACSR_8A = bytes(b ^ (0x2E - i) for i, b in enumerate(b"ACCOUNT_SECRET"))
_K_CID_8A = bytes(b ^ (0x2F - i) for i, b in enumerate(b"CLIENT_ID"))
_K_VID_8A = bytes(b ^ (0x2F - i) for i, b in enumerate(b"voucherId"))


def _u64(x: int) -> int:
    return x & M64


def _s64(x: int) -> int:
    v = x & M64
    return v - 0x10000000000000000 if v >= 0x8000000000000000 else v


def _s8(b: int) -> int:
    b &= 0xFF
    return b - 0x100 if b & 0x80 else b


def _s32(x: int) -> int:
    x &= M32
    return x - 0x100000000 if x & 0x80000000 else x


def _c_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("division by zero")
    q = abs(a) // abs(b)
    return -q if (a < 0) ^ (b < 0) else q


def _c_rem(a: int, b: int) -> int:
    return a - _c_div(a, b) * b


def _cvttsd2si64(x: float) -> int:
    if math.isnan(x) or math.isinf(x):
        return -0x8000000000000000
    t = int(x)
    if t < -0x8000000000000000 or t >= 0x8000000000000000:
        return -0x8000000000000000
    return t


def _cvttsd2si32(x: float) -> int:
    if math.isnan(x) or math.isinf(x):
        return -0x80000000
    t = int(x)
    if t < -0x80000000 or t >= 0x80000000:
        return -0x80000000
    return t


def _rol64(v: int, c: int) -> int:
    v &= M64
    c &= 63
    if c == 0:
        return v
    return ((v << c) | (v >> (64 - c))) & M64


def _normalize_lock_pairs(
    lock_pairs: Sequence[tuple[str | bytes, str | bytes]] | None,
) -> list[tuple[bytes, bytes]]:
    if not lock_pairs:
        return []
    out: list[tuple[bytes, bytes]] = []
    for k, v in lock_pairs:
        kb = k.encode("utf-8") if isinstance(k, str) else bytes(k)
        vb = v.encode("utf-8") if isinstance(v, str) else bytes(v)
        out.append((kb, vb))
    return out


# Producer 4: 0x1801d04d0 -> 0x18023fe40, selector 0x8a
def _gf256_mul_23fd30(edx: int, r8d: int) -> int:
    """GF(2^8) multiply mod 0x11b, from 0x18023fd30."""
    res = 0
    for i in range(7, -1, -1):
        res = (res * 2) ^ ((res >> 7) * 0x11B) ^ (((r8d >> i) & 1) * edx)
    return res & 0xFF


def _simd_nibble_pass_8a(buf: list[int]) -> None:
    """Per 64-bit lane: nibble swap, then 4-step shift-XOR. 0x18023f7a2,
    0x18023fc40."""
    mask5 = 0x0F0F0F0F0F0F0F0F
    mask6 = 0xFF0F0F0F0F0F0F0F
    for i in range(32):
        w = buf[i]
        x = (((w & mask6) << 4) & M64) | ((w >> 4) & mask5)
        a = ((x << 1) & M64) ^ x
        a = ((a << 1) & M64) ^ x
        a = ((a << 1) & M64) ^ x
        a = ((a << 1) & M64) ^ x
        buf[i] = a


# the 256-byte mixers, all in place: 0x18023f480, 0x18023f8e0, 0x18023fac0
def _f480_8a(buf: list[int], r14: int, r9b: int) -> None:
    r9b &= 0xFF
    r12 = (r9b * 0x85EBCA6B3D83917F) & M64
    not_eax = _s32(~r9b) & M64
    r13 = (not_eax * 0xBF58476D1CE4E5B9) & M64
    for edi in range(3):
        r9 = ((edi * 0x9E3779B9) & M32) ^ r14
        for p in range(16):
            u0 = buf[2 * p]
            u1 = buf[2 * p + 1]
            c0 = ((2 * p + 1) * r9) & M64
            c1 = ((2 * p + 2) * r9) & M64
            buf[2 * p] = (c0 ^ (u1 >> 23) ^ ((u0 << 17) & M64) ^ r12) & M64
            buf[2 * p + 1] = (c1 ^ ((u1 << 23) & M64) ^ (u0 >> 17) ^ r13) & M64
        _simd_nibble_pass_8a(buf)

    r8 = 0
    for r11d in range(32):
        rax = buf[r11d]
        rdx = (((rax * 0x1B) & M64) ^ (rax >> 8) ^ r8 ^ r14) & M64
        ecx = r11d & 7
        eax = (r9b << ecx) & M32
        rcx = _s32(eax) & M64
        r8 = (r8 + 0x41C64E6D) & M64
        buf[r11d] = (rcx ^ (rdx >> 19) ^ ((rdx << 13) & M64)) & M64


def _f8e0_8a(buf: list[int], r8_arg: int, r9b_arg: int) -> None:
    r9b_arg &= 0xFF
    for r15d in range(3):
        ebp_outer = 32 - r15d
        rax = (((r8_arg << (ebp_outer & 63)) & M64) ^ (r8_arg >> (r15d & 63))) & M64
        r12 = rax >> 8
        r13 = rax >> 16
        rot0 = (rax & 7) + 7
        rot1 = (r12 & 7) + 9
        rot2 = (r13 & 7) + 13
        rot3 = ((rax >> 24) & 7) + 18
        r8_sh = (rax << 8) & M64
        for k in range(8):
            rdx = 4 * k
            ebp = 4 * k + 1
            idx0 = rdx
            idx1 = ebp & 0x1F
            idx2 = (ebp + 1) & 0x1F
            idx3 = (ebp + 2) & 0x1F
            rbx = buf[idx0]
            rsi = buf[idx3]
            rdi = _rol64(((rsi + rbx) & M64) ^ rax, rot0) ^ buf[idx1]
            r9_v = _rol64(((rdi + rbx) & M64) ^ r13, rot1) ^ buf[idx2]
            rdx_v = _rol64(((r9_v + rdi) & M64) ^ r8_sh, rot2)
            rsi ^= rdx_v
            r8_v = (((_s32(r15d + ebp) & M64) * r8_arg) & M64) ^ r9b_arg
            rdx_v2 = _rol64(((rsi + r9_v) & M64) ^ r12, rot3) ^ (r9_v >> 17) ^ r8_v
            rbx ^= rdx_v2
            rdi ^= (r8_v >> 16) ^ ((rsi << 23) & M64)
            buf[idx0] = rbx
            buf[idx1] = rdi
            buf[idx2] = (((r8_v << 8) & M64) ^ (rbx >> 29) ^ r9_v) & M64
            buf[idx3] = ((r8_v >> 24) ^ ((rdi << 31) & M64) ^ rsi) & M64


def _fac0_8a(buf: list[int], r12: int, rdx_byte: int) -> None:
    rdx_byte &= 0xFF
    for eax_iter in range(5):
        r15d_outer = 32 - eax_iter
        rdi = ((r12 >> (r15d_outer & 63)) ^ ((r12 << (eax_iter & 63)) & M64)) & M64
        rbp = rdi >> 16
        rot0 = (rdi & 7) + 16
        rot1 = ((rdi >> 8) & 7) + 12
        rot2 = (rbp & 7) + 8
        rot3 = ((rdi >> 24) & 7) + 4
        for k in range(8):
            esi = 4 * k + 1
            u0, u1, u2, u3 = buf[4 * k], buf[4 * k + 1], buf[4 * k + 2], buf[4 * k + 3]
            rbx = (((_s32(esi) & M64) * r12) & M64) ^ rdx_byte
            rdx_v = ((u0 + u1) & M64) ^ rdi
            r11 = _rol64(rdx_v ^ u3, rot0)
            r8_v = ((u2 + r11) & M64) ^ rbp
            r9_v = _rol64(r8_v ^ u1, rot1)
            rdx_v = ((rdx_v + r9_v) & M64) ^ rbx
            rbx >>= 16
            r11 = _rol64(r11 ^ rdx_v, rot2)
            r8_v = ((r8_v + r11) & M64) ^ rbx
            buf[4 * k] = rdx_v
            buf[4 * k + 1] = _rol64(r8_v ^ r9_v, rot3)
            buf[4 * k + 2] = r8_v
            buf[4 * k + 3] = r11
        _simd_nibble_pass_8a(buf)


def derive_v0x8a_v_pure_math(
    lock_pairs: Sequence[tuple[str | bytes, str | bytes]] | None = None,
    word: bytes | str = b"HmacSHA256",
) -> bytes:
    """Producer 4, selector 0x8a."""
    word_bytes = word.encode("utf-8") if isinstance(word, str) else bytes(word)
    pairs = _normalize_lock_pairs(lock_pairs)
    all_pairs = list(pairs) + [(b"voucherId", word_bytes)]
    all_pairs.sort(key=lambda item: item[0])

    s_acsr = b""
    s_cid = b""
    s_vid = b""
    for k, v in all_pairs:
        if k == _K_ACSR_8A:
            s_acsr = v
        elif k == _K_CID_8A:
            s_cid = v
        elif k == _K_VID_8A:
            s_vid = v

    r13d = 0
    for s in (s_vid, s_acsr, s_cid):
        for b in s:
            r13d = (r13d * 31 + _s8(b)) & M32
    r12b = r13d & 3

    buf240 = bytearray(256)
    rbx = 0
    if r12b == 0:
        for k, v in all_pairs:
            if not k:
                continue
            for i, kb in enumerate(k):
                if rbx >= 256:
                    break
                cl = v[i % len(v)] if v else 0xA5
                buf240[rbx] = (cl ^ kb ^ 0xA5) & 0xFF
                rbx += 1
    elif r12b == 1:
        for k, _v in all_pairs:
            if not k:
                continue
            for i, kb in enumerate(k):
                if rbx >= 256:
                    break
                r8b = (i // 7) & 0xFF
                cl1 = ((i & 0xFF) - ((r8b * 7) & 0xFF) + 1) & 0x1F
                dl = (kb << cl1) & 0xFF
                r8b_next = (r8b + 1) & 0xFF
                cl2 = (((r8b_next * 7) & 0xFF) - (i & 0xFF)) & 0x1F
                r9b = (kb >> cl2) & 0xFF
                buf240[rbx] = (dl | r9b) ^ 0x96
                rbx += 1
    elif r12b == 2:
        for k, v in all_pairs:
            if not k:
                continue
            for i, kb in enumerate(k):
                if rbx >= 256:
                    break
                al = v[i % len(v)] if v else 0x2F
                edi = _gf256_mul_23fd30(al, 0x2F)
                eax = _gf256_mul_23fd30(kb, 0x83)
                buf240[rbx] = (edi ^ eax) & 0xFF
                rbx += 1
    else:
        eax_fib = 1
        r11_fib = 1
        for k, v in all_pairs:
            if not k:
                continue
            for i, kb in enumerate(k):
                if rbx >= 256:
                    break
                r9d = (eax_fib + r11_fib) & M32
                r8b = v[i % len(v)] if v else 0
                buf240[rbx] = (r8b ^ kb ^ (r9d & 0xFF)) & 0xFF
                rbx += 1
                eax_fib = r11_fib & 0xFF
                r11_fib = r9d & 0xFF

    r10 = 0x9E3779B97F4A7C15
    for b in s_vid:
        rcx = ((_s8(b) & M64) << 13) & M64
        rax = (r10 * 0x85EBCA6B3D83917F) & M64
        r10 = rcx ^ rax

    rsi = 1
    for k, v in all_pairs:
        r8 = 0x0123456789ABCDEF
        rdx = 0xFEDCBA9876543210
        for b in k:
            rcx = ((_s8(b) & M64) * 0x9E3779B97F4A7C15) & M64
            r8 = (rcx ^ (r8 >> 27) ^ ((r8 << 5) & M64)) & M64
        for b in v:
            rcx = ((_s8(b) & M64) * 0xBF58476D1CE4E5B9) & M64
            rdx = (rcx ^ (rdx >> 25) ^ ((rdx << 7) & M64)) & M64
        rax = (rsi + 1) & M64
        rdx = (rdx * rax) & M64
        r8 = (r8 * rsi) & M64
        r10 ^= rdx ^ r8
        rsi = rax

    if rbx < 256:
        rdx_step = 0x41C64E6D3B83917F
        r8_mul = 0xBF58476D1CE4E5B9
        rcx = (rbx * rdx_step) & M64
        while rbx < 256:
            r10 ^= r10 >> 29
            r10 = (r10 * r8_mul) & M64
            r10 ^= (r10 >> 32) ^ rcx
            buf240[rbx] = (((rbx & 0xFF) << 3) ^ (r10 & 0xFF)) & 0xFF
            rbx += 1
            rcx = (rcx + rdx_step) & M64

    buf100 = list(struct.unpack("<32Q", buf240))

    r8d = 0x9E3779B9
    for b in s_vid:
        r8d = ((r8d >> 31) ^ ((r8d << 1) & M32) ^ b) & M32
    for b in s_acsr:
        r8d = ((r8d >> 29) ^ ((r8d << 3) & M32) ^ b) & M32
    for b in s_cid:
        r8d = ((r8d >> 27) ^ ((r8d << 5) & M32) ^ b) & M32

    edx_q = ((r8d * 0xAAAAAAAB) >> 34) & M32
    dl_m = ((edx_q & 0xFF) * 6) & 0xFF
    perm_idx = (r8d - dl_m) & 0xFF
    rdi = (r13d | 1) & M32

    perms = {
        0: (_fac0_8a, _f8e0_8a, _f480_8a),
        1: (_fac0_8a, _f480_8a, _f8e0_8a),
        2: (_f8e0_8a, _fac0_8a, _f480_8a),
        3: (_f8e0_8a, _f480_8a, _fac0_8a),
        4: (_f480_8a, _fac0_8a, _f8e0_8a),
        5: (_f480_8a, _f8e0_8a, _fac0_8a),
    }
    # anything outside 0..5 leaves the matrix untouched here
    for fn in perms.get(perm_idx, ()):
        fn(buf100, rdi, r12b)

    buf240_u64 = [buf100[(k - 16) & 0x1F] ^ buf100[k] for k in range(32)]

    rsi = (~rdi) & M64
    r12 = r12b & 0xFF
    r14 = (rdi << 4) & M64
    r15 = rdi
    for pair_idx in range(16):
        rbx_w = buf240_u64[2 * pair_idx]
        r11_w = buf240_u64[2 * pair_idx + 1]
        r10_v = r12 ^ r15
        cl1 = (r10_v & 7) + 24
        r8d_v = (r10_v >> 8) & 0xF
        rdi = _rol64(((rdi + rbx_w) & M64) ^ r10_v, cl1) ^ (rbx_w >> (r10_v & 0x1F)) ^ rsi
        r9d_v = r10_v & 0xF
        rsi = (
            _rol64(((rsi + r11_w) & M64) ^ (r10_v >> 16), r8d_v + 16)
            ^ ((r11_w << r9d_v) & M64)
            ^ rdi
        )
        rdx_out = _rol64(rdi, 32) ^ (r11_w >> r9d_v) ^ rdi
        rax_out = _rol64(rsi, 16) ^ ((rbx_w << r9d_v) & M64) ^ rsi
        buf240_u64[2 * pair_idx] = rdx_out
        buf240_u64[2 * pair_idx + 1] = rax_out
        r15 = (r15 + r14) & M64

    return struct.pack("<32Q", *buf240_u64)


# producer 1: 0x1801a6be0, family="0x79" / V2746 {0x77, 0x83}
# producer 2: 0x1801baff0, family="0x77" / V3332 {0x79, 0x84, 0x87, 0x89}
_P1_PERM13 = (5, 1, 13, 8, 3, 9, 11, 2, 4, 6, 7, 10, 12)
_P1_PERM10 = (5, 1, 8, 3, 9, 2, 4, 6, 7, 10)
_P2_PERM10 = (6, 7, 10, 8, 3, 9, 5, 1, 2, 4)

_P1_TAB68 = (
    -1352, 297, 67, -93, -543, 2, 109, -38, 29, 958, -392, -19, 41, -108, 157, 73,
    -107, -876, 297, 721, -284, 7, 13, -175, 38, 523, -97, 8739, -298, 36, 74, -19,
    1945, 4713, 469713, -5120245, 2382618, -469713, 498828, 4234600, 4738322, 3012283,
    3289097, 5653822, 3516855, -474495, 3248926, -2031080, 4601003, 4848292, -3826460,
    -70125, 3483979, 4534964, -1489775, -4115709, 1859517, 986941, -3642892, 5720305,
    1552230, 4071436, 4783483, -2912949, 3785412, 5664036, 549970, -2352699,
)
_P1_KERN9 = (2, 1, -3, -1, -2, 4, 2, 0, -1)
_P1_DR8 = (1, 0, 0, 1, -1, -1, -1, 1)
_P1_DC8 = (1, 1, -1, 0, 0, -1, 1, -1)

_P2_TAB68 = (
    2023, 284, -2613, 3103, 139, -9805, 8206, 10, -90324, 4153, 114, -13735, 6686, 221,
    -60551, 2062, 224, -71829, 3940, 160, -8678, 6884, 235, -58542, 8294, 296, -50204,
    1627, 207, -9514, 152079, 1410, -16763, 38859, 2059, -62809, 36958, 4938, -17525,
    104657, 411, -47675, 292986, 3496, -30159, 6766, 1944, -25956, 126988, 5733, -42065,
    68520, 4333, -55549, 300886, 4332, -43866, 391819, 4434, -35723, 103399, -4, 15995,
    79987, -722, 10607, 13450, -849,
)
_P2_KERN9 = (1, -5, -3, -2, -1, 3, -4, 5, 2)
_P2_DR8 = (-1, 1, 1, 0, 0, 1, -1, -1)
_P2_DC8 = (1, -1, 1, 1, -1, 0, 0, -1)

_P2_EE6F0_DR8 = (0, 1, -1, -1, -1, 1, 1, 0)
_P2_EE6F0_DC8 = (-1, 0, 0, -1, 1, -1, 1, 1)

_P1_DIV16 = (7, 5, 3, 11, 9, 6, 10, 4, 8, 3, 9, 5, 11, 7, 10, 6)
_P2_DIV16 = (4, 8, 3, 9, 5, 11, 7, 10, 6, 7, 5, 3, 11, 9, 6, 10)


def _mod5_adjust(val: int) -> int:
    rem = _s32(_c_rem(val, 5))
    if rem == 1:
        return _s64(-val)
    if rem == 2:
        return _s64(val << 2)
    if rem == 3:
        return _s64((-val) << 3)
    if rem == 4:
        return _s64(val >> 2)
    return _s64(val << 3)


def _init_grid(
    dim: int,
    vals: Sequence[bytes],
    table_169: Sequence[int],
    is_p2: bool,
) -> list[list[int]]:
    p0 = math.pow(2.0, 20.0)
    if is_p2:
        scale = _cvttsd2si64(p0 + p0)
        p_bias = math.pow(-2.0, 20.0)
    else:
        p_bias = math.pow(2.0, -20.0)
        scale = _cvttsd2si64(p0 - p_bias)
    limit = dim * dim
    grid = [[0] * dim for _ in range(dim)]
    idx = 0
    for s in vals:
        for b in s:
            v = _mod5_adjust(_cvttsd2si64(p_bias + float(_s64(_s8(b) * scale)) / 255.0))
            if idx >= limit:
                break
            grid[idx // dim][idx % dim] = v
            idx += 1
    t_idx = 0
    while idx < limit:
        grid[idx // dim][idx % dim] = _s64(table_169[t_idx])
        t_idx += 1
        idx += 1
    return grid


def _p1_idx_1afcc0(
    table_169: Sequence[int],
    lock_pairs: Sequence[tuple[bytes, bytes]],
    word: bytes,
) -> int:
    """0x1801afcc0: producer 1 schedule index, 0..4."""
    grid = _init_grid(13, [v for _, v in lock_pairs] + [word], table_169, is_p2=False)

    vec: list[int] = []
    for p in _P1_PERM13:
        col = p - 1
        for row in range(13):
            vec.append(grid[row][col])

    r10d = 0
    wlen = len(word)
    for rbx in range(169):
        r11 = _c_rem(vec[rbx], 0x2000)
        r10 = _s8(word[rbx % wlen]) if wlen else 0
        r9 = _c_div(r11, 100)
        r8 = _c_rem(r11, 100)
        rdx = _c_div(r10, 100)
        rcx = _c_rem(r10, 100)
        term = _s64(_s32(r9 * r8 - rcx + rdx))
        root = math.sqrt(float(r10 * r10 + r11 * r11))
        fval = float(math.floor(float(term * term + 1) * root))
        rax = _cvttsd2si64(fval)
        rcx_mod = _c_rem(_s64(rax << 3), 255)
        r10d = _s32(r10d + (rcx_mod & 1))
    return _s32(_c_rem(r10d, 5))


def _p2_idx_1c3430(
    table_169: Sequence[int],
    lock_pairs: Sequence[tuple[bytes, bytes]],
    word: bytes,
) -> int:
    """0x1801c3430: producer 2 schedule index, 0..9."""
    grid = _init_grid(13, [v for _, v in lock_pairs] + [word], table_169, is_p2=True)

    r8d = 0
    for row in range(13):
        for col in range(13):
            val = grid[row][col]
            if _c_rem(_c_rem(val, 9), 2) == 1:
                r11 = _c_rem((val ^ 0x260) >> 5, 3)
            elif (val & 1) == 0:
                r11 = _c_rem((val ^ 0xF8) >> 3, 5)
            else:
                r11 = _c_rem((val ^ 0x34) >> 2, 7)

            if (r11 & 1) == 0:
                r14 = _c_rem(r11, 0x2000)
                rbx = _c_div(r14, 100)
                rdi = _c_rem(r14, 100)
                s1 = _c_div(rdi * (rdi + 1) + rbx * rbx, 2)
                rsi = _cvttsd2si64(math.sqrt(float(s1)) if s1 >= 0 else 0.0)
                s2 = _c_div(rbx * (rbx - 1) + rdi * rdi, 2)
                rdi2 = _cvttsd2si64(math.sqrt(float(s2)) if s2 >= 0 else 0.0) >> 2
                p15 = _cvttsd2si64(math.pow(2.0, 15.0))
                num = (rdi2 + rsi * 4) ^ abs(r14)
                rem = _c_rem(num, p15)
                bit = (~rem) & 1
            else:
                rdi = _c_rem(r11, 0x2000)
                rdx = _c_div(rdi, 100)
                rax = _c_rem(rdi, 100)
                diff = abs(rax * rax - 4 * rdx * rdi)
                root = _cvttsd2si64(math.sqrt(float(diff)))
                bit = (~(root + rdi * 2)) & 1
            r8d = _s32(r8d + bit)
    return _s32(_c_rem(r8d, 10))


def _mat_init_common(
    table_169: Sequence[int],
    lock_pairs: Sequence[tuple[bytes, bytes]],
    word: bytes,
    is_p2: bool,
) -> list[list[int]]:
    """16x16 matrix seed: 0x1801add20 (p1), 0x1801c1380 (p2)."""
    vals = ([v for _, v in lock_pairs] + [word]) if is_p2 else [v for _, v in lock_pairs]
    perm10 = _P2_PERM10 if is_p2 else _P1_PERM10
    grid = _init_grid(10, vals, table_169, is_p2)

    vec100: list[int] = []
    for p in perm10:
        col = p - 1
        for row in range(10):
            vec100.append(grid[row][col])

    mat = [[0] * 16 for _ in range(16)]
    wlen = len(word)
    for rbx in range(100):
        ch = _s8(word[rbx % wlen]) if wlen else 0
        val = vec100[rbx]
        r15 = ch ^ val
        prod = _cvttsd2si64(float(ch) * (float(val) * 3.14))
        root = math.sqrt(float(abs(r15)))
        lg = math.log(float(abs(prod))) if prod else float("-inf")
        r9 = _s64(_cvttsd2si64(float(r15) * 0.5 * root * lg) * 4)
        edi = 2 * rbx
        mat[edi // 16][edi % 16] = _u64(r9)
        mat[(edi + 1) // 16][(edi + 1) % 16] = _u64(prod)

    t_back = len(table_169) - 1
    for edi in range(200, 256):
        mat[edi // 16][edi % 16] = _u64(table_169[t_back])
        t_back -= 1
    return mat


def _g1_common(mat: list[list[int]], is_p2: bool) -> None:
    dr8, dc8, kern9, tab68 = (
        (_P2_DR8, _P2_DC8, _P2_KERN9, _P2_TAB68)
        if is_p2
        else (_P1_DR8, _P1_DC8, _P1_KERN9, _P1_TAB68)
    )
    shift = 7 if is_p2 else 8
    m_neg, m_clamp = (7, 5) if is_p2 else (3, 11)
    for r in range(16):
        for c in range(16):
            v = _s64(mat[r][c])
            acc = ~v if is_p2 else _s64(-2 * v)
            for d in range(8):
                dr, dc = dr8[d], dc8[d]
                nr, nc = r + dr, c + dc
                k = kern9[(dr + 1) * 3 + (dc + 1)]
                cell = (
                    _s64(mat[nr][nc])
                    if (0 <= nr < 16 and 0 <= nc < 16)
                    else tab68[_c_rem(_s32((r + c) << shift), 68)]
                )
                acc = _s64(acc + _c_rem(_s64((k ^ cell) if is_p2 else (k * cell)), 0x100000))
            r8 = _c_rem(_s64(mat[r][c]), 0x2000)
            rax = _c_rem(_s64(mat[r][(c + 1) & 15]), 0x2000)
            root = math.sqrt(float(r8 * r8 + rax * rax))
            mult = float(_s64(acc + 1) ^ 2)
            nv = _c_rem(_s64(_cvttsd2si64(root * mult) << 2), 0x40000000)
            if _c_rem(nv, m_neg) == 1:
                nv = -_c_rem(nv, 0x100000)
            if _c_rem(nv, m_clamp) == 0:
                nv = _c_rem(nv, 0x2000)
            mat[r][c] = _u64(nv)


def _g2_common(mat: list[list[int]], is_p2: bool) -> None:
    dr8, dc8 = (_P2_EE6F0_DR8, _P2_EE6F0_DC8) if is_p2 else (_P1_DR8, _P1_DC8)
    visited = [[False] * 16 for _ in range(16)]
    flat256: list[int] = []
    stack: list[tuple[int, int]] = []
    for r in range(16):
        for c in range(16):
            if not visited[r][c]:
                stack.append((r, c))
                flat256.append(_s64(mat[r][c]))
                visited[r][c] = True
                while stack:
                    cr, cc = stack[-1]
                    cur_v = _s64(mat[cr][cc])
                    for d in range(8):
                        nr = cr + dr8[d]
                        nc = cc + dc8[d]
                        if 0 <= nr < 16 and 0 <= nc < 16 and not visited[nr][nc]:
                            if cur_v >= _s64(mat[nr][nc]):
                                visited[nr][nc] = True
                                flat256.append(_s64(mat[nr][nc]))
                                stack.append((nr, nc))
                    stack.pop()
    for i in range(256):
        r, c = i >> 4, i & 15
        v0 = flat256[i]
        rdi = _c_rem(v0, 0x100000)
        r8 = _c_rem(flat256[(i + 1) & 0xFF], 0x100000)
        rbx = _c_rem(flat256[(i + 2) & 0xFF], 0x100000)
        root = math.sqrt(float(r8 * r8 + rdi * rdi))
        if is_p2:
            mult = float(_s64(rbx * rdi + 1))
            nv = _s64(_cvttsd2si64(mult * root) * 2)
        else:
            mult = float(_s64(rbx + 1) ^ rdi)
            nv = _s64(_cvttsd2si64(mult * root) << 2)
        mat[r][c] = _u64(nv)


def _g3_common(mat: list[list[int]], is_p2: bool) -> None:
    div16 = _P2_DIV16 if is_p2 else _P1_DIV16
    items: list[tuple[int, int]] = []
    for r in range(16):
        d = div16[r]
        for c in range(16):
            v = _s64(mat[r][c])
            items.append((_s32(_c_rem(v, d)), v))
    items.sort()
    p_val = _cvttsd2si64(math.pow(2.0, 17.0 if is_p2 else 15.0))
    for k in range(256):
        r, c = k >> 4, k & 15
        nc = (k + 1) & 15
        top_val = items[k][1]
        r15 = _c_rem(top_val, 0x100000)
        rdi = _c_rem(_s64(mat[r][nc]), 0x100000)
        r14 = _c_rem(_s64(mat[nc][c]), 0x100000)
        diff = abs(rdi * rdi - 4 * r14 * r15)
        root = _cvttsd2si64(math.sqrt(float(diff)))
        if is_p2:
            rdx = _s64(((root >> 1) + r15) ^ 2)
            r15_2 = _c_rem(rdx, 0x800)
            rbx = _c_div(r15_2, 100)
            rdi_2 = _c_rem(r15_2, 100)
            s1 = _c_div(rdi_2 * (rdi_2 + 1) + rbx * rbx, 2)
            r14d = _s32(_cvttsd2si32(math.sqrt(float(s1))) >> 2)
            s2 = _c_div(rbx * (rbx - 1) + rdi_2 * rdi_2, 2)
            edi = _s32(_cvttsd2si32(math.sqrt(float(s2))) * 4)
            nv = _c_rem(_s64(_s32(edi + r14d)) ^ abs(r15_2), p_val)
            if _c_rem(nv, 5) == 1:
                nv = -_c_rem(nv, 0x100000)
        else:
            rdx = _s64((root + r15) * 2)
            r15_2 = _c_rem(rdx, 0x2000)
            rbx = _c_div(r15_2, 100)
            rdi_2 = _c_rem(r15_2, 100)
            s1 = _c_div(rdi_2 * (rdi_2 + 1) + rbx * rbx, 2)
            r14d = _s32(_cvttsd2si32(math.sqrt(float(s1))) * 4)
            s2 = _c_div(rbx * (rbx - 1) + rdi_2 * rdi_2, 2)
            edi = _s32(_cvttsd2si32(math.sqrt(float(s2))) >> 2)
            nv = _c_rem(_s64(_s32(edi + r14d)) ^ abs(r15_2), p_val)
            if _c_rem(nv, 3) == 1:
                nv = -_c_rem(nv, 0x100000)
        mat[r][c] = _u64(nv)


def _g4_common(mat: list[list[int]], is_p2: bool) -> None:
    sq6 = math.sqrt(6.28)
    for r in range(16):
        nr = (r + 1) & 15
        for c in range(16):
            nc = (c + 1) & 15
            r10 = _s64(mat[r][c])
            r8 = _s64(mat[r][nc])
            rdx = _s64(mat[nr][c])
            mmin = min(r10, r8, rdx)
            sum3 = _s64(rdx + r8 + r10)
            diff = _s64(r8 - rdx)
            r8_sq = _s64(diff * diff)
            rcx = _s64(mmin + sum3 * 3 + 1)
            mat[r][c] = _u64(rcx)
            if is_p2:
                exp_arg = _c_rem(_s64((rcx ^ 2) + r8_sq), 15)
            else:
                exp_arg = _c_rem(_s64(rcx + 2 + r8_sq), 15)
            r9_pow = _cvttsd2si64(math.pow(2.7, float(exp_arg)))
            rem255 = _c_rem(rcx, 255)
            t_mul = _cvttsd2si64(sq6 * float(rem255))
            rax = _c_rem(t_mul ^ r9_pow, 0x100000)
            mat[r][c] = _u64(rax)

            r8_2 = _c_rem(_s64(mat[r][c]), 0x22D0)
            r9_2 = _c_rem(_s64(mat[r][nc]), 0x22D0)
            q8 = _s32(_c_div(r8_2, 100))
            rem8 = _s32(_c_rem(r8_2, 100))
            q9 = _s32(_c_div(r9_2, 100))
            rem9 = _s32(_c_rem(r9_2, 100))
            rt1 = _s64(_cvttsd2si32(math.sqrt(float(_s32(q9 * q9 + q8 * q8)))))
            rt2 = _s64(_cvttsd2si32(math.sqrt(float(_s32(rem9 * rem9 + rem8 * rem8)))))
            r12 = rt1 ^ rt2
            if is_p2:
                comb = _s64(_s32(q8 + rem9)) ^ _s64(q9) ^ _s64(rem8)
                nv = _c_rem(_s64((r12 * comb) << 2), 0x40000000)
                if _c_rem(nv, 5) == 1:
                    nv = -_c_rem(nv, 0x100000)
                if _c_rem(nv, 7) == 0:
                    nv = _c_rem(nv, 0x2000)
            else:
                comb = _s64(_s32(q9 * rem9 + q8 * rem8))
                nv = _c_rem(_s64((r12 * comb) << 2), 0x40000000)
                if _c_rem(nv, 3) == 1:
                    nv = -_c_rem(nv, 0x100000)
                if _c_rem(nv, 11) == 0:
                    nv = _c_rem(nv, 0x2000)
            mat[r][c] = _u64(nv)


def _g5_common(mat: list[list[int]], is_p2: bool) -> None:
    flat256: list[int] = []
    for k in range(8):
        if is_p2:
            for r in range(k, 16 - k):
                flat256.append(_s64(mat[r][15 - k]))
            for c in range(14 - k, k - 1, -1):
                flat256.append(_s64(mat[15 - k][c]))
            for r in range(14 - k, k - 1, -1):
                flat256.append(_s64(mat[r][k]))
            for c in range(k + 1, 15 - k):
                flat256.append(_s64(mat[k][c]))
        else:
            for c in range(15 - k, k - 1, -1):
                flat256.append(_s64(mat[k][c]))
            for r in range(k + 1, 16 - k):
                flat256.append(_s64(mat[r][k]))
            for c in range(k + 1, 16 - k):
                flat256.append(_s64(mat[15 - k][c]))
            for r in range(14 - k, k, -1):
                flat256.append(_s64(mat[r][15 - k]))

    for i in range(256):
        r, c = i >> 4, i & 15
        r9 = _c_rem(flat256[i], 0x2000)
        r8 = _c_rem(flat256[(i + 1) & 0xFF], 0x2000)
        rax = _c_rem(flat256[(i + 2) & 0xFF], 0x2000)
        r13 = _s32(_c_div(r9, 100))
        rem9 = _s32(_c_rem(r9, 100))
        ebp = _s32(_c_div(r8, 100))
        rem8 = _s32(_c_rem(r8, 100))
        rt_rem = _s64(_cvttsd2si32(math.sqrt(float(_s32(rem8 * rem8 + rem9 * rem9)))))
        rt_quo = _s64(_cvttsd2si32(math.sqrt(float(_s32(ebp * ebp + r13 * r13)))))
        x_rt = rt_quo ^ rt_rem
        diff = abs(r8 * r8 - 4 * rax * r9)
        rcx = _cvttsd2si64(math.sqrt(float(diff)))
        if is_p2:
            comb = _s64(_s32(rem8 + r13)) ^ _s64(ebp) ^ _s64(rem9)
            v1 = _s64((x_rt * comb) >> 3)
            if _c_rem(v1, 5) == 1:
                v1 = -v1
            nv = _s64((v1 + rcx * 4) ^ 2)
        else:
            comb = _s64(_s32(ebp * rem8 + r13 * rem9))
            v1 = _s64((x_rt * comb) >> 2)
            if _c_rem(v1, 3) == 1:
                v1 = -v1
            nv = _s64((rcx + v1) * 2)
        mat[r][c] = _u64(nv)


def _g6_common(mat: list[list[int]], is_p2: bool) -> None:
    m_clamp = 7 if is_p2 else 11
    for br in range(0, 16, 4):
        for bc in range(0, 16, 4):
            r_iter = range(br + 3, br - 1, -1) if is_p2 else range(br, br + 4)
            c_iter = range(bc + 3, bc - 1, -1) if is_p2 else range(bc, bc + 4)
            for r in r_iter:
                nr = (r + 1) & 15
                for c in c_iter:
                    if r > c:
                        continue
                    nc = (c + 1) & 15
                    mat[c][r], mat[r][c] = mat[r][c], mat[c][r]
                    v_cr, v_rc = _s64(mat[c][r]), _s64(mat[r][c])

                    r12, rdx = _s64(mat[r][nc]), _s64(mat[nr][c])
                    a = abs(_s64(v_rc - rdx))
                    b = _s64(r12 - rdx)
                    s = _s64(r12 + v_rc)
                    sq = _s64(s * s)
                    if is_p2:
                        rad1 = abs(_s64((a ^ b) + sq))
                        r8_f = _cvttsd2si64(float(math.floor(math.sqrt(float(rad1)))))
                        d1 = _s64(abs(_s64(v_rc - r12)) * abs(b))
                        mat[r][c] = _u64(_s64(d1 + r8_f * 2))
                    else:
                        rad1 = abs(_s64(_s64(a + sq) & b))
                        f1 = float(math.floor(math.sqrt(float(rad1)))) * 2.0
                        d1 = _s64(abs(_s64(v_rc - r12)) ^ abs(b))
                        mat[r][c] = _u64(_cvttsd2si64(f1 + float(d1)))

                    r12_2, rdx_2 = _s64(mat[c][nr]), _s64(mat[nc][r])
                    a2 = abs(_s64(v_cr - rdx_2))
                    b2 = _s64(r12_2 - rdx_2)
                    s2 = _s64(r12_2 + v_cr)
                    sq2 = _s64(s2 * s2)
                    d2 = _s64(abs(_s64(v_cr - r12_2)) ^ abs(b2))
                    if is_p2:
                        rad2 = abs(_s64((a2 | b2) + sq2))
                        r8_f2 = _cvttsd2si64(float(math.floor(math.sqrt(float(rad2)))))
                        mat[c][r] = _u64(_s64(d2 + r8_f2 * 2))
                    else:
                        rad2 = abs(_s64(_s64(a2 + sq2) & b2))
                        f2 = float(math.floor(math.sqrt(float(rad2)))) * 2.0
                        mat[c][r] = _u64(_cvttsd2si64(f2 + float(d2)))

                    nv = _c_rem(_s64(mat[r][c]), 0x40000000)
                    if _c_rem(nv, 3) == 1:
                        nv = -_c_rem(nv, 0x100000)
                    if _c_rem(nv, m_clamp) == 0:
                        nv = _c_rem(nv, 0x2000)
                    mat[r][c] = _u64(nv)


def _g7_common(mat: list[list[int]], is_p2: bool) -> None:
    sq6 = math.sqrt(6.28)
    for br in (0, 8):
        for bc in (0, 8):
            sum1 = 0
            sum2 = 0
            for r in range(br, br + 8):
                for c in range(bc, bc + 8):
                    if r < c:
                        sum1 = _s64(sum1 + _c_rem(_s64(mat[r][c]), 0x2000))
                    elif r > c:
                        sum2 = _s64(sum2 + _c_rem(_s64(mat[r][c]), 0x2000))
            diff = _s64(sum1 - sum2)
            diff_sq = _s64(diff * diff)
            for r in range(br, br + 8):
                nr = (r + 1) & 15
                for c in range(bc, bc + 8):
                    nc = (c + 1) & 15
                    v = _s64(mat[r][c])
                    if is_p2:
                        exp_arg = _c_rem(_s64((v ^ 2) + diff_sq), 20)
                    else:
                        exp_arg = _c_rem(_s64(v + 2 + diff_sq), 20)
                    p_val = _cvttsd2si64(math.pow(2.7, float(exp_arg)))
                    t_mul = _cvttsd2si64(sq6 * float(_c_rem(v, 255)))
                    if is_p2:
                        v1 = _s64((p_val ^ t_mul) | (1 << 20))
                    else:
                        v1 = _c_rem(t_mul ^ p_val, 0x100000)
                    mat[r][c] = _u64(v1)

                    r13 = _s64(mat[r][c])
                    r12_n = _s64(mat[nr][c])
                    rcx_n = _s64(mat[r][nc])
                    a = _s64(r13 - rcx_n)
                    b = _s64(r12_n - rcx_n)
                    d = _s64(abs(_s64(r13 - r12_n)) ^ abs(b))
                    s = _s64(r12_n + r13)
                    sq = _s64(s * s)
                    if is_p2:
                        rad = _s64((a ^ b) + sq)
                        f_fl = float(math.floor(math.sqrt(float(rad)) * 2.0)) if rad >= 0 else float("nan")
                        nv = _c_rem(_cvttsd2si64(f_fl + float(d)), 0x40000000)
                        if _c_rem(nv, 5) == 1:
                            nv = -nv
                    else:
                        rad = _s64((a & b) + sq)
                        root = math.sqrt(float(rad)) if rad >= 0 else float("nan")
                        nv = _c_rem(_cvttsd2si64(root * 2.0 + float(d)), 0x40000000)
                        if _c_rem(nv, 3) == 1:
                            nv = -nv
                    mat[r][c] = _u64(nv)


def _g8_common(mat: list[list[int]], is_p2: bool) -> None:
    p_val = _cvttsd2si64(math.pow(2.0, 15.0))
    for br in (0, 8):
        for bc in (0, 8):
            dsum = 0
            for k in range(8):
                dsum = _s64(dsum + _s64(mat[br + k][bc + k]))
            abs_dsum = abs(dsum)
            for r in range(br, br + 8):
                nr = (r + 1) & 15
                for c in range(bc, bc + 8):
                    nc = (c + 1) & 15
                    v = _s64(mat[r][c])
                    rbx = _c_rem(v, 0x2000)
                    r13 = _s32(_c_div(rbx, 100))
                    rem_b = _s32(_c_rem(rbx, 100))
                    s1 = _s32(_c_div(_s32(rem_b * (rem_b - 1) + r13 * r13), 2))
                    rt1 = _cvttsd2si32(math.sqrt(float(s1)))
                    s2 = _s32(_c_div(_s32(r13 * (r13 + 1) + rem_b * rem_b), 2))
                    rt2 = _cvttsd2si32(math.sqrt(float(s2)))
                    if is_p2:
                        comb = _s64((_s64(rt2) >> 2) + _s64(rt1) * 4)
                        v1 = _c_rem(comb, abs_dsum + 1) ^ p_val
                        if _c_rem(v1, 5) == 1:
                            v1 = -v1
                    else:
                        comb = _s64(_s32((rt1 >> 2) + rt2 * 4)) ^ abs_dsum
                        v1 = _c_rem(comb, p_val)
                        if _c_rem(v1, 3) == 1:
                            v1 = -v1
                    mat[r][c] = _u64(v1)

                    cur = _s64(mat[r][c])
                    r8 = _c_rem(_s64(mat[r][nc]), 0x100000)
                    rax = _c_rem(_s64(mat[nr][c]), 0x100000)
                    diff = abs(_s64(r8 * r8 - 4 * rax * cur))
                    root = _cvttsd2si64(math.sqrt(float(diff)))
                    if is_p2:
                        nv = _c_rem(_s64(((root >> 1) + cur) ^ 2), 0x100000)
                        if _c_rem(nv, 7) == 0:
                            nv = -_c_rem(nv, 0x2000)
                    else:
                        nv = _c_rem(_s64((root + cur) * 2), 0x100000)
                        if _c_rem(nv, 11) == 0:
                            nv = -_c_rem(nv, 0x2000)
                    mat[r][c] = _u64(nv)


def _build_f10e0_trees() -> tuple[
    tuple[tuple[tuple[int, int], ...], dict[tuple[int, int], tuple[tuple[int, int], ...]]],
    ...,
]:
    dr4 = (1, 0, -1, 0)
    dc4 = (0, -1, 0, 1)
    quads = (
        (0, 0, 4, 4),
        (0, 8, 4, 11),
        (8, 0, 11, 4),
        (8, 8, 11, 11),
    )
    trees = []
    for r0, c0, rr, rc in quads:
        visited = [[False] * 16 for _ in range(16)]
        visited[rr][rc] = True
        q: deque[tuple[int, int]] = deque([(rr, rc)])
        adj: dict[tuple[int, int], tuple[tuple[int, int], ...]] = {}
        order: list[tuple[int, int]] = []
        while q:
            cr, cc = q.popleft()
            order.append((cr, cc))
            children: list[tuple[int, int]] = []
            for d in range(4):
                nr = cr + dr4[d]
                nc = cc + dc4[d]
                if r0 <= nr < r0 + 8 and c0 <= nc < c0 + 8 and not visited[nr][nc]:
                    visited[nr][nc] = True
                    children.append((nr, nc))
                    q.append((nr, nc))
            if children:
                adj[(cr, cc)] = tuple(children)
        trees.append((tuple(order), adj))
    return tuple(trees)


_F10E0_TREES = _build_f10e0_trees()


def _p2_t_1f10e0(mat: list[list[int]], _is_p2: bool = True) -> None:
    p_val = _cvttsd2si64(math.pow(2.0, 15.0))
    for order, adj in _F10E0_TREES:
        ret_val: dict[tuple[int, int], int] = {}
        for r, c in reversed(order):
            children = adj.get((r, c))
            if not children:
                ret_val[(r, c)] = 0x7FFF
            else:
                r15 = -0x8000
                for ch in children:
                    cv = ret_val[ch]
                    if cv > r15:
                        r15 = cv
                v = _s64(mat[r][c])
                rbx = _c_rem(v, 0x2000)
                s1 = _c_div(rbx * (rbx + 1) + r15 * r15, 2)
                r12d = _s32(_cvttsd2si32(math.sqrt(float(s1))) * 4)
                s2 = _c_div(r15 * (r15 - 1) + rbx * rbx, 2)
                ebx = _s32(_cvttsd2si32(math.sqrt(float(s2))) >> 2)
                nv = _c_rem(_s64(_s32(ebx + r12d)) ^ abs(v), p_val)
                mat[r][c] = _u64(nv)
                ret_val[(r, c)] = nv


_GROUP_FNS = (
    None,
    _g1_common,
    _g2_common,
    _g3_common,
    _g4_common,
    _g5_common,
    _g6_common,
    _g7_common,
    _g8_common,
    _p2_t_1f10e0,
)

_P1_SCHEDULE = {
    0: (0, 1, 2, 8, 5),
    1: (3, 0, 2, 6, 7),
    2: (1, 3, 0, 7, 4),
    3: (2, 3, 8, 0, 4),
    4: (1, 2, 6, 5, 0),
}

_P2_SCHEDULE = {
    0: (9, 8, 0, 4, 7),
    1: (5, 3, 8, 0, 6),
    2: (7, 1, 6, 0, 5),
    3: (0, 2, 8, 5, 7),
    4: (8, 3, 4, 5, 0),
    5: (9, 3, 0, 6, 4),
    6: (1, 0, 5, 6, 7),
    7: (6, 0, 2, 8, 5),
    8: (7, 4, 0, 6, 9),
    9: (0, 1, 6, 8, 5),
}


def produce_v_pure_math(
    table: Sequence[int],
    word: bytes | str,
    lock_pairs: Sequence[tuple[str | bytes, str | bytes]],
    *,
    family: str = "0x77",
) -> bytes:
    word_bytes = word.encode("utf-8") if isinstance(word, str) else bytes(word)
    pairs = _normalize_lock_pairs(lock_pairs)
    is_p2 = family == "0x77"
    if is_p2:
        mat = _mat_init_common(table, pairs, word_bytes, is_p2=True)
        idx = _p2_idx_1c3430(table, pairs, word_bytes)
        sched = _P2_SCHEDULE.get(idx, ())
    else:
        idx = _p1_idx_1afcc0(table, pairs, word_bytes)
        mat = _mat_init_common(table, pairs, word_bytes, is_p2=False)
        sched = _P1_SCHEDULE.get(idx, ())
    for step_id in sched:
        fn = _GROUP_FNS[step_id]
        if fn is not None:
            fn(mat, is_p2)
    return bytes(cell & 0xFF for row in mat for cell in row)

