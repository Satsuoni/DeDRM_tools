"""Stage 8 stepper: closed-form 162-cell 2x9x9 tensor transform."""

from __future__ import annotations

import math

from . import constants
from .verdict import fn_c1810_pure

M32 = 0xFFFFFFFF
T850_LEN = 1256
T868_LEN = 1079
T880_LEN = 2743

_B7C10_S = (0x3DFAF6CC, 0xA153529D, 0x2BD535A4)
_VEC6_CBC70 = (b"yqr", b"yrq", b"qyr", b"qry", b"ryq", b"rqy")

REF_VOUCHER_ID = "amzn1.drm-voucher.v1.01234567-89ab-cdef-0123-456789abcdef"

_DANCE_K = 0x00000388
_DANCE_W188 = 3
_DANCE_ARR0 = (5, 8, 6)
_DANCE_MAP0 = {120: 1, 112: 3, 122: 4, 121: 7, 114: 2, 113: 9}
_DANCE_KEY_OF_M6 = (120, 112, 122, 121, 114, 113)

KERNEL_OF_K = {
    0: ("b6e5c", None),
    1: ("cbc70w0", 0),
    2: ("b8f14", None),
    3: ("c741c", None),
    4: ("d2378", None),
    5: ("cbc70w1", 1),
    6: ("c9aac", None),
    7: ("b9924", None),
    8: ("b7c10", None),
}


def s32(v: int) -> int:
    v &= M32
    return v - (1 << 32) if v >= (1 << 31) else v


def cmod(a: int, m: int) -> int:
    a = int(a)
    r = abs(a) % int(m)
    return -r if a < 0 else r


def cmod9(v: int) -> int:
    return abs(cmod(s32(v), 9))


def fold32(x: int) -> int:
    return ((x & 0x7FFFFFFF) - ((x >> 31) & 1)) & M32


def _lcg_signed_raw(w8: int) -> int:
    w8 = s32(w8)
    w9 = w8 >> 15
    w8_low = w8 & 0x7FFF
    w10 = (w9 * 0x7E0D8000) & 0x7FFF8000
    w9_mul = s32(w9 * 0x8FC1B)
    return s32(w8_low * 0x8FC1B + w10 + (w9_mul >> 16))


def lcg31x(v: int) -> int:
    return fold32(_lcg_signed_raw(v) & M32)


def _lcg_unsigned_raw(w10: int) -> int:
    w10 &= M32
    w11 = w10 >> 15
    w10_low = w10 & 0x7FFF
    w12 = (w11 * 0x7E0D8000) & 0x7FFF8000
    w11_mul = (w11 * 0x8FC1B) & M32
    w8 = (w10_low * 0x8FC1B + w12 + (w11_mul >> 16)) & M32
    return ((w8 & 0x7FFFFFFF) + (w8 >> 31)) & M32


def _fcvtps_s32(d: float) -> int:
    if math.isnan(d):
        return 0
    if d >= 2147483647.0:
        return 0x7FFFFFFF
    if d <= -2147483648.0:
        return -0x80000000
    return int(math.ceil(d))


def phase2_limit(hash_acc: int) -> int:
    x = (hash_acc ^ 0x28) & M32
    prod = s32(x) * s32(0xBAB65611)
    w = (((prod >> 32) & M32) + x) & M32
    q = ((s32(w) >> 8) + (1 if w & 0x80000000 else 0)) & M32
    return (q + 0x3C) & M32


class Tensor:
    def __init__(self, fills=None):
        self.t = [[[0] * 9 for _ in range(9)] for _ in range(2)]
        if fills is not None:
            for i, v in enumerate(fills):
                r, c = divmod(i, 81)
                self.t[r][c // 9][c % 9] = v & M32

    def flat(self) -> list[int]:
        return [self.t[r][p][c] & M32 for r in range(2) for p in range(9) for c in range(9)]


def helper_ce85c(T: Tensor, root: int, p0: int, c0: int) -> None:
    for i, j in ((0, 1), (0, 2), (1, 2)):
        pa, ca, pb, cb = p0 + i, c0 + j, p0 + j, c0 + i
        T.t[root][pb][cb], T.t[root][pa][ca] = T.t[root][pa][ca], T.t[root][pb][cb]


def helper_cfa04(T: Tensor, root: int, pa: int, pb: int, c0: int) -> None:
    for k in range(3):
        c = c0 + k
        T.t[root][pb][c], T.t[root][pa][c] = T.t[root][pa][c], T.t[root][pb][c]


def helper_d0fec(T: Tensor, root: int, p0: int, ca: int, cb: int) -> None:
    for k in range(3):
        p = p0 + k
        T.t[root][p][ca], T.t[root][p][cb] = T.t[root][p][cb], T.t[root][p][ca]


def _apply_box_rot(T: Tensor, root: int, face_val: int, flip_rows: bool) -> None:
    q, r = geometry_trits(face_val)
    p0, c0 = 3 * q, 3 * r
    helper_ce85c(T, root, p0, c0)
    if flip_rows:
        helper_cfa04(T, root, p0 + 2, p0, c0)
    else:
        helper_d0fec(T, root, p0, c0, c0 + 2)


def c741c_main(T: Tensor, root: int, b: int, cycle) -> None:
    for d in (2, 1, 0):
        cells = [(3 * a + b, 3 * c + d) for (a, c) in cycle]
        snap = [T.t[root][p][c] for (p, c) in cells]
        for k, (p, c) in enumerate(cells):
            T.t[root][p][c] = snap[(k + 1) % 4] & M32


def b9924_crossmix(T: Tensor) -> None:
    for p, c in (
        (3, 3), (2, 3), (1, 3), (0, 3),
        (3, 3), (3, 4), (3, 5), (3, 6), (0, 3), (1, 4), (2, 5), (3, 6),
    ):
        T.t[0][p][c], T.t[1][p][c] = T.t[1][p][c] & M32, T.t[0][p][c] & M32


def c9aac_main(T: Tensor, P: int, c0: int, pattern) -> None:
    t868 = constants.T868
    cells_all = [[(P + po, (c0 - g + co) % 9) for po, co in pattern] for g in range(3)]
    olds = {g: [T.t[0][p][cl] & M32 for p, cl in cells_all[g]] for g in range(3)}
    for g in range(3):
        cells = cells_all[g]
        oldk = olds[g]
        for k in range(3):
            idx = abs(s32(oldk[k])) % T868_LEN
            T.t[0][cells[k][0]][cells[k][1]] = ((t868[idx] & M32) ^ oldk[(k + 1) % 4]) & M32
        T.t[0][cells[3][0]][cells[3][1]] = oldk[0] & M32


def b7c10_state_mask(T: Tensor, A0: int, A1: int, s_words=None) -> None:
    t880 = constants.T880
    S = s_words if s_words is not None else _B7C10_S
    v = T.t[1][A0][3] & M32
    q = abs(s32(v)) % T880_LEN
    idx = -q if s32(v) < 0 else q
    mix = lcg31x(t880[abs(idx)])
    for i in range(3):
        old_r1 = T.t[1][8 - i][3] & M32
        old_r0 = T.t[0][A0 + i][A1] & M32
        T.t[0][A0 + i][A1] = (old_r1 * old_r1 - 3 * S[i]) & M32
        T.t[1][8 - i][3] = (mix ^ old_r0) & M32


def b6e5c_row_swap(T: Tensor) -> None:
    T.t[0][7], T.t[1][7] = T.t[1][7][:], T.t[0][7][:]


def phase_a_hash(voucher_id=None) -> int:
    vid = REF_VOUCHER_ID if voucher_id is None else voucher_id
    return sum(2 if ord(ch) % 2 == 0 else 5 for ch in vid)


def dispatcher_increment(state256=None) -> int:
    if state256 is None:
        return 0x0BEDA8AE
    return ((int(state256[255]) & M32) + 5) & M32


def w4_of_kernel(label: str, seed: int, counter: int) -> int | None:
    seed &= M32
    c = counter
    if label == "cbc70w0":
        return cmod(lcg31x((seed * (c + 1)) & M32), 3)
    if label == "cbc70w1":
        return cmod(lcg31x((cmod(s32(seed), 9) * (c + 1)) & M32), 3)
    if label == "c741c":
        return cmod(lcg31x(((seed + 9) * (c + 5)) & M32), 3)
    if label == "c9aac":
        return cmod(lcg31x((((c + 3) * (c + 4)) & M32) ^ ((seed + 5) & M32)), 3)
    if label == "d2378":
        return c & 1
    return None


def dance_m6(c: int, seed: int, w188: int = _DANCE_W188) -> int:
    t = ((3 * c) * (w188 ^ ((seed << 3) & M32)) + 9) & M32
    return lcg31x(t) % 6


def dance_w22(c: int, seed: int, m6: int, k: int = _DANCE_K) -> int:
    t = ((((4 * c + 1) * 3) & M32) * m6 + k + 1) & M32
    return lcg31x(t) % 3


class DanceStepper:
    def __init__(self, seeds, arr0=_DANCE_ARR0, map0=None, w188: int = _DANCE_W188):
        self.seeds = seeds
        self.arr = list(arr0)
        self.mp = dict(_DANCE_MAP0 if map0 is None else map0)
        self.w188 = w188
        self.i = 0

    def step(self, kcell: int) -> None:
        i = self.i
        s = self.seeds[i] if i < len(self.seeds) else 0
        m6 = dance_m6(i, s, self.w188)
        w22 = dance_w22(i, s, m6, kcell)
        key = _DANCE_KEY_OF_M6[m6]
        old = self.mp[key]
        self.mp[key] = self.arr[w22]
        self.arr[w22] = old
        self.i += 1


def geometry_trits(v: int) -> tuple[int, int]:
    t = v - 1
    q = t // 3 if t >= 0 else -((-t + 2) // 3)
    return (q, t - 3 * q)


def c741c_geometry(dance_row: dict, w4: int) -> list[list[int]]:
    k_a, k_b = (113, 112) if w4 == 0 else (112, 113)
    return [list(geometry_trits(dance_row[ch])) for ch in (120, k_a, k_b, 122)]


def c9aac_geometry(dance_row: dict, w4: int) -> tuple[int, list[list[int]]]:
    _qx, rx = geometry_trits(dance_row[120])
    c0 = 2 + 3 * rx
    s1a, s1b = (114, 122) if w4 == 0 else (122, 114)
    pattern = []
    for ch in (120, s1a, s1b, 121):
        q, r = geometry_trits(dance_row[ch])
        pattern.append([3 * q, 3 * ((r - rx) % 3)])
    return c0, pattern


def _fn_33cbc70(T: Tensor, map_row: dict[int, int], w4: int = 2, w5: int = 0) -> None:
    # closed-form 0x33cbc70 blend over constants.T850 (0x33ce1ac) and constants.T868 (0x33ce378)
    w19 = 3
    w10 = (w4 * w4 + 1) & M32
    x25 = _lcg_unsigned_raw(w10)
    w_74 = s32(w19 * w4 + w19)
    w0 = fn_c1810_pure(x25)
    idx = abs(cmod(w0, 6))
    s = bytearray(b"x" + _VEC6_CBC70[idx])
    if (w5 & 1) != 0:
        s.reverse()

    w8_init = s32(w_74 * s[-1])
    lcg_init = _lcg_signed_raw(w8_init)
    plane = (lcg_init + ((lcg_init & M32) >> 31)) & 1
    plane_saved = plane

    t850 = constants.T850
    t868 = constants.T868

    for k in range(w19):
        row_off = w19 - 1 - k
        d8 = float(k * k + 1) / 2.0
        q_last, r_last = geometry_trits(map_row[s[-1]])
        r_prev = 3 * q_last + row_off
        c_prev = 3 * r_last + w4
        saved_val = s32(T.t[plane][r_prev][c_prev])

        w8_exp = s32(s32(r_prev * r_prev) * c_prev + c_prev)
        try:
            exp_val = math.exp(float(w8_exp) * d8)
        except OverflowError:
            exp_val = math.inf
        lcg_e = _lcg_signed_raw(_fcvtps_s32(exp_val))
        plane_alt = (lcg_e + ((lcg_e & M32) >> 31)) & 1

        for i in range(len(s) - 2, -1, -1):
            q_i, r_i = geometry_trits(map_row[s[i]])
            ri = 3 * q_i + row_off
            ci = 3 * r_i + w4
            v_prev = s32(T.t[plane][r_prev][c_prev])
            idx1 = 0x7FFFFFFF if v_prev == -0x80000000 else abs(v_prev)
            t1 = cmod(s32(t850[idx1 % T850_LEN] ^ v_prev), 256) & M32

            v_curr = s32(T.t[plane][ri][ci])
            v_add = s32(v_curr + i)
            idx2 = 0x7FFFFFFF if v_add == -0x80000000 else abs(v_add)
            t2 = cmod(s32(t868[idx2 % T868_LEN] ^ v_curr), 256) & M32

            T.t[plane_alt][r_prev][c_prev] = t2
            T.t[plane][ri][ci] = t1
            r_prev = ri
            c_prev = ci
            plane ^= 1
            plane_alt ^= 1

        q_f, r_f = geometry_trits(map_row[s[0]])
        rf = 3 * q_f + row_off
        cf = 3 * r_f + w4
        T.t[plane_saved][rf][cf] = saved_val & M32


def dispatcher_plan(state256=None, voucher_id=None, steps: int = 72) -> dict:
    h = phase_a_hash(voucher_id)
    limit = phase2_limit(h)
    inc = dispatcher_increment(state256)

    def seed_at(i: int) -> int:
        return (1 + i * inc) & M32

    sched = []
    counter = 0
    while counter < limit and counter < 4 * steps + 40:
        s = seed_at(counter)
        k = cmod9(s)
        label, w5 = KERNEL_OF_K[k]
        w4 = w4_of_kernel(label, s, counter)
        sched.append((label, w5, w4))
        if k == 1:
            limit = max(limit, 0x3D) - 1
        elif k in (0, 3, 5):
            limit = min(limit, 0x63) + 1
        counter += 1
    seeds = [seed_at(i) for i in range(max(len(sched), steps))]
    return {"schedule": sched, "seeds": seeds}


def b7c10_select(r0, r1) -> tuple[int, int]:
    fold = lcg31x(((r0[0][0] * r0[3][6]) + r1[4][5]) & M32)
    n = abs(s32(fold)) % 9
    return (3 * (n // 3), 3 * (n % 3))


def replacement(
    tensor_flat,
    state256=None,
    voucher_id=None,
) -> list[int]:
    T = Tensor(tensor_flat)
    plan = dispatcher_plan(state256, voucher_id)
    dancer = DanceStepper(plan["seeds"])
    sw = None if state256 is None else [int(w) & M32 for w in state256[:3]]

    for label, w5, w4 in plan["schedule"]:
        row = dancer.mp
        if label in ("b8f14", "d2378"):
            dancer.step(T.t[1][5][3] & M32)
            continue
        if label.startswith("cbc70"):
            w5_val = w5 or 0
            _fn_33cbc70(T, row, w4, w5_val)
            if w4 in (0, 2):
                _apply_box_rot(T, w5_val & 1, row[122 if w4 == 2 else 112], w4 == 0)
        elif label == "b6e5c":
            b6e5c_row_swap(T)
        elif label == "b9924":
            b9924_crossmix(T)
        elif label == "b7c10":
            A0, A1 = b7c10_select(T.t[0], T.t[1])
            b7c10_state_mask(T, A0, A1, s_words=sw)
        elif label == "c741c":
            c741c_main(T, 0, w4, c741c_geometry(row, w4))
            if w4 in (0, 2):
                _apply_box_rot(T, 0, row[121 if w4 == 0 else 113], w4 == 0)
        elif label == "c9aac":
            c0, pattern = c9aac_geometry(row, w4)
            c9aac_main(T, w4, c0, pattern)
            if w4 in (0, 2):
                _apply_box_rot(T, 0, row[113 if w4 == 2 else 120], w4 == 2)
        else:
            raise RuntimeError(f"gen: unhandled schedule label {label!r}")
        dancer.step(T.t[1][5][3] & M32)

    return T.flat()

