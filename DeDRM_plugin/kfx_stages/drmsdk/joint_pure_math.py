"""Pure-math closed forms of the 64-bit mobile joint producers, selectors
0x7a (0x1005c3e68) and 0x82 (0x10063f408).

No ARM64 stepping (CPU, Mem, decode_pc, _PageMapHarness) at call time.
"""
from __future__ import annotations

import math
import struct
from collections import deque
from typing import Final, Sequence

MASK32: Final[int] = 0xFFFFFFFF
MASK64: Final[int] = 0xFFFFFFFFFFFFFFFF

# IEEE-754 double constant at 0x1055f2dc0 (pi / 180.0)
_DEG_TO_RAD_C3E68: Final[float] = struct.unpack("<d", struct.pack("<Q", 0x3F91DF46A2529D39))[0]


def _u32(x: int) -> int:
    return x & MASK32


def _s32(x: int) -> int:
    x &= MASK32
    return x - 0x100000000 if x & 0x80000000 else x


def _u64(x: int) -> int:
    return x & MASK64


def _s64(x: int) -> int:
    x &= MASK64
    return x - (1 << 64) if x & (1 << 63) else x


def _c_div(a: int, b: int) -> int:
    if b == 0:
        return 0
    q = abs(a) // abs(b)
    return -q if (a < 0) ^ (b < 0) else q


def _c_rem(a: int, b: int) -> int:
    return a - _c_div(a, b) * b


def _fcvtzs_i64(d: float) -> int:
    if math.isnan(d):
        return 0
    if d >= float((1 << 63) - 1):
        return (1 << 63) - 1
    if d < float(-(1 << 63)):
        return -(1 << 63)
    return int(math.trunc(d))


def _fcvtms_i64(d: float) -> int:
    if math.isnan(d):
        return 0
    if d >= float((1 << 63) - 1):
        return (1 << 63) - 1
    if d < float(-(1 << 63)):
        return -(1 << 63)
    return int(math.floor(d))


def _normalize_lock_pairs(
    lock_pairs: Sequence[tuple[str | bytes, str | bytes]],
) -> list[tuple[bytes, bytes]]:
    out: list[tuple[bytes, bytes]] = []
    for k, v in lock_pairs:
        kb = k.encode("ascii") if isinstance(k, str) else bytes(k)
        vb = v.encode("ascii") if isinstance(v, str) else bytes(v)
        out.append((kb, vb))
    return out


class _RBNode:
    __slots__ = ("key", "left", "right", "color", "parent")

    def __init__(self, key: int, color: int = 0x52) -> None:
        self.key: int = key
        # +0x08 is right, +0x10 is left in the binary's struct; the slot
        # names follow that reading
        self.left: _RBNode | None = None
        self.right: _RBNode | None = None
        self.color: int = color  # 0x52 ('R') or 0x42 ('B')
        self.parent: _RBNode | None = None


class _RBTree0x7a:
    # mirror of the red-black tree at 0x10062e07c / 0x10062e838 / 0x10062e0e4
    __slots__ = ("root", "height", "diameter", "ll", "rr", "lr", "rl")

    def __init__(self) -> None:
        self.root: _RBNode | None = None
        self.height: int = 0
        self.diameter: int = 0
        self.ll: bool = False
        self.rr: bool = False
        self.lr: bool = False
        self.rl: bool = False

    @staticmethod
    def _rotate_left(node: _RBNode) -> _RBNode:
        x = node.right
        assert x is not None
        y = x.left
        x.left = node
        node.right = y
        node.parent = x
        if y is not None:
            y.parent = node
        return x

    @staticmethod
    def _rotate_right(node: _RBNode) -> _RBNode:
        x = node.left
        assert x is not None
        y = x.right
        x.right = node
        node.left = y
        node.parent = x
        if y is not None:
            y.parent = node
        return x

    def _insert_help(self, root: _RBNode | None, key: int, w3: int) -> _RBNode:
        f = False
        init_color = 0x42 if w3 != 0 else 0x52
        if root is None:
            return _RBNode(key, init_color)

        if root.key <= key:
            root.left = self._insert_help(root.left, key, 1)
            root.left.parent = root
            if root is not self.root:
                if root.color == 0x42 and root.left.color == 0x42:
                    f = True
        else:
            root.right = self._insert_help(root.right, key, 0)
            root.right.parent = root
            if root is not self.root:
                if root.color == 0x42 and root.right.color == 0x42:
                    f = True

        if self.ll:
            root = self._rotate_left(root)
            root.color = 0x52
            assert root.left is not None
            root.left.color = 0x42
            self.ll = False
        elif self.rr:
            root = self._rotate_right(root)
            root.color = 0x52
            assert root.right is not None
            root.right.color = 0x42
            self.rr = False
        elif self.rl:
            assert root.right is not None
            root.right = self._rotate_right(root.right)
            root.right.parent = root
            root = self._rotate_left(root)
            root.color = 0x52
            assert root.left is not None
            root.left.color = 0x42
            self.rl = False
        elif self.lr:
            assert root.left is not None
            root.left = self._rotate_left(root.left)
            root.left.parent = root
            root = self._rotate_right(root)
            root.color = 0x52
            assert root.right is not None
            root.right.color = 0x42
            self.lr = False

        if f:
            assert root.parent is not None
            if root.parent.right is root:
                s = root.parent.left
                if s is None or s.color == 0x52:
                    if root.left is not None and root.left.color == 0x42:
                        self.rl = True
                    elif root.right is not None and root.right.color == 0x42:
                        self.ll = True
                else:
                    s.color = 0x52
                    root.color = 0x52
                    if root.parent is not self.root:
                        root.parent.color = 0x42
            else:
                s = root.parent.right
                if s is None or s.color == 0x52:
                    if root.left is not None and root.left.color == 0x42:
                        self.rr = True
                    elif root.right is not None and root.right.color == 0x42:
                        self.lr = True
                else:
                    s.color = 0x52
                    root.color = 0x52
                    if root.parent is not self.root:
                        root.parent.color = 0x42
        return root

    def insert(self, key: int) -> None:
        if self.root is None:
            self.root = _RBNode(key, 0x52)
        else:
            self.root = self._insert_help(self.root, key, 0)

    def compute_height_diam(self) -> tuple[int, int]:
        def _walk(node: _RBNode | None) -> int:
            if node is None:
                return 0
            lh = _walk(node.left)
            rh = _walk(node.right)
            if lh + rh > self.diameter:
                self.diameter = lh + rh
            h = max(lh, rh) + 1
            self.height = h
            return h

        h = _walk(self.root)
        return h, self.diameter


def _largest_rect_hist(heights: list[int]) -> int:
    stack: list[int] = []
    max_area = 0
    idx = 0
    n = len(heights)
    while idx < n:
        if not stack or heights[stack[-1]] <= heights[idx]:
            stack.append(idx)
            idx += 1
        else:
            top = stack.pop()
            w = idx if not stack else (idx - stack[-1] - 1)
            area = _s32(heights[top] * w)
            if area > max_area:
                max_area = area
    while stack:
        top = stack.pop()
        w = idx if not stack else (idx - stack[-1] - 1)
        area = _s32(heights[top] * w)
        if area > max_area:
            max_area = area
    return max_area


def _is_prime_u32(n: int) -> bool:
    if n < 2:
        return False
    if n < 4:
        return True
    limit = n >> 1
    for d in range(2, limit + 1):
        if n % d == 0:
            return False
    return True


def _mat7_mul(a: list[list[int]], b: list[list[int]]) -> list[list[int]]:
    out = [[0] * 7 for _ in range(7)]
    for r in range(7):
        for c in range(7):
            acc = 0
            for k in range(7):
                acc = _s64(acc + b[k][c] * a[r][k])
            out[r][c] = acc
    return out


def _mat7_combine(
    m1: list[list[int]],
    m2: list[list[int]],
    m3: list[list[int]],
    m4: list[list[int]],
    use_0x7a: bool = True,
) -> list[list[int]]:
    # 0x1005c1644 (use_0x7a=True): B = (m2 @ S) @ m4; 0x1006390f0 (False): B = (m3 @ m4) @ S
    s_mat = [[_s64(m2[r][c] + m3[r][c] + m4[r][c]) for c in range(7)] for r in range(7)]
    b_mat = _mat7_mul(_mat7_mul(m2, s_mat), m4) if use_0x7a else _mat7_mul(_mat7_mul(m3, m4), s_mat)
    return [[_s64(m1[6 - r][6 - c] * b_mat[r][c]) for c in range(7)] for r in range(7)]


def _mean_ldexp_scale(arr: list[int]) -> list[int]:
    out = [int(v) for v in arr]
    n = len(out)
    if n == 0:
        return out
    total_u64 = 0
    for v in out:
        total_u64 = _u64(total_u64 + _u64(v))
    mean_u64 = total_u64 // n
    for i in range(n):
        diff_s64 = _s64(mean_u64 - _u64(out[i]))
        abs_diff = -diff_s64 if diff_s64 < 0 else diff_s64
        exp_i = int(math.ceil(math.sqrt(float(_s32(abs_diff)))))
        scaled = _fcvtzs_i64(math.ldexp(1.0, exp_i) * float(out[i]))
        if diff_s64 >= 0:
            scaled = _s64(-scaled)
        out[i] = scaled
    return out


def _hist_max_4(arr: list[int]) -> list[int]:
    n = len(arr)
    base_len = _c_div(n, 4)
    rem_len = _c_rem(n, 4)
    out: list[int] = []
    for k in range(4):
        clen = base_len + (rem_len if k == 3 else 0)
        start = k * base_len
        out.append(_s64(_largest_rect_hist(arr[start : start + clen])))
    return out


def _doolittle_lu_7x7(mat: list[list[int]]) -> list[list[int]]:
    mat_l = [[0] * 7 for _ in range(7)]
    mat_u = [[0] * 7 for _ in range(7)]
    for i in range(7):
        mat_l[i][i] = _s64(mat[i][i] + 1)
    for i in range(7):
        for j in range(i, 7):
            s = 0
            for k in range(i):
                s = _s64(s + mat_l[i][k] * mat_u[k][j])
            mat_u[i][j] = _s64(mat[i][j] - s)
        for j in range(i, 7):
            if j == i:
                mat_l[i][i] = _s64(mat[i][i] + 1)
            else:
                s = 0
                for k in range(i):
                    s = _s64(s + mat_l[j][k] * mat_u[k][i])
                mat_l[j][i] = _s64(_s64(mat[j][i] - s) + mat_u[i][i])
    return [[_s64(mat_l[r][c] + mat_u[r][c]) for c in range(7)] for r in range(7)]


def _tree_dfs_nodes(root: _RBNode | None) -> list[_RBNode]:
    if root is None:
        return []
    stack = [root]
    out: list[_RBNode] = []
    while stack:
        u = stack.pop()
        out.append(u)
        if u.right is not None:
            stack.append(u.right)
        if u.left is not None:
            stack.append(u.left)
    return out


def _tree_color_scale(tree: _RBTree0x7a) -> None:
    nodes = _tree_dfs_nodes(tree.root)
    sum_r = 0
    sum_b = 0
    for u in nodes:
        if u.color == 0x52:
            sum_r = _s64(sum_r + u.key)
        else:
            sum_b = _s64(sum_b + u.key)
    h_cur = _s64(tree.height)
    d_cur = _s64(tree.diameter)
    v_sum = _s64(h_cur + d_cur)
    v_avg = _u64(abs(_s64(sum_r + sum_b))) >> 1
    diff0 = abs(_s64(h_cur - sum_r))
    diff1 = abs(_s64(d_cur - sum_b))
    x8 = _u64(abs(_s64(diff0 - diff1)))
    if (x8 >> 62) != 0:
        x8 = _u64(x8 - 0x4000000000000000)
    v_diff = _s64(x8)
    v_mid = _c_div(_s64(v_diff + _s64(v_avg) + v_sum), 2)
    rad = _s64(
        abs(_s64(v_mid - v_sum))
        + abs(_s64(v_mid - _s64(v_avg)))
        + v_mid
        + abs(_s64(v_mid - v_diff))
        + 6
    )
    factor = _c_rem(_fcvtzs_i64(math.sqrt(float(rad))), 100000)
    for u in nodes:
        w = _s64(_s64(u.key - sum_b) + sum_r)
        u.key = _s64(w * factor + w)


def _tree_hypot_scale(tree: _RBTree0x7a, h1: int, d1: int, h2: int, d2: int) -> None:
    hs = float(_s32(h1 + h2))
    ds = float(_s32(d1 + d2))
    scale = _fcvtzs_i64(abs(math.sqrt(hs * hs + ds * ds)))
    for u in _tree_dfs_nodes(tree.root):
        u.key = _s64(u.key * scale)


def _tree_ratio_scale(tree: _RBTree0x7a, h1: int, d1: int, h2: int, d2: int) -> None:
    num_q = abs(_s64(_s64(h2 + d2) * d1))
    den_q = _s64(_s64(h1 + d1) * h2)
    q_val = _s64(_c_div(num_q, den_q) + 1)
    a_f = float(_s32(h2 * d2 + h1 * d1))
    b_f = float(_s32(h1 * d2 + d1 * h2))
    r_num = _fcvtzs_i64(math.sqrt(a_f * a_f + b_f * b_f))
    r_den = _fcvtzs_i64(float(d1) * float(d1) + float(d2) * float(d2))
    scale = _s64(q_val * _c_rem(r_num, r_den))
    for u in _tree_dfs_nodes(tree.root):
        u.key = _s64(u.key * scale)


def _tree_level_order(root: _RBNode | None, zigzag: bool = False) -> list[int]:
    if root is None:
        return []
    out: list[int] = []
    q_bfs: deque[_RBNode] = deque([root])
    rev = False
    while q_bfs:
        lvl_vals: list[int] = []
        for _ in range(len(q_bfs)):
            u = q_bfs.popleft()
            lvl_vals.append(u.key)
            if u.left is not None:
                q_bfs.append(u.left)
            if u.right is not None:
                q_bfs.append(u.right)
        if rev:
            lvl_vals.reverse()
        if zigzag:
            rev = not rev
        out.extend(lvl_vals)
    return out


def _tree_vertical_order(root: _RBNode | None) -> list[int]:
    if root is None:
        return []
    hd_map: dict[int, list[int]] = {}
    q_vo: deque[tuple[_RBNode, int]] = deque([(root, 0)])
    min_hd = 0
    max_hd = 0
    while q_vo:
        u, hd = q_vo.popleft()
        hd_map.setdefault(hd, []).append(u.key)
        if u.left is not None:
            q_vo.append((u.left, _s32(hd - 1)))
        if u.right is not None:
            q_vo.append((u.right, _s32(hd + 1)))
        if hd > max_hd:
            max_hd = hd
        if hd < min_hd:
            min_hd = hd
    out: list[int] = []
    for hd in range(min_hd, max_hd + 1):
        if hd in hd_map:
            out.extend(hd_map[hd])
    return out


def _finalize_vwords(vwords: list[int], h1: int, d1: int, h3: int, d3: int) -> list[int]:
    acc = 0
    for w in vwords:
        if w < 0:
            acc = _s64(acc - (abs(w) & 0x7FFFFFFF))
        else:
            acc = _s64(acc + (w & 0x7FFFFFFF))
    abs_acc_p2 = float(_u64((abs(acc) if acc < 0 else acc) + 2))
    d0_log = math.floor(math.log(abs_acc_p2) if abs_acc_p2 > 0.0 else 0.0)
    d1_f = float(h1)
    d2_f = float(d1)
    d4_f = d1_f * _DEG_TO_RAD_C3E68
    d5_f = d4_f * d2_f * _DEG_TO_RAD_C3E68 * d1_f * d2_f * _DEG_TO_RAD_C3E68 * d1_f * d2_f
    d4_f = d4_f * d2_f + (d5_f / -6.0)
    d5_f = d5_f * _DEG_TO_RAD_C3E68 * d1_f * d2_f * _DEG_TO_RAD_C3E68 * d1_f * d2_f
    d4_f = d4_f + (d5_f / 120.0)
    d5_f = d5_f * _DEG_TO_RAD_C3E68 * d1_f * d2_f * _DEG_TO_RAD_C3E68 * d1_f * d2_f
    d1_sin = d4_f + (d5_f / -5040.0)
    hypot_3 = math.sqrt(float(h3) * float(h3) + float(d3) * float(d3))
    d1_ceil = math.ceil(hypot_3 + d1_sin)
    w8_diff = _s32(_fcvtzs_i64(abs(d0_log - d1_ceil)))
    k_rev = _c_rem(w8_diff, 48) + 1
    out = [-((w) & 0x7FFFFFFF) if w <= 0 else (w & 0x7FFFFFFF) for w in vwords]
    if k_rev > 1:
        for pos in range(0, len(out), k_rev):
            end = min(pos + k_rev, len(out))
            out[pos:end] = reversed(out[pos:end])
    return out


def _combine_ossvec2(bn1: list[int], bn2: list[int], h1: int, d1: int, h3: int, d3: int) -> list[int]:
    vec_a = list(bn1)
    vec_b = list(bn2)
    if len(vec_a) > len(vec_b):
        vec_b.extend([1] * (len(vec_a) - len(vec_b)))
    out: list[int] = []
    hd_dot = _s64(h1 * h3 + d1 * d3)
    hd_sum_sq = float(_s32(h1 + h3)) ** 2 + float(_s32(d1 + d3)) ** 2
    for a, b in zip(vec_a, vec_b):
        num = _s64(a * b + hd_dot)
        diff_ab = float(_s64(a - b))
        den = _fcvtzs_i64(math.cbrt(hd_sum_sq + diff_ab * diff_ab))
        out.append(_fcvtms_i64(float(num) / float(den)))
    return out


def derive_c3e68_vectors_pure(
    lock_pairs: Sequence[tuple[str | bytes, str | bytes]],
) -> tuple[list[int], list[int]]:
    # (carrier_words, oss_vector) for 0x7a (0x1005c3e68)
    norm_pairs = _normalize_lock_pairs(lock_pairs)
    dsn = b"".join(v for _, v in norm_pairs)
    L = len(dsn)

    # Stage 2: ROT47 + 32-bit Gray code -> arr490
    arr490: list[int] = []
    for b in dsn:
        sb = b - 256 if b >= 128 else b
        if ((b - 0x21) & 0xFF) < 0x2F:
            rot = _s32(sb + 0x2F)
        elif _u32(sb - 0x50) < 0x2F:
            rot = _s32(sb - 0x2F)
        else:
            rot = sb
        arr490.append(_s32(rot ^ (rot >> 1)))

    # Stage 3 & 4: Mean-deviation ldexp transform & 4-chunk histogram max
    x27 = _mean_ldexp_scale(arr490)
    hist_max = _hist_max_4(arr490)

    # Stage 5: 196-element buffer buf980 and 14x14 matrix mat_8d8
    buf980 = [0] * 196
    for idx, v in enumerate(x27):
        ax = abs(v)
        rem9 = ax % 9
        d1 = 9.0 if rem9 == 0 else float(_u32(rem9))
        val = _fcvtzs_i64(d1 * d1 + float(v))
        if idx < 196:
            buf980[idx] = val if (idx & 1) == 0 else _s64(-val)

    m_cnt = L
    for fill_idx in range(L, 196):
        r = m_cnt % (L + 1)
        addend = _s32(m_cnt + (fill_idx >> 2))
        buf980[fill_idx] = _s64(buf980[r] + addend)
        m_cnt += 1

    mat_8d8 = [[0] * 14 for _ in range(14)]
    i1 = 0
    i2 = 0
    for flat in range(196):
        r, c = divmod(flat, 14)
        if i1 < L:
            mat_8d8[r][c] = x27[i1]
            i1 += 1
        else:
            mat_8d8[r][c] = buf980[i2 % 196]
            i2 += 1

    # Stage 6: Split mat_8d8 into 4 7x7 quadrants vec_8f0[0..3] and dispatch 0x1005c1644
    quads = [
        [[mat_8d8[(q // 2) * 7 + r][(q % 2) * 7 + c] for c in range(7)] for r in range(7)]
        for q in range(4)
    ]
    center_sum = _s64(mat_8d8[6][6] + mat_8d8[6][7] + mat_8d8[7][6] + mat_8d8[7][7])
    center_avg = _c_div(center_sum, 4)
    total_c = _s64(mat_8d8[0][0] + center_avg + mat_8d8[13][13])
    r9 = _c_rem(total_c, 9)
    rem_val = 9 if r9 == 0 else _s32(r9)

    perm_map = {
        0: (0, 1, 2, 3),
        1: (1, 2, 3, 0),
        2: (2, 3, 0, 1),
        3: (3, 1, 2, 0),
        4: (2, 1, 0, 3),
        5: (0, 1, 2, 3),
        6: (1, 2, 3, 0),
        7: (2, 3, 0, 1),
        8: (3, 1, 2, 0),
    }
    p0, p1, p2, p3 = perm_map.get(rem_val, (1, 0, 2, 3))
    mat_8c0 = _mat7_combine(quads[p0], quads[p1], quads[p2], quads[p3], use_0x7a=True)

    # Stage 7: Doolittle/Crout-style LU decomposition -> mat_8a8 -> clockwise spiral vec_7b0
    mat_8a8 = _doolittle_lu_7x7(mat_8c0)

    vec_7b0: list[int] = []
    top, bottom, left, right = 0, 6, 0, 6
    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            vec_7b0.append(mat_8a8[top][c])
        top += 1
        for r in range(top, bottom + 1):
            vec_7b0.append(mat_8a8[r][right])
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                vec_7b0.append(mat_8a8[bottom][c])
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                vec_7b0.append(mat_8a8[r][left])
            left += 1

    # Stage 8: Red-Black Tree insertion + Zigzag BFS -> bn2_908
    tree = _RBTree0x7a()
    for val in vec_7b0:
        tree.insert(val)
    h1, d1 = tree.compute_height_diam()
    bn2_908 = _tree_level_order(tree.root, zigzag=True)

    # Stage 9: Tree mutations (Op 1, Op 2, Op 3) based on (h1 % 3) + 1 and is_prime(h1)
    mod3_arm = _c_rem(h1, 3) + 1
    prime_h1 = _is_prime_u32(h1)

    if mod3_arm == 1:
        tree.insert(hist_max[3 if prime_h1 else 0])
        _tree_color_scale(tree)
    elif mod3_arm == 2:
        tree.insert(hist_max[1 if prime_h1 else 3])
        _tree_color_scale(tree)
        h2, d2 = tree.compute_height_diam()
        tree.insert(hist_max[2 if prime_h1 else 0])
        _tree_hypot_scale(tree, h1, d1, h2, d2)
    else:
        tree.insert(hist_max[0 if prime_h1 else 3])
        _tree_color_scale(tree)
        h2, d2 = tree.compute_height_diam()
        tree.insert(hist_max[1 if prime_h1 else 2])
        _tree_hypot_scale(tree, h1, d1, h2, d2)
        tree.insert(hist_max[3 if prime_h1 else 0])
        _tree_ratio_scale(tree, h1, d1, h2, d2)

    h3, d3 = tree.compute_height_diam()

    # Stage 10: Vertical Order Traversal -> bn1_938
    bn1_938 = _tree_vertical_order(tree.root)

    # Stage 11: LCG-driven tree walk -> vwords_920
    vwords_920: list[int] = []
    if tree.root is not None:
        node_list: list[_RBNode] = [tree.root]
        lcg_state = 42
        while node_list:
            step_sum = _s64(lcg_state + 0x693D4A4 + 0x3039)
            f_rem = math.fmod(float(step_sum), float(-0x80000000))
            lcg_state = _fcvtzs_i64(f_rem)
            pick_idx = _fcvtzs_i64(math.fmod(float(int(f_rem)), float(len(node_list))))
            u = node_list.pop(pick_idx)
            vwords_920.append(u.key)
            if u.left is not None:
                node_list.append(u.left)
            if u.right is not None:
                node_list.append(u.right)

    return (
        _finalize_vwords(vwords_920, h1, d1, h3, d3),
        _combine_ossvec2(bn1_938, bn2_908, h1, d1, h3, d3),
    )


# ------------------------------------------- selector 0x82 (0x10063f408 .. 0x10069cdb0)

# 28-byte constant decrypted when len(lock_pairs) == 0, and 21-byte constant
# decrypted from 0x105616ba8 -> 0x106ab5a20 via 0x1006b0c2c when len(lock_pairs) < 2.
_EMPTY_28B_63F408: Final[bytes] = b"?AH(_u@\\/D>u#m^h&b$!arm+pt_y"
_DEFAULT_21B_63F408: Final[bytes] = b"O@<n;e.$e*N?\\'/,PC(&l"

# LCG constants at 0x105616b20 and modulus at 0x100666a8c
_LCG_C778_63F408: Final[int] = 190544521  # 0x0b5b7a89
_LCG_C780_63F408: Final[int] = 42819      # 0x0000a743
_LCG_MOD_63F408: Final[int] = 0x20000000

# 20-entry jump table at 0x1006ab3ac / 0x1006ab3fc / 0x1006ab44c / 0x1006afef8
# mapping sel in 0..19 -> (use_634c2c, (q0, q1, q2, q3)), with negative/default -> (False, (1, 0, 2, 3))
_QUAD_PERM_63F408: Final[dict[int, tuple[bool, tuple[int, int, int, int]]]] = {
    0: (False, (0, 1, 2, 3)),
    1: (True, (1, 2, 3, 0)),
    2: (False, (2, 3, 0, 1)),
    3: (False, (3, 1, 2, 0)),
    4: (False, (2, 1, 0, 3)),
    5: (False, (0, 1, 2, 3)),
    6: (True, (1, 2, 3, 0)),
    7: (False, (2, 3, 0, 1)),
    8: (False, (3, 1, 2, 0)),
    9: (False, (0, 2, 1, 3)),
    10: (True, (1, 3, 0, 2)),
    11: (False, (0, 2, 1, 3)),
    12: (False, (2, 3, 1, 0)),
    13: (True, (3, 2, 0, 1)),
    14: (False, (2, 3, 1, 0)),
    15: (True, (1, 3, 0, 2)),
    16: (True, (3, 2, 0, 1)),
    17: (False, (3, 2, 1, 0)),
    18: (False, (2, 1, 0, 3)),
    19: (False, (3, 2, 1, 0)),
}
_QUAD_PERM_63F408_DEFAULT: Final[tuple[bool, tuple[int, int, int, int]]] = (
    False,
    (1, 0, 2, 3),
)


def _s8(x: int) -> int:
    x &= 0xFF
    return x - 0x100 if x & 0x80 else x


def derive_63f408_vectors_pure(
    lock_pairs: Sequence[tuple[str | bytes, str | bytes]],
) -> tuple[list[int], list[int]]:
    # (carrier_words, oss_vector) for 0x82 (0x10063f408)
    norm_pairs = _normalize_lock_pairs(lock_pairs)

    # Stage 1: String list (prepend 28B if empty, prepend 21B if len < 2), reverse each, concatenate
    strs: list[bytes] = []
    if len(norm_pairs) == 0:
        strs.append(_EMPTY_28B_63F408)
    if len(norm_pairs) < 2:
        strs.append(_DEFAULT_21B_63F408)
    for _, v in norm_pairs:
        strs.append(v)
    dsn_str = b"".join(s[::-1] for s in strs)
    L = len(dsn_str)

    # Stage 2A: Polynomial ROT47 + modified Gray code + mean-deviation ldexp -> arr_3f0
    x26: list[int] = [0] * L
    for i, u in enumerate(dsn_str):
        s = _s8(u)
        if ((u - 0x21) & 0xFF) < 0x2F:
            t = _s32(s * s * 0x2F - 1)
            x26[i] = _c_rem(t, 256)
        elif _u32(s - 0x50) < 0x2F:
            t = _s32((s + 0x1F) * s - 0x2F)
            x26[i] = _c_rem(t, 256)
        else:
            x26[i] = s

    arr_3f0 = _mean_ldexp_scale(
        [_s64(_s32(((w9 + 1) ^ (w9 << 1)) ^ (w9 + (w9 >> 1)))) for w9 in x26]
    )

    # Stage 2B: Standard ROT47 + modified Gray code + Largest Rectangle in Histogram -> hist_max[0..3]
    arr_370: list[int] = [0] * L
    for i, u in enumerate(dsn_str):
        s = _s8(u)
        if ((u - 0x21) & 0xFF) < 0x2F:
            r = _s32(s + 0x2F)
        elif _u32(s - 0x50) < 0x2F:
            r = _s32(s - 0x2F)
        else:
            r = s
        arr_370[i] = _s32(((r + 1) ^ (r << 1)) ^ (r + (r >> 1)))

    hist_max = _hist_max_4(arr_370)

    # Stage 3: 196-element buffer buf9f0 & 14x14 matrix mat_948
    buf9f0: list[int] = [0] * 196
    idx = 0
    m = 0
    for v in arr_3f0:
        if v != 0:
            d0 = float(_u64(v * v))
            rem9 = abs(v) % 9
            d1_f9 = 9.0 if rem9 == 0 else float(_u32(rem9))
            w_val = _fcvtzs_i64(d1_f9 * d1_f9 + d0)
        else:
            w_val = 0
        if idx < 196:
            if (idx & 1) == 0:
                buf9f0[idx] = _s64(3 * w_val + 5)
            else:
                buf9f0[idx] = _s64(-7 * w_val + 50)
        idx += 1
        m += 1

    mod_div = L + 1
    fill_idx = m
    while fill_idx < 196:
        r = _u32(m * m + 1) % mod_div
        addend = _s32((m + (fill_idx >> 1)) | (fill_idx >> 2))
        buf9f0[fill_idx] = _s64(buf9f0[r] + addend)
        fill_idx += 1
        m += 1

    mat_948: list[list[int]] = [[0] * 14 for _ in range(14)]
    i1 = 0
    i2 = 0
    for flat in range(196):
        row = flat // 14
        col = flat % 14
        if i1 < L:
            v = arr_3f0[i1]
            i1 += 1
            mat_948[row][col] = _s64(_c_rem(v, 10009) + _s32(7 * flat))
        else:
            b_val = buf9f0[_c_rem(i2, 196)]
            i2 += 1
            r1 = _s32(_c_rem(b_val, 10003))
            x_val = arr_3f0[i1 % L]
            r2 = _s32(_c_rem(x_val, 10093))
            prod = _s32(r1 * r2)
            mat_948[row][col] = _s64(_c_rem(prod, 199947))

    # Stage 4: Quadrant split + selector + matrix combine + modular reduction
    quads: list[list[list[int]]] = [[[0] * 7 for _ in range(7)] for _ in range(4)]
    for q in range(4):
        r_base = (q // 2) * 7
        c_base = (q % 2) * 7
        for r in range(7):
            for c in range(7):
                offset = _s32((2 * r + 2) * (c + 3))
                quads[q][r][c] = _s64(mat_948[r_base + r][c_base + c] + offset)

    val_c = _s64(_s64(mat_948[7][6] + mat_948[7][7]) * mat_948[6][6] + mat_948[6][7])
    avg4 = _c_div(val_c, 4)
    total_c = _s64(mat_948[0][0] + _s64(3 * avg4) + mat_948[13][13])
    if total_c == 0:
        sel = 0
    elif _c_rem(total_c, 19) == 0:
        sel = 19
    else:
        sel = _s32(_c_rem(total_c, 17))

    use_634c2c, (p0, p1, p2, p3) = _QUAD_PERM_63F408.get(sel, _QUAD_PERM_63F408_DEFAULT)
    mat_930 = _mat7_combine(quads[p0], quads[p1], quads[p2], quads[p3], use_0x7a=use_634c2c)

    for r in range(7):
        for c in range(7):
            x = mat_930[r][c]
            mod_val = 100129 if _c_rem(x, 3) == 0 else 10091
            mat_930[r][c] = _c_rem(x, mod_val)

    # Stage 5: Modified Doolittle LU Decomposition + Anti-Diagonal Zigzag Walk -> vec_808
    mat_918 = _doolittle_lu_7x7(mat_930)

    vec_808: list[int] = []
    for d in range(13):
        c_start = min(6, d)
        r_start = max(0, d - 6)
        diag: list[int] = []
        r_cur, c_cur = r_start, c_start
        while c_cur >= 0 and r_cur < 7:
            diag.append(mat_918[r_cur][c_cur])
            r_cur += 1
            c_cur -= 1
        if (d & 1) == 0:
            vec_808.extend(reversed(diag))
        else:
            vec_808.extend(diag)

    # Stage 6: Red-Black Tree Insertion + Plain Level-Order Traversal -> bn2_978
    tree = _RBTree0x7a()
    for v in vec_808:
        tree.insert(v)
    h1, d1 = tree.compute_height_diam()
    bn2_978 = _tree_level_order(tree.root, zigzag=False)

    # Stage 7: LCG + Conditional hist_max Insertions & Tree Mutations
    lcg_state = _s64(h1) << 1

    def lcg_step() -> int:
        nonlocal lcg_state
        s_val = _s64(_s64(lcg_state + _LCG_C778_63F408) + _LCG_C780_63F408)
        lcg_state = _fcvtzs_i64(math.fmod(float(s_val), float(_LCG_MOD_63F408)))
        return lcg_state

    mod4_arm = _c_rem(h1, 4) + 1
    if mod4_arm == 1:
        tree.insert((hist_max[1] ^ hist_max[3]) if _is_prime_u32(h1) else (hist_max[2] ^ hist_max[0]))
        _tree_color_scale(tree)
    elif mod4_arm == 2:
        if _is_prime_u32(d1):
            tree.insert(_s64(hist_max[0] + hist_max[1]))
            _tree_color_scale(tree)
            h2, d2 = tree.compute_height_diam()
            st_val = lcg_step()
            tree.insert(_c_rem(_s64(hist_max[2] * st_val), 10001))
        else:
            tree.insert(hist_max[3])
            _tree_color_scale(tree)
            h2, d2 = tree.compute_height_diam()
            tree.insert(hist_max[2] ^ hist_max[0])
        _tree_hypot_scale(tree, h1, d1, h2, d2)
    else:
        if _is_prime_u32(h1):
            r1 = _c_rem(hist_max[0], 999)
            st_val = lcg_step()
            tree.insert(_c_rem(_s64(r1 * st_val), 1001))
            _tree_color_scale(tree)
            h2, d2 = tree.compute_height_diam()
            tree.insert(hist_max[1])
            _tree_hypot_scale(tree, h1, d1, h2, d2)
            r2 = _c_rem(hist_max[3], 9387)
            st_val2 = lcg_step()
            tree.insert(_s64(r2 * st_val2 + hist_max[2]))
        else:
            r1 = _c_rem(hist_max[3], 9387)
            st_val = lcg_step()
            tree.insert(_s64(r1 * st_val + hist_max[1]))
            _tree_color_scale(tree)
            h2, d2 = tree.compute_height_diam()
            tree.insert(hist_max[2])
            _tree_hypot_scale(tree, h1, d1, h2, d2)
            tree.insert(hist_max[0])
        _tree_ratio_scale(tree, h1, d1, h2, d2)

    h3, d3 = tree.compute_height_diam()

    # Stage 8: LCG-Driven Tree Walk with Conditional Node Key XOR -> vwords_990
    vwords_990: list[int] = []
    if tree.root is not None:
        node_list: list[_RBNode] = [tree.root]
        while node_list:
            st_val = lcg_step()
            pick_idx = _fcvtzs_i64(math.fmod(float(st_val), float(len(node_list))))
            u = node_list.pop(pick_idx)
            vwords_990.append(u.key)
            st_val2 = lcg_step()
            rem9 = _c_rem(st_val2, 9)
            if rem9 < 6:
                if u.left is not None:
                    if _c_rem(u.key, 7) > 3:
                        st_val3 = lcg_step()
                        u.key = _s64(u.key ^ st_val3)
                    node_list.append(u.left)
                if u.right is not None:
                    node_list.append(u.right)
            else:
                if u.right is not None:
                    node_list.append(u.right)
                if u.left is not None:
                    node_list.append(u.left)

    bn1_9a8 = _tree_vertical_order(tree.root)
    return (
        _finalize_vwords(vwords_990, h1, d1, h3, d3),
        _combine_ossvec2(bn1_9a8, bn2_978, h1, d1, h3, d3),
    )

