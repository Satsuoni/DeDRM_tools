"""Stage 9 FIFO ring traversal and stage 10 M1 serializer."""

from __future__ import annotations

M32 = 0xFFFFFFFF
TENSOR_N = 162


class GateMachine:
    def __init__(self, tensor: list[list[list[int]]]) -> None:
        self.tensor = [[plane[:] for plane in root] for root in tensor]
        self.flags = [[[0] * 9 for _ in range(9)] for _ in range(2)]
        self.pushes: list[tuple[int, int, int]] = []
        self._front = 0

    @property
    def size(self) -> int:
        return len(self.pushes) - self._front

    def ring_push(self, triple: tuple[int, int, int]) -> None:
        self.pushes.append((triple[0], triple[1], triple[2]))

    def ring_pop(self) -> tuple[int, int, int]:
        assert self.size > 0
        tri = self.pushes[self._front]
        self._front += 1
        return tri

    def value(self, plane: int, cell: int, root: int) -> int:
        return self.tensor[root][plane][cell] & M32

    def set_flag(self, plane: int, cell: int, root: int, v: int = 1) -> None:
        self.flags[root][plane][cell] = v & 1

    def call_gate(self, plane: int, cell: int, root: int, V: int) -> bool:
        if (
            not (0 <= plane < 9 and 0 <= cell < 9 and 0 <= root < 2)
            or self.flags[root][plane][cell] != 0
        ):
            return False
        cv = self.tensor[root][plane][cell] & M32
        cv_s = cv - (1 << 32) if cv >= (1 << 31) else cv
        v32 = V & M32
        V_s = v32 - (1 << 32) if v32 >= (1 << 31) else v32
        accept = (
            ((cv_s < V_s) or bool(cv & 1)) if (v32 & 1) == 0 else ((cv_s > V_s) or not bool(cv & 1))
        )
        if accept:
            self.set_flag(plane, cell, root, 1)
            self.ring_push((plane, cell, root))
            return True
        return False


def walk_emitted(
    tensor_flat: list[int],
    leftover: bool = True,
    *,
    seeds: tuple[tuple[int, int, int], ...] = ((0, 0, 0), (0, 1, 0)),
    max_reseed: int | None = 8,
) -> tuple[list[int], list[tuple[int, int, int]], list[tuple[int, int, int]]]:
    grid = [[[0] * 9 for _ in range(9)] for _ in range(2)]
    for r in range(2):
        for p in range(9):
            for c in range(9):
                v = tensor_flat[r * 81 + p * 9 + c] & M32
                grid[r][p][c] = v - (1 << 32) if v >= (1 << 31) else v

    gm = GateMachine(grid)
    for seed in seeds:
        gm.ring_push(seed)
        gm.set_flag(seed[0], seed[1], seed[2], 1)

    nref = 0
    while True:
        while gm.size != 0:
            plane, cell, root = gm.ring_pop()
            V = gm.value(plane, cell, root)
            for a, b, cc in (
                (plane + 1, cell, root),
                (plane - 1, cell, root),
                (plane, cell + 1, root),
                (plane, cell - 1, root),
                (plane, cell, 1 - root),
            ):
                if len(gm.pushes) >= TENSOR_N:
                    break
                gm.call_gate(a, b, cc, V)
            if len(gm.pushes) >= TENSOR_N:
                break

        if len(gm.pushes) >= TENSOR_N or not leftover:
            break

        seen = set(gm.pushes)
        nxt = next(
            (
                (a, b, c)
                for c in range(2)
                for a in range(9)
                for b in range(9)
                if (a, b, c) not in seen
            ),
            None,
        )
        if nxt is None:
            break
        gm.ring_push(nxt)
        gm.set_flag(nxt[0], nxt[1], nxt[2], 1)
        nref += 1
        if max_reseed is not None and nref > max_reseed:
            break

    ring = list(gm.pushes)
    if leftover and len(ring) < TENSOR_N:
        seen = set(ring)
        for c in range(2):
            for a in range(9):
                for b in range(9):
                    if (a, b, c) not in seen:
                        ring.append((a, b, c))
                        seen.add((a, b, c))

    emitted = [tensor_flat[r * 81 + p * 9 + c] & M32 for (p, c, r) in ring[:TENSOR_N]]
    return emitted, ring[:TENSOR_N], gm.pushes


def walk_emitted_corrected(final: list[int]) -> list[int]:
    emitted, _ring, _pushes = walk_emitted(final, seeds=((0, 0, 0),), max_reseed=None)
    return emitted


def render_digits(emitted: list[int]) -> str:
    out = []
    for i in range(len(emitted) - 1, -1, -1):
        v = emitted[i]
        v = v - (1 << 32) if v >= (1 << 31) else v
        if v <= 0:
            continue
        a = b = v & 0xFF
        while a > 0 or b > 0:
            # it's the same byte twice: base 16 digits off a, base 8 off b
            if a > 0:
                out.append(str(a % 16))
                a >>= 4
            if b > 0:
                out.append(str(b % 8))
                b >>= 3
    return "".join(out)


def pack_digits(s: str, tail: str = "lone_digit") -> bytes:
    m1 = bytearray()
    for i in range(0, len(s), 2):
        if i + 1 < len(s):
            m1.append(int(s[i]) * 10 + int(s[i + 1]))
        elif tail == "penultimate":
            # a lone last digit can't pair, so tail decides what it pairs with
            m1.append(int(s[i]) * 10 + int(s[-2]))
        else:
            m1.append(int(s[i]))
    return bytes(m1)


def serialize_m1(emitted: list[int], tail: str = "lone_digit") -> bytes:
    return pack_digits(render_digits(emitted), tail)
