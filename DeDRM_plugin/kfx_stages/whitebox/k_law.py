"""Stage 4: the 256-byte K mask, from the 57-char voucher ID.

state[j] ^= K[j] on the low byte, word by word, just after compute_state.
"""

from __future__ import annotations

from . import constants

M32 = 1 << 32


def _s32(x: int) -> int:
    return x - M32 if x >= (1 << 31) else x


def _amod(v: int, m: int) -> int:
    return abs(_s32(v)) % m


# which byte K[j] copies, for state word j (0..255): the schedule picks one of five
# paths.
#   C: idx(j) = |s32(T868[j+5])| % 57
#   D: idx(j) = |s32(T880[j+2])| % 57
#   B: idx(j) = |s32(T898[j])| % 57
#   A: idx(j) = |s32(T868[ |s32(T898[j+5])| % 1079 ])| % 57
#   E: skip -- K[j] = 0
def _idx_of(
    j: int,
    path: str,
    t868: list[int],
    t880: list[int],
    t898: list[int],
) -> int | None:
    if path == "C":
        return _amod(t868[j + 5], 57)
    if path == "D":
        return _amod(t880[j + 2], 57)
    if path == "B":
        return _amod(t898[j], 57)
    if path == "A":
        k1 = _amod(t898[j + 5], 1079)
        return _amod(t868[k1], 57)
    return None


def compute_K(
    voucher: str | bytes,
    schedule: str | None = None,
    t868: list[int] | None = None,
    t880: list[int] | None = None,
    t898: list[int] | None = None,
) -> list[int]:
    v_b = voucher.encode("ascii") if isinstance(voucher, str) else bytes(voucher)
    if len(v_b) != 57:
        raise ValueError(f"Expected 57-char voucher ID, got {len(v_b)}")

    sched = schedule if schedule is not None else constants.SCHEDULE
    tab868 = t868 if t868 is not None else constants.T868
    tab880 = t880 if t880 is not None else constants.T880
    tab898 = t898 if t898 is not None else constants.T898

    K = []
    for j in range(256):
        p = sched[j]
        if p == "E":
            K.append(0)
            continue
        idx = _idx_of(j, p, tab868, tab880, tab898)
        K.append(v_b[idx] if idx is not None and idx < 57 else 0)
    return K


def apply_mask(
    state256: list[int],
    voucher: str | bytes,
    schedule: str | None = None,
    t868: list[int] | None = None,
    t880: list[int] | None = None,
    t898: list[int] | None = None,
) -> list[int]:
    K = compute_K(voucher, schedule, t868=t868, t880=t880, t898=t898)
    return [(w & ~0xFF) | ((w & 0xFF) ^ K[j]) for j, w in enumerate(state256[:256])]
