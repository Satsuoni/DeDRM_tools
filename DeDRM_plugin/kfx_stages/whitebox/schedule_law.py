"""Stage 4: the K-mask schedule selection law.

Replaces the section-19 observed-schedule recovery with a prediction.  The
engine's mask pass is a 27-state flattened-control-flow dispatcher (jump table
0xa596ac, selector global 0xa5fdec, trampoline 0x33c00c0); its j-phase XOR loop
picks one of five handlers per state word through a four-rung ladder.  The
per-book input is only the parity bit at the 46 v == 4 positions, since
compute_state(vecB(message), voucher_id) is pure Python here.
"""

from __future__ import annotations

from .verdict import fn_c1810_pure

# F0[j] = helper_0x33c1810((2j+2) ^ (3j+1)) % 5.  A function of j alone: no
# voucher, state or book bytes.  The helper is a park-miller/lehmer step mod
# 2^31-1 with A = 0x4feab0ff in Schrage form (fn_c1810_pure).
_HANDLER = {0: "B", 1: "C", 2: "D", 3: "A"}


def _derive_f0() -> list[int]:
    return [fn_c1810_pure(((2 * j + 2) ^ (3 * j + 1)) & 0xFFFFFFFF) % 5 for j in range(256)]


F0 = _derive_f0()


# The decoded ladder, on v = F0[j]:
#   v == 0 -> s7  (path B)      v == 1 -> s5  (path C)     v == 2 -> s21 (path D)
#   v == 3 -> s15 (path A)
#   v == 4 -> parity rung (0x33c0094 tst x8,#1 on the state word):
#             state[j] odd  -> s15 (path A)
#             state[j] even -> fall-through to s20 (path E, no XOR)
# Exact statically, not only statistically: with the w22 chain the (w22 * imm) >> 17
# opaque terms are constants (s22: term 0x6df3 -> 7/14; s23: 0x36 -> 21/8; s8: 0xf91
# -> 15/20).
def predict_schedule(state256: list[int]) -> str:
    if len(state256) < 256:
        raise ValueError(f"need 256 state words, got {len(state256)}")
    out = []
    for j in range(256):
        v = F0[j]
        if v == 4:
            out.append("A" if state256[j] & 1 else "E")
        else:
            out.append(_HANDLER[v])
    return "".join(out)

