"""whitebox -- the pure-Python key-derivation engine (15 stages, all in-process).

The fifteen-stage app-generation engine, packaged here.  What changed: import
paths, the table byte source (kfx_stages.whitebox.constants), and delivery, which goes
through kfx_stages.container now instead of a single monolithic-assembly module.
"""

# Stage map -- no engine calls behind any of these:
#  1  identity: recipient class constant
#  2  lcg: byte stream + 3-tap filter -> vector B
#  3  verdict.compute_state -> 256-word state
#  4  k_law / schedule_law: per-book K-mask schedule law
#  5  builder -> 60-byte vector A
#  6  verdict.mix_vectorC: A x B -> C
#  7  derive.fills_scaled: fills tensor, 162 cells
#  8  stepper: dispatcher-2 -> the final 162-cell tensor
#  9  gate_walk: FIFO ring walk over the 2x9x9 grid
# 10  gate_walk.serialize_m1: M1 serializer (lone-digit tail law)
# 11  unwrapper.seed_from_m1: HMAC-SHA256(SHA256(M1), "PIDv3")
# 12  unwrapper.m32_for_blob: AES-256-CBC(K_C0_0X7E, blob64[:16], blob64[16:48]) -> m32
# 13  unwrapper.pure_unwrap_doc: k_eff = seed ^ m32
# 14  unwrapper.pure_unwrap_doc: AES-256-CBC(k_eff, iv, ct512) -> KeySet -> 16-B key
# 15  derive.oracle_check: first page has to start 00 5d

from __future__ import annotations

from pathlib import Path

from .builder import builder_vectorA_pure
from .derive import (
    DerivationError,
    derive_identities,
    identity_chain,
    stage_family,
    unwrap_seed,
)
from .gate_walk import serialize_m1, walk_emitted
from .identity import (
    Identity,
    candidate_identities_for_class,
    classify_envelope,
    classify_recipient,
    class_of_lock_parameters,
    empty_class_message,
    load_constant,
)
from .k_law import apply_mask, compute_K
from .lcg import tokens_to_vectorB
from .message import message_law
from .schedule_law import predict_schedule
from .stepper import replacement
from .unwrapper import derive_book_key as derive_book_key_from_m1
from .unwrapper import extract_voucher_id, seed_from_m1
from .verdict import compute_state, fills_tensor, mix_vectorC

__all__ = [
    "DerivationError",
    "Identity",
    "apply_mask",
    "builder_vectorA_pure",
    "candidate_identities_for_class",
    "class_of_lock_parameters",
    "classify_envelope",
    "classify_recipient",
    "compute_K",
    "compute_state",
    "derive_book_key_from_m1",
    "derive_identities",
    "derive_m1",
    "empty_class_message",
    "extract_voucher_id",
    "fills_tensor",
    "identity_chain",
    "load_constant",
    "message_law",
    "mix_vectorC",
    "predict_schedule",
    "replacement",
    "seed_from_m1",
    "stage_family",
    "serialize_m1",
    "tokens_to_vectorB",
    "unwrap_seed",
    "walk_emitted",
]


def derive_m1(
    blob57: bytes | list[int],
    voucher_id: str | bytes,
    lib_path: str | Path | None = None,
) -> bytes:
    # client token + voucher id -> M1 bytes, stages 1..9
    _ = lib_path
    v_id = voucher_id.decode("ascii") if isinstance(voucher_id, (bytes, bytearray)) else voucher_id
    if len(blob57) != 57:
        raise ValueError(f"Expected 57-byte token blob, got {len(blob57)}")
    if len(v_id) != 57:
        raise ValueError(f"Expected 57-char voucher ID, got {len(v_id)}")

    msg = message_law(blob57)
    vecB = tokens_to_vectorB(msg)
    state = compute_state(vecB, v_id)
    sched = predict_schedule(state)
    masked_state = apply_mask(state, v_id, schedule=sched)
    vecA = builder_vectorA_pure(masked_state)
    vecC = mix_vectorC(vecA, vecB)
    fills = fills_tensor(vecC)
    final_tensor = replacement(fills, state256=masked_state, voucher_id=v_id)
    emitted, _ring, _ = walk_emitted(final_tensor)
    return serialize_m1(emitted)

