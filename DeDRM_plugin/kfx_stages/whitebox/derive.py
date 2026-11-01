"""Pure-Python offline book-key derivation for one .kfx-zip."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from . import identity as ident
from .builder import builder_vectorA_pure
from .gate_walk import serialize_m1, walk_emitted_corrected
from .k_law import apply_mask
from .lcg import tap3, tokens_to_lcgbytes
from .schedule_law import predict_schedule
from .stepper import replacement
from .unwrapper import (
    blob64_from_voucher,
    extract_voucher_id,
    keyset_key,
    m32_for_blob,
    pure_unwrap_doc,
    seed_from_m1,
    voucher_fields,
)
from .verdict import compute_state, fills_tensor, mix_vectorC

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF


class DerivationError(RuntimeError):
    """A derivation stage failed.  The message is safe to log."""


def sha16(data: bytes) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()[:16]


def sha16_words(words: list[int]) -> str:
    return sha16(b"".join(int(w & M64).to_bytes(8, "little") for w in words))


# The fifteen stages are one chain in two halves, and three entry points share it.
# Stages 1..10 take one identity message plus the 57-character voucher id to M1 and
# its 32-byte seed; stages 11..14 take seed + descriptor + wrapped region to the
# KeySet doc and its 16-byte content key; stage_family runs 1..15 for one message.
# The id is the only delivery-specific input to stages 3..9, and the recipient lock
# class picks which message law runs (see identity).


def identity_chain(message: bytes, voucher_id: str) -> dict:
    """Stages 1..10 for one identity message and one voucher id.

    The chain sub-dict holds lengths and digests only, never message bytes.
    """
    if not message:
        raise DerivationError("the stage-1 identity message is empty")
    if len(voucher_id) != 57:
        raise DerivationError(f"voucher id must be 57 chars, got {len(voucher_id)}")

    vec_b = tap3(tokens_to_lcgbytes(message), L=len(message))
    unmasked = compute_state(vec_b, voucher_id)
    schedule = predict_schedule(unmasked)
    masked = apply_mask(unmasked, voucher_id, schedule=schedule)
    vec_a = builder_vectorA_pure(masked)
    vec_c = mix_vectorC(vec_a, vec_b)
    fills = fills_scaled(vec_c)
    final = replacement(fills, state256=masked, voucher_id=voucher_id)
    emitted = walk_emitted_corrected(final)
    m1 = serialize_m1(emitted, tail="lone_digit")
    seed = seed_from_m1(m1)
    return {
        "vec_b": vec_b,
        "unmasked": unmasked,
        "schedule": schedule,
        "masked": masked,
        "vec_a": vec_a,
        "vec_c": vec_c,
        "fills": fills,
        "final": final,
        "emitted": emitted,
        "m1": m1,
        "seed": seed,
        "chain": {
            "message_len": len(message),
            "vecB_len": len(vec_b),
            "masked_sha16": sha16_words(masked),
            "vecA_len": len(vec_a),
            "vecC_len": len(vec_c),
            "fills_len": len(fills),
            "emitted_len": len(emitted),
            "m1_len": len(m1),
            "m1_sha16": sha16(m1),
            "seed_sha16": sha16(seed),
        },
    }


def unwrap_seed(seed: bytes, voucher_bytes: bytes, *, desc_bytes: bytes | None = None) -> dict:
    """Stages 11..14: seed plus the wrapped region give the 16-byte content key."""
    iv, ct = voucher_fields(voucher_bytes)
    iv = iv or b"\0" * 16
    blob64: bytes | None = None
    tags_error: str | None = None
    if desc_bytes is None:
        try:
            blob64 = blob64_from_voucher(voucher_bytes)
        except Exception as exc:  # noqa: BLE001 - absence is reported, not raised
            tags_error = repr(exc)
    m32 = m32_for_blob(blob64)
    desc_source = (
        "per-book tag schedule"
        if blob64 is not None
        else ("supplied descriptor" if desc_bytes is not None else "bundled descriptor template")
    )
    k_eff = bytes(a ^ b for a, b in zip(seed, m32))
    doc = pure_unwrap_doc(seed, iv, ct, blob64=blob64)
    key = keyset_key(doc)
    return {
        "iv": iv,
        "ct": ct,
        "tags": blob64,
        "tags_error": tags_error,
        "desc": m32,
        "desc_source": desc_source,
        "mat": k_eff,
        "doc": doc,
        "key": key,
    }


def stage_family(
    message: bytes,
    voucher_bytes: bytes,
    voucher_id: str,
    *,
    desc_bytes: bytes | None = None,
) -> dict:
    stages = identity_chain(message, voucher_id)
    stages.update(unwrap_seed(stages["seed"], voucher_bytes, desc_bytes=desc_bytes))
    key = stages["key"]
    doc = stages["doc"]
    stages["report"] = {
        "message_len": len(message),
        "m1_len": len(stages["m1"]),
        "m1_sha16": sha16(stages["m1"]),
        "seed_len": len(stages["seed"]),
        "seed_sha16": sha16(stages["seed"]),
        "descriptor_source": stages["desc_source"],
        "descriptor_sha16": sha16(stages["desc"]),
        "tag_schedule_sha16": sha16(stages["tags"]) if stages["tags"] else None,
        "tag_schedule_error": stages["tags_error"],
        "doc_len": len(doc),
        "doc_keyset_marker": doc.count(b"KeySet"),
        "doc_aes_marker": doc.count(b"AES"),
        "key_found": key is not None,
        "key_sha16": sha16(key) if key else None,
    }
    return stages


def derive_identities(
    voucher_bytes: bytes,
    identities: Sequence[ident.Identity],
    voucher_id: str | None = None,
    *,
    desc_bytes: bytes | None = None,
    progress=None,
) -> tuple[bytes | None, dict]:
    """Stages 1..15 per candidate identity; the first key produced wins.

    The report holds one content-free record per candidate -- class, message and
    M1 lengths, digests, verdict -- never a credential value.
    """
    say = progress or (lambda *_a, **_k: None)
    data = bytes(voucher_bytes)
    if voucher_id is None:
        voucher_id = extract_voucher_id(data)
    if isinstance(voucher_id, (bytes, bytearray)):
        voucher_id = bytes(voucher_id).decode("ascii")

    candidates: list[dict] = []
    key: bytes | None = None
    index = 0
    for cand_index, identity in enumerate(identities):
        message = identity.message
        if not message:
            continue
        record = {
            "index": cand_index,
            "class": identity.klass,
            "recipient": identity.recipient,
            "message_len": len(message),
        }
        say("identity", {"class": identity.klass, "message_len": len(message)})
        try:
            stages = stage_family(message, data, voucher_id, desc_bytes=desc_bytes)
        except DerivationError as exc:
            record["error"] = str(exc)
            candidates.append(record)
            continue
        record.update(stages["report"])
        candidates.append(record)
        say("chain", stages["report"])
        index += 1
        if stages["key"] is not None:
            key = bytes(stages["key"])
            break

    report = {
        "class": identities[0].klass if identities else None,
        "declared_classes": sorted({item.klass for item in identities}),
        "candidates_tried": index,
        "candidates_offered": len([item for item in identities if item.message]),
        "key_found": key is not None,
        "key_len": len(key) if key else 0,
        "key_sha16": sha16(key) if key else None,
        "candidates": candidates,
    }
    return key, report


fills_scaled = fills_tensor

