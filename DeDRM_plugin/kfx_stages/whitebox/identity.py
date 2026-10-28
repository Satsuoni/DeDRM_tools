"""Class-aware identity selection for the offline lane.

The bare-ARM64 lane assembles its own 116-char registration-token message, the wrong
invocation for a CLIENT_ID-class voucher (EMPTY-class ones it already gets right), so the
identity to inject is a class constant picked from the recipient tag at slot 52. Injecting
it rebinds state -> K -> tensor -> M1 -> seed -> key -- the 89-char constant in an
EMPTY-class lane is a byte-identical no-op. These are engine constants, never account
material: only lengths and sha-256 16-hex prefixes get emitted.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

from . import message

# The recipient-tag slot and its certified values. Slot 52 carries a tagged Ion list:
# 0xBA 0x89 (ba 89 at the slot) introduces the single-element list ["CLIENT_ID"]; 0xB0 is
# the empty list; 0xBE ... introduces ["ACCOUNT_SECRET"] or the 2-element list
# ["ACCOUNT_SECRET", "CLIENT_ID"].
RECIPIENT_SLOT = 52
RECIPIENT_WINDOW = 48
TAG_CLIENT_ID = b"\xba\x89"
TAG_EMPTY = b"\xb0"

CLASS_CLIENT_ID = "CLIENT_ID"
CLASS_EMPTY = "EMPTY"
CLASS_ACCOUNT_SECRET = "ACCOUNT_SECRET"
CLASS_TWO_PARAM = "ACCOUNT_SECRET+CLIENT_ID"
CLASS_OTHER = "OTHER"

CLASSES = (CLASS_EMPTY, CLASS_CLIENT_ID, CLASS_ACCOUNT_SECRET, CLASS_TWO_PARAM)

# name -> (filename, byte length, sha-256 16-hex prefix). Length and prefix are asserted on
# every load: K recovery came out 256/256 with these, and a truncated or substituted constant
# has to fail loudly rather than silently derive a wrong key.
SYNTHETIC_CLIENT_ID_DSN = "0123456789ABCDEF0123456789ABCDEF"
CLIENT_ID_SHA16 = "6c36afc3ce4f6e65"
EMPTY_SHA16 = "1b5c9a64670257c3"

CONSTANTS: dict[str, tuple[str | None, int, str]] = {
    CLASS_CLIENT_ID: (None, 93, CLIENT_ID_SHA16),
    CLASS_EMPTY: (None, 89, EMPTY_SHA16),
}

_CLIENT_ID_MSG_CACHE: bytes | None = None


def sha16(data: bytes) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()[:16]


@dataclass(frozen=True)
class Identity:
    recipient: str  # CLIENT_ID | EMPTY | CLIENT_ID_off52 | EMPTY_child | OTHER
    klass: str  # CLIENT_ID | EMPTY | OTHER  (the constant family)
    message: bytes  # the class constant, or b"" when no constant applies
    slot52: str  # hex of voucher[52:56] (evidence only)


def classify_recipient(blob: bytes) -> str:
    """Structural read of the recipient declaration at slot 52; nothing echoed."""
    if len(blob) < 56:
        return CLASS_OTHER
    window = blob[RECIPIENT_SLOT : RECIPIENT_SLOT + RECIPIENT_WINDOW]
    has_secret_win = b"ACCOUNT_SECRET" in window
    has_cid_win = b"CLIENT_ID" in window
    if has_secret_win and has_cid_win:
        return CLASS_TWO_PARAM
    if has_secret_win:
        return CLASS_ACCOUNT_SECRET
    tag52 = blob[RECIPIENT_SLOT : RECIPIENT_SLOT + 2]
    client_id_count = blob.count(b"CLIENT_ID")
    if tag52 == TAG_CLIENT_ID and client_id_count:
        return CLASS_CLIENT_ID
    if blob[RECIPIENT_SLOT : RECIPIENT_SLOT + 1] == TAG_EMPTY:
        return CLASS_EMPTY
    if client_id_count:
        return "CLIENT_ID_off52"
    if blob.count(TAG_EMPTY):
        return "EMPTY_child"
    return CLASS_OTHER


# recipient classes that resolve to each constant family
_FAMILY: dict[str, str] = {
    CLASS_CLIENT_ID: CLASS_CLIENT_ID,
    "CLIENT_ID_off52": CLASS_CLIENT_ID,
    CLASS_EMPTY: CLASS_EMPTY,
    "EMPTY_child": CLASS_EMPTY,
    CLASS_ACCOUNT_SECRET: CLASS_ACCOUNT_SECRET,
    CLASS_TWO_PARAM: CLASS_TWO_PARAM,
}


def load_client_id_message() -> bytes:
    # the 93-byte synthetic CLIENT_ID message, built once and checked against its sha16
    global _CLIENT_ID_MSG_CACHE
    if _CLIENT_ID_MSG_CACHE is None:
        msg = message.message_for_client_id(SYNTHETIC_CLIENT_ID_DSN)
        if len(msg) != 93:
            raise ValueError(
                f"CLIENT_ID: expected 93 bytes, got {len(msg)} — synthetic constant is corrupt"
            )
        got = sha16(msg)
        if got != CLIENT_ID_SHA16:
            raise ValueError(
                f"CLIENT_ID: sha16 {got} != expected {CLIENT_ID_SHA16} — synthetic constant is corrupt"
            )
        _CLIENT_ID_MSG_CACHE = msg
    return _CLIENT_ID_MSG_CACHE


def load_constant(klass: str) -> bytes:
    if klass not in CONSTANTS:
        raise KeyError(f"no identity constant for class {klass!r}")
    _filename, want_len, want_sha = CONSTANTS[klass]
    data = empty_class_message() if klass == CLASS_EMPTY else load_client_id_message()
    if len(data) != want_len:
        raise ValueError(
            f"{klass}: expected {want_len} bytes, got {len(data)} — bundle constant is corrupt"
        )
    got = sha16(data)
    if got != want_sha:
        raise ValueError(
            f"{klass}: sha16 {got} != expected {want_sha} — bundle constant is corrupt"
        )
    return data


# Envelope form of the same declaration: the lock_parameters list (sid 0x23) sits inside the
# nested voucher document or the outer strategy struct. The structural read is preferred when
# the envelope is Ion, since it doesn't depend on an offset; the slot read stays as the
# fallback for a raw voucher blob, so both shapes land on the same four classes.


def _lock_parameters_from_nodes(envelope: bytes) -> tuple[bool, tuple[str, ...]]:
    """Structural lock-parameter read; returns (is_voucher_document, names).

    Search is document order: outer struct's strategy struct first (the outer declaration
    wins when both are there, the rule the newest-family parser uses), then the nested
    voucher document, then the root. Not an Ion struct is probably the raw voucher shape --
    (False, ()), and the slot-52 read takes over. A document declaring nothing gives
    (True, ()): the empty lock class, not "unknown".
    """
    from .. import _ion

    data = bytes(envelope)
    if not data.startswith(_ion.BVM):
        return False, ()
    try:
        root = _ion.IonReader(data).read_value()
    except Exception:  # noqa: BLE001 - unparseable means "not structural", not a crash
        return False, ()
    if root is None or not root.is_struct:
        return False, ()
    strategy = root.field(_ion.STRATEGY_SID)
    if strategy is not None and strategy.is_struct:
        declared = strategy.field(_ion.LOCK_PARAMETERS_SID)
        if declared is not None:
            return True, _ion.lock_parameter_names(declared)
    stream = root.field(_ion.VOUCHER_STREAM_SID)
    if stream is not None and stream.is_blob:
        try:
            document = _ion.IonReader(stream.raw).read_value()
        except Exception:  # noqa: BLE001
            document = None
        if document is not None and document.is_struct:
            declared = document.field(_ion.LOCK_PARAMETERS_SID)
            if declared is not None:
                return True, _ion.lock_parameter_names(declared)
    declared = root.field(_ion.LOCK_PARAMETERS_SID)
    if declared is not None:
        return True, _ion.lock_parameter_names(declared)
    return True, ()


def class_of_lock_parameters(names: Sequence[str] | None) -> str | None:
    """Recipient class for a declared lock-parameter list, None when it isn't one.

    Empty declaration is the empty lock class; names or an order outside the four certified
    ones map to None, so the caller says "no engine" instead of guessing a message law.
    """
    ordered = tuple(str(name) for name in (names or ()))
    if ordered == ():
        return CLASS_EMPTY
    if ordered == ("CLIENT_ID",):
        return CLASS_CLIENT_ID
    if ordered == ("ACCOUNT_SECRET",):
        return CLASS_ACCOUNT_SECRET
    if ordered in (("ACCOUNT_SECRET", "CLIENT_ID"), ("CLIENT_ID", "ACCOUNT_SECRET")):
        return CLASS_TWO_PARAM
    return None


def classify_envelope(
    envelope: bytes,
) -> tuple[str, tuple[str, ...], str]:
    """Classify one envelope: (class, names, source).

    source is "lock_parameters" when the envelope's own Ion declaration decided it and
    "slot52" when the fixed-offset read did. Never a guess: outside the four certified
    orders comes back as OTHER.
    """
    is_document, names = _lock_parameters_from_nodes(envelope)
    if is_document:
        structural = class_of_lock_parameters(names)
        return (structural or CLASS_OTHER), names, "lock_parameters"
    recipient = classify_recipient(bytes(envelope))
    return _FAMILY.get(recipient, CLASS_OTHER), (), "slot52"


def _as_list(value: object) -> list:
    if value is None:
        return []
    if isinstance(value, (str, bytes, bytearray)):
        return [bytes(value) if isinstance(value, bytearray) else value]
    try:
        items = list(value)  # type: ignore[arg-type]
    except TypeError:
        return [value]
    return [bytes(item) if isinstance(item, bytearray) else item for item in items if item is not None]


def _dedupe(items: Sequence) -> list:
    out = []
    seen = set()
    for item in items:
        key = item if isinstance(item, (bytes, str)) else repr(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def empty_class_message() -> bytes:
    """The empty-lock fallback identity: the fixed 30-byte token through the message law.

    It lands on the certified 89-byte empty-class constant (1b5c9a64670257c3), so this and
    load_constant() agree by construction; the digest check makes a corrupted token fail
    loudly rather than derive a wrong key.
    """
    msg = message.message_from_token(message.EMPTY_TOKEN_30)
    if len(msg) != CONSTANTS[CLASS_EMPTY][1] or sha16(msg) != EMPTY_SHA16:
        raise ValueError("EMPTY: the empty-class fallback token no longer matches its constant")
    return msg


def candidate_identities_for_class(
    klass: str,
    client_ids: Sequence[str | bytes] | str | bytes | None = None,
    secrets: Sequence[str | bytes] | str | bytes | None = None,
    *,
    lock_names: Sequence[str] | None = None,
    slot52: str = "",
) -> list[Identity]:
    """Every identity message to try for one class, in candidate order.

    The class picks the message law, the credentials are its operands: EMPTY one fixed
    fallback, CLIENT_ID one per identifier or the static 93-byte constant, ACCOUNT_SECRET
    one per secret or the 20-byte empty-value fallback, two-parameter one per (secret,
    identifier) pair in the declared lock order plus the reverse pairing when the envelope
    declared CLIENT_ID first. A class outside the four certified ones gives [].
    """
    klass = str(klass)
    ids = _dedupe([value for value in _as_list(client_ids) if value])
    secs = _dedupe([value for value in _as_list(secrets) if value])
    recipient = klass

    if klass == CLASS_EMPTY:
        return [
            Identity(
                recipient=recipient,
                klass=klass,
                message=empty_class_message(),
                slot52=slot52,
            )
        ]

    if klass == CLASS_CLIENT_ID:
        if ids:
            return [
                Identity(
                    recipient=recipient,
                    klass=klass,
                    message=message.message_for_client_id(value),
                    slot52=slot52,
                )
                for value in ids
            ]
        return [
            Identity(
                recipient=recipient,
                klass=klass,
                message=load_constant(CLASS_CLIENT_ID),
                slot52=slot52,
            )
        ]

    if klass == CLASS_ACCOUNT_SECRET:
        if not secs:
            secs = [""]
        return [
            Identity(
                recipient=recipient,
                klass=klass,
                message=message.message_for_account_secret(value),
                slot52=slot52,
            )
            for value in secs
        ]

    if klass == CLASS_TWO_PARAM:
        ordered = tuple(str(name) for name in (lock_names or ("ACCOUNT_SECRET", "CLIENT_ID")))
        out: list[Identity] = []
        if ids and secs:
            for sec in secs:
                for cid in ids:
                    if ordered[:1] == ("CLIENT_ID",):
                        msg = message.message_for_two_param(cid, sec)
                    else:
                        msg = message.message_for_two_param(sec, cid)
                    out.append(
                        Identity(
                            recipient=recipient,
                            klass=klass,
                            message=msg,
                            slot52=slot52,
                        )
                    )
            if ordered[:1] == ("CLIENT_ID",):
                for sec in secs:
                    for cid in ids:
                        out.append(
                            Identity(
                                recipient=recipient,
                                klass=klass,
                                message=message.message_for_two_param(sec, cid),
                                slot52=slot52,
                            )
                        )
            elif lock_names is not None:
                for sec in secs:
                    for cid in ids:
                        out.append(
                            Identity(
                                recipient=recipient,
                                klass=klass,
                                message=message.message_for_two_param(cid, sec),
                                slot52=slot52,
                            )
                        )
            return _dedupe_identities(out)
        return [
            Identity(
                recipient=recipient,
                klass=klass,
                message=message.message_for_two_param("", ""),
                slot52=slot52,
            )
        ]

    return []


def _dedupe_identities(items: Sequence[Identity]) -> list[Identity]:
    out: list[Identity] = []
    seen: set[bytes] = set()
    for item in items:
        if item.message in seen:
            continue
        seen.add(item.message)
        out.append(item)
    return out

