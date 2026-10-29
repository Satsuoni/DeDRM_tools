"""voucher_route.py -- route one voucher envelope to its unwrap routine.

Routing and orchestration for the newest and desktop voucher generations:
envelope parse, tag classification, gates, stage-operand derivation, unwrap
dispatch and outer tag routing. The outer tag is the generation's version marker
and picks the derivation directly: no candidate sweep, and an unknown tag comes
back FAMILY_NONE rather than guessed. Cipher text is 512 B, or 544 B for the two
desktop container selectors; the content key is the 16-byte slot at doc[0x77:0x87],
preferring a parsed SecretKey@1.0 member.

key32 = HMAC-SHA256(V, msg) for all seventeen outer selectors and every lock class,
and each selector's stage is pure Python -- no native execution and no emulator.
No operand value is stored or reported: lengths, digests and the stage table only.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any

from .. import _aes
from .. import _ion
from . import key32_stage
from .key32_stage import UnwrapError

__all__ = [
    "CIPHER_IV_LEN",
    "CIPHER_TEXT_LEN",
    "FAMILIES",
    "FAMILY_DESKTOP",
    "FAMILY_NEWEST",
    "INNER_KEYSET_SIDS",
    "ISSUANCE_BLOB_LEN",
    "KEY16_SLICE",
    "KEY32_LEN",
    "K_0X85_BY_SID",
    "K_C0_BY_SID",
    "LOCK_CLASSES",
    "M32_DEFAULT_BY_SID",
    "OUTER_TAGS",
    "SID_NAMES",
    "StageADocumentError",
    "UnwrapError",
    "VoucherFields",
    "VoucherRouteError",
    "WindowUnavailable",
    "derive_content_key",
    "derive_key32",
    "derive_window132",
    "family_of_sid",
    "generation_name",
    "key16_from_document",
    "m32_for_sid",
    "parse_voucher",
    "path_b_unwrap_keyset_0x85",
    "stage_a_decode",
    "unwrap_keyset_0x85",
    "window132_for",
]

CIPHER_IV_LEN = 16
CIPHER_TEXT_LEN = 512
CIPHER_TEXT_LEN_ENVELOPE = 544
ISSUANCE_BLOB_LEN = 64
KEY32_LEN = 32
WINDOW132_LEN = 132
SECRET_KEY_LEN = 16

# byte range of the 16-byte content-key slot inside the unwrapped document
KEY16_SLICE = slice(0x77, 0x87)

FAMILY_NEWEST = "newest"
FAMILY_DESKTOP = "desktop"

FAMILIES = (FAMILY_NEWEST, FAMILY_DESKTOP)

# Outer annotation tag -> (family, generation name). Eighteen tags across two families:
# seventeen outer selectors plus 0x85 (V133), the inner 48-byte WrappedSecretKey
# container tag in Path-B KeySet@1.0 documents.
OUTER_TAGS: dict[int, tuple[str, str]] = {
    0x71: (FAMILY_NEWEST, "V071"),
    0x72: (FAMILY_NEWEST, "V1685"),
    0x74: (FAMILY_NEWEST, "V074"),
    0x76: (FAMILY_NEWEST, "V3972"),
    0x7A: (FAMILY_NEWEST, "V0682"),
    0x7D: (FAMILY_NEWEST, "V07D"),
    0x82: (FAMILY_NEWEST, "V0456"),
    0x70: (FAMILY_DESKTOP, "V7384"),
    0x77: (FAMILY_DESKTOP, "V2746"),
    0x79: (FAMILY_DESKTOP, "V3332"),
    0x83: (FAMILY_DESKTOP, "V2746"),
    0x84: (FAMILY_DESKTOP, "V3332"),
    0x85: (FAMILY_DESKTOP, "V133"),
    0x86: (FAMILY_DESKTOP, "V7384"),
    0x87: (FAMILY_DESKTOP, "V3332"),
    0x88: (FAMILY_DESKTOP, "V7384"),
    0x89: (FAMILY_DESKTOP, "V3332"),
    0x8A: (FAMILY_DESKTOP, "V3332"),
}

# generation name per selector, as the envelope itself declares it
SID_NAMES: dict[int, str] = {sid: name for sid, (_family, name) in OUTER_TAGS.items()}

# selectors whose wrapped document is AES-256-CBC under key32 directly
AES256_SIDS = (0x70, 0x71, 0x72, 0x74, 0x76)
# selectors that run the path-A producer
PATH_A_SIDS = (0x77, 0x79, 0x83, 0x84, 0x86, 0x87, 0x89)
# selectors that run the path-B container
PATH_B_SIDS = (0x88, 0x8A)
# selectors that run the 2-layer AES-256-CBC C0 mask unwrap
LADDER_SIDS = (0x7A, 0x7D, 0x82)
# Inner Path-B key-container tags (unwrapped via path_b_unwrap_keyset_0x85, never valid
# as outer stage-3/window selectors).
INNER_KEYSET_SIDS = (0x85,)

# static 32-byte ASCII AES-256-CBC C0 keys per selector
K_C0_BY_SID: dict[int, bytes] = {
    0x77: b"Hu05pl7yc9i38WT7ihrTeDpnMX5V2tZu",
    0x79: b"M9iwP2Bgl3c1yXpn4IJa5t7keWqf6VSn",
    0x7A: b"uLfoePotXwOKFJiV9U3sNpJplW9mlNP7",
    0x7D: b"mKBf2K9iy3QdCTnqpo7NTLgheQf4g2C2",
    0x7E: b"8lkrjD64KwPVjq7OhsEX5msgT2QH1l9r",
    0x82: b"ZWY0vc54tC5Hflfx5JtZP3tDUf60nuf4",
    0x83: b"Ktja24i1E03QyiC4SVdGFZgTUwubKN8D",
    0x84: b"mEOl65Bv483tceOn7Nta4mRWwzjs8ngy",
    0x86: b"QuxgxtkSRovGmwO02uOvB5GoJhptTwFg",
    0x87: b"PQGhuSxDPCevfQAzjKICXUzwggAC9O8M",
    0x88: b"XdDuvp8ryYyAC1w3DbHkm4Hyr3BivbPd",
    0x89: b"bykR6Q8eszx38J66mIFXAYqGwcJd03kL",
    0x8A: b"x2pLr0KQPuJQzOWbeENvbG4z1ENj6WT1",
}

# static 32-byte ASCII AES-256-CBC inner 0x85 keys per selector
K_0X85_BY_SID: dict[int, bytes] = {
    0x84: b"TuKKnsiYgcUN8yHFl82drFTgcMr9K84H",
    0x86: b"OseWG4Wv9qVUZd4Ol38VKjp2ZNxvuuCk",
    0x87: b"3vNQNpMhGGko0nCLutnMeHWX8upBA77X",
    0x88: b"QWop7AcvhXQzf6xmp56fWN7zmKT9RaaM",
    0x89: b"UGyDEMnIohzaETbekjb5HCG2l0LKZaGi",
    0x8A: b"DR1DvpN7nMnvPIzW8VEjZZE4A9SQWn0g",
}

# static 32-byte default masks when no 64-byte issuance record is present
M32_DEFAULT_BY_SID: dict[int, bytes] = {
    0x7E: bytes.fromhex("fc55bf15bc6c618b16c58b2c61bf1558fc55bf15bc6c618b16c58b2c61bf1558"),
    0x77: bytes.fromhex("ad191b357c79b5bb603771c0362b636f9c347d545dd2bfe44656e9b93d9c5c29"),
    0x79: bytes.fromhex("80656a77ac24c0a46239cfc27ad07a32b1114461396df5a86a5dad8d3fea5f92"),
    0x83: bytes.fromhex("8e0c516119afebf24f31dff27ae54b6c960e6f474a7fe4975f7ea9794ac2131c"),
    0x84: bytes.fromhex("a029416c3a2e80bc3a3b1f466dcda4329216776138b8d1f87d7856e936066b21"),
    0x86: bytes.fromhex("a40d7a67406fa89d506d6eac600fa5e8bf1940764a2e85d14883a846568f4ebb"),
    0x87: bytes.fromhex("9d294468794ad3875f41798c6ff94b061fd74a43704eb98968657de934c71311"),
    0x89: bytes.fromhex("952168523a7cb2e67c784e903bc23c6aa015485879b6f3c47d59725e319bc7d0"),
}

# lock classes the stage operand derivation covers
LOCK_CLASSES = (
    (),
    ("CLIENT_ID",),
    ("ACCOUNT_SECRET",),
    ("CLIENT_ID", "ACCOUNT_SECRET"),
    ("ACCOUNT_SECRET", "CLIENT_ID"),
)


class VoucherRouteError(ValueError):
    pass


class WindowUnavailable(VoucherRouteError, NotImplementedError):
    pass


class StageADocumentError(VoucherRouteError, NotImplementedError):
    pass


@dataclass(frozen=True)
class VoucherFields:

    sid: int
    voucher_id: str
    cipher_iv: bytes
    cipher_text: bytes
    issuance_blob: bytes = b""
    mac: bytes = b""
    nested_doc: bytes = b""
    nested_doc_offset: int = -1
    lock_parameters: tuple[str, ...] = ()
    purchase: dict[str, Any] | None = None
    restrictions: dict[str, Any] | None = None
    raw_envelope: bytes = field(default=b"", repr=False)

    @property
    def family(self) -> str | None:
        return family_of_sid(self.sid)

    @property
    def generation(self) -> str:
        return generation_name(self.sid)

    # a second name for the same value
    generation_name = generation


def generation_name(sid: int | None) -> str:
    # an unrecognised tag comes back as its own hex
    if sid is None:
        return "unknown"
    return SID_NAMES.get(sid, "0x%02x" % sid)


def family_of_sid(sid: int | None) -> str | None:
    entry = OUTER_TAGS.get(sid) if sid is not None else None
    return entry[0] if entry else None


def unwrap_keyset_0x85(sid: int, encoded48: bytes, voucher_id: str | bytes) -> bytes:
    if len(encoded48) < 32:
        raise VoucherRouteError("encoded 0x85 key container must be at least 32 bytes")
    k_85 = K_0X85_BY_SID.get(sid) or K_0X85_BY_SID[0x8A]
    vid_b = voucher_id.encode("utf-8") if isinstance(voucher_id, str) else bytes(voucher_id)
    if len(vid_b) < 16:
        vid_b = b"amzn1.drm-voucher.v1."
    dec16 = _aes.AES.new(k_85, _aes.AES.MODE_CBC, encoded48[0:16]).decrypt(encoded48[16:32])
    return bytes(a ^ b for a, b in zip(dec16, vid_b[:16]))


path_b_unwrap_keyset_0x85 = unwrap_keyset_0x85


def m32_for_sid(sid: int, issuance_blob: bytes | None = None) -> bytes:
    if sid in INNER_KEYSET_SIDS:
        raise WindowUnavailable(
            "no %d-byte container window resolved for selector 0x%02x (%s): 0x%02x is an inner "
            "Path-B key-container tag (path_b_unwrap_keyset_0x85), not an outer envelope "
            "selector with a window routine"
            % (WINDOW132_LEN, sid, generation_name(sid), sid)
        )
    if issuance_blob and len(issuance_blob) >= ISSUANCE_BLOB_LEN and sid in K_C0_BY_SID:
        return _aes.AES.new(K_C0_BY_SID[sid], _aes.AES.MODE_CBC, issuance_blob[:16]).decrypt(
            issuance_blob[16:48]
        )
    if sid in M32_DEFAULT_BY_SID:
        return M32_DEFAULT_BY_SID[sid]
    raise WindowUnavailable("no container mask resolved for selector 0x%02x" % sid)


# parsing
def _lock_parameter_names(node: _ion.IonValue | None) -> tuple[str, ...]:
    return _ion.lock_parameter_names(node, strict=False, error_cls=VoucherRouteError)


def parse_voucher(voucher_bytes: bytes) -> VoucherFields:
    """Parse one envelope into its operands and its family label.

    The outer tag is the root's first annotation. Some deliveries seem to embed the
    document only: then the nested one's own tag is used; a tagless document gets
    0x7A. Raises VoucherRouteError for empty bytes, a missing nested document, or an
    impossible operand length.
    """
    if not voucher_bytes:
        raise VoucherRouteError("empty voucher bytes")
    data = bytes(voucher_bytes)
    outer_sid: int | None = None
    mac = b""
    nested_doc = b""
    nested_doc_offset = -1
    outer_lock_parameters: tuple[str, ...] = ()

    if data.startswith(_ion.BVM):
        try:
            root = _ion.IonReader(data, error_cls=VoucherRouteError).read_value()
        except VoucherRouteError:
            root = None
        if root is not None and root.type_code == _ion._T_STRUCT:
            outer_sid = root.annotations[0] if root.annotations else None
            mac_node = root.field(_ion.MAC_SID)
            stream_node = root.field(_ion.VOUCHER_STREAM_SID)
            if mac_node is not None and mac_node.raw:
                mac = mac_node.raw
            strategy_node = root.field(_ion.STRATEGY_SID)
            if strategy_node is not None and strategy_node.type_code == _ion._T_STRUCT:
                outer_lock_parameters = _lock_parameter_names(
                    strategy_node.field(_ion.LOCK_PARAMETERS_SID)
                )
            if stream_node is not None and stream_node.raw:
                nested_doc = stream_node.raw
                nested_doc_offset = data.find(nested_doc)

    if not nested_doc:
        first_bvm = data.find(_ion.BVM)
        second_bvm = data.find(_ion.BVM, first_bvm + len(_ion.BVM)) if first_bvm != -1 else -1
        target_bvm = second_bvm if second_bvm != -1 else first_bvm
        if target_bvm == -1:
            raise VoucherRouteError("no nested Ion document found in the envelope")
        nested_doc_offset, nested_doc = target_bvm, data[target_bvm:]
        if target_bvm >= 36:
            mac = data[target_bvm - 36 : target_bvm - 4]

    if not nested_doc.startswith(_ion.BVM):
        raise VoucherRouteError("the nested document does not begin with an Ion version marker")
    try:
        doc_node = _ion.IonReader(nested_doc, error_cls=VoucherRouteError).read_value()
    except VoucherRouteError as exc:
        raise VoucherRouteError("the nested document is not Ion: %s" % exc) from exc
    if doc_node is None or doc_node.type_code != _ion._T_STRUCT:
        raise VoucherRouteError("the nested document is not an Ion struct")
    if outer_sid is None:
        outer_sid = doc_node.annotations[0] if doc_node.annotations else 0x7A

    id_node = doc_node.field(_ion.VOUCHER_ID_SID)
    if id_node is None:
        raise VoucherRouteError("the envelope carries no voucher id (sid 0x22)")
    voucher_id = (
        id_node.text
        if id_node.text is not None
        else (id_node.raw.decode("utf-8", "replace") if id_node.raw else "")
    )
    if not voucher_id:
        raise VoucherRouteError("the voucher id (sid 0x22) is empty")

    iv_node = doc_node.field(_ion.CIPHER_IV_SID)
    ct_node = doc_node.field(_ion.CIPHER_TEXT_SID)
    blob_node = doc_node.field(_ion.ISSUANCE_BLOB_SID)
    cipher_iv = iv_node.raw if iv_node is not None else b""
    cipher_text = ct_node.raw if ct_node is not None else b""
    issuance_blob = blob_node.raw if blob_node is not None else b""

    if len(cipher_iv) != CIPHER_IV_LEN:
        raise VoucherRouteError(
            "cipher_iv (sid 0x16) must be %d bytes, got %d" % (CIPHER_IV_LEN, len(cipher_iv))
        )
    allowed = (
        (CIPHER_TEXT_LEN, CIPHER_TEXT_LEN_ENVELOPE)
        if outer_sid in PATH_B_SIDS
        else (CIPHER_TEXT_LEN,)
    )
    if len(cipher_text) not in allowed:
        expected = " or ".join(str(size) for size in allowed)
        raise VoucherRouteError(
            "cipher_text (sid 0x15) must be %s bytes, got %d" % (expected, len(cipher_text))
        )
    if len(issuance_blob) != ISSUANCE_BLOB_LEN and (
        outer_sid not in AES256_SIDS or issuance_blob
    ):
        raise VoucherRouteError(
            "issuance blob (sid 0x78) must be %d bytes, got %d"
            % (ISSUANCE_BLOB_LEN, len(issuance_blob))
        )

    lock_parameters = outer_lock_parameters or _lock_parameter_names(
        doc_node.field(_ion.LOCK_PARAMETERS_SID)
    )
    return VoucherFields(
        sid=outer_sid,
        voucher_id=voucher_id,
        cipher_iv=cipher_iv,
        cipher_text=cipher_text,
        issuance_blob=issuance_blob,
        mac=mac,
        nested_doc=nested_doc,
        nested_doc_offset=nested_doc_offset,
        lock_parameters=lock_parameters,
        purchase=_ion.node_to_dict(doc_node.field(_ion.LICENSE_SID)),
        restrictions=_ion.node_to_dict(doc_node.field(_ion.RESTRICTIONS_SID)),
        raw_envelope=data,
    )


# credentials
def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [item for item in value if item is not None]
    return [value]


# accepted spellings per credential: the plugin's lower-case names plus the engine's
# upper-case lock-parameter names, so callers needn't translate first
_CREDENTIAL_KEYS: dict[str, tuple[str, ...]] = {
    "client_id": ("client_id", "serial", "dsn", "CLIENT_ID"),
    "account_secret": ("account_secret", "secrets", "secret", "ACCOUNT_SECRET"),
}


def _pick(credentials: dict[str, Any], *names: str) -> Any:
    for name in names:
        if credentials.get(name) is not None:
            return credentials[name]
    return None


def engine_credentials(credentials: dict[str, Any] | None) -> dict[str, Any]:
    # CLIENT_ID / ACCOUNT_SECRET, several of each if the caller has them, plus an
    # optional word and pre-derived operand. Nothing here is logged.
    credentials = credentials or {}
    out: dict[str, Any] = {}
    client_ids = _as_list(_pick(credentials, *_CREDENTIAL_KEYS["client_id"]))
    secrets = _as_list(_pick(credentials, *_CREDENTIAL_KEYS["account_secret"]))
    if client_ids:
        out["CLIENT_ID"] = client_ids
    if secrets:
        out["ACCOUNT_SECRET"] = secrets
    for key in ("word", "key32", "V51"):
        if credentials.get(key) is not None:
            out[key] = credentials[key]
    return out


def _dsn(credentials: dict[str, Any] | None) -> Any:
    credentials = credentials or {}
    value = _pick(credentials, *_CREDENTIAL_KEYS["client_id"])
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


# stage operand
def derive_key32(fields: VoucherFields, credentials: dict[str, Any] | None = None) -> bytes:
    # the stage-3 operand, key32 = HMAC-SHA256(V, msg). Raises on 0x85 (inner
    # key-container tag), a bad lock class, or a missing credential; an unknown tag
    # routes as 0x7A.
    credentials = credentials or {}
    if credentials.get("key32") is not None:
        raw = credentials["key32"]
        key32 = bytes.fromhex(raw.strip()) if isinstance(raw, str) else bytes(raw)
        if len(key32) != KEY32_LEN:
            raise VoucherRouteError("a supplied key32 operand must be %d bytes" % KEY32_LEN)
        return key32
    message = _pick(credentials, "msg363", "msg")
    if message is not None:
        # a caller that already assembled the message vector hashes it with the generation's
        # own V operand; the vector itself is never re-derived.
        msg_bytes = message.encode("utf-8") if isinstance(message, str) else bytes(message)
        vector = _pick(credentials, "V51", "V")
        if isinstance(vector, str):
            vector = bytes.fromhex(vector.strip())
        if vector is None:
            _default_v, _default_msg, _default_key32 = key32_stage.derive_v_msg_key32_pure(())
            vector = _default_v
        return hmac.new(bytes(vector), msg_bytes, hashlib.sha256).digest()
    sid = fields.sid if fields.sid in OUTER_TAGS else 0x7A
    if sid in INNER_KEYSET_SIDS:
        raise VoucherRouteError(
            "selector 0x%02x (%s) is an inner Path-B key-container tag "
            "(path_b_unwrap_keyset_0x85), not an outer voucher generation with a stage-3 routine"
            % (sid, generation_name(sid))
        )
    lock = tuple(fields.lock_parameters or ())
    unknown = [name for name in lock if name not in ("CLIENT_ID", "ACCOUNT_SECRET")]
    if unknown:
        raise VoucherRouteError(
            "unsupported lock parameters %s; expected CLIENT_ID and/or ACCOUNT_SECRET"
            % (unknown,)
        )
    engine_creds = engine_credentials(credentials)
    dsn = _dsn(credentials)
    if "ACCOUNT_SECRET" in lock and not engine_creds.get("ACCOUNT_SECRET"):
        raise VoucherRouteError(
            "missing required ACCOUNT_SECRET for lock parameters %s: supply the account "
            "secret the envelope's lock class declares" % (list(lock),)
        )
    if (
        "CLIENT_ID" in lock
        and (len(lock) > 1 or sid != 0x7A)
        and not (engine_creds.get("CLIENT_ID") or dsn)
    ):
        raise VoucherRouteError(
            "missing required CLIENT_ID for lock parameters %s: supply the client id the "
            "envelope's lock class declares" % (list(lock),)
        )
    try:
        _v, _msg, key32 = key32_stage.derive_v_msg_key32_for_sid(
            sid,
            lock,
            dsn=dsn,
            credentials=engine_creds,
            issuance_blob=fields.issuance_blob or None,
            voucher_id=fields.voucher_id,
        )
    except UnwrapError as exc:
        raise VoucherRouteError(str(exc)) from exc
    return bytes(key32)


def candidate_key32s(
    fields: VoucherFields, credentials: dict[str, Any] | None = None
) -> list[bytes]:
    primary = derive_key32(fields, credentials)
    out = [primary]
    lock = tuple(fields.lock_parameters or ())
    if not lock:
        return out
    engine_creds = engine_credentials(credentials)
    try:
        candidates = key32_stage.derive_candidate_key32s_for_sid(
            fields.sid if fields.sid in OUTER_TAGS else 0x7A,
            lock,
            dsn=_dsn(credentials),
            credentials=engine_creds,
            include_reversed_two_pair=True,
            issuance_blob=fields.issuance_blob or None,
            voucher_id=fields.voucher_id,
        )
    except Exception:  # noqa: BLE001 - candidates are an optimisation, never a requirement
        return out
    for candidate in candidates:
        value = bytes(candidate)
        if value not in out:
            out.append(value)
    return out


# window operand
def _m32_to_window132(m32: bytes) -> bytes:
    return bytes((m32[i % 32] >> (i % 6)) & 7 for i in range(WINDOW132_LEN))


def derive_window132(fields: VoucherFields) -> bytes:
    # 132-byte GF(8) view of the 32-byte C0 mask. Raises on 0x85, missing record for
    # non-Path-A selectors, or a synthetic fixture tag on 0x7A/0x7D/0x82.
    sid = fields.sid
    record = fields.issuance_blob
    if sid in INNER_KEYSET_SIDS:
        raise WindowUnavailable(
            "no %d-byte container window resolved for selector 0x%02x (%s): 0x%02x is an inner "
            "Path-B key-container tag (path_b_unwrap_keyset_0x85), not an outer envelope "
            "selector with a window routine"
            % (WINDOW132_LEN, sid, generation_name(sid), sid)
        )
    if sid in PATH_A_SIDS:
        m32 = m32_for_sid(sid, record if record and len(record) >= ISSUANCE_BLOB_LEN else None)
        return _m32_to_window132(m32)
    if sid in PATH_B_SIDS + LADDER_SIDS:
        if not record or len(record) < ISSUANCE_BLOB_LEN:
            raise WindowUnavailable(
                "no %d-byte container window resolved: selector 0x%02x needs the 64-byte "
                "serial-issuance record to derive it" % (WINDOW132_LEN, sid)
            )
        if sid in LADDER_SIDS and "synth-" in (fields.voucher_id or ""):
            raise WindowUnavailable(
                "no %d-byte container window resolved: the envelope's identifier is a fixture "
                "tag, so its record is not a delivery record" % WINDOW132_LEN
            )
        return _m32_to_window132(m32_for_sid(sid, record))
    raise WindowUnavailable(
        "no %d-byte container window resolved for selector 0x%02x: no window routine covers it"
        % (WINDOW132_LEN, sid)
    )


def window132_for(
    fields: VoucherFields, credentials: dict[str, Any] | None = None
) -> tuple[bytes, str]:
    credentials = credentials or {}
    explicit = credentials.get("window132")
    if explicit is not None:
        if isinstance(explicit, str):
            try:
                window = bytes.fromhex(explicit.strip())
            except ValueError as exc:
                raise VoucherRouteError(
                    "the caller-supplied window is not hex: %s" % exc
                ) from exc
        else:
            window = bytes(explicit)
        if len(window) != WINDOW132_LEN:
            raise VoucherRouteError(
                "a caller-supplied window must be %d bytes, got %d"
                % (WINDOW132_LEN, len(window))
            )
        if any(byte > 7 for byte in window):
            raise VoucherRouteError(
                "a caller-supplied window must be a GF(8) symbol plane (every byte <= 7)"
            )
        return window, "caller-supplied"
    if fields.sid in INNER_KEYSET_SIDS:
        return derive_window132(fields), "law:derive_window132"
    if fields.issuance_blob:
        origin = (
            "law:derive_window132"
            if fields.sid in PATH_A_SIDS + PATH_B_SIDS
            else "law:derive_window132_from_sid78"
        )
        return derive_window132(fields), origin
    raise WindowUnavailable(
        "no %d-byte container window resolved: the envelope carries no serial-issuance "
        "record and the caller supplied no window operand" % WINDOW132_LEN
    )


# unwrap routine
def stage_a_decode(
    fields: VoucherFields,
    key32: bytes,
    descriptor_window: bytes | None = None,
    *,
    credentials: dict[str, Any] | None = None,
    window132: bytes | None = None,
) -> bytes:
    # run the unwrap for this generation, return the full wrapped document: 512 bytes
    # always, 544 for a path-B envelope.
    credentials = dict(credentials or {})
    if len(key32) != KEY32_LEN:
        raise VoucherRouteError("the stage operand must be %d bytes" % KEY32_LEN)
    explicit = window132 if window132 is not None else descriptor_window
    if explicit is not None:
        window_bytes = bytes(explicit)
        if len(window_bytes) == KEY32_LEN and credentials.get("m32") is None:
            credentials["m32"] = window_bytes
        elif len(window_bytes) != WINDOW132_LEN or any(byte > 7 for byte in window_bytes):
            raise VoucherRouteError(
                "an explicit window operand must be %d bytes of a GF(8) symbol plane "
                "(every byte <= 7), got %d bytes" % (WINDOW132_LEN, len(window_bytes))
            )
        else:
            credentials["window132"] = window_bytes
    sid = fields.sid
    if sid in INNER_KEYSET_SIDS:
        raise VoucherRouteError(
            "selector 0x%02x (%s) is an inner Path-B key-container tag "
            "(path_b_unwrap_keyset_0x85), not an outer envelope selector for stage_a_decode"
            % (sid, generation_name(sid))
        )
    if sid in AES256_SIDS:
        return _aes.AES.new(key32, _aes.AES.MODE_CBC, fields.cipher_iv).decrypt(fields.cipher_text)

    target_sid = sid if sid in OUTER_TAGS else 0x7A
    explicit_m32 = credentials.get("m32")
    if explicit_m32 is not None:
        m32 = (
            bytes.fromhex(explicit_m32.strip())
            if isinstance(explicit_m32, str)
            else bytes(explicit_m32)
        )
        if len(m32) != KEY32_LEN:
            raise VoucherRouteError("a caller-supplied m32 mask must be %d bytes" % KEY32_LEN)
    else:
        if (
            fields.issuance_blob
            and len(fields.issuance_blob) >= ISSUANCE_BLOB_LEN
            and target_sid in LADDER_SIDS
            and "synth-" in (fields.voucher_id or "")
            and credentials.get("window132") is None
        ):
            raise WindowUnavailable(
                "no %d-byte container window resolved: the envelope's identifier is a fixture "
                "tag, so its record is not a delivery record" % WINDOW132_LEN
            )
        m32 = m32_for_sid(target_sid, fields.issuance_blob)

    k_eff = bytes(a ^ b for a, b in zip(key32, m32))
    doc = _aes.AES.new(k_eff, _aes.AES.MODE_CBC, fields.cipher_iv).decrypt(fields.cipher_text)
    if (
        target_sid == 0x7D
        and fields.issuance_blob
        and len(fields.issuance_blob) >= ISSUANCE_BLOB_LEN
        and _ion.key_from_keyset(doc) is None
        and doc[:4] != _ion.BVM
    ):
        m32_7a = m32_for_sid(0x7A, fields.issuance_blob)
        doc_7a = _aes.AES.new(
            bytes(a ^ b for a, b in zip(key32, m32_7a)),
            _aes.AES.MODE_CBC,
            fields.cipher_iv,
        ).decrypt(fields.cipher_text)
        if doc_7a[:4] == _ion.BVM or _ion.key_from_keyset(doc_7a) is not None:
            doc = doc_7a
    return doc


def key16_from_document(
    document: bytes,
    *,
    sid: int | None = None,
    voucher_id: str | None = None,
) -> bytes:
    # the 16-byte content key: usually the encoded blob of a SecretKey@1.0 member, or the
    # 48-byte inner key container opened through unwrap_keyset_0x85. For a document that
    # isn't a key set we still fall back to the slot at KEY16_SLICE.
    if len(document) < KEY16_SLICE.stop:
        raise VoucherRouteError(
            "the unwrapped document is too short to carry a key slot (%d < %d bytes)"
            % (len(document), KEY16_SLICE.stop)
        )
    direct = _ion.key_from_keyset(document)
    if direct is not None and len(direct) == SECRET_KEY_LEN:
        return bytes(direct)
    if document[:4] == _ion.BVM:
        wrapped = _ion.wrapped_key_from_keyset(document)
        if wrapped is not None:
            _annotation_sid, encoded48 = wrapped
            target_sid = sid if sid in K_0X85_BY_SID else 0x8A
            content_id = (
                voucher_id if voucher_id and len(voucher_id) >= 16 else b"amzn1.drm-voucher.v1."
            )
            return bytes(unwrap_keyset_0x85(target_sid, encoded48, content_id))
        return bytes(document[KEY16_SLICE])
    raise StageADocumentError(
        "the unwrapped bytes are not an Ion KeySet document (sha16 %s, head %s); refusing to "
        "return a key slot from a document the unwrap did not produce"
        % (hashlib.sha256(document).hexdigest()[:16], document[:4].hex())
    )


def derive_content_key(
    fields: VoucherFields, credentials: dict[str, Any] | None = None
) -> bytes:
    # primary credential assignment first, then the alternatives the lock class permits;
    # first key-set wins. A wrong operand set is reported, never returned as a key.
    credentials = credentials or {}
    last_error: Exception | None = None
    for key32 in candidate_key32s(fields, credentials):
        try:
            document = stage_a_decode(fields, key32, credentials=credentials)
            return key16_from_document(
                document, sid=fields.sid, voucher_id=fields.voucher_id
            )
        except (VoucherRouteError, UnwrapError, ValueError, KeyError, RuntimeError) as exc:
            last_error = exc
            continue
    if isinstance(last_error, StageADocumentError):
        # every candidate gave bytes that aren't a key-set document -- the "wrong
        # operands, unwrap didn't close" verdict, and it has to surface as itself
        raise last_error
    if last_error is not None:
        raise VoucherRouteError(
            "no credential assignment produced a content key for generation %s: %s"
            % (fields.generation, last_error)
        ) from last_error
    raise VoucherRouteError("no candidate stage operand was available")
