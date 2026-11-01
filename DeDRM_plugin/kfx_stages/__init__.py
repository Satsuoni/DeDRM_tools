"""kfx_stages -- key-derivation engines for the KFX path.

Pure-Python rehosting of two derivation engine families lifted out of the vendor
client's engine tier, plus the relational container reader that hands a decrypted
delivery on to the format step: whitebox (the current app-generation engine,
fifteen stages from a client token and a voucher id to the 16-byte content key,
table driven) and drmsdk, which serves the newest voucher generation and the same
generation as issued to desktop clients -- newest (the 18 outer envelope tags, the
stage-A unwrap ladder and the path-A producer) and desktop (the path-B 512-byte
and 544-byte outer containers, and the 48-byte inner key-container unwrapper).

Exports classify, derive, verify_page -- the first-page oracle, a decrypted page
opens 00 5d --, decrypt_relational, scrub_delivery and status. Nothing static is
trusted: every inlined table is checked against its pinned digest before use. A
wrong key isn't guessed at either: it's reported as
rejected rather than returned. Credentials are arguments, never stored here; only
lengths and digests are reported back. Python 2 syntax throughout so a legacy host
can't hit a parse error importing the subpackage; the engine imports happen inside
functions, under Python 3.
"""

from __future__ import print_function

import hashlib

from .drmsdk.voucher_route import OUTER_TAGS

__all__ = [
    "FAMILIES",
    "FAMILY_DESKTOP",
    "FAMILY_NEWEST",
    "FAMILY_WHITEBOX",
    "OUTER_TAGS",
    "classify",
    "decrypt_relational",
    "derive",
    "derive_auto",
    "family_of_tag",
    "oracle",
    "outer_tag",
    "scrub_delivery",
    "signatures",
    "status",
    "verify_page",
]

FAMILY_WHITEBOX = "whitebox"
FAMILY_NEWEST = "newest"
FAMILY_DESKTOP = "desktop"

FAMILIES = (FAMILY_NEWEST, FAMILY_DESKTOP, FAMILY_WHITEBOX)

# the tag of the app-generation family (the whitebox engine)
WHITEBOX_TAG = 0x7E


def _sha16(data):
    """Leading 16 hex chars of the sha256 digest -- the content-safe pin."""
    return hashlib.sha256(bytes(data)).hexdigest()[:16]


def family_of_tag(tag):
    if tag is None:
        return None
    if tag == WHITEBOX_TAG:
        return FAMILY_WHITEBOX
    entry = OUTER_TAGS.get(tag)
    return entry[0] if entry else None


def outer_tag(envelope):
    """The envelope's outer annotation tag, or None when it carries none.

    Only the header is read -- the tag is the first annotation of the document root,
    so classification never touches the payload or a credential.
    """
    from . import _ion

    data = bytes(envelope)
    try:
        root = _ion.IonReader(data).read_value()
    except Exception:  # noqa: BLE001 - unparseable means "no tag", not a crash
        return None
    if root is not None and root.annotations:
        return root.annotations[0]
    return None


def classify(envelope):
    """Which family owns this envelope, or None -- no engine here claims it, so a
    miss is safe: the caller keeps its own candidate sweep."""
    return family_of_tag(outer_tag(envelope))


def signatures(envelope):
    from . import _envelope

    data = bytes(envelope)
    tag = outer_tag(data)
    entry = OUTER_TAGS.get(tag) if tag is not None else None
    return {
        "outer_tag": tag,
        "generation": entry[1] if entry else ("app-generation" if tag == WHITEBOX_TAG else None),
        "family": family_of_tag(tag),
        "kind": _envelope.payload_kind(data),
        "length": len(data),
        "sha16": _sha16(data),
    }


def _normalize_credentials(credentials):
    if credentials is None:
        return {}
    raw = dict(credentials)
    out = {}
    for key in ("client_id", "serial", "dsn"):
        if raw.get(key) is not None:
            out["client_id"] = raw[key]
            break
    for key in ("account_secret", "secrets", "secret"):
        if raw.get(key) is not None:
            out["account_secret"] = raw[key]
            break
    for key in ("token", "client_token", "device_token"):
        if raw.get(key) is not None:
            out["token"] = raw[key]
            break
    for key in ("voucher_id", "asin", "content_id"):
        if raw.get(key) is not None:
            out["voucher_id"] = raw[key]
            break
    for key in ("window132", "key32", "word"):
        if raw.get(key) is not None:
            out[key] = raw[key]
    return out


def derive(family, envelope, credentials=None):
    """The 16-byte content key for one envelope of the named family. ValueError on
    an unknown family or an incomplete operand set, RuntimeError for a missing or
    pin-failed table, or for an AES backend the host doesn't have.
    """
    creds = _normalize_credentials(credentials)
    data = bytes(envelope)
    if family == FAMILY_WHITEBOX:
        return _derive_whitebox(data, creds)
    if family in (FAMILY_NEWEST, FAMILY_DESKTOP):
        return _derive_drmsdk(data, creds, family)
    raise ValueError(
        "unknown engine family %r; known families are %s" % (family, ", ".join(FAMILIES))
    )


def derive_auto(envelope, credentials=None):
    """Classify then derive. (None, None) means no engine here owns it, so the
    caller keeps whatever path it already runs."""
    family = classify(envelope)
    if family is None:
        return None, None
    return family, derive(family, envelope, credentials)


def _derive_whitebox(data, creds):
    """The 16-byte key for an app-generation envelope; two lanes in.

    With credentials['token'] already built, token plus envelope identifier run
    stages 1..10 into M1, then 11..15. With only client_id / account_secret (one
    value or a list), the envelope's lock declaration picks the recipient class, a
    stage-1 identity message is built per matching combination, and each candidate
    runs 1..15 until one produces a key.
    """
    from .whitebox import identity as wb_identity
    from .whitebox.derive import derive_identities, extract_voucher_id
    from .whitebox import derive_m1
    from .whitebox.unwrapper import derive_book_key as derive_book_key_from_m1

    token = creds.get("token")
    if token is not None:
        if isinstance(token, str):
            try:
                token = bytes.fromhex(token.strip())
            except ValueError:
                token = token.encode("latin-1")
        token = bytes(token)
        voucher_id = creds.get("voucher_id") or extract_voucher_id(data)
        if isinstance(voucher_id, bytes):
            voucher_id = voucher_id.decode("ascii")
        m1 = derive_m1(token, voucher_id)
        key16, _doc = derive_book_key_from_m1(m1, data)
        return bytes(key16)

    klass, names, source = wb_identity.classify_envelope(data)
    candidates = wb_identity.candidate_identities_for_class(
        klass,
        creds.get("client_id"),
        creds.get("account_secret"),
        lock_names=names,
    )
    if not candidates:
        raise ValueError(
            "the app-generation envelope declares recipient class %r, which is outside the "
            "certified classes (%s); no stage-1 identity message law applies"
            % (klass, ", ".join(wb_identity.CLASSES))
        )
    voucher_id = creds.get("voucher_id")
    key, report = derive_identities(data, candidates, voucher_id)
    if key is None:
        raise ValueError(
            "no candidate identity produced a key for the app-generation envelope "
            "(%s class, %d candidate(s) tried, declared by %s)"
            % (klass, report["candidates_tried"], source)
        )
    return bytes(key)


def _derive_drmsdk(data, creds, family):
    from .drmsdk import voucher_route

    fields = voucher_route.parse_voucher(data)
    if fields.family != family:
        raise ValueError(
            "the envelope declares the %s family, not %s; refusing to run a law that does "
            "not own it" % (fields.family, family)
        )
    return voucher_route.derive_content_key(fields, creds)


def oracle(key, iv, cipher_text):
    """The first-page oracle: does this key open the page to an LZMA stream?"""
    from . import _envelope

    return _envelope.oracle_check(bytes(key), bytes(iv), bytes(cipher_text))


def verify_page(source, key):
    """Run the first-page oracle over a delivery (zip, staged directory or raw
    component bytes). Returns a dict with the verdict ("CONFIRMED", "REJECTED" or
    "NO_PAGE"), a structural label and the key's sha16 -- no key material, no page
    content.
    """
    from . import _envelope

    key = bytes(key)
    if isinstance(source, (bytes, bytearray)):
        data = bytes(source)
        iv = ct = None
        label = "component"
        if data.startswith(_envelope.ENVELOPE_MAGIC):
            for page_iv, page_ct in _envelope.envelope_pages(data):
                if page_iv is not None and page_ct[:2] != _envelope.PAGE_PREFIX:
                    iv, ct = page_iv, page_ct
                    break
        elif _envelope.is_relational_container(data):
            from . import container

            iv, ct, label = container.first_encrypted_page(data, label)
    else:
        iv, ct, label = _envelope.first_encrypted_page(source)
    if iv is None or ct is None:
        return {"verdict": "NO_PAGE", "label": label or "", "sha16": _sha16(key)}
    confirmed = _envelope.oracle_check(key, iv, ct)
    return {
        "verdict": "CONFIRMED" if confirmed else "REJECTED",
        "label": label or "",
        "sha16": _sha16(key),
    }


def decrypt_relational(data, key):
    from . import container

    return container.decrypt_container(bytes(data), bytes(key))


def scrub_delivery(source, key, destination=None):
    """Opens every component of a delivery and writes the decrypted archive.
    destination defaults beside the source; returns the output path."""
    from . import container

    return container.scrub_delivery(source, bytes(key), destination)


def status():
    from . import _aes
    from .whitebox import constants, identity

    const_ok = (
        len(constants._RAW_TABLES) == 11429
        and _sha16(constants._RAW_TABLES) == constants.TABLES_SHA16
    )
    ident_raw = identity.empty_class_message()
    ident_ok = len(ident_raw) == 89 and _sha16(ident_raw) == identity.EMPTY_SHA16
    present = int(const_ok) + int(ident_ok)
    tables = {"whitebox": {"pinned": 2, "packaged": present}}
    families = {}
    for family in FAMILIES:
        families[family] = {"engine": True}
    return {
        "families": families,
        "outer_tags": len(OUTER_TAGS),
        "tables": tables,
        "aes_backend": _aes.backend_name() or None,
    }
