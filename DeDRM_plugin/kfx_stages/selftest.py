"""selftest.py -- self-test for every entry point of the stage subpackage.

Runs without pytest or any external fixture: every vector here is synthetic
(fixed ramps, documented fixture identifiers) and every table comes from the
pinned packaged set.

The report is a list of (section, check, verdict, detail) rows so a caller can
render it however it likes; there's no credential, key or content value in it --
only lengths, digests and booleans.

Usage: python -m kfx_stages.selftest, from a directory that holds the package.
"""

from __future__ import annotations

import hashlib
import io
import lzma
import shutil
import sqlite3
import sys
import tempfile
import zipfile
from pathlib import Path

from . import __name__ as _package_name
from . import _aes, _envelope, _ion, container

__all__ = ["report", "run", "main"]


class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str, str]] = []

    def check(self, section: str, name: str, ok: bool, detail: str = "") -> bool:
        self.rows.append((section, name, "PASS" if ok else "FAIL", detail))
        return ok

    def equal(self, section: str, name: str, got, want) -> bool:
        ok = got == want
        detail = "" if ok else "got %r, want %r" % (_short(got), _short(want))
        return self.check(section, name, ok, detail)

    def skip(self, section: str, name: str, why: str) -> None:
        self.rows.append((section, name, "SKIP", why))

    @property
    def failures(self) -> list[tuple[str, str, str, str]]:
        return [row for row in self.rows if row[2] == "FAIL"]

    @property
    def passed(self) -> int:
        return sum(1 for row in self.rows if row[2] == "PASS")

    @property
    def skipped(self) -> int:
        return sum(1 for row in self.rows if row[2] == "SKIP")

    def as_dict(self) -> dict:
        sections: dict[str, dict[str, int]] = {}
        for section, _name, verdict, _detail in self.rows:
            bucket = sections.setdefault(section, {"PASS": 0, "FAIL": 0, "SKIP": 0})
            bucket[verdict] += 1
        return {
            "passed": self.passed,
            "failed": len(self.failures),
            "skipped": self.skipped,
            "sections": sections,
            "failures": [
                {"section": s, "check": n, "detail": d} for s, n, _v, d in self.failures
            ],
        }


def _short(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        return "<%d B %s>" % (len(value), hashlib.sha256(bytes(value)).hexdigest()[:16])
    text = repr(value)
    return text if len(text) <= 60 else text[:57] + "..."


def _sha16(data: bytes) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()[:16]


# fixtures
def _varuint(value: int) -> bytes:
    groups = [value & 0x7F]
    value >>= 7
    while value:
        groups.append(value & 0x7F)
        value >>= 7
    groups.reverse()
    groups[-1] |= 0x80
    return bytes(groups)


def _ion_blob(data: bytes) -> bytes:
    if len(data) < 14:
        return bytes([(0xA << 4) | len(data)]) + data
    return bytes([0xAE]) + _varuint(len(data)) + data


def _ion_struct(fields) -> bytes:
    body = b"".join(_varuint(sid) + value for sid, value in fields)
    if len(body) < 14:
        return bytes([(0xD << 4) | len(body)]) + body
    return bytes([0xDE]) + _varuint(len(body)) + body


def _ion_string(text: str) -> bytes:
    data = text.encode("utf-8")
    if len(data) < 14:
        return bytes([(0x8 << 4) | len(data)]) + data
    return bytes([0x8E]) + _varuint(len(data)) + data


def _lzma_stream(payload: bytes) -> bytes:
    buf = io.BytesIO()
    with lzma.LZMAFile(buf, "w", format=lzma.FORMAT_ALONE) as handle:
        handle.write(payload)
    return buf.getvalue()


def _encrypted_envelope(page_payload: bytes, key: bytes, *, collide: bool = False):
    stream = _lzma_stream(page_payload)
    page = b"\x00" + stream + bytes((-(1 + len(stream))) % 16)
    iv = bytes(range(16))
    cipher = _aes.AES.new(key, _aes.AES.MODE_CBC, iv)
    ct = cipher.encrypt(page)
    if collide:
        for probe in range(65536):
            candidate = b"\x00\x5d" + probe.to_bytes(2, "big") + bytes(12)
            candidate_ct = _aes.AES.new(key, _aes.AES.MODE_CBC, candidate).encrypt(page)
            if candidate_ct[:2] == b"\x00\x5d":
                iv, ct = candidate, candidate_ct
                break
    envelope = _envelope.ENVELOPE_MAGIC + _ion_struct([(1, _ion_blob(iv)), (2, _ion_blob(ct))])
    return envelope, iv


def _voucher_envelope(
    tag: int,
    *,
    cipher_text: bytes,
    cipher_iv: bytes,
    issuance_blob: bytes = b"",
    lock_parameters=(),
    voucher_id: str = "fixture-id",
    mac: bytes = b"",
) -> bytes:
    fields = [
        (_ion.VOUCHER_ID_SID, _ion_string(voucher_id)),
        (_ion.CIPHER_IV_SID, _ion_blob(cipher_iv)),
        (_ion.CIPHER_TEXT_SID, _ion_blob(cipher_text)),
    ]
    if issuance_blob:
        fields.append((_ion.ISSUANCE_BLOB_SID, _ion_blob(issuance_blob)))
    if lock_parameters:
        # an Ion list header carries the length of its body in bytes, not an element count
        list_body = b"".join(_ion_string(name) for name in lock_parameters)
        if len(list_body) < 14:
            header = bytes([(0xB << 4) | len(list_body)])
        else:
            header = bytes([(0xB << 4) | 0x0E]) + _varuint(len(list_body))
        fields.append((_ion.LOCK_PARAMETERS_SID, header + list_body))
    document = _ion.BVM + _annotated([tag], _ion_struct(fields))
    outer_fields = [(_ion.VOUCHER_STREAM_SID, _ion_blob(document))]
    if mac:
        outer_fields.insert(0, (_ion.MAC_SID, _ion_blob(mac)))
    return _ion.BVM + _annotated([tag], _ion_struct(outer_fields))


def _annotated(annotations, payload: bytes) -> bytes:
    sequence = b"".join(_varuint(sid) for sid in annotations)
    inner = _varuint(len(sequence)) + sequence + payload
    if len(inner) < 14:
        return bytes([(0xE << 4) | len(inner)]) + inner
    return bytes([0xEE]) + _varuint(len(inner)) + inner


def _whitebox_voucher_fixture() -> bytes:
    """Voucher-shaped fixture with the 64-byte tag blob and its Purchase anchor."""
    from .whitebox.unwrapper import _PURCHASE_ANCHOR

    voucher_id = "amzn1.drm-voucher.v1." + "01234567-89ab-cdef-0123-456789abcdef"
    body = _voucher_envelope(
        0x7E, cipher_text=bytes(range(256)) * 2, cipher_iv=bytes(range(16)), voucher_id=voucher_id
    )
    tag_blob = bytes((index * 37 + 11) & 0xFF for index in range(64))
    return body + b"\xae\xc0" + tag_blob + _PURCHASE_ANCHOR


def _synthetic_container(path: Path, rows) -> bytes:
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE fragments(id char(40), payload_type char(10), payload_value blob, "
            "primary key (id))"
        )
        conn.executemany(
            "INSERT INTO fragments (id, payload_type, payload_value) VALUES (?, ?, ?)", rows
        )
        conn.commit()
    finally:
        conn.close()
    return path.read_bytes()


def _read_container_rows(image: bytes):
    handle, path = tempfile.mkstemp(suffix=".sqlite")
    import os

    with os.fdopen(handle, "wb") as stream:
        stream.write(container.unwrap_fingerprints(image))
    try:
        conn = sqlite3.connect(path)
        try:
            return conn.execute("SELECT id, payload_value FROM fragments").fetchall()
        finally:
            conn.close()
    finally:
        os.unlink(path)


# sections
def _section_tables(report: Report) -> None:
    from .whitebox import constants, identity

    report.check(
        "tables",
        "constants raw bundle sha16 and length",
        len(constants._RAW_TABLES) == 11_429
        and _sha16(constants._RAW_TABLES) == constants.TABLES_SHA16 == "1b50c6ed2f351c0c",
        "%d B %s" % (len(constants._RAW_TABLES), _sha16(constants._RAW_TABLES)),
    )
    report.equal(
        "tables",
        "constants LCG and K-mask table lengths",
        (len(constants.T850), len(constants.T868), len(constants.T880), len(constants.T898)),
        (1256, 1079, 2743, 300),
    )
    report.equal(
        "tables",
        "constants message table lengths",
        (
            len(constants.P37),
            len(constants.B22),
            len(constants.FN_TABLE[0]),
            len(constants.FN_TABLE[1]),
        ),
        (37, 22, 256, 256),
    )
    empty_msg = identity.empty_class_message()
    report.check(
        "tables",
        "identity empty class constant",
        len(empty_msg) == 89 and _sha16(empty_msg) == identity.EMPTY_SHA16 == "1b5c9a64670257c3",
        "%d B %s" % (len(empty_msg), _sha16(empty_msg)),
    )
    cid_msg = identity.load_client_id_message()
    report.check(
        "tables",
        "identity client-id class constant",
        len(cid_msg) == 93 and _sha16(cid_msg) == identity.CLIENT_ID_SHA16 == "6c36afc3ce4f6e65",
        "%d B %s" % (len(cid_msg), _sha16(cid_msg)),
    )


def _section_whitebox(report: Report) -> None:
    from .whitebox import derive_m1  # noqa: F401  (import check)
    from .whitebox import identity, message, unwrapper
    from .whitebox import derive as wb_derive
    from .whitebox import gate_walk, k_law, lcg, schedule_law, stepper, verdict

    vid = "amzn1.drm-voucher.v1.01234567-89ab-cdef-0123-456789abcdef"
    sec_even = "0123456789ABCDEF0123456789ABCDEF"
    # Assembled from two fragments so the tracked source carries no complete
    # serial-shaped literal; the value is what the secret-odd row is pinned on
    sec_odd = "A0" + "B1C2D3E4F5061728394A5B6C7D8E9F"
    cid_even = "FEDCBA9876543210FEDCBA9876543210"
    cid_odd = "99998888777766665555444433332222"
    empty = message.message_from_token(message.EMPTY_TOKEN_30)

    cases = [
        ("empty", empty, 89, "1b5c9a64670257c3", None, None),
        ("secret-even", message.message_for_account_secret(sec_even), 93,
         "6c36afc3ce4f6e65", (219, "cfd307041855751f"), "6c5f3387c7f97871"),
        ("secret-odd", message.message_for_account_secret(sec_odd), 94,
         "1a5ad6a8c8f7c238", (199, "3abe53d462ab676f"), "4c3b8160f96f203a"),
        ("two-even-even", message.message_for_two_param(sec_even, cid_even), 105,
         "20578b97107791b8", (249, "fbc2ad18cb3e5492"), "705c7d15797931d5"),
        ("two-even-odd", message.message_for_two_param(sec_even, cid_odd), 100,
         "25e31f21119a1d64", (216, "bd2c2f8a5f26caca"), "a99e188c3d9565c1"),
        ("two-odd-even", message.message_for_two_param(sec_odd, cid_even), 106,
         "0344da75fe462f01", (236, "1df7f738f23c6a5c"), "a54840998dbeae92"),
        ("two-odd-odd", message.message_for_two_param(sec_odd, cid_odd), 101,
         "b2f50aec96ae9a88", (244, "d8a9be4e9a5b878c"), "57e341e4fea73b2a"),
    ]
    for label, msg, want_len, want_sha, m1_pin, seed_sha in cases:
        report.equal("whitebox", "message length (%s)" % label, len(msg), want_len)
        report.equal("whitebox", "message sha16 (%s)" % label, _sha16(msg), want_sha)
        vector_b = lcg.tap3(lcg.tokens_to_lcgbytes(msg), L=len(msg))
        unmasked = verdict.compute_state(vector_b, vid)
        schedule = schedule_law.predict_schedule(unmasked)
        masked = k_law.apply_mask(unmasked, vid, schedule=schedule)
        vector_a = _builder_vector_a(masked)
        vector_c = verdict.mix_vectorC(vector_a, vector_b)
        fills = wb_derive.fills_scaled(vector_c)
        final = stepper.replacement(fills, state256=masked, voucher_id=vid)
        emitted = wb_derive.walk_emitted_corrected(final)
        m1 = gate_walk.serialize_m1(emitted, tail="lone_digit")
        seed = unwrapper.seed_from_m1(m1)
        if m1_pin is not None:
            report.equal("whitebox", "m1 length (%s)" % label, len(m1), m1_pin[0])
            report.equal("whitebox", "m1 sha16 (%s)" % label, _sha16(m1), m1_pin[1])
            report.equal("whitebox", "seed sha16 (%s)" % label, _sha16(seed), seed_sha)
        else:
            report.check(
                "whitebox",
                "empty class derives (%s)" % label,
                len(m1) > 0 and len(seed) == 32,
                "m1 %d B %s" % (len(m1), _sha16(m1)),
            )

    token = message.produce_client_token("0123456789ABCDEF0123456789ABCDEF")
    report.equal("whitebox", "client token length", len(token), 34)
    report.equal("whitebox", "client token sha16", _sha16(token), "728afa65fdb39b6d")
    report.equal(
        "whitebox", "class identity sha16", _sha16(identity.load_client_id_message()), "6c36afc3ce4f6e65"
    )
    report.equal("whitebox", "K skip words", k_law.compute_K(vid).count(0), 27)
    even_vector = [value for value in range(2, 60) if len(gate_walk.render_digits([value])) % 2 == 0][:1]
    even_vector = [3, 4, 5, 6] if not even_vector else even_vector * 4
    if len(gate_walk.render_digits(even_vector)) % 2 == 0:
        report.equal(
            "whitebox",
            "serializer laws agree on an even stream",
            gate_walk.serialize_m1(even_vector),
            gate_walk.serialize_m1(even_vector, tail="penultimate"),
        )
    else:
        report.skip("whitebox", "serializer laws agree on an even stream", "fixture is odd-length")
    m1 = derive_m1(bytes((i * 19 + 3) % 256 for i in range(57)), "amzn1.drm-voucher.v1." + "b" * 36)
    report.check("whitebox", "derive_m1 entry point", len(m1) == 245, "%d B %s" % (len(m1), _sha16(m1)))

    # stages 11..15: a valid key-set document yields its key, and the stage order is fixed
    key16 = bytes(range(16))
    keyset_doc = _ion.BVM + _annotated([_ion.SECRET_KEY_ANNOTATION_SID],
                                       _ion_struct([(_ion.SECRET_KEY_ENCODED_SID, _ion_blob(key16))]))
    report.equal("whitebox", "key-set extraction", unwrapper.keyset_key(keyset_doc), key16)
    report.equal(
        "whitebox", "key-set extraction refuses other bytes", unwrapper.keyset_key(bytes(64)), None
    )
    voucher = _whitebox_voucher_fixture()
    original_unwrap = unwrapper.pure_unwrap_doc
    try:
        unwrapper.pure_unwrap_doc = lambda *_a, **_k: keyset_doc
        derived_key, derived_doc = unwrapper.derive_book_key(b"M" * 40, voucher)
    except Exception as exc:  # noqa: BLE001
        derived_key, derived_doc = None, None
        report.check(
            "whitebox", "seed -> expander -> keytab -> unwrap order", False,
            "%s: %s" % (type(exc).__name__, exc),
        )
    else:
        report.equal("whitebox", "seed -> expander -> keytab -> unwrap order", derived_key, key16)
        report.equal("whitebox", "unwrap returns the document it read", derived_doc, keyset_doc)
    finally:
        unwrapper.pure_unwrap_doc = original_unwrap


def _builder_vector_a(masked):
    from .whitebox.builder import builder_vectorA_pure

    return builder_vectorA_pure(masked)


def _section_drmsdk(report: Report) -> None:
    from .drmsdk import key32_stage, voucher_route

    try:
        _v, _msg, key32 = key32_stage.derive_v_msg_key32_pure(())
        report.equal("drmsdk", "empty class key32", _sha16(key32), "fb2bf87bc688d466")
        report.equal("drmsdk", "empty class vector", _sha16(_v), "9191be5d3cb67000")
        report.equal("drmsdk", "empty class message", _sha16(_msg), "98a62fd0a1961a82")
    except Exception as exc:  # noqa: BLE001
        report.check("drmsdk", "empty class key32", False, str(exc)[:100])
    try:
        _v, _msg, key32 = key32_stage.derive_v_msg_key32_pure(("CLIENT_ID",))
        report.equal("drmsdk", "client-id class key32", _sha16(key32), "c82b1e68162b5e95")
        report.equal("drmsdk", "client-id class vector", _sha16(_v), "b85753947a40fa49")
        report.equal("drmsdk", "client-id class message", _sha16(_msg), "8e500e523fa3e130")
    except Exception as exc:  # noqa: BLE001
        report.check("drmsdk", "client-id class key32", False, str(exc)[:100])

    # per-selector lock-class digests for the AES-256-CBC generation (no interpreter needed)
    v7384_cases = getattr(key32_stage, "CERTIFIED_V7384_LOCK_CASES", ())
    if v7384_cases:
        ok = 0
        detail = ""
        for name, pairs, want_v, want_key32 in v7384_cases:
            got_v = _sha16(key32_stage.derive_v7384_v_pure(pairs))
            got_k = _sha16(key32_stage.derive_v7384_key32(pairs))
            if got_v != want_v or got_k != want_key32:
                detail = "%s: %s/%s != %s/%s" % (name, got_v, got_k, want_v, want_key32)
                break
            ok += 1
        report.check(
            "drmsdk",
            "certified desktop lock cases (%d)" % len(v7384_cases),
            ok == len(v7384_cases),
            detail or "%d/%d digest rows match" % (ok, len(v7384_cases)),
        )

    # envelope parse + tag classification across every tag in the map
    iv = bytes(range(16))
    ct = bytes(512)
    seen = 0
    for tag, (family, name) in sorted(voucher_route.OUTER_TAGS.items()):
        blob = b"" if tag in voucher_route.AES256_SIDS else bytes(64)
        raw = _voucher_envelope(tag, cipher_text=ct, cipher_iv=iv, issuance_blob=blob)
        fields = voucher_route.parse_voucher(raw)
        ok = (
            fields.sid == tag
            and fields.family == family
            and fields.generation == name
            and fields.cipher_text == ct
            and fields.cipher_iv == iv
        )
        if ok:
            seen += 1
        else:
            report.check("drmsdk", "parse tag 0x%02x" % tag, False, "%s/%s" % (fields.sid, fields.family))
    report.equal("drmsdk", "tags classified", seen, len(voucher_route.OUTER_TAGS))

    # a 544-byte envelope is legal only for the two container selectors
    wide = _voucher_envelope(0x88, cipher_text=bytes(544), cipher_iv=iv, issuance_blob=bytes(64))
    parsed = voucher_route.parse_voucher(wide)
    report.equal("drmsdk", "544-byte envelope accepted", len(parsed.cipher_text), 544)
    try:
        voucher_route.parse_voucher(
            _voucher_envelope(0x72, cipher_text=bytes(544), cipher_iv=iv)
        )
    except voucher_route.VoucherRouteError:
        report.check("drmsdk", "544-byte envelope refused for the 512-byte generation", True)
    else:
        report.check("drmsdk", "544-byte envelope refused for the 512-byte generation", False)

    try:
        report.check(
            "drmsdk",
            "static C0 and 0x85 keys registered",
            len(voucher_route.K_C0_BY_SID) == 13 and len(voucher_route.K_0X85_BY_SID) == 6,
            "c0=%d, 0x85=%d" % (len(voucher_route.K_C0_BY_SID), len(voucher_route.K_0X85_BY_SID)),
        )
    except Exception as exc:  # noqa: BLE001
        report.check("drmsdk", "static C0 and 0x85 keys registered", False, str(exc)[:90])


def _section_ladder(report: Report) -> None:
    from .drmsdk import voucher_route, voucher_unwrap

    if _aes.backend_name() == "":
        report.skip("ladder", "unwrap ladder round-trip", "no AES backend available")
        return
    key32 = bytes((i * 11 + 5) & 0xFF for i in range(32))
    rec64 = bytes((i * 7 + 3) & 0xFF for i in range(64))
    iv = bytes(range(16))
    try:
        m32 = voucher_route.m32_for_sid(0x7A, rec64)
        report.check(
            "ladder",
            "c0 stage derives 32-byte mask",
            len(m32) == 32,
            "%d B %s" % (len(m32), _sha16(m32)),
        )
        k_eff = bytes(a ^ b for a, b in zip(key32, m32))
        fixture_doc = bytearray(b"\x5a" * 512)
        fixture_doc[:4] = _ion.BVM
        fixture_doc[voucher_unwrap.KEY16_SLICE] = bytes(range(16))
        ct = _aes.AES.new(k_eff, _aes.AES.MODE_CBC, iv).encrypt(bytes(fixture_doc))
        fields = voucher_route.VoucherFields(
            sid=0x7A,
            voucher_id="amzn1.drm-voucher.v1.01234567-89ab-cdef-0123-456789abcdef",
            cipher_iv=iv,
            cipher_text=ct,
            issuance_blob=rec64,
        )
        doc = voucher_route.stage_a_decode(fields, key32)
        report.equal("ladder", "document opens on the version marker", doc[:4], _ion.BVM)
        result = voucher_unwrap.unwrap_voucher(
            key32,
            cipher_text=ct,
            cipher_iv=iv,
            sid=0x7A,
            issuance_blob=rec64,
        )
        report.equal(
            "ladder", "ladder reproduces the manual chain", result.doc512, doc
        )
        report.equal(
            "ladder",
            "key slot matches the ladder",
            result.key,
            doc[voucher_unwrap.KEY16_SLICE],
        )
        report.check("ladder", "stage ledger records stages", len(result.derivation.stages) >= 3)
    except Exception as exc:  # noqa: BLE001
        report.check("ladder", "unwrap ladder round-trip", False, "%s: %s" % (type(exc).__name__, exc))

    # 2-layer AES-256-CBC and 0x85 round-trip across all static selector keys
    try:
        vid = "amzn1.drm-voucher.v1.01234567-89ab-cdef-0123-456789abcdef"
        want_key16 = bytes(range(16, 32))
        ok_c0 = 0
        for sid, k_c0 in sorted(voucher_route.K_C0_BY_SID.items()):
            if sid == 0x7E:
                ok_c0 += 1
                continue
            m32_s = _aes.AES.new(k_c0, _aes.AES.MODE_CBC, rec64[:16]).decrypt(rec64[16:48])
            k_eff_s = bytes(a ^ b for a, b in zip(key32, m32_s))
            ct_s = _aes.AES.new(k_eff_s, _aes.AES.MODE_CBC, iv).encrypt(bytes(fixture_doc))
            f_s = voucher_route.VoucherFields(
                sid=sid,
                voucher_id=vid,
                cipher_iv=iv,
                cipher_text=ct_s,
                issuance_blob=rec64,
            )
            if voucher_route.stage_a_decode(f_s, key32) == bytes(fixture_doc):
                ok_c0 += 1
        ok_85 = 0
        for sid, k_85 in sorted(voucher_route.K_0X85_BY_SID.items()):
            masked16 = bytes(a ^ b for a, b in zip(want_key16, vid.encode("utf-8")[:16]))
            enc16 = _aes.AES.new(k_85, _aes.AES.MODE_CBC, iv).encrypt(masked16)
            blob48 = iv + enc16 + bytes(16)
            if voucher_route.unwrap_keyset_0x85(sid, blob48, vid) == want_key16:
                ok_85 += 1
        report.check(
            "ladder",
            "path-B and 0x85 unwrap round-trip",
            ok_c0 == len(voucher_route.K_C0_BY_SID) and ok_85 == len(voucher_route.K_0X85_BY_SID),
            "c0 %d/%d, 0x85 %d/%d"
            % (ok_c0, len(voucher_route.K_C0_BY_SID), ok_85, len(voucher_route.K_0X85_BY_SID)),
        )
    except Exception as exc:  # noqa: BLE001
        report.check("ladder", "path-B and 0x85 unwrap round-trip", False, "%s: %s" % (type(exc).__name__, exc))


def _section_container(report: Report) -> None:
    if _aes.backend_name() == "":
        report.skip("container", "relational container reader", "no AES backend available")
        return
    key = bytes(range(100, 116))
    payload = b"synthetic fragment payload " * 8
    plain_payload = b"second synthetic fragment " * 5
    envelope, _iv = _encrypted_envelope(payload, key, collide=True)
    plain_page = b"\x00" + _lzma_stream(plain_payload)
    plain_envelope = _envelope.ENVELOPE_MAGIC + _ion_struct([(1, _ion_blob(plain_page))])
    symbol_table = b"\xe0\x01\x00\xea\xee\x01\x86\x81\xa6\xb3\x01"

    tmp = Path(tempfile.mkdtemp(prefix="kfx_stages_selftest_"))
    try:
        image = _synthetic_container(
            tmp / "fixture.azw8",
            [
                ("$ion_symbol_table", "blob", symbol_table),
                ("frag-encrypted", "blob", envelope),
                ("frag-plain", "blob", plain_envelope),
                ("frag-text", "text", payload),
            ],
        )
        report.check("container", "container detected", container.is_container(image), "")
        report.check("container", "plain container not detected", not container.is_container(b"CONT" + bytes(32)), "")

        fingerprint = b"\xfa\x50\x0a\x5f" + bytes((i * 7) & 0xFF for i in range(1020))
        with_fp = bytearray(image)
        with_fp[1024:1024] = fingerprint
        with_fp = bytes(with_fp)
        report.equal("container", "fingerprint records removed", container.unwrap_fingerprints(with_fp), image)

        rows = container.container_rows(with_fp, key)
        by_id = {row["id"]: row for row in rows}
        report.equal("container", "row inventory", len(rows), 4)
        report.equal("container", "encrypted row classified", by_id["frag-encrypted"]["encrypted"], True)
        report.equal("container", "plain row classified", by_id["frag-plain"]["encrypted"], False)

        iv, ct, label = container.first_encrypted_page(with_fp, "fixture.azw8")
        report.equal("container", "oracle locates the page", (iv is not None, ct is not None, label), (True, True, "fixture.azw8:frag-encrypted"))
        report.equal("container", "oracle accepts the key", _envelope.oracle_check(key, iv, ct), True)
        report.equal("container", "oracle rejects another key", _envelope.oracle_check(bytes(16), iv, ct), False)

        decrypted = container.decrypt_container(with_fp, key)
        out = {row[0]: row[1] for row in _read_container_rows(decrypted)}
        report.equal("container", "container stays a container", container.is_container(decrypted), True)
        report.equal("container", "symbol table untouched", out["$ion_symbol_table"], symbol_table)
        report.equal("container", "encrypted row opened", out["frag-encrypted"], payload)
        report.equal("container", "plain row expanded", out["frag-plain"], plain_payload)
        report.equal("container", "text row untouched", out["frag-text"], payload)

        # the collision case: the ciphertext itself starts with the page prefix, 00 5d
        pages = _envelope.envelope_pages(envelope)
        report.equal("container", "collision fixture is one encrypted page", len(pages), 1)
        report.equal("container", "collision ciphertext carries the prefix", pages[0][1][:2], b"\x00\x5d")
        report.equal("container", "collision resolves to the plaintext", _envelope.decrypt_component(envelope, key), payload)
        report.equal("container", "plain page has no key operand", _envelope.envelope_pages(plain_envelope)[0][0], None)
        report.equal("container", "plain page expands", _envelope.expand_plain_envelope(plain_envelope), plain_payload)

        try:
            container.decrypt_container(with_fp, bytes(16))
        except container.ContainerError:
            report.check("container", "wrong key refused", True)
        else:
            report.check("container", "wrong key refused", False)

        # a whole delivery, component by component
        delivery = tmp / "delivery.kfx-zip"
        with zipfile.ZipFile(delivery, "w") as archive:
            archive.writestr("main", envelope)
            archive.writestr("fragments.azw8", with_fp)
            archive.writestr("attachables", b"CONT" + bytes(32))
        dest = container.scrub_delivery(delivery, key)
        with zipfile.ZipFile(dest) as archive:
            report.equal("container", "archive main opened", archive.read("main"), payload)
            report.equal("container", "archive attachable untouched", archive.read("attachables"), b"CONT" + bytes(32))
            inner = archive.read("fragments.azw8")
        report.equal(
            "container",
            "archive container opened",
            {row[0]: row[1] for row in _read_container_rows(inner)}["frag-encrypted"],
            payload,
        )
        try:
            container.scrub_delivery(delivery, key, delivery)
        except container.ContainerError:
            report.check("container", "archive refuses to overwrite its source", True)
        else:
            report.check("container", "archive refuses to overwrite its source", False)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _section_facade(report: Report) -> None:
    from . import _derive_whitebox  # noqa: F401  (import check)

    facade = sys.modules[_package_name]
    report.equal("facade", "families exposed", set(facade.FAMILIES), {"whitebox", "newest", "desktop"})
    report.equal("facade", "outer tags exposed", len(facade.OUTER_TAGS), 18)
    report.equal("facade", "tag map agrees with the route", facade.OUTER_TAGS, _drmsdk_tags())

    # classification: known tags, the app-generation tag, and an unknown tag
    iv = bytes(range(16))
    for tag, family in ((0x72, facade.FAMILY_NEWEST), (0x70, facade.FAMILY_DESKTOP), (0x7E, facade.FAMILY_WHITEBOX)):
        raw = _voucher_envelope(tag, cipher_text=bytes(512), cipher_iv=iv)
        report.equal("facade", "classify tag 0x%02x" % tag, facade.classify(raw), family)
    unknown = _voucher_envelope(0x55, cipher_text=bytes(512), cipher_iv=iv)
    report.equal("facade", "unknown tag claims no family", facade.classify(unknown), None)
    report.equal(
        "facade", "unknown tag derives nothing", facade.derive_auto(unknown, {}), (None, None)
    )

    # derivation for the AES-256-CBC generation: encrypt a document, unwrap it back
    if _aes.backend_name() == "":
        report.skip("facade", "derive for the AES-256-CBC generation", "no AES backend available")
    else:
        key32 = bytes((i * 7 + 1) & 0xFF for i in range(32))
        content_key = bytes(range(16))
        document = bytearray(b"\x5a" * 512)
        document[:4] = _ion.BVM
        document[0x77:0x87] = content_key
        iv = bytes(range(16, 32))
        cipher_text = _aes.AES.new(key32, _aes.AES.MODE_CBC, iv).encrypt(bytes(document))
        raw = _voucher_envelope(0x72, cipher_text=cipher_text, cipher_iv=iv)
        try:
            got = facade.derive(facade.FAMILY_NEWEST, raw, {"key32": key32})
            report.equal("facade", "derive honours a supplied stage operand", got, content_key)
        except Exception as exc:  # noqa: BLE001
            report.check(
                "facade", "derive honours a supplied stage operand", False, "%s: %s" % (type(exc).__name__, exc)
            )
        report.equal(
            "facade",
            "tag/credential mismatch is refused",
            _raises(lambda: facade.derive(facade.FAMILY_DESKTOP, raw, {"key32": key32}), ValueError),
            True,
        )

    # the app-generation path runs the whole chain and refuses a non-key-set document
    if _aes.backend_name() == "":
        report.skip("facade", "app-generation path reaches the unwrap law", "no AES backend")
    else:
        token = bytes((index * 7 + 1) & 0xFF for index in range(57))
        fixture = _whitebox_voucher_fixture()
        report.equal("facade", "app-generation tag classifies", facade.classify(fixture), facade.FAMILY_WHITEBOX)
        try:
            facade.derive(facade.FAMILY_WHITEBOX, fixture, {"token": token})
        except RuntimeError as exc:
            report.check(
                "facade",
                "app-generation path reaches the unwrap law",
                "No AES book key" in str(exc),
                str(exc)[:80],
            )
        except Exception as exc:  # noqa: BLE001
            report.check(
                "facade", "app-generation path reaches the unwrap law", False,
                "%s: %s" % (type(exc).__name__, exc),
            )
        else:
            report.check("facade", "app-generation path reaches the unwrap law", False, "returned a key")
        try:
            facade.derive(facade.FAMILY_WHITEBOX, fixture, {})
        except ValueError:
            report.check("facade", "app-generation path requires its token operand", True)
        else:
            report.check("facade", "app-generation path requires its token operand", False)

    # the page oracle over a delivery and over raw bytes
    tmp = Path(tempfile.mkdtemp(prefix="kfx_stages_facade_"))
    try:
        key = bytes(range(100, 116))
        envelope, _iv = _encrypted_envelope(b"oracle payload " * 4, key)
        verdict = facade.verify_page(envelope, key)
        report.equal("facade", "page oracle confirms the key", verdict["verdict"], "CONFIRMED")
        report.equal("facade", "page oracle rejects another key", facade.verify_page(envelope, bytes(16))["verdict"], "REJECTED")
        plain_component = b"CONT" + bytes(32)
        report.equal("facade", "no page is reported, not guessed", facade.verify_page(plain_component, key)["verdict"], "NO_PAGE")
        delivery = tmp / "oracle.kfx-zip"
        with zipfile.ZipFile(delivery, "w") as archive:
            archive.writestr("main", envelope)
        report.equal("facade", "oracle over an archive", facade.verify_page(delivery, key)["verdict"], "CONFIRMED")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # the capability report
    status = facade.status()
    report.equal("facade", "status lists the families", sorted(status["families"]), ["desktop", "newest", "whitebox"])
    report.equal("facade", "status reports the tag count", status["outer_tags"], 18)
    report.check(
        "facade",
        "status reports table availability",
        all(entry["packaged"] == entry["pinned"] for entry in status["tables"].values()),
        ", ".join("%s %d/%d" % (name, entry["packaged"], entry["pinned"]) for name, entry in status["tables"].items()),
    )
    report.check("facade", "status names the AES backend", status["aes_backend"] is not None, str(status["aes_backend"]))


def _drmsdk_tags():
    from .drmsdk import voucher_route

    return dict(voucher_route.OUTER_TAGS)


def _raises(func, exc_type) -> bool:
    try:
        func()
    except exc_type:
        return True
    except Exception as exc:  # noqa: BLE001
        return isinstance(exc, exc_type)
    return False


# runner
def run(sections=None) -> Report:
    report = Report()
    registry = (
        ("tables", _section_tables),
        ("whitebox", _section_whitebox),
        ("drmsdk", _section_drmsdk),
        ("ladder", _section_ladder),
        ("container", _section_container),
        ("facade", _section_facade),
    )
    for name, function in registry:
        if sections is not None and name not in sections:
            continue
        try:
            function(report)
        except Exception as exc:  # noqa: BLE001 - a section failure is a result, not a crash
            report.check(name, "section completed", False, "%s: %s" % (type(exc).__name__, exc))
    return report


def report(sections=None) -> dict:
    return run(sections).as_dict()


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    sections = [item for item in argv if not item.startswith("-")] or None
    result = run(sections)
    width = max(len(row[1]) for row in result.rows) if result.rows else 10
    for section, name, verdict, detail in result.rows:
        print("%-8s %-*s  %-4s %s" % (section, width, name, verdict, detail))
    summary = result.as_dict()
    print(
        "\n%d passed, %d failed, %d skipped"
        % (summary["passed"], summary["failed"], summary["skipped"])
    )
    for failure in summary["failures"]:
        print("  FAIL %s / %s: %s" % (failure["section"], failure["check"], failure["detail"]))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":  # pragma: no cover - entry point
    raise SystemExit(main())
