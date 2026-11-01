"""_ion.py -- binary Ion 1.0 parser plus ProtectedData / KeySet@1.0 helpers."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Final

BVM = bytes.fromhex("e00100ea")
_ION_SYSTEM_SYMBOLS: Final[tuple[str, ...]] = (
    "$ion", "$ion_1_0", "$ion_symbol_table", "name", "version",
    "imports", "symbols", "max_id", "$ion_shared_symbol_table",
)  # fmt: skip
_ANNOTATION_SID_ION_SYMBOL_TABLE = 3
_SID_IMPORTS, _SID_SYMBOLS = 6, 7

_T_NULL, _T_BOOL, _T_POS_INT, _T_NEG_INT = 0x0, 0x1, 0x2, 0x3
_T_FLOAT, _T_DECIMAL, _T_TIMESTAMP, _T_SYMBOL = 0x4, 0x5, 0x6, 0x7
_T_STRING, _T_CLOB, _T_BLOB = 0x8, 0x9, 0xA
_T_LIST, _T_SEXP, _T_STRUCT, _T_ANNOTATION = 0xB, 0xC, 0xD, 0xE

KEY_VOUCHER_ENVELOPE: Final = "com.amazon.drm.VoucherEnvelope@"
_EXTRA_ENV_VERSIONS: Final = (9708, 1031, 2069, 9041, 3646, 6052, 9479, 9888, 4648, 5683)
_PROTECTED_DATA_BASE: Final[tuple[str, ...]] = (
    "com.amazon.drm.Envelope@1.0", "com.amazon.drm.EnvelopeMetadata@1.0", "size", "page_size",
    "encryption_key", "encryption_transformation", "encryption_voucher", "signing_key",
    "signing_algorithm", "signing_voucher", "com.amazon.drm.EncryptedPage@1.0", "cipher_text",
    "cipher_iv", "com.amazon.drm.Signature@1.0", "data", "com.amazon.drm.EnvelopeIndexTable@1.0",
    "length", "offset", "algorithm", "encoded", "encryption_algorithm", "hashing_algorithm",
    "expires", "format", "id", "lock_parameters", "strategy", "com.amazon.drm.Key@1.0",
    "com.amazon.drm.KeySet@1.0", "com.amazon.drm.PIDv3@1.0", "com.amazon.drm.PlainTextPage@1.0",
    "com.amazon.drm.PlainText@1.0", "com.amazon.drm.PrivateKey@1.0", "com.amazon.drm.PublicKey@1.0",
    "com.amazon.drm.SecretKey@1.0", "com.amazon.drm.Voucher@1.0", "public_key", "private_key",
    "com.amazon.drm.KeyPair@1.0", "com.amazon.drm.ProtectedData@1.0", "doctype",
    "com.amazon.drm.EnvelopeIndexTableOffset@1.0", "enddoc", "license_type", "license",
    "watermark", "key", "value", "com.amazon.drm.License@1.0", "category", "metadata",
    "categorized_metadata", "com.amazon.drm.CategorizedMetadata@1.0",
    "com.amazon.drm.VoucherEnvelope@1.0", "mac", "voucher", "com.amazon.drm.ProtectedData@2.0",
    "com.amazon.drm.Envelope@2.0", "com.amazon.drm.EnvelopeMetadata@2.0",
    "com.amazon.drm.EncryptedPage@2.0", "com.amazon.drm.PlainText@2.0", "compression_algorithm",
    "com.amazon.drm.Compressed@1.0", "page_index_table",
)  # fmt: skip

PROTECTED_DATA_PLANE: Final[tuple[str, ...]] = (
    *_PROTECTED_DATA_BASE,
    *(f"{KEY_VOUCHER_ENVELOPE}{v}.0" for v in (*range(2, 29), *_EXTRA_ENV_VERSIONS)),
)
_SYMBOL_ID_MIN: Final = len(_ION_SYSTEM_SYMBOLS) + 1

CIPHER_TEXT_SID = 0x15
CIPHER_IV_SID = 0x16
KEY_ALGORITHM_SID = 0x1C
SECRET_KEY_ENCODED_SID = 0x1D
KEY_FORMAT_SID = 0x21
VOUCHER_ID_SID = KEY_ID_SID = 0x22
LOCK_PARAMETERS_SID = 0x23
STRATEGY_SID = 0x24
KEYSET_ANNOTATION_SID = 0x26
SECRET_KEY_ANNOTATION_SID = 0x2C
LICENSE_SID = 0x36
RESTRICTIONS_SID = 0x3D
MAC_SID = 0x40
VOUCHER_STREAM_SID = 0x41
ISSUANCE_BLOB_SID = 0x78
WRAPPED_SECRET_KEY_ANNOTATION_SID = 0x85
_SECRET_KEY_LEN: Final = 16
_WRAPPED_SECRET_KEY_LEN: Final = 48


class VoucherError(ValueError):
    """A modern-family voucher this build can't use as given."""


class VoucherParseError(VoucherError):
    """Bytes that aren't an Ion 1.0 voucher document."""


def symbol_name(sid: int) -> str | None:
    index = sid - _SYMBOL_ID_MIN
    return PROTECTED_DATA_PLANE[index] if 0 <= index < len(PROTECTED_DATA_PLANE) else None


@dataclass
class IonValue:
    type_code: int
    annotations: tuple[int, ...] = ()
    raw: bytes = b""
    text: str | None = None
    sid: int | None = None
    fields: dict[int, tuple[IonValue, ...]] = field(default_factory=dict)
    items: tuple[IonValue, ...] = ()

    def field(self, sid: int) -> IonValue | None:
        values = self.fields.get(sid)
        return values[0] if values else None

    @property
    def is_struct(self) -> bool:
        return self.type_code == _T_STRUCT

    @property
    def is_sequence(self) -> bool:
        return self.type_code in (_T_LIST, _T_SEXP)

    @property
    def is_blob(self) -> bool:
        return self.type_code in (_T_BLOB, _T_CLOB)


def blob_of(value: IonValue | None) -> bytes | None:
    return value.raw if value is not None and value.is_blob else None


def _as_int(value: IonValue | None, *, default: int) -> int:
    if value is None or not value.raw or value.type_code not in (_T_POS_INT, _T_NEG_INT):
        return default
    return int.from_bytes(value.raw, "big")


class IonReader:
    """Binary Ion 1.0 reader with local symbol tables."""

    def __init__(
        self, data: bytes, offset: int = 0, *, error_cls: type[Exception] = VoucherParseError
    ) -> None:
        self.data = bytes(data)
        self.pos = offset
        self.symbols: list[str | None] = [None, *_ION_SYSTEM_SYMBOLS]
        self.imports: list[tuple[str, int, int]] = []
        self._error_cls = error_cls

    def _u8(self) -> int:
        if self.pos >= len(self.data):
            raise self._error_cls("unexpected end of Ion stream")
        octet = self.data[self.pos]
        self.pos += 1
        return octet

    def _take(self, count: int) -> bytes:
        if count < 0 or self.pos + count > len(self.data):
            raise self._error_cls("Ion value runs past the end of the stream")
        chunk = self.data[self.pos : self.pos + count]
        self.pos += count
        return chunk

    def _varuint(self) -> int:
        octet = self._u8()
        value = octet & 0x7F
        guard = 0
        while not (octet & 0x80):
            guard += 1
            if guard > 16:
                raise self._error_cls("malformed VarUInt (no terminator)")
            octet = self._u8()
            value = (value << 7) | (octet & 0x7F)
        return value

    def _length(self, nibble: int) -> int | None:
        if nibble == 0x0F:
            return None
        return self._varuint() if nibble == 0x0E else nibble

    def name(self, sid: int) -> str | None:
        return self.symbols[sid] if 0 <= sid < len(self.symbols) else None

    def read(self) -> IonValue | None:
        while self.pos < len(self.data):
            value = self._raw()
            if value is None:
                continue
            if value.is_struct and _ANNOTATION_SID_ION_SYMBOL_TABLE in value.annotations:
                self._apply_local_symbol_table(value)
                continue
            return value
        return None

    read_value = read

    def _raw(self) -> IonValue | None:
        descriptor = self._u8()
        type_code, nibble = descriptor >> 4, descriptor & 0x0F
        if descriptor == BVM[0]:
            if bytes([descriptor]) + self._take(3) != BVM:
                raise self._error_cls("unsupported Ion version marker")
            self.symbols = [None, *_ION_SYSTEM_SYMBOLS]
            return None
        if type_code == _T_NULL and nibble != 0x0F:
            length = self._length(nibble)
            if length:
                self._take(length)
            return None
        if type_code != _T_ANNOTATION:
            return self._value(type_code, nibble, ())
        total = self._length(nibble)
        if total is None:
            raise self._error_cls("null annotation wrapper")
        end = self.pos + total
        seq_len = self._varuint()
        seq_end = self.pos + seq_len
        annotations: list[int] = []
        while self.pos < seq_end:
            annotations.append(self._varuint())
        if self.pos != seq_end:
            raise self._error_cls("annotation sequence length mismatch")
        value = self._raw()
        while value is None:
            value = self._raw()
        value.annotations = tuple(annotations) + value.annotations
        if self.pos != end:
            raise self._error_cls("annotation wrapper length mismatch")
        return value

    def _value(self, type_code: int, nibble: int, annotations: tuple[int, ...]) -> IonValue:
        if type_code == _T_STRUCT:
            return self._struct(nibble, annotations)
        length = self._length(nibble)
        if length is None:
            return IonValue(type_code, annotations)
        if type_code in (_T_LIST, _T_SEXP):
            end = self.pos + length
            items: list[IonValue] = []
            while self.pos < end:
                child = self._raw()
                if child is not None:
                    items.append(child)
            if self.pos != end:
                raise self._error_cls("sequence length mismatch")
            return IonValue(type_code, annotations, items=tuple(items))
        raw = self._take(length)
        if type_code == _T_STRING:
            return IonValue(type_code, annotations, raw=raw, text=raw.decode("utf-8", "replace"))
        if type_code == _T_SYMBOL:
            sid = int.from_bytes(raw, "big") if raw else 0
            return IonValue(type_code, annotations, raw=raw, sid=sid, text=self.name(sid))
        return IonValue(type_code, annotations, raw=raw)

    def _struct(self, nibble: int, annotations: tuple[int, ...]) -> IonValue:
        length = self._length(nibble)
        if length is None:
            return IonValue(_T_STRUCT, annotations)
        if nibble == 1:
            length = self._varuint()
        end = self.pos + length
        fields: dict[int, list[IonValue]] = {}
        while self.pos < end:
            name = self._varuint()
            child = self._raw()
            if child is not None:
                fields.setdefault(name, []).append(child)
        if self.pos != end:
            raise self._error_cls("struct length mismatch")
        return IonValue(
            _T_STRUCT, annotations, fields={sid: tuple(vals) for sid, vals in fields.items()}
        )

    def _apply_local_symbol_table(self, value: IonValue) -> None:
        symbols = list(self.symbols)
        imports = value.field(_SID_IMPORTS)
        for entry in imports.items if imports is not None and imports.is_sequence else ():
            if not entry.is_struct:
                continue
            name_val = entry.field(4)
            name = name_val.text if name_val is not None else None
            max_id = _as_int(entry.field(8), default=0)
            version = _as_int(entry.field(5), default=1)
            if name is not None and max_id > 0:
                self.imports.append((name, version, max_id))
            plane = PROTECTED_DATA_PLANE if name == "ProtectedData" else ()
            symbols.extend(plane[:max_id])
            if len(plane) < max_id:
                symbols.extend([None] * (max_id - len(plane)))
        appended = value.field(_SID_SYMBOLS)
        if appended is not None and appended.is_sequence:
            for item in appended.items:
                symbols.append(item.text if item.type_code == _T_STRING else None)
        self.symbols = symbols


def walk_ion(value: IonValue) -> Iterator[IonValue]:
    yield value
    for children in value.fields.values():
        for child in children:
            yield from walk_ion(child)
    for child in value.items:
        yield from walk_ion(child)


def _strip_pkcs7_tail(data: bytes) -> bytes:
    if data and len(data) % 16 == 0:
        pad = data[-1]
        if 1 <= pad <= 16 and data[-pad:] == bytes([pad]) * pad:
            return data[:-pad]
    return data


def decode_ion_stream(
    data: bytes, *, error_cls: type[Exception] = VoucherParseError
) -> tuple[IonValue, IonReader]:
    if not data.startswith(BVM):
        raise error_cls("not an Ion 1.0 binary stream (no BVM)")
    reader = IonReader(data, error_cls=error_cls)
    roots: list[IonValue] = []
    while reader.pos < len(reader.data):
        try:
            value = reader.read()
        except error_cls:
            if len(roots) == 1 and (roots[0].is_struct or roots[0].is_sequence):
                break
            raise
        if value is not None:
            if (
                len(roots) == 1
                and (roots[0].is_struct or roots[0].is_sequence)
                and not (value.is_struct or value.is_sequence)
            ):
                break
            roots.append(value)
    if len(roots) != 1:
        raise error_cls(f"expected one Ion root value, found {len(roots)}")
    return roots[0], reader


def key_from_keyset(plaintext: bytes, error_cls: type[Exception] | None = None) -> bytes | None:
    unpadded = _strip_pkcs7_tail(plaintext)
    root = None
    last_exc: VoucherParseError | None = None
    for candidate in (unpadded, plaintext) if unpadded != plaintext else (plaintext,):
        try:
            root, _reader = decode_ion_stream(candidate)
            break
        except VoucherParseError as exc:
            last_exc = exc
    if root is None:
        if error_cls is not None:
            raise error_cls("plaintext is not a valid Ion KeySet document") from last_exc
        return None
    annotated: list[bytes] = []
    unannotated: list[bytes] = []
    for value in walk_ion(root):
        if not value.is_struct:
            continue
        encoded = blob_of(value.field(SECRET_KEY_ENCODED_SID))
        if encoded is None or len(encoded) != _SECRET_KEY_LEN:
            if SECRET_KEY_ANNOTATION_SID not in value.annotations:
                continue
            encoded = next(
                (c.raw for c in walk_ion(value) if c.is_blob and len(c.raw) == _SECRET_KEY_LEN),
                None,
            )
            if encoded is None:
                continue
        (annotated if SECRET_KEY_ANNOTATION_SID in value.annotations else unannotated).append(
            encoded
        )
    if annotated:
        return annotated[0]
    if len(unannotated) == 1:
        return unannotated[0]
    if error_cls is None:
        for value in walk_ion(root):
            if not value.is_struct or "AES" not in (c.text for c in walk_ion(value) if c.text):
                continue
            k16 = next(
                (c.raw for c in walk_ion(value) if c.is_blob and len(c.raw) == _SECRET_KEY_LEN),
                None,
            )
            if k16 is not None:
                return k16
    if error_cls is not None:
        raise error_cls("KeySet document carries no 16-byte SecretKey@1.0 encoded blob")
    return None


def wrapped_key_from_keyset(plaintext: bytes) -> tuple[int, bytes] | None:
    """The 48-byte wrapped key (sid 0x85 / 133) out of a KeySet@1.0 document, if there is one."""
    unpadded = _strip_pkcs7_tail(plaintext)
    root = None
    for candidate in (unpadded, plaintext) if unpadded != plaintext else (plaintext,):
        try:
            root, _reader = decode_ion_stream(candidate)
            break
        except VoucherParseError:
            continue
    if root is None:
        return None
    for value in walk_ion(root):
        if not value.is_struct:
            continue
        encoded = blob_of(value.field(SECRET_KEY_ENCODED_SID))
        if encoded is not None and len(encoded) == _WRAPPED_SECRET_KEY_LEN:
            ann_sid = (
                value.annotations[0] if value.annotations else WRAPPED_SECRET_KEY_ANNOTATION_SID
            )
            return ann_sid, encoded
    return None


def lock_parameter_names(
    value: IonValue | None, *, strict: bool = False, error_cls: type[Exception] = VoucherParseError
) -> tuple[str, ...]:
    if value is None:
        return ()
    if not value.is_sequence:
        if strict:
            raise error_cls("lock_parameters is not a list")
        return ()
    names: list[str] = []
    for item in value.items:
        if item.type_code == _T_STRING:
            text = item.text
        elif item.type_code == _T_SYMBOL:
            text = item.text or symbol_name(item.sid or 0) or f"${item.sid}"
        elif not strict and item.raw:
            text = item.raw.decode("utf-8", "replace")
        else:
            raise error_cls("lock_parameters entry is not a string or symbol")
        if not text:
            if strict:
                raise error_cls("lock_parameters entry has no resolvable name")
            continue
        names.append(text)
    return tuple(names)


def node_to_dict(node: IonValue | None) -> dict[str, Any] | None:
    if node is None or node.type_code != _T_STRUCT:
        return None
    res: dict[str, Any] = {}
    for fid, values in node.fields.items():
        if not values:
            continue
        v = values[0]
        if v.type_code == _T_STRUCT:
            res[f"${fid}"] = node_to_dict(v)
        elif v.text is not None:
            res[f"${fid}"] = v.text
        elif v.raw:
            res[f"${fid}"] = v.raw
        elif v.sid is not None:
            res[f"${fid}"] = v.sid
        else:
            res[f"${fid}"] = True
    return res

