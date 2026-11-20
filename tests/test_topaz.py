"""Topaz 7-bit encoded numbers / strings and metadata parsing (D1, D2)."""
import io

import pytest

import genbook
import topazextract


def encode_number(value):
    """Inverse of genbook.readEncodedNumber / topazextract.bookReadEncodedNumber."""
    prefix = b""
    if value < 0:
        prefix, value = b"\xff", -value
    groups = []
    while True:
        groups.insert(0, value & 0x7F)
        value >>= 7
        if value == 0:
            break
    return prefix + bytes([g | 0x80 for g in groups[:-1]] + [groups[-1]])


def encode_string(data):
    return encode_number(len(data)) + data


# Note: a leading 0xFF byte is the negative marker, so values whose top 7-bit
# group is 0x7F with a continuation (e.g. 0x3FFF) are not representable.
@pytest.mark.parametrize("value", [0, 1, 0x7F, 0x80, 300, 0x2000, 0x4000, 1 << 20, -1, -0x80, -12345])
def test_encoded_number_round_trip(value):
    blob = encode_number(value)
    assert genbook.readEncodedNumber(io.BytesIO(blob)) == value
    assert topazextract.bookReadEncodedNumber(io.BytesIO(blob)) == value


def test_read_encoded_number_at_eof_returns_none():
    assert genbook.readEncodedNumber(io.BytesIO(b"")) is None


def test_read_string_returns_bytes():
    assert genbook.readString(io.BytesIO(encode_string(b"metadata"))) == b"metadata"
    assert genbook.readString(io.BytesIO(encode_number(10) + b"short")) == b""
    assert topazextract.bookReadString(io.BytesIO(encode_string(b"metadata"))) == b"metadata"


def test_get_meta_array_decodes_to_str(tmp_path):
    entries = {b"Title": "Café Stories".encode("utf-8"), b"Authors": b"A. Author", b"GUID": b"abc123"}
    blob = encode_number(len(entries)) + b"".join(encode_string(k) + encode_string(v) for k, v in entries.items())
    meta_file = tmp_path / "metadata0000.dat"
    meta_file.write_bytes(blob)
    meta = genbook.getMetaArray(str(meta_file))
    assert meta == {"Title": "Café Stories", "Authors": "A. Author", "GUID": "abc123"}
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in meta.items())


def test_dictionary_escapes_and_lookup(tmp_path):
    words = [b"plain", b"a<b>&c=d"]
    blob = encode_number(len(words)) + b"".join(encode_string(w) for w in words)
    dict_file = tmp_path / "dict0000.dat"
    dict_file.write_bytes(blob)
    d = genbook.Dictionary(str(dict_file))
    assert d.getSize() == 2
    assert d.lookup(0) == b"plain"
    assert d.lookup(1) == b"a&lt;b&gt;&amp;c&#61;d"
    with pytest.raises(genbook.TpzDRMError):
        d.lookup(2)
