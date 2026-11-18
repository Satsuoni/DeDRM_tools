"""Amazon Ion binary parser: decimal decoding (A3)."""
import io

import pytest

import ion


def _parser(payload, valuelen):
    parser = ion.BinaryIonParser(io.BytesIO(payload))
    parser.valuelen = valuelen
    parser.localremaining = -1
    return parser


@pytest.mark.parametrize("payload, expected", [
    (b"\x80\x01\x02", 258),                     # exponent 0, mantissa 0x0102
    (b"\x80\x81\x02", -258),                    # sign bit in first mantissa byte
    (b"\x82\x01", 100),                         # exponent +2
    (b"\xc1\x7b", 12.3),                        # exponent -1 -> 123 * 10**-1
    (b"\x80\x01\x00\x00\x00\x00\x00\x00\x00", 1 << 56),   # full 8-byte mantissa
    (b"\x80\x7f\xff\xff\xff\xff\xff\xff\xff", (1 << 63) - 1),
])
def test_readdecimal(payload, expected):
    value = _parser(payload, len(payload)).readdecimal()
    assert value == pytest.approx(expected)


def test_readdecimal_zero_length_is_zero():
    assert _parser(b"", 0).readdecimal() == 0


def test_readdecimal_rejects_overlong_mantissa():
    payload = b"\x80" + b"\x01" * 9
    with pytest.raises(Exception):
        _parser(payload, len(payload)).readdecimal()
