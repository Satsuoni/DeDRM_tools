"""Kindle for Android serial extraction (A5)."""
import binascii

import pytest

import androidkindlekey as ak


@pytest.mark.parametrize("length", list(range(0, 34)))
def test_pad_unpad_round_trip(length):
    data = b"x" * length
    padded = ak.pad(data, 16)
    assert isinstance(padded, bytes)
    assert len(padded) % 16 == 0 and 0 < len(padded) - length <= 16
    assert ak.unpad(padded, 16) == data


def test_obfuscation_round_trip():
    obf = ak.AndroidObfuscation()
    assert obf.decrypt(obf.encrypt("DsnId")) == b"DsnId"
    obf2 = ak.AndroidObfuscationV2(binascii.a2b_hex("00112233445566778899aabbccddeeff"))
    assert obf2.decrypt(obf2.encrypt("kindle.account.tokens")) == b"kindle.account.tokens"


def _write_preferences(path, obf, entries):
    lines = ['<?xml version="1.0" encoding="utf-8" standalone="yes" ?>', "<map>"]
    for key, value in entries.items():
        lines.append('<string name="{0}">{1}</string>'.format(
            obf.encrypt(key).decode("ascii"), obf.encrypt(value).decode("ascii")))
    lines.append("</map>")
    path.write_text("\n".join(lines))


def test_get_serials1_from_preferences_xml(tmp_path):
    obf = ak.AndroidObfuscation()
    prefs = tmp_path / "preferences.xml"
    _write_preferences(prefs, obf, {"DsnId": "B0123456789ABCDE", "kindle.account.tokens": "tokA,tokB"})
    serials = ak.get_serials1(str(prefs))
    assert "B0123456789ABCDE" in serials
    assert {"tokA", "tokB", "B0123456789ABCDEtokA", "B0123456789ABCDEtokB"} <= set(serials)


def test_get_serials1_missing_file():
    assert ak.get_serials1("/nonexistent/preferences.xml") == []
