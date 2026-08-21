"""Kindle for Mac/PC key-file helpers (A4, prime-offset guard)."""
import importlib.util
import os
import sys
import types

import pytest
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2

from conftest import PLUGIN_DIR

import kindlekey


def test_primes():
    assert kindlekey.primes(1) == []
    assert kindlekey.primes(2) == [2]
    assert kindlekey.primes(20) == [2, 3, 5, 7, 11, 13, 17, 19]


@pytest.mark.parametrize("contlen, expected", [(0, 0), (5, 0), (6, 6 - 2), (30, 30 - 7), (300, 300 - 97)])
def test_split_offset_never_raises(contlen, expected):
    assert kindlekey.split_offset(contlen) == expected


def test_encode_decode_round_trip():
    import kgenpids
    data = bytes(range(256))
    assert kindlekey.decode(kindlekey.encode(data, kgenpids.charMap1), kgenpids.charMap1) == data


@pytest.fixture
def kindlekey_macos(monkeypatch):
    """Load kindlekey.py as if running on macOS (the branch defining CryptUnprotectData)."""
    fake_calibre = types.ModuleType("calibre")
    fake_constants = types.ModuleType("calibre.constants")
    fake_constants.iswindows, fake_constants.isosx = False, True
    fake_calibre.constants = fake_constants
    monkeypatch.setitem(sys.modules, "calibre", fake_calibre)
    monkeypatch.setitem(sys.modules, "calibre.constants", fake_constants)
    monkeypatch.setenv("USER", "tester")
    path = os.path.join(PLUGIN_DIR, "kindlekey.py")
    spec = importlib.util.spec_from_file_location("DeDRM_plugin.kindlekey_macos", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_mac_crypt_unprotect_data_decrypts(kindlekey_macos):
    kk = kindlekey_macos
    entropy, idstring = b"123456" + b"A1B2C3D4", b"deadbeef"
    cud = kk.CryptUnprotectData(entropy, idstring)

    # independent derivation of the record key/IV
    passwd = kk.encode(kk.SHA256(b"tester" + b"+@#$%+" + idstring), kk.charMap2)
    key_iv = PBKDF2(passwd, entropy, count=0x800, dkLen=0x400)
    assert (cud.key, cud.iv) == (key_iv[:32], key_iv[32:48])

    secret = b"kindle.account.secrets"
    plaintext = kk.encode(secret, kk.charMap2)
    plaintext += b"\x00" * (-len(plaintext) % 16)
    ciphertext = AES.new(cud.key, AES.MODE_CBC, cud.iv).encrypt(plaintext)

    assert cud.decrypt(ciphertext) == secret
    assert cud.decrypt(ciphertext) == secret   # independent per record
