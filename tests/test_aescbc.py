"""Known-answer and differential tests for the pure-Python aescbc module (A6)."""
import os

import pytest
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

import aescbc
import alfcrypto

# NIST SP 800-38A, F.2.1 / F.2.2 (CBC-AES128)
NIST_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
NIST_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
NIST_PT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef" "f69f2445df4f9b17ad2b417be66c3710")
NIST_CT = bytes.fromhex(
    "7649abac8119b246cee98e9b12e9197d" "5086cb9b507219ee95db113a917678b2"
    "73bed6b8e3c1743b7116e69e22229516" "3ff1caa1681fac09120eca307586e1a7")


def test_nist_cbc_aes128_encrypt():
    cipher = aescbc.AES_CBC(NIST_KEY, aescbc.noPadding(), 16)
    assert cipher.encrypt(NIST_PT, iv=NIST_IV) == NIST_CT


def test_nist_cbc_aes128_decrypt():
    cipher = aescbc.AES_CBC(NIST_KEY, aescbc.noPadding(), 16)
    assert cipher.decrypt(NIST_CT, iv=NIST_IV) == NIST_PT


@pytest.mark.parametrize("key_size", [16, 24, 32])
@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 31, 32, 100])
def test_matches_pycryptodome_with_padding(key_size, length):
    key, iv, data = os.urandom(key_size), os.urandom(16), os.urandom(length)
    ours = aescbc.AES_CBC(key, aescbc.padWithPadLen(), key_size).encrypt(data, iv=iv)
    reference = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, 16))
    assert ours == reference
    assert aescbc.AES_CBC(key, aescbc.padWithPadLen(), key_size).decrypt(ours, iv=iv) == data


def test_padding_edge_cases():
    # empty input -> exactly one block of padding; exact block -> one extra block
    key, iv = os.urandom(16), os.urandom(16)
    assert len(aescbc.AES_CBC(key, aescbc.padWithPadLen(), 16).encrypt(b"", iv=iv)) == 16
    assert len(aescbc.AES_CBC(key, aescbc.padWithPadLen(), 16).encrypt(b"x" * 16, iv=iv)) == 32
    assert aescbc.padWithPadLen().addPad(b"abc", 16) == b"abc" + b"\x0d" * 13
    assert aescbc.padWithPadLen().removePad(b"abc" + b"\x0d" * 13, 16) == b"abc"


def test_non_block_aligned_ciphertext_is_rejected():
    cipher = aescbc.AES_CBC(os.urandom(16), aescbc.noPadding(), 16)
    with pytest.raises(aescbc.DecryptNotBlockAlignedError):
        cipher.decrypt(b"\x00" * 17, iv=os.urandom(16))


def test_streaming_decrypt_round_trip():
    # exercises the 'more' path, including the leftover-bytes buffer
    key, iv, data = os.urandom(16), os.urandom(16), os.urandom(64)
    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(data)
    cipher = aescbc.AES_CBC(key, aescbc.noPadding(), 16)
    out = cipher.decrypt(ciphertext[:20], iv=iv, more=True)
    out += cipher.decrypt(ciphertext[20:50], more=True)
    out += cipher.decrypt(ciphertext[50:])
    assert out == data


def test_alfcrypto_wrapper_is_reusable_and_matches_reference():
    key, iv, data = os.urandom(32), os.urandom(16), os.urandom(48)
    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(data)
    wrapper = alfcrypto.AES_CBC()
    wrapper.set_decrypt_key(key, iv)
    assert wrapper.decrypt(ciphertext) == data
    # each call is independent: same IV is re-applied
    assert wrapper.decrypt(ciphertext) == data
