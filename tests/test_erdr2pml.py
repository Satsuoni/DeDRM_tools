"""eReader (.pdb) helpers: key derivation, PML cleanup, footnote/sidebar text (D3)."""
import binascii
import struct
import zlib

from Cryptodome.Cipher import DES

import erdr2pml


def test_getuser_key_is_deterministic_and_normalised():
    key = erdr2pml.getuser_key("Mr Jonathan Q Smith", "1234 5678 9012 3456")
    assert isinstance(key, bytes) and len(key) == 8
    assert key == erdr2pml.getuser_key("MRJONATHANQSMITH", "123456789012 3456")
    # independent derivation: crc32(normalised name) || crc32(last 8 card digits)
    expected = struct.pack(">LL",
                           binascii.crc32(b"mrjonathanqsmith") & 0xFFFFFFFF,
                           binascii.crc32(b"90123456") & 0xFFFFFFFF)
    assert key == expected
    # what the config dialog stores must be JSON-safe text
    assert binascii.hexlify(key).decode("ascii").isalnum()


def test_cleanpml_escapes_high_bytes():
    assert erdr2pml.cleanPML(b"ab\x80c\xff") == b"ab\\a128c\\a255"


def test_dexor():
    assert erdr2pml.deXOR(b"\x01\x02\x03", 0, b"\x01\x01\x01") == b"\x00\x03\x02"


def _encrypted_page(content_key, text):
    des = DES.new(erdr2pml.fixKey(content_key), DES.MODE_ECB)
    data = zlib.compress(text)
    data += b"\x00" * (-len(data) % 8)
    return des.encrypt(data)


def test_gettext_with_footnotes_and_sidebars():
    content_key = b"\x10\x32\x54\x76\x98\xba\xdc\xfe"
    xortable = bytes(range(1, 41))
    fnote_ids = b"\x00\x00" + bytes([4]) + b"fn01" + b"\x00"
    sbar_ids = b"\x00\x00" + bytes([3]) + b"sb1" + b"\x00"
    sections = {
        1: _encrypted_page(content_key, b"Body text."),
        2: _encrypted_page(content_key, b"More body."),
        10: bytes(a ^ b for a, b in zip(fnote_ids, xortable)),
        11: _encrypted_page(content_key, b"Footnote one."),
        20: bytes(a ^ b for a, b in zip(sbar_ids, xortable)),
        21: _encrypted_page(content_key, b"Sidebar one."),
    }
    er = erdr2pml.EreaderProcessor.__new__(erdr2pml.EreaderProcessor)
    er.content_key = content_key
    er.xortable = xortable
    er.num_text_pages = 2
    er.num_footnote_pages, er.first_footnote_page = 2, 10
    er.num_sidebar_pages, er.first_sidebar_page = 2, 20
    er.section_reader = sections.__getitem__

    text = er.getText()

    assert text == (b"Body text.More body."
                    b"\n<footnote id=\"fn01\">\nFootnote one.\n</footnote>\n"
                    b"\n<sidebar id=\"sb1\">\nSidebar one.\n</sidebar>\n")
    assert erdr2pml.cleanPML(text) == text
