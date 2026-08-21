"""Builders for genuinely DRM-encrypted ebooks, used by the end-to-end tests.

These produce real ciphertext using the same algorithms the DRM schemes use, so
the decryptors under test do actual cryptographic work rather than parsing a
mock. Each builder asserts that the plaintext canary is absent from the file it
wrote, so a builder that silently stops encrypting fails loudly.
"""
import base64
import struct
import zipfile
import zlib

from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes

MOBI_T1_KEYVEC = b'QDCVEPMU675RUBSZ'
MOBI_HEADER_LEN = 0xE4
ADEPT_CHAPTER = 'OEBPS/chapter1.xhtml'


def build_mobi(path, plaintexts, book_key=None):
    """Write a Mobipocket book with crypto type 1 (fixed-key) DRM.

    :param path: output file path
    :param plaintexts: list of bytes, one per text record
    :param book_key: 16-byte key, or None for a fixed test key
    :return: the book key used
    """
    from DeDRM_plugin.mobidedrm import PC1
    book_key = book_key or bytes(range(16))

    rec0 = bytearray(MOBI_HEADER_LEN + 32)
    struct.pack_into('>H', rec0, 0x00, 1)                               # no compression
    struct.pack_into('>L', rec0, 0x04, sum(len(p) for p in plaintexts))  # text length
    struct.pack_into('>H', rec0, 0x08, len(plaintexts))                 # record count
    struct.pack_into('>H', rec0, 0x0A, 4096)                            # record size
    struct.pack_into('>H', rec0, 0x0C, 1)                               # encryption type 1
    rec0[0x10:0x14] = b'MOBI'
    struct.pack_into('>L', rec0, 0x14, MOBI_HEADER_LEN)                 # header length
    struct.pack_into('>L', rec0, 0x18, 2)                               # mobi type: book
    struct.pack_into('>L', rec0, 0x1C, 65001)                           # utf-8
    struct.pack_into('>L', rec0, 0x68, 6)                               # version >= 5
    struct.pack_into('>L', rec0, 0x80, 0)                               # no EXTH
    struct.pack_into('>H', rec0, 0xF2, 0)                               # extra data flags
    # the type-1 book key sits just past the MOBI header, wrapped with the fixed vector
    rec0[MOBI_HEADER_LEN + 16:MOBI_HEADER_LEN + 32] = PC1(MOBI_T1_KEYVEC, book_key, False)

    records = [bytes(rec0)] + [PC1(book_key, p, False) for p in plaintexts]

    header = bytearray(78)
    header[0:32] = b'DeDRM Test Book'.ljust(32, b'\0')
    header[0x3C:0x44] = b'BOOKMOBI'
    struct.pack_into('>H', header, 76, len(records))
    entries, offset = bytearray(), 78 + 8 * len(records) + 2
    for i, record in enumerate(records):
        entries += struct.pack('>LBBBB', offset, 0, 0, 0, i)
        offset += len(record)

    with open(path, 'wb') as fh:
        fh.write(bytes(header) + bytes(entries) + b'\0\0' + b''.join(records))
    for plain in plaintexts:
        assert plain not in open(path, 'rb').read(), "plaintext leaked: not encrypted"
    return book_key


def _pkcs7(data, block=16):
    pad = block - len(data) % block
    return data + bytes([pad]) * pad


def _adept_encrypt(book_key, data):
    """Raw-deflate, pad, prepend a random block, AES-128-CBC with a zero IV."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    deflated = compressor.compress(data) + compressor.flush()
    blob = get_random_bytes(16) + _pkcs7(deflated)
    return AES.new(book_key, AES.MODE_CBC, b'\x00' * 16).encrypt(blob)


def build_adept_epub(path, content):
    """Write an Adobe ADEPT-encrypted EPUB; returns the RSA private key in DER form."""
    rsa = RSA.generate(1024)                       # 1024-bit -> 172-char base64 blob
    book_key = get_random_bytes(16)
    wrapped = base64.b64encode(PKCS1_v1_5.new(rsa.publickey()).encrypt(book_key)).decode('ascii')
    assert len(wrapped) == 172, "ADEPT encryptedKey must be 172 chars, got %d" % len(wrapped)

    rights = ('<?xml version="1.0"?>\n<adept:rights xmlns:adept="http://ns.adobe.com/adept">'
              '<adept:licenseToken><adept:encryptedKey>%s</adept:encryptedKey>'
              '</adept:licenseToken></adept:rights>' % wrapped)
    encryption = ('<?xml version="1.0"?>\n<encryption '
                  'xmlns="urn:oasis:names:tc:opendocument:xmlns:container" '
                  'xmlns:enc="http://www.w3.org/2001/04/xmlenc#"><enc:EncryptedData>'
                  '<enc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>'
                  '<enc:CipherData><enc:CipherReference URI="%s"/></enc:CipherData>'
                  '</enc:EncryptedData></encryption>' % ADEPT_CHAPTER)
    opf = ('<?xml version="1.0"?><package xmlns="http://www.idpf.org/2007/opf" version="2.0" '
           'unique-identifier="i"><metadata xmlns:dc="http://purl.org/dc/elements/1.1/">'
           '<dc:title>ADEPT Test Book</dc:title><dc:identifier id="i">urn:uuid:t</dc:identifier>'
           '</metadata><manifest><item id="c1" href="chapter1.xhtml" '
           'media-type="application/xhtml+xml"/></manifest><spine><itemref idref="c1"/></spine>'
           '</package>')
    container = ('<?xml version="1.0"?><container version="1.0" '
                 'xmlns="urn:oasis:names:tc:opendocument:xmlns:container"><rootfiles><rootfile '
                 'full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>'
                 '</rootfiles></container>')

    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(zipfile.ZipInfo('mimetype'), 'application/epub+zip', zipfile.ZIP_STORED)
        zf.writestr('META-INF/container.xml', container)
        zf.writestr('META-INF/rights.xml', rights)
        zf.writestr('META-INF/encryption.xml', encryption)
        zf.writestr('OEBPS/content.opf', opf)
        zf.writestr(ADEPT_CHAPTER, _adept_encrypt(book_key, content))

    assert content not in open(path, 'rb').read(), "plaintext leaked: not encrypted"
    return rsa.export_key('DER')
