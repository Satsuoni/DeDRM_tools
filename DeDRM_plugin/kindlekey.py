#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# kindlekey.py
# Copyright © 2008-2022 Apprentice Harper et al.

__license__ = 'GPL v3'
__version__ = '4.0'

# Revision history:
#  1.0   - Kindle info file decryption, extracted from k4mobidedrm, etc.
#  1.1   - Added Tkinter to match adobekey.py
#  1.2   - Fixed testing of successful retrieval on Mac
#  1.3   - Added getkey interface for Windows DeDRM application
#          Simplified some of the Kindle for Mac code.
#  1.4   - Remove dependency on alfcrypto
#  1.5   - moved unicode_argv call inside main for Windows DeDRM compatibility
#  1.6   - Fixed a problem getting the disk serial numbers
#  1.7   - Work if TkInter is missing
#  1.8   - Fixes for Kindle for Mac, and non-ascii in Windows user names
#  1.9   - Fixes for Unicode in Windows user names
#  2.0   - Added comments and extra fix for non-ascii Windows user names
#  2.1   - Fixed Kindle for PC encryption changes March 2016
#  2.2   - Fixes for Macs with bonded ethernet ports
#          Also removed old .kinfo file support (pre-2011)
#  2.3   - Added more field names thanks to concavegit's KFX code.
#  2.4   - Fix for complex Mac disk setups, thanks to Tibs
#  2.5   - Final Fix for Windows user names with non-ascii characters, thanks to oneofusoneofus
#  2.6   - Start adding support for Kindle 1.25+ .kinf2018 file
#  2.7   - Finish .kinf2018 support, PC & Mac by Apprentice Sakuya
#  2.8   - Fix for Mac OS X Big Sur
#  3.0   - Python 3 for calibre 5.0
#  3.1   - Only support PyCryptodome; clean up the code
#  4.0   - Support Kindle for PC 1.36+ .kinf2024 (ObfuscatorV1 records + AES-256-GCM
#          values, storage key unwrapped from the CNG key "KindleForPC_SS").
#          New options: -m <hex32> -s <salt> -b <blob> --dump-master <file>


"""
Retrieve Kindle for PC/Mac user key.
"""

import sys, os, re
import codecs
import base64
import hmac
from struct import pack, unpack, unpack_from
from string import ascii_uppercase
import json
import getopt
import traceback
import hashlib

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util import Counter
    from Cryptodome.Protocol.KDF import PBKDF2
except ImportError:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
    from Crypto.Protocol.KDF import PBKDF2

try:
    RegError
except NameError:
    class RegError(Exception):
        pass

# Routines common to Mac and PC

#@@CALIBRE_COMPAT_CODE@@
try:
  from .utilities import SafeUnbuffered
  from .argv_utils import unicode_argv
except:
  from utilities import SafeUnbuffered
  from argv_utils import unicode_argv
  
    

try:
    from calibre.constants import iswindows, isosx
except:
    iswindows = sys.platform.startswith('win')
    isosx = sys.platform.startswith('darwin')



class DrmException(Exception):
    pass

# crypto digestroutines

def MD5(message):
    return hashlib.md5(message).digest()

def SHA1(message):
    return hashlib.sha1(message).digest()

def SHA256(message):
    return hashlib.sha256(message).digest()


# For K4M/PC 1.6.X and later
def primes(n):
    """
    Return a list of prime integers smaller than or equal to n
    :param n: int
    :return: list->int
    """
    if n == 2:
        return [2]
    elif n < 2:
        return []
    primeList = [2]

    for potentialPrime in range(3, n + 1, 2):
        isItPrime = True
        for prime in primeList:
            if potentialPrime % prime == 0:
                isItPrime = False
        if isItPrime is True:
            primeList.append(potentialPrime)

    return primeList

# Encode the bytes in data with the characters in map
# data and map should be byte arrays
def encode(data, map):
    result = b''
    for char in data:
        if sys.version_info[0] == 2:
            value = ord(char)
        else:
            value = char

        Q = (value ^ 0x80) // len(map)
        R = value % len(map)

        result += bytes(bytearray([map[Q]]))
        result += bytes(bytearray([map[R]]))

    return result

# Hash the bytes in data and then encode the digest with the characters in map
def encodeHash(data,map):
    return encode(MD5(data),map)

# Decode the string in data with the characters in map. Returns the decoded bytes
def decode(data,map):
    result = b''
    for i in range (0,len(data)-1,2):
        high = map.find(data[i])
        low = map.find(data[i+1])
        if (high == -1) or (low == -1) :
            break
        value = (((high * len(map)) ^ 0x80) & 0xFF) + low
        result += pack('B',value)
    return result

def UnprotectHeaderData(encryptedData):
    passwdData = b'header_key_data'
    salt = b'HEADER.2011'
    key_iv = PBKDF2(passwdData, salt, dkLen=256, count=128)
    return AES.new(key_iv[0:32], AES.MODE_CBC, key_iv[32:48]).decrypt(encryptedData)


# ---------------------------------------------------------------------------
# MSIX Kindle  1.36+ : the .kinf2024 container
#
#   file      = <header> '#' rec0 '}' rec1 '}' ...
#   reci      = reverse(base64std(payload)) + '8'
#   record    = F5 Caesar strip -> base64 -> F4 LZW -> F3 permutation (dwF3Key)
#               -> B64Enc2 -> F2 rotate (dwF2Key = dwF3Key % 5) -> F1 transpose -> split on '*'
#   KEY       = encodeHash(MD5(entry name), testMap8)   <- same scheme as .kinf2018
#   VALUE     = A64( nonce(12) || ciphertext || tag(16) )          AES-256-GCM
#   storageIKM= HKDF-SHA256(ikm=master32, salt=main_shared.salt, info='kindle_ss')
#   entryKey  = HKDF-SHA256(ikm=storageIKM, salt=SHA1(KEY text), info='kindle_ss_token')
#
# The GCM tag makes the whole thing self-checking: a wrong master key, salt or
# info string fails the tag, so a non-empty result is proof the key is right.
# Courtesy of Qwen Flash Next Q3_S
# ---------------------------------------------------------------------------

# identical to the K4PC 1.9+ testMap8 already used above - the new format kept it
KINF2024_MAP = b"YvaZ3FfUm9Nn_c1XuG4yCAzB0beVg-TtHh5SsIiR6rJjQdW2wEq7KkPpL8lOoMxD"
# The ObfuscatorV1 keys are NOT constants.  SecureStorageFileObfuscatorV1Ctor_18011c5b0
# derives all four from one string `s` (dsx_storage.md 24 and 25):
#
#   s        = sprintf("%u", GetVolumeInformationW(QDir::rootPath()).VolumeSerialNumber),
#              or "9999999999" when that call fails   <- GetVolumeSerialDecimalString_1810059e0
#   f1_key   = last 5 chars of s                -> F1_Dec uses only its length: 5 rows, always
#   dwF3_key = sum of the bytes of s            -> F3 permutation parameter p = dwF3_key - 1
#   dwF2_key = dwF3_key % 5                     -> F2 bit-string rotate amount
#   f5_key   = str(sum(byte[i] * (i+1)) % 8)    -> always 1 char, so the F5 shift is always 1
#
# Reference device: volume serial 236943134 -> s = "236943134", which reproduces every live
# value ever captured for this build: f1_key "43134", dwF3_key 467, dwF2_key 2, f5_key "7".
# Only dwF3_key / dwF2_key move between machines, so 467 / 2 are a fallback, not a constant.

KINF2024_DWKEY = 467          # reference-device dwF3_key; prefer obfDeriveKeys()/kinf2024RecoverKeys()
KINF2024_F5_SHIFT = 1         # len(f5_key) & 7 -- f5_key is always one char, so this one IS universal
KINF2024_F2_ROTATE = 2        # reference-device dwF2_key, i.e. 467 % 5
KINF2024_VOLSERIAL_FALLBACK = '9999999999'      # `s` when GetVolumeInformationW fails
KINF2024_DWKEY_MIN = 48       # s is 1..10 decimal digits -> sum(bytes) in 1*'0' .. 10*'9'
KINF2024_DWKEY_MAX = 570
KINF2024_INFO_STORAGE = b'kindle_ss'
KINF2024_INFO_ENTRY = b'kindle_ss_token'

# entry names seen in 1.36+ that the pre-2018 list does not carry
KINF2024_EXTRA_NAMES = [
    b'_KEY_DIRECTED_ID_',
    b'_COLLECTION_ENTRIES_SYNC_COUNT_',
    b'kindle.metrics.checksum',
]

# every name worth resolving in a 1.36+ container: the pre-2018 set plus the new ones
KINF2024_NAMES = [
    b'kindle.account.tokens', b'kindle.cookie.item', b'eulaVersionAccepted', b'login_date',
    b'kindle.token.item', b'login', b'kindle.key.item', b'kindle.name.info',
    b'kindle.device.info', b'MazamaRandomNumber', b'max_date', b'SIGVERIF',
    b'build_version', b'SerialNumber', b'UsernameHash', b'kindle.directedid.info',
    b'DSN', b'kindle.accounttype.info', b'krx.flashcardsplugin.data.encryption_key',
    b'krx.notebookexportplugin.data.encryption_key', b'proxy.http.password',
    b'proxy.http.username', b'kindle.note', b'kindle.highlight', b'kindle.bookmark',
    b'kindle.graphical_highlight', b'kindle.most_recent_read',
] + KINF2024_EXTRA_NAMES


def kinf2024Records(data):
    """container bytes -> list of record byte strings"""
    h = data.find(b'#')
    if h < 0:
        raise DrmException('.kinf2024: no header terminator')
    return [r for r in data[h + 1:].split(b'}') if r]


def isKinf2024(path, data=None):
    """True if this looks like the 1.36+ container rather than a .kinf2011/2018 file.
    The old formats are '/'-separated and have no '#' or '}'."""
    if path.endswith('2024'):
        return True
    if data is None:
        try:
            with open(path, 'rb') as fh:
                data = fh.read(4096)
        except OSError:
            return False
    return data.find(b'}') >= 0 and 0 <= data.find(b'#') < data.find(b'}')


# ---------------------------------------------------------------------------
# ObfuscatorV1 key derivation -- SecureStorageFileObfuscatorV1Ctor_18011c5b0
# ---------------------------------------------------------------------------

def obfDeriveF3Key(src):
    """ObfV1_DeriveF3Key_18011d230.  The CFF state machine reduces to: while the string is
    longer than 5 characters, replace it by the decimal form of its byte sum, then parse it.
    For any realistic key source that single pass is the whole computation, i.e. dwF3_key is
    just the sum of the bytes of `s`."""
    t = src
    while len(t) > 5:
        t = str(sum(bytearray(t.encode('latin1'))) & 0xffffffff)
    try:
        return int(t)
    except ValueError:
        raise DrmException('ObfuscatorV1: key source %r does not reduce to a number' % (src,))


def obfDeriveF1KeyTail5(src):
    """ObfV1_DeriveF1KeyTail5_18011d8a0 -- the last 5 characters of the key source.
    ObfV1_F1_Dec only reads its length, so the digits themselves never matter."""
    if len(src) < 5:
        raise DrmException('ObfuscatorV1: key source shorter than 5 characters')
    return src[-5:]


def obfDeriveF5Key(src):
    """ObfV1_DeriveF5Key_18011cfa0 -- position-weighted byte sum, mod 8, as a decimal string.
    ObfV1_F5_CaesarStrip uses len(f5_key) & 7 and this is always a single char, which is why
    the Caesar shift is 1 on every device.  s = "236943134" gives w = 2327 -> "7"."""
    w = sum(b * (i + 1) for i, b in enumerate(bytearray(src.encode('latin1')))) & 0xffffffff
    return str(w % 8)


def obfDeriveKeys(src):
    """key-source string -> dict of the four ObfuscatorV1 keys."""
    k3 = obfDeriveF3Key(src)
    return {'src': src, 'f1Key': obfDeriveF1KeyTail5(src), 'dwF3Key': k3,
            'dwF2Key': k3 % 5, 'f5Key': obfDeriveF5Key(src)}


def obfKeysFromVolumeSerial(serial):
    """DWORD volume serial number -> keys.  This is all you need off the target machine:
    PowerShell (Get-Volume -DriveLetter C).SerialNumber, or cmd `vol`.  `s` is that number
    in DECIMAL, not hex -- 236943134, not 0x0e2244de."""
    return obfDeriveKeys('%u' % (int(serial) & 0xffffffff))


def obfKeysFromDwKey(dwF3Key):
    """Keys when only dwF3_key is known.  f1_key and f5_key cannot be recovered from it, but
    F1_Dec and F5_CaesarStrip consume only their lengths (5 and 1), which these placeholders
    reproduce exactly."""
    return {'src': None, 'f1Key': '0' * 5, 'dwF3Key': int(dwF3Key),
            'dwF2Key': int(dwF3Key) % 5, 'f5Key': '0'}


def obfF5Strip(rec, k=KINF2024_F5_SHIFT):
    """ObfV1_F5_CaesarStrip: reverse the record, drop the one marker char the encoder
    prepended, then apply +k to even indices and -k to odd ones.  Each character class
    wraps in its own range; '+' '/' '=' and everything else pass through."""
    body = rec[::-1][1:]
    out = []
    for i, c in enumerate(body):
        o = ord(c)
        s = k if i % 2 == 0 else -k
        if 65 <= o <= 90:
            out.append(chr((o - 65 + s) % 26 + 65))
        elif 97 <= o <= 122:
            out.append(chr((o - 97 + s) % 26 + 97))
        elif 48 <= o <= 57:
            out.append(chr((o - 48 + s) % 10 + 48))
        else:
            out.append(c)
    return ''.join(out)


def obfF4Decode(codes):
    """ObfV1_F4_Dec: LZW whose dictionary starts as the identity over 0..255."""
    d = {k: bytes(bytearray([k])) for k in range(256)}
    res = bytearray()
    prev = None
    for c in codes:
        if c in d:
            e = d[c]
        elif prev is not None:
            e = prev + prev[:1]              # the LZW corner case
        else:
            raise DrmException('F4: unknown code with no history')
        res += e
        if prev is not None:
            d[len(d)] = prev + e[:1]
        prev = e
    return res.decode('latin1')


def obfF3Perm(L, dwKey=KINF2024_DWKEY):
    """ObfV1_F3_Dec in closed form: out[j] = in[perm[j]].
    The permutation is the reading order of a triangular bounce, so cell i maps to
    bounce(i, dwKey-1); sorting the (bounce, index) pairs gives the write order.
    dwKey is dwF3_key from obfDeriveKeys() -- device-specific.  Note that for dwKey-1 >= L
    the permutation degenerates to the identity, so a record shorter than the key carries no
    information about it."""
    p = dwKey - 1
    if p <= 0:
        return list(range(L))

    def bounce(i):
        m = 2 * p
        r = i % m
        return r if r <= p else m - r

    mark = [(bounce(i), i) for i in range(L)]
    wr = sorted(mark)
    pos = {}
    for idx, cell in enumerate(wr):
        pos[cell[1]] = idx
    return [pos[cell[1]] for cell in mark]


def obfB64Enc2(s):
    """ObfV1_B64Enc2: the 7-symbol alphabet {a..f, A, Z} back to a bit string.
    'Z' separates runs, a run of length rank(c)+1; 'xAy' emits (rank(x)+1) zeros
    followed by (rank(y)+1) ones."""
    rank = {'a': 0, 'b': 1, 'c': 2, 'd': 3, 'e': 4, 'f': 5}
    bits = []
    tokens = s.split('Z')
    for index, tok in enumerate(tokens):
        if not tok:
            continue
        if index == len(tokens) - 1 and len(tok) == 2 and tok[0] in rank and tok[1] == 'A':
            # An xA suffix encodes a final zero run without a following one run.
            bits.append('0' * (rank[tok[0]] + 1))
            continue
        if len(tok) == 3 and tok[1] == 'A':
            if tok[0] not in rank or tok[2] not in rank:
                raise DrmException('B64Enc2: bad symbol in %r' % tok)
            bits.append('0' * (rank[tok[0]] + 1))
            bits.append('1' * (rank[tok[2]] + 1))
        else:
            if tok[-1] not in rank:
                raise DrmException('B64Enc2: bad symbol in %r' % tok)
            bits.append('1' * (rank[tok[-1]] + 1))
    return ''.join(bits)


def obfF2Decode(bits, n=KINF2024_F2_ROTATE):
    """ObfV1_F2_Dec: rotate the bit string right by n, then pack 8 bits per char.
    n is dwF2_key, which the constructor sets to dwF3_key % 5 -- it is not independent."""
    if len(bits) % 8 != 0:
        raise DrmException('F2: bit count %d is not a multiple of 8' % len(bits))
    rot = bits[-n:] + bits[:-n]
    return ''.join(chr(int(rot[i:i + 8], 2)) for i in range(0, len(rot), 8))


def obfF1Decode(s):
    """ObfV1_F1_Dec: 5-row column-major transpose, '^' standing for ' '."""
    nc = s.count('^')
    ncols = (len(s) - nc) // 5 + 1
    rows = [s[i * ncols:(i + 1) * ncols] for i in range(5)]
    out = []
    for c in range(ncols):
        for r in range(5):
            ch = rows[r][c]
            out.append(' ' if ch == '^' else ch)
    return ''.join(out)


def kinf2024RecordLooksValid(rec, keys):
    """Cheap structural oracle for key recovery: the KEY field is always 32 characters of the
    A64 alphabet and the VALUE only ever holds A64 characters, so a wrong dwF3_key (and with
    it a wrong dwF2_key = dwF3_key % 5) essentially never survives."""
    try:
        keytext, valtext = kinf2024DecodeRecord(rec, keys)
    except Exception:
        return False
    alpha = set(KINF2024_MAP.decode('latin1'))
    if len(keytext) != 32:
        return False
    return all(c in alpha for c in keytext) and all(c in alpha for c in valtext)


def kinf2024RecoverKeys(recs, lo=KINF2024_DWKEY_MIN, hi=KINF2024_DWKEY_MAX):
    """Recover the ObfuscatorV1 keys from the container alone, with no device access.
    `s` is a decimal digit string of 1..10 characters, so dwF3_key = sum(bytes) is confined
    to 48..570 and dwF2_key is then fixed at dwF3_key % 5 -- 523 candidates, and the record
    structure picks out the one that works.  Returns None if none does."""
    probe = recs[:4]
    if not probe:
        return None
    for k in range(lo, hi + 1):
        keys = obfKeysFromDwKey(k)
        if all(kinf2024RecordLooksValid(r, keys) for r in probe):
            return keys
    return None


def kinf2024DecodeRecord(rec, keys=None):
    """record bytes -> (KEY text, VALUE text) as latin1 strings.
    The KEY text is exactly what encodeHash(name, KINF2024_MAP) produces.
    `keys` is a dict from obfDeriveKeys() / obfKeysFromVolumeSerial() /
    kinf2024RecoverKeys(), or a bare dwF3_key integer.  Omit it only to get the
    reference-device keys."""
    if keys is None:
        keys = obfKeysFromDwKey(KINF2024_DWKEY)
    elif not isinstance(keys, dict):
        keys = obfKeysFromDwKey(keys)
    x = obfF5Strip(rec.decode('latin1'))
    codes = [int(t) for t in base64.b64decode(x + '=' * (-len(x) % 4)).decode('latin1')
             .rstrip(',').split(',') if t != '']
    f4 = obfF4Decode(codes)
    perm = obfF3Perm(len(f4), keys['dwF3Key'])
    f3 = ''.join(f4[j] for j in perm)
    flat = obfF1Decode(obfF2Decode(obfB64Enc2(f3), keys['dwF2Key']))
    keytext, _, valtext = flat.rstrip(' ').partition('*')
    if not valtext:
        raise DrmException('record has no KEY/VALUE separator')
    return keytext, valtext


def hkdfSha256(ikm, salt, info, dkLen):
    """RFC 5869 HKDF-SHA256 (the binary reaches it through OpenSSL's EVP_PKEY HKDF)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b''
    t = b''
    i = 1
    while len(okm) < dkLen:
        t = hmac.new(prk, t + info + bytes(bytearray([i])), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:dkLen]


def kinf2024StorageIkm(master32, salt):
    """The 32 bytes the binary hands to HKDF_KEY after CryptUnprotectMemory."""
    return hkdfSha256(master32, salt, KINF2024_INFO_STORAGE, 32)


def kinf2024EntryKey(storageIkm, keytext):
    return hkdfSha256(storageIkm, SHA1(keytext.encode('latin1')), KINF2024_INFO_ENTRY, 32)


def aesGcmDecrypt(key, blob):
    """nonce(12) || ciphertext || tag(16) -> plaintext, or b'' if the tag fails."""
    if len(blob) < 28:
        return b''
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=blob[:12])
        return cipher.decrypt_and_verify(blob[12:-16], blob[-16:])
    except (ValueError, KeyError, IndexError):
        return b''


# the master key last recovered from main_shared.blob, so --dump-master can save it
_kinf2024MasterKey = None


def kinf2024MasterKey():
    return _kinf2024MasterKey

# Routines unique to Mac and PC
def getDBfromFile2024(kInfoFile, master32=None, saltFile=None, blobFile=None,
                     volumeSerial=None):
    """Kindle for PC 1.36+ .kinf2024 -> {name: plaintext}.

    Everything here except the NCrypt unwrap is pure computation, so master32 (the
    32-byte storage master key, as hex) can be supplied with -m and the .kinf2024 file
    can then be decrypted on any machine that has the key.  Without -m it needs Windows
    plus main_shared.blob next to the .kinf2024 file (or given with -b).
    """
    with open(kInfoFile, 'rb') as fh:
        data = fh.read()
    recs = kinf2024Records(data)

    # The F3/F2 keys come from the device's volume serial, not from the file.  Prefer an
    # explicit serial, else recover them from the records, else fall back to the reference
    # device's 467/2 (which is only right for serial 236943134).
    keys = None
    if volumeSerial is not None:
        keys = obfKeysFromVolumeSerial(volumeSerial)
    if keys is None:
        keys = kinf2024RecoverKeys(recs)
    if keys is None:
        keys = obfKeysFromDwKey(KINF2024_DWKEY)
        print('.kinf2024: could not recover the ObfuscatorV1 keys from the records; using the '
              'reference-device dwF3_key=%d. Pass the volume serial if this is another machine.'
              % KINF2024_DWKEY)

    storagedir = os.path.dirname(kInfoFile) or '.'
    if saltFile is None:
        saltFile = os.path.join(storagedir, 'main_shared.salt')
    if blobFile is None:
        blobFile = os.path.join(storagedir, 'main_shared.blob')

    if not os.path.isfile(saltFile):
        print('Cannot find main_shared.salt (looked in ' + storagedir + ', or pass -s)')
        return {}
    with open(saltFile, 'rb') as fh:
        salt = fh.read()

    key = None
    how = None
    if master32:
        try:
            key = bytes.fromhex(str(master32).replace('0x', '').replace(':', '').replace(' ', ''))
        except ValueError:
            print('-m expects a hexadecimal master key (supplied content suppressed)')
            return {}
        if len(key) != 32:
            print('-m expects 32 bytes (64 hex digits), got %d bytes' % len(key))
            return {}
        how = 'supplied with -m'
    else:
        if not iswindows:
            print('Unwrapping main_shared.blob needs Windows; pass the master key with -m.')
            return {}
        if not os.path.isfile(blobFile):
            print('Cannot find main_shared.blob (looked in ' + storagedir + ', or pass -b)')
            return {}
        with open(blobFile, 'rb') as fh:
            blob = fh.read()
        key = NCryptUnwrapMasterKey(blob)
        if key is None:
            print('Could not unwrap main_shared.blob with the CNG key %r.' % KINDLE_CNG_KEY_NAME)
            print('If Kindle is not installed for this user, pass the master key with -m.')
            return {}
        how = 'unwrapped from ' + os.path.basename(blobFile)

    ikm = kinf2024StorageIkm(key, salt)
    namehashmap = {encodeHash(n, KINF2024_MAP): n for n in KINF2024_NAMES}
    DB = {}
    for rec in recs:
        try:
            keytext, valtext = kinf2024DecodeRecord(rec, keys)
        except (DrmException, ValueError, IndexError):
            continue
        vb = decode(valtext.encode('latin1'), KINF2024_MAP)
        # the GCM tag is the test: only the right master key yields any plaintext
        pt = aesGcmDecrypt(kinf2024EntryKey(ikm, keytext), vb)
        if not pt:
            continue
        DB[namehashmap.get(keytext.encode('latin1'), keytext.encode('latin1'))] = pt

    if not DB:
        if volumeSerial is not None:
            print('No .kinf2024 entry passed its GCM tag. The volume serial given with -V '
                  '(%s) does not match this container -- drop -V and let the keys be recovered.'
                  % volumeSerial)
        else:
            print('No .kinf2024 entry passed its GCM tag - wrong master key or salt.')
        return {}
    global _kinf2024MasterKey
    _kinf2024MasterKey = key
    print('Decrypted .kinf2024: %d of %d entries, master key %s, ObfuscatorV1 dwF3_key=%d '
          'dwF2_key=%d' % (len(DB), len(recs), how, keys['dwF3Key'], keys['dwF2Key']))
    if iswindows:
        # The MSIX client ID lives in LocalState/registration_data, not in
        # .kinf2024. The DPAPI blob is decryptable under the registered user's
        # Windows account, without loading or patching the Kindle runtime.
        if b'DSN' not in DB:
            try:
                try:
                    from msix_registration import recover_registration_dsn
                except ImportError:
                    from .msix_registration import recover_registration_dsn
                registration_dsn = recover_registration_dsn(kInfoFile)
                if registration_dsn:
                    DB[b'DSN'] = registration_dsn
                    print('MSIX Kindle DSN recovered from registration_data (content suppressed)')
                else:
                    print('MSIX Kindle DSN unavailable from registration_data')
            except Exception as e:
                print('MSIX registration lookup failed: {}'.format(type(e).__name__))
        DB[b'IDString'] = GetIDString().encode('utf-8')
        DB[b'UserName'] = GetUserName()
    return DB

if iswindows:
    from ctypes import windll, c_char_p, c_wchar_p, c_uint, POINTER, byref, \
        create_unicode_buffer, create_string_buffer, CFUNCTYPE, addressof, \
        string_at, Structure, c_void_p, cast

    try:
        import winreg
    except ImportError:
        import _winreg as winreg

    MAX_PATH = 255
    kernel32 = windll.kernel32
    advapi32 = windll.advapi32
    crypt32 = windll.crypt32

    # Various character maps used to decrypt kindle info values.
    # Probably supposed to act as obfuscation
    charMap2 = b"AaZzB0bYyCc1XxDdW2wEeVv3FfUuG4g-TtHh5SsIiR6rJjQq7KkPpL8lOoMm9Nn_"
    charMap5 = b"AzB0bYyCeVvaZ3FfUuG4g-TtHh5SsIiR6rJjQq7KkPpL8lOoMm9Nn_c1XxDdW2wE"
    # New maps in K4PC 1.9.0
    testMap1 = b"n5Pr6St7Uv8Wx9YzAb0Cd1Ef2Gh3Jk4M"
    testMap6 = b"9YzAb0Cd1Ef2n5Pr6St7Uvh3Jk4M8WxG"
    testMap8 = b"YvaZ3FfUm9Nn_c1XuG4yCAzB0beVg-TtHh5SsIiR6rJjQdW2wEq7KkPpL8lOoMxD"

    # interface with Windows OS Routines
    class DataBlob(Structure):
        _fields_ = [('cbData', c_uint),
                    ('pbData', c_void_p)]
    DataBlob_p = POINTER(DataBlob)


    def GetSystemDirectory():
        GetSystemDirectoryW = kernel32.GetSystemDirectoryW
        GetSystemDirectoryW.argtypes = [c_wchar_p, c_uint]
        GetSystemDirectoryW.restype = c_uint
        def GetSystemDirectory():
            buffer = create_unicode_buffer(MAX_PATH + 1)
            GetSystemDirectoryW(buffer, len(buffer))
            return buffer.value
        return GetSystemDirectory
    GetSystemDirectory = GetSystemDirectory()

    def GetVolumeSerialNumber():
        GetVolumeInformationW = kernel32.GetVolumeInformationW
        GetVolumeInformationW.argtypes = [c_wchar_p, c_wchar_p, c_uint,
                                          POINTER(c_uint), POINTER(c_uint),
                                          POINTER(c_uint), c_wchar_p, c_uint]
        GetVolumeInformationW.restype = c_uint
        def GetVolumeSerialNumber(path = GetSystemDirectory().split('\\')[0] + '\\'):
            vsn = c_uint(0)
            GetVolumeInformationW(path, None, 0, byref(vsn), None, None, None, 0)
            return str(vsn.value)
        return GetVolumeSerialNumber
    GetVolumeSerialNumber = GetVolumeSerialNumber()

    def GetIDString():
        vsn = GetVolumeSerialNumber()
        # Volume serial is device-specific; never print it in the plugin log.
        return vsn

    def getLastError():
        GetLastError = kernel32.GetLastError
        GetLastError.argtypes = None
        GetLastError.restype = c_uint
        def getLastError():
            return GetLastError()
        return getLastError
    getLastError = getLastError()

    def GetUserName():
        GetUserNameW = advapi32.GetUserNameW
        GetUserNameW.argtypes = [c_wchar_p, POINTER(c_uint)]
        GetUserNameW.restype = c_uint
        def GetUserName():
            buffer = create_unicode_buffer(2)
            size = c_uint(len(buffer))
            while not GetUserNameW(buffer, byref(size)):
                errcd = getLastError()
                if errcd == 234:
                    # bad wine implementation up through wine 1.3.21
                    return "AlternateUserName"
                # double the buffer size
                buffer = create_unicode_buffer(len(buffer) * 2)
                size.value = len(buffer)

            # replace any non-ASCII values with 0xfffd
            for i in range(0,len(buffer)):
                if sys.version_info[0] == 2:
                    if buffer[i]>u"\u007f":
                        #print "swapping char "+str(i)+" ("+buffer[i]+")"
                        buffer[i] = u"\ufffd"
                else: 
                    if buffer[i]>"\u007f":
                        #print "swapping char "+str(i)+" ("+buffer[i]+")"
                        buffer[i] = "\ufffd"
            # return utf-8 encoding of modified username
            #print "modified username:"+buffer.value
            return buffer.value.encode('utf-8')
        return GetUserName
    GetUserName = GetUserName()

    def CryptUnprotectData():
        _CryptUnprotectData = crypt32.CryptUnprotectData
        _CryptUnprotectData.argtypes = [DataBlob_p, c_wchar_p, DataBlob_p,
                                       c_void_p, c_void_p, c_uint, DataBlob_p]
        _CryptUnprotectData.restype = c_uint
        def CryptUnprotectData(indata, entropy, flags):
            indatab = create_string_buffer(indata)
            indata = DataBlob(len(indata), cast(indatab, c_void_p))
            entropyb = create_string_buffer(entropy)
            entropy = DataBlob(len(entropy), cast(entropyb, c_void_p))
            outdata = DataBlob()
            if not _CryptUnprotectData(byref(indata), None, byref(entropy),
                                       None, None, flags, byref(outdata)):
                # raise DrmException("Failed to Unprotect Data")
                return b'failed'
            return string_at(outdata.pbData, outdata.cbData)
        return CryptUnprotectData
    CryptUnprotectData = CryptUnprotectData()

    # ------------------------------------------------------------------ NCrypt
    # In MSIX 1.36+ the storage master key is not DPAPI-protected.  <storage>\main_shared.blob
    # is a 256-byte RSA-2048 ciphertext, unwrapped by the persisted CNG key
    # "KindleForPC_SS" This is a direct port of the decrypt_blob() reference
    # implementation that unwraps the real key.
    #
    # Two things there are easy to get "right" and still be wrong, so they are copied
    # exactly: the padding info is the BCRYPT_ struct handed straight to pPaddingInfo
    # rather than wrapped in an NCRYPT_OAEP_PADDING_INFO, and dwFlags is 4 rather than
    # NCRYPT_PAD_OAEP_FLAG.  That is what the binary passes and what the provider accepts.
    # The provider name the binary uses is decrypted at runtime and so cannot be read out
    # of the image; MS_PLATFORM_CRYPTO_PROVIDER is the one that holds the key (it is a TPM
    # key), with the software provider tried as a fallback for a non-TPM copy.
    ncrypt = windll.ncrypt

    NCRYPT_DECRYPT_FLAGS = 4
    BCRYPT_SHA256_ALGORITHM = u'SHA256'
    MS_PLATFORM_CRYPTO_PROVIDER = u'Microsoft Platform Crypto Provider'
    MS_SOFTWARE_KEY_STORAGE_PROVIDER = u'Microsoft Software Key Storage Provider'
    KINDLE_CNG_KEY_NAME = u'KindleForPC_SS'
    NTE_BAD_KEYSET = 0x80090016

    class BCRYPT_OAEP_PADDING_INFO(Structure):
        _fields_ = [('pszAlgId', c_wchar_p),
                    ('pbLabel', c_void_p),
                    ('cbLabel', c_uint)]

    def NCryptUnwrapMasterKey(blob, keyname=KINDLE_CNG_KEY_NAME):
        """Unwrap main_shared.blob into the 32-byte storage master key, or None."""
        _open_provider = ncrypt.NCryptOpenStorageProvider
        _open_provider.argtypes = [POINTER(c_void_p), c_wchar_p, c_uint]
        _open_provider.restype = c_uint
        _open_key = ncrypt.NCryptOpenKey
        _open_key.argtypes = [c_void_p, POINTER(c_void_p), c_wchar_p, c_uint, c_uint]
        _open_key.restype = c_uint
        _decrypt = ncrypt.NCryptDecrypt
        _decrypt.argtypes = [c_void_p, c_char_p, c_uint, c_void_p, c_void_p, c_uint,
                             POINTER(c_uint), c_uint]
        _decrypt.restype = c_uint
        _free = ncrypt.NCryptFreeObject
        _free.argtypes = [c_void_p]
        _free.restype = c_uint

        for provider in (MS_PLATFORM_CRYPTO_PROVIDER, MS_SOFTWARE_KEY_STORAGE_PROVIDER):
            hProvider = c_void_p(0)
            status = _open_provider(byref(hProvider), provider, 0)
            if status != 0:
                print('NCryptOpenStorageProvider(%s) failed: 0x%08x' % (provider, status))
                continue
            try:
                hKey = c_void_p(0)
                status = _open_key(hProvider, byref(hKey), keyname, 0, 0)
                if status != 0:
                    if status == NTE_BAD_KEYSET:
                        print('The CNG key %r does not exist for this user' % keyname)
                    else:
                        print('NCryptOpenKey(%s) failed: 0x%08x' % (keyname, status))
                    continue
                try:
                    oaep = BCRYPT_OAEP_PADDING_INFO(BCRYPT_SHA256_ALGORITHM, None, 0)
                    out = create_string_buffer(len(blob))
                    cbres = c_uint(0)
                    status = _decrypt(hKey, blob, len(blob), byref(oaep),
                                      cast(out, c_void_p), len(out), byref(cbres),
                                      NCRYPT_DECRYPT_FLAGS)
                    if status != 0:
                        print('NCryptDecrypt via %s failed: 0x%08x' % (provider, status))
                        continue
                    raw = string_at(out, cbres.value)
                    # the unwrap leaves the 32-byte key followed by zero padding
                    if len(raw) >= 32:
                        print('CNG storage master unwrapped (content suppressed)')
                        return raw[:32]
                    print('NCryptDecrypt returned only %d bytes' % len(raw))
                finally:
                    _free(hKey)
            finally:
                _free(hProvider)
        return None

    # Returns Environmental Variables that contain unicode
    # name must be unicode string, not byte string.
    def getEnvironmentVariable(name):
        import ctypes
        n = ctypes.windll.kernel32.GetEnvironmentVariableW(name, None, 0)
        if n == 0:
            return None
        buf = ctypes.create_unicode_buffer("\0"*n)
        ctypes.windll.kernel32.GetEnvironmentVariableW(name, buf, n)
        return buf.value

    # Locate all of the kindle-info style files and return as list
    def getKindleInfoFiles():
        kInfoFiles = []
        # some 64 bit machines do not have the proper registry key for some reason
        # or the python interface to the 32 vs 64 bit registry is broken
        path = ""
        if 'LOCALAPPDATA' in os.environ.keys():
            # Python 2.x does not return unicode env. Use Python 3.x
            if sys.version_info[0] == 2:
                path = winreg.ExpandEnvironmentStrings(u"%LOCALAPPDATA%")
            else:
                path = winreg.ExpandEnvironmentStrings("%LOCALAPPDATA%")
            # this is just another alternative.
            # path = getEnvironmentVariable('LOCALAPPDATA')
            if not os.path.isdir(path):
                path = ""
        else:
            # User Shell Folders show take precedent over Shell Folders if present
            try:
                # this will still break
                regkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\")
                path = winreg.QueryValueEx(regkey, 'Local AppData')[0]
                if not os.path.isdir(path):
                    path = ""
                    try:
                        regkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\")
                        path = winreg.QueryValueEx(regkey, 'Local AppData')[0]
                        if not os.path.isdir(path):
                            path = ""
                    except RegError:
                        pass
            except RegError:
                pass

        found = False
        if path == "":
            print ('Could not find the folder in which to look for kinfoFiles.')
        else:
            # Probably not the best. To Fix (shouldn't ignore in encoding) or use utf-8
            print("searching for kinfoFiles in " + path)

            # look for (K4PC 1.25.1 and later) .kinf2018 file
            kinfopath = path +'\\Amazon\\Kindle\\storage\\.kinf2018'
            if os.path.isfile(kinfopath):
                found = True
                print('Found K4PC 1.25+ kinf2018 file: ' + kinfopath)
                kInfoFiles.append(kinfopath)
            kinfodir = path +'\\Packages\\AMZNKindle.AmazonKindleReadingApp_m1sc522ngdk36\\LocalState\\Classic\\Data\\storage\\'
            if os.path.isdir(kinfodir):
              kinfopath =kinfodir+".kinf2024"
              if os.path.isfile(kinfopath):
                  found = True
                  print('Found MSIX K4PC kinf2024 file: ' + kinfopath)
                  kInfoFiles.append(kinfopath)
            
            # look for (K4PC 1.9.0 and later) .kinf2011 file
            kinfopath = path +'\\Amazon\\Kindle\\storage\\.kinf2011'
            if os.path.isfile(kinfopath):
                found = True
                print('Found K4PC 1.9+ kinf2011 file: ' + kinfopath)
                kInfoFiles.append(kinfopath)

            # look for (K4PC 1.6.0 and later) rainier.2.1.1.kinf file
            kinfopath = path +'\\Amazon\\Kindle\\storage\\rainier.2.1.1.kinf'
            if os.path.isfile(kinfopath):
                found = True
                print('Found K4PC 1.6-1.8 kinf file: ' + kinfopath)
                kInfoFiles.append(kinfopath)

            # look for (K4PC 1.5.0 and later) rainier.2.1.1.kinf file
            kinfopath = path +'\\Amazon\\Kindle For PC\\storage\\rainier.2.1.1.kinf'
            if os.path.isfile(kinfopath):
                found = True
                print('Found K4PC 1.5 kinf file: ' + kinfopath)
                kInfoFiles.append(kinfopath)

           # look for original (earlier than K4PC 1.5.0) kindle-info files
            kinfopath = path +'\\Amazon\\Kindle For PC\\{AMAwzsaPaaZAzmZzZQzgZCAkZ3AjA_AY}\\kindle.info'
            if os.path.isfile(kinfopath):
                found = True
                print('Found K4PC kindle.info file: ' + kinfopath)
                kInfoFiles.append(kinfopath)

        if not found:
            print('No K4PC kindle.info/kinf/kinf2011 files have been found.')
        return kInfoFiles


    # determine type of kindle info provided and return a
    # database of keynames and values
    def getDBfromFile(kInfoFile, master32=None, saltFile=None, blobFile=None, volumeSerial=None):
        if isKinf2024(kInfoFile):
            return getDBfromFile2024(kInfoFile, master32, saltFile, blobFile, volumeSerial)
        names = [\
            b'kindle.account.tokens',\
            b'kindle.cookie.item',\
            b'eulaVersionAccepted',\
            b'login_date',\
            b'kindle.token.item',\
            b'login',\
            b'kindle.key.item',\
            b'kindle.name.info',\
            b'kindle.device.info',\
            b'MazamaRandomNumber',\
            b'max_date',\
            b'SIGVERIF',\
            b'build_version',\
            b'SerialNumber',\
            b'UsernameHash',\
            b'kindle.directedid.info',\
            b'DSN',\
            b'kindle.accounttype.info',\
            b'krx.flashcardsplugin.data.encryption_key',\
            b'krx.notebookexportplugin.data.encryption_key',\
            b'proxy.http.password',\
            b'proxy.http.username'
            ]
        namehashmap = {encodeHash(n,testMap8):n for n in names}
        # print(namehashmap)
        DB = {}
        with open(kInfoFile, 'rb') as infoReader:
            data = infoReader.read()
        # assume .kinf2011 or .kinf2018 style .kinf file
        # the .kinf file uses "/" to separate it into records
        # so remove the trailing "/" to make it easy to use split
        data = data[:-1]
        items = data.split(b'/')

        # starts with an encoded and encrypted header blob
        headerblob = items.pop(0)
        encryptedValue = decode(headerblob, testMap1)
        cleartext = UnprotectHeaderData(encryptedValue)
        #print "header  cleartext:",cleartext
        # now extract the pieces that form the added entropy
        pattern = re.compile(br'''\[Version:(\d+)\]\[Build:(\d+)\]\[Cksum:([^\]]+)\]\[Guid:([\{\}a-z0-9\-]+)\]''', re.IGNORECASE)
        for m in re.finditer(pattern, cleartext):
            version = int(m.group(1))
            build = m.group(2)
            guid = m.group(4)

        if version == 5:  # .kinf2011
            added_entropy = build + guid
        elif version == 6:  # .kinf2018
            salt = str(0x6d8 * int(build)).encode('utf-8') + guid
            sp = GetUserName() + b'+@#$%+' + GetIDString().encode('utf-8')
            passwd = encode(SHA256(sp), charMap5)
            key = PBKDF2(passwd, salt, count=10000, dkLen=0x400)[:32]  # this is very slow

        # loop through the item records until all are processed
        while len(items) > 0:

            # get the first item record
            item = items.pop(0)

            # the first 32 chars of the first record of a group
            # is the MD5 hash of the key name encoded by charMap5
            keyhash = item[0:32]

            # the remainder of the first record when decoded with charMap5
            # has the ':' split char followed by the string representation
            # of the number of records that follow
            # and make up the contents
            srcnt = decode(item[34:],charMap5)
            rcnt = int(srcnt)

            # read and store in rcnt records of data
            # that make up the contents value
            edlst = []
            for i in range(rcnt):
                item = items.pop(0)
                edlst.append(item)

            # key names now use the new testMap8 encoding
            if keyhash in namehashmap:
                keyname=namehashmap[keyhash]
                #print "keyname found from hash:",keyname
            else:
                keyname = keyhash
                #print "keyname not found, hash is:",keyname

            # the testMap8 encoded contents data has had a length
            # of chars (always odd) cut off of the front and moved
            # to the end to prevent decoding using testMap8 from
            # working properly, and thereby preventing the ensuing
            # CryptUnprotectData call from succeeding.

            # The offset into the testMap8 encoded contents seems to be:
            # len(contents)-largest prime number <=  int(len(content)/3)
            # (in other words split "about" 2/3rds of the way through)

            # move first offsets chars to end to align for decode by testMap8
            # by moving noffset chars from the start of the
            # string to the end of the string
            encdata = b"".join(edlst)
            #print "encrypted data:",encdata
            contlen = len(encdata)
            noffset = contlen - primes(int(contlen/3))[-1]
            pfx = encdata[0:noffset]
            encdata = encdata[noffset:]
            encdata = encdata + pfx
            #print "rearranged data:",encdata

            if version == 5:
                # decode using new testMap8 to get the original CryptProtect Data
                encryptedValue = decode(encdata,testMap8)
                #print "decoded data:",encryptedValue.encode('hex')
                entropy = SHA1(keyhash) + added_entropy
                cleartext = CryptUnprotectData(encryptedValue, entropy, 1)
            elif version == 6:
                # decode using new testMap8 to get IV + ciphertext
                iv_ciphertext = decode(encdata, testMap8)
                # pad IV so that we can substitute AES-CTR for GCM
                iv = iv_ciphertext[:12] + b'\x00\x00\x00\x02'
                ciphertext = iv_ciphertext[12:]
                # convert IV to int for use with pycrypto
                iv_ints = unpack('>QQ', iv)
                iv = iv_ints[0] << 64 | iv_ints[1]
                # set up AES-CTR
                ctr = Counter.new(128, initial_value=iv)
                cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
                # decrypt and decode
                cleartext = decode(cipher.decrypt(ciphertext), charMap5)

            if len(cleartext)>0:
                #print "cleartext data:",cleartext,":end data"
                DB[keyname] = cleartext
            #print keyname, cleartext

        if len(DB)>6:
            # store values used in decryption
            DB[b'IDString'] = GetIDString().encode('utf-8')
            DB[b'UserName'] = GetUserName()
            print("Decrypted key file using IDString '{0:s}' and UserName '{1:s}'".format(GetIDString(), GetUserName().decode('utf-8')))
        else:
            print("Couldn't decrypt file.")
            DB = {}
        return DB
elif isosx:
    import subprocess

    # Various character maps used to decrypt books. Probably supposed to act as obfuscation
    charMap1 = b'n5Pr6St7Uv8Wx9YzAb0Cd1Ef2Gh3Jk4M'
    charMap2 = b'ZB0bYyc1xDdW2wEV3Ff7KkPpL8UuGA4gz-Tme9Nn_tHh5SvXCsIiR6rJjQaqlOoM'

    # For kinf approach of K4Mac 1.6.X or later
    # On K4PC charMap5 = 'AzB0bYyCeVvaZ3FfUuG4g-TtHh5SsIiR6rJjQq7KkPpL8lOoMm9Nn_c1XxDdW2wE'
    # For Mac they seem to re-use charMap2 here
    charMap5 = charMap2

    # new in K4M 1.9.X
    testMap8 = b'YvaZ3FfUm9Nn_c1XuG4yCAzB0beVg-TtHh5SsIiR6rJjQdW2wEq7KkPpL8lOoMxD'

    # uses a sub process to get the Hard Drive Serial Number using ioreg
    # returns serial numbers of all internal hard drive drives
    def GetVolumesSerialNumbers():
        sernums = []
        sernum = os.getenv('MYSERIALNUMBER')
        if sernum != None:
            sernums.append(sernum.strip())
        cmdline = '/usr/sbin/ioreg -w 0 -r -c AppleAHCIDiskDriver'
        cmdline = cmdline.encode(sys.getfilesystemencoding())
        p = subprocess.Popen(cmdline, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=False)
        out1, out2 = p.communicate()
        #print out1
        reslst = out1.split(b'\n')
        cnt = len(reslst)
        for j in range(cnt):
            resline = reslst[j]
            pp = resline.find(b'\"Serial Number\" = \"')
            if pp >= 0:
                sernum = resline[pp+19:-1]
                sernums.append(sernum.strip())
        return sernums

    def GetDiskPartitionNames():
        names = []
        cmdline = '/sbin/mount'
        cmdline = cmdline.encode(sys.getfilesystemencoding())
        p = subprocess.Popen(cmdline, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=False)
        out1, out2 = p.communicate()
        reslst = out1.split(b'\n')
        cnt = len(reslst)
        for j in range(cnt):
            resline = reslst[j]
            if resline.startswith(b'/dev'):
                (devpart, mpath) = resline.split(b' on ')[:2]
                dpart = devpart[5:]
                names.append(dpart)
        return names

    # uses a sub process to get the UUID of all disk partitions
    def GetDiskPartitionUUIDs():
        uuids = []
        uuidnum = os.getenv('MYUUIDNUMBER')
        if uuidnum != None:
            uuids.append(uuidnum.strip())
        cmdline = '/usr/sbin/ioreg -l -S -w 0 -r -c AppleAHCIDiskDriver'
        cmdline = cmdline.encode(sys.getfilesystemencoding())
        p = subprocess.Popen(cmdline, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=False)
        out1, out2 = p.communicate()
        #print out1
        reslst = out1.split(b'\n')
        cnt = len(reslst)
        for j in range(cnt):
            resline = reslst[j]
            pp = resline.find(b'\"UUID\" = \"')
            if pp >= 0:
                uuidnum = resline[pp+10:-1]
                uuidnum = uuidnum.strip()
                uuids.append(uuidnum)
        return uuids

    def GetMACAddressesMunged():
        macnums = []
        macnum = os.getenv('MYMACNUM')
        if macnum != None:
            macnums.append(macnum)
        cmdline = 'networksetup -listallhardwareports' # en0'
        cmdline = cmdline.encode(sys.getfilesystemencoding())
        p = subprocess.Popen(cmdline, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=False)
        out1, out2 = p.communicate()
        reslst = out1.split(b'\n')
        cnt = len(reslst)
        for j in range(cnt):
            resline = reslst[j]
            pp = resline.find(b'Ethernet Address: ')
            if pp >= 0:
                #print resline
                macnum = resline[pp+18:]
                macnum = macnum.strip()
                maclst = macnum.split(b':')
                n = len(maclst)
                if n != 6:
                    continue
                #print 'original mac', macnum
                # now munge it up the way Kindle app does
                # by xoring it with 0xa5 and swapping elements 3 and 4
                for i in range(6):
                    maclst[i] = int(b'0x' + maclst[i], 0)
                mlst = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
                mlst[5] = maclst[5] ^ 0xa5
                mlst[4] = maclst[3] ^ 0xa5
                mlst[3] = maclst[4] ^ 0xa5
                mlst[2] = maclst[2] ^ 0xa5
                mlst[1] = maclst[1] ^ 0xa5
                mlst[0] = maclst[0] ^ 0xa5
                macnum = b'%0.2x%0.2x%0.2x%0.2x%0.2x%0.2x' % (mlst[0], mlst[1], mlst[2], mlst[3], mlst[4], mlst[5])
                #print 'munged mac', macnum
                macnums.append(macnum)
        return macnums


    # uses unix env to get username instead of using sysctlbyname
    def GetUserName():
        username = os.getenv('USER')
        #print "Username:",username
        return username.encode('utf-8')

    def GetIDStrings():
        # Return all possible ID Strings
        strings = []
        strings.extend(GetMACAddressesMunged())
        strings.extend(GetVolumesSerialNumbers())
        strings.extend(GetDiskPartitionNames())
        strings.extend(GetDiskPartitionUUIDs())
        strings.append(b'9999999999')
        #print "ID Strings:\n",strings
        return strings

    # implements an Pseudo Mac Version of Windows built-in Crypto routine
    class CryptUnprotectData(object):
        def __init__(self, entropy, IDString):
            sp = GetUserName() + b'+@#$%+' + IDString
            passwdData = encode(SHA256(sp),charMap2)
            salt = entropy
            key_iv = PBKDF2(passwdData, salt, count=0x800, dkLen=0x400)
            self.key = key_iv[0:32]
            self.iv = key_iv[32:48]
            self.crp.set_decrypt_key(self.key, self.iv)

        def decrypt(self, encryptedData):
            cleartext = self.crp.decrypt(encryptedData)
            cleartext = decode(cleartext, charMap2)
            return cleartext


    # Locate the .kindle-info files
    def getKindleInfoFiles():
        # file searches can take a long time on some systems, so just look in known specific places.
        kInfoFiles=[]
        found = False
        home = os.getenv('HOME')
        # check for  .kinf2018 file in new location (App Store Kindle for Mac)
        testpath = home + '/Library/Containers/com.amazon.Kindle/Data/Library/Application Support/Kindle/storage/.kinf2018'
        if os.path.isfile(testpath):
            kInfoFiles.append(testpath)
            print('Found k4Mac kinf2018 file: ' + testpath)
            found = True
        # check for  .kinf2018 files
        testpath = home + '/Library/Application Support/Kindle/storage/.kinf2018'
        if os.path.isfile(testpath):
            kInfoFiles.append(testpath)
            print('Found k4Mac kinf2018 file: ' + testpath)
            found = True
        # check for  .kinf2011 file in new location (App Store Kindle for Mac)
        testpath = home + '/Library/Containers/com.amazon.Kindle/Data/Library/Application Support/Kindle/storage/.kinf2011'
        if os.path.isfile(testpath):
            kInfoFiles.append(testpath)
            print('Found k4Mac kinf2011 file: ' + testpath)
            found = True
        # check for  .kinf2011 files from 1.10
        testpath = home + '/Library/Application Support/Kindle/storage/.kinf2011'
        if os.path.isfile(testpath):
            kInfoFiles.append(testpath)
            print('Found k4Mac kinf2011 file: ' + testpath)
            found = True
        # check for  .rainier-2.1.1-kinf files from 1.6
        testpath = home + '/Library/Application Support/Kindle/storage/.rainier-2.1.1-kinf'
        if os.path.isfile(testpath):
            kInfoFiles.append(testpath)
            print('Found k4Mac rainier file: ' + testpath)
            found = True
        # check for  .kindle-info files from 1.4
        testpath = home + '/Library/Application Support/Kindle/storage/.kindle-info'
        if os.path.isfile(testpath):
            kInfoFiles.append(testpath)
            print('Found k4Mac kindle-info file: ' + testpath)
            found = True
        # check for  .kindle-info file from 1.2.2
        testpath = home + '/Library/Application Support/Amazon/Kindle/storage/.kindle-info'
        if os.path.isfile(testpath):
            kInfoFiles.append(testpath)
            print('Found k4Mac kindle-info file: ' + testpath)
            found = True
        # check for  .kindle-info file from 1.0 beta 1 (27214)
        testpath = home + '/Library/Application Support/Amazon/Kindle for Mac/storage/.kindle-info'
        if os.path.isfile(testpath):
            kInfoFiles.append(testpath)
            print('Found k4Mac kindle-info file: ' + testpath)
            found = True
        if not found:
            print('No k4Mac kindle-info/rainier/kinf2011 files have been found.')
        return kInfoFiles

    # determine type of kindle info provided and return a
    # database of keynames and values
    def getDBfromFile(kInfoFile, master32=None, saltFile=None, blobFile=None, volumeSerial=None):
        if isKinf2024(kInfoFile):
            return getDBfromFile2024(kInfoFile, master32, saltFile, blobFile, volumeSerial)
        names = [\
            b'kindle.account.tokens',\
            b'kindle.cookie.item',\
            b'eulaVersionAccepted',\
            b'login_date',\
            b'kindle.token.item',\
            b'login',\
            b'kindle.key.item',\
            b'kindle.name.info',\
            b'kindle.device.info',\
            b'MazamaRandomNumber',\
            b'max_date',\
            b'SIGVERIF',\
            b'build_version',\
            b'SerialNumber',\
            b'UsernameHash',\
            b'kindle.directedid.info',\
            b'DSN',\
            b'kindle.accounttype.info',\
            b'krx.flashcardsplugin.data.encryption_key',\
            b'krx.notebookexportplugin.data.encryption_key',\
            b'proxy.http.password',\
            b'proxy.http.username'
            ]
        with open(kInfoFile, 'rb') as infoReader:
            filedata = infoReader.read()

        data = filedata[:-1]
        items = data.split(b'/')
        IDStrings = GetIDStrings()
        print ("trying username ", GetUserName(), " on file ", kInfoFile)
        for IDString in IDStrings:
            print ("trying IDString:",IDString)
            try:
                DB = {}
                items = data.split(b'/')

                # the headerblob is the encrypted information needed to build the entropy string
                headerblob = items.pop(0)
                #print ("headerblob: ",headerblob)
                encryptedValue = decode(headerblob, charMap1)
                #print ("encryptedvalue: ",encryptedValue)
                cleartext = UnprotectHeaderData(encryptedValue)
                #print ("cleartext: ",cleartext)

                # now extract the pieces in the same way
                pattern = re.compile(br'''\[Version:(\d+)\]\[Build:(\d+)\]\[Cksum:([^\]]+)\]\[Guid:([\{\}a-z0-9\-]+)\]''', re.IGNORECASE)
                for m in re.finditer(pattern, cleartext):
                    version = int(m.group(1))
                    build = m.group(2)
                    guid = m.group(4)

                #print ("version",version)
                #print ("build",build)
                #print ("guid",guid,"\n")

                if version == 5:  # .kinf2011: identical to K4PC, except the build number gets multiplied
                    entropy = str(0x2df * int(build)).encode('utf-8') + guid
                    cud = CryptUnprotectData(entropy,IDString)
                    #print ("entropy",entropy)
                    #print ("cud",cud)

                elif version == 6:  # .kinf2018: identical to K4PC
                    salt = str(0x6d8 * int(build)).encode('utf-8') + guid
                    sp = GetUserName() + b'+@#$%+' + IDString
                    passwd = encode(SHA256(sp), charMap5)
                    key = PBKDF2(passwd, salt, count=10000, dkLen=0x400)[:32]

                    #print ("salt",salt)
                    #print ("sp",sp)
                    #print ("passwd",passwd)
                    #print ("key",key)

               # loop through the item records until all are processed
                while len(items) > 0:

                    # get the first item record
                    item = items.pop(0)

                    # the first 32 chars of the first record of a group
                    # is the MD5 hash of the key name encoded by charMap5
                    keyhash = item[0:32]
                    keyname = b'unknown'

                    # unlike K4PC the keyhash is not used in generating entropy
                    # entropy = SHA1(keyhash) + added_entropy
                    # entropy = added_entropy

                    # the remainder of the first record when decoded with charMap5
                    # has the ':' split char followed by the string representation
                    # of the number of records that follow
                    # and make up the contents
                    srcnt = decode(item[34:],charMap5)
                    rcnt = int(srcnt)

                    # read and store in rcnt records of data
                    # that make up the contents value
                    edlst = []
                    for i in range(rcnt):
                        item = items.pop(0)
                        edlst.append(item)

                    keyname = b'unknown'
                    for name in names:
                        if encodeHash(name,testMap8) == keyhash:
                            keyname = name
                            break
                    if keyname == b'unknown':
                        keyname = keyhash

                    # the testMap8 encoded contents data has had a length
                    # of chars (always odd) cut off of the front and moved
                    # to the end to prevent decoding using testMap8 from
                    # working properly, and thereby preventing the ensuing
                    # CryptUnprotectData call from succeeding.

                    # The offset into the testMap8 encoded contents seems to be:
                    # len(contents) - largest prime number less than or equal to int(len(content)/3)
                    # (in other words split 'about' 2/3rds of the way through)

                    # move first offsets chars to end to align for decode by testMap8
                    encdata = b''.join(edlst)
                    contlen = len(encdata)

                    # now properly split and recombine
                    # by moving noffset chars from the start of the
                    # string to the end of the string
                    noffset = contlen - primes(int(contlen/3))[-1]
                    pfx = encdata[0:noffset]
                    encdata = encdata[noffset:]
                    encdata = encdata + pfx

                    if version == 5:
                        # decode using testMap8 to get the CryptProtect Data
                        encryptedValue = decode(encdata,testMap8)
                        cleartext = cud.decrypt(encryptedValue)

                    elif version == 6:
                        # decode using new testMap8 to get IV + ciphertext
                        iv_ciphertext = decode(encdata, testMap8)
                        # pad IV so that we can substitute AES-CTR for GCM
                        iv = iv_ciphertext[:12] + b'\x00\x00\x00\x02'
                        ciphertext = iv_ciphertext[12:]
                        # convert IV to int for use with pycrypto
                        iv_ints = unpack('>QQ', iv)
                        iv = iv_ints[0] << 64 | iv_ints[1]
                        # set up AES-CTR
                        ctr = Counter.new(128, initial_value=iv)
                        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
                        # decrypt and decode
                        cleartext = decode(cipher.decrypt(ciphertext), charMap5)

                    # print keyname
                    # print cleartext
                    if len(cleartext) > 0:
                        DB[keyname] = cleartext

                if len(DB)>6:
                    break

            except Exception:
                print (traceback.format_exc())
                pass
        if len(DB)>6:
            # store values used in decryption
            print("Decrypted key file using IDString '{0:s}' and UserName '{1:s}'".format(IDString.decode('utf-8'), GetUserName().decode('utf-8')))
            DB[b'IDString'] = IDString
            DB[b'UserName'] = GetUserName()
        else:
            print("Couldn't decrypt file.")
            DB = {}
        return DB
else:
    def getDBfromFile(kInfoFile, master32=None, saltFile=None, blobFile=None, volumeSerial=None):
        if isKinf2024(kInfoFile):
            return getDBfromFile2024(kInfoFile, master32, saltFile, blobFile, volumeSerial)
        raise DrmException("This script only runs under Windows or Mac OS X.")
        return {}

def kindlekeys(files = [], master32=None, saltFile=None, blobFile=None, volumeSerial=None):
    keys = []
    if files == []:
        files = getKindleInfoFiles()
    for file in files:
        key = getDBfromFile(file, master32, saltFile, blobFile, volumeSerial)
        if key:
            # convert all values to hex, just in case.
            n_key = {}
            for k,v in key.items():
                n_key[k.decode()]=codecs.encode(v, 'hex_codec').decode()
            # key = {k.decode():v.decode() for k,v in key.items()}
            keys.append(n_key)
    return keys


# The e-ink firmware keeps its account secret in /var/local/java/prefs/acsr, which is not
# exported over the USB mount, so a jailbroken device's copy under de-drm-secrets is read.
KINDLE_DEVICE_SETTING_DIRS = ('de-drm-secrets', os.path.join('documents', 'de-drm-secrets'))
"""
from calibre.devices.interface import currently_connected_device
from calibre.devices.mtp.driver import MTP_DEVICE
if isinstance(currently_connected_device.device, MTP_DEVICE):
    mtp_device: MTP_DEVICE = currently_connected_device.device
    books = mtp_device.books()
    # do whatever else
"""
try:
  from calibre.devices.interface import currently_connected_device
  from calibre.devices.mtp.driver import MTP_DEVICE
  mtp_loaded=True
except:
  mtp_loaded=False
  
def _listdir(path):
    """os.listdir for an optional path: an absent or unreadable one yields nothing."""
    try:
        return os.listdir(path)
    except OSError:
        return []
#def get_potential_device():
#  from calibre.devices.scanner import DeviceScanner
def get_potential_kindle_roots(book_root):
    """Since there was no actual scan, but just enumeration of all possible disks, I decided to "simplify" it to this """
    candidates=["../","../..","../../.."]
    return [path for path in candidates if os.path.isfile(os.path.join(book_root,path, 'system', 'version.txt'))]

from io import BytesIO
def scan_for_name(nm,book_root):
  if not mtp_loaded:
    print("MTP driver not loaded")
  else:
    print("Currently connected device.device: {}".format(currently_connected_device.device))
  if mtp_loaded and isinstance(currently_connected_device.device, MTP_DEVICE):
    mtp_device = currently_connected_device.device
    print("MTP device found {}".format(mtp_device))
    pths = [('de-drm-secrets',nm),('documents','de-drm-secrets',nm)]
    try: 
      storages = mtp_device.filesystem_cache.entries
    except:
      print("No MTP storages found")
      storages=[]
    # unwalkable storage isn't fatal: the mounted-filesystem search below is the
    # fallback, so the try spans the walk
    try:
      for storage in storages:
        for pth in pths:
          file_id=storage.find_path(pth)
          if file_id is not None:
            data = BytesIO()
            mtp_device.get_mtp_file(file_id, data)
            return data.getvalue()
    except Exception as ex:
      print("MTP device-secret lookup failed: {0}: {1}".format(type(ex).__name__, ex))
  candidates=["../","../..","../../.."]
  try:
    from calibre.constants import config_dir
  except:
    print("No calibre.constants.config_dir?")
    config_dir="."
  candidates.append(os.path.join(config_dir,"plugins"))

  for pos in candidates:
    for dirname in KINDLE_DEVICE_SETTING_DIRS:
      pth=os.path.join(book_root,pos,dirname,nm)
      #print("scanning {}".format(pth))
      if os.path.isfile(pth):
        with open(pth, 'rb') as fh:
          return fh.read().strip()


def get_device_setting(name,book_root):
    """Read one device DRM setting from a mounted Kindle, or return None."""
    return scan_for_name(name, book_root)


# interface for Python DeDRM
# returns single key or multiple keys, depending on path or file passed in
def getkey(outpath, files=[], master32=None, saltFile=None, blobFile=None, dumpMaster=None,
             volumeSerial=None):
    keys = kindlekeys(files, master32, saltFile, blobFile, volumeSerial)
    if dumpMaster and kinf2024MasterKey():
        try:
            with open(dumpMaster, 'wb') as f:
                f.write(kinf2024MasterKey().hex().encode('ascii') + b'\n')
            print('Saved the .kinf2024 storage master key to ' + dumpMaster)
            print('Recover it later with:  kindlekey.py -m "$(cat ' + dumpMaster + ')" ...')
        except (IOError, OSError) as e:
            print('Could not write ' + dumpMaster + ': ' + str(e))
    if len(keys) > 0:
        if not os.path.isdir(outpath):
            outfile = outpath
            with open(outfile, 'w') as keyfileout:
                keyfileout.write(json.dumps(keys[0]))
            print("Saved a key to {0}".format(outfile))
        else:
            keycount = 0
            for key in keys:
                while True:
                    keycount += 1
                    outfile = os.path.join(outpath,"kindlekey{0:d}.k4i".format(keycount))
                    if not os.path.exists(outfile):
                        break
                with open(outfile, 'w') as keyfileout:
                    keyfileout.write(json.dumps(key))
                print("Saved a key to {0}".format(outfile))
        return True
    return False

def usage(progname):
    print("Finds, decrypts and saves the default Kindle For Mac/PC encryption keys.")
    print("Keys are saved to the current directory, or a specified output directory.")
    print("If a file name is passed instead of a directory, only the first key is saved, in that file.")
    print("Usage:")
    print("    {0:s} [-h] [-k <kindle.info>] [-m hex] [-s salt] [-b blob] [-V serial] [--dump-master f] [<outpath>]".format(progname))
    print("Options for Kindle for PC 1.36+ (.kinf2024):")
    print("  -m HEX | --master-key HEX   32-byte storage master key as 64 hex digits. Skips the")
    print("                              NCrypt unwrap of main_shared.blob, so the .kinf2024 file")
    print("                              can be decrypted on any machine that has the key.")
    print("  -s FILE | --salt-file FILE  main_shared.salt (default: alongside the .kinf2024 file).")
    print("  -b FILE | --blob-file FILE  main_shared.blob (default: alongside the .kinf2024 file).")
    print("  -V N | --volume-serial N    Volume serial number, in DECIMAL, of the volume holding")
    print("                              the Kindle storage root. ObfuscatorV1 derives its F3/F2")
    print("                              keys from it: s = the serial as a decimal string,")
    print("                              dwF3_key = sum of the bytes of s, dwF2_key = dwF3_key mod 5.")
    print("                              Only needed for a container from another machine; otherwise")
    print("                              the keys are recovered from the records. To read it back:")
    print("                              PowerShell (Get-Volume -DriveLetter C).SerialNumber")
    print("  --dump-master FILE          Write the master key recovered from main_shared.blob to")
    print("                              FILE so later runs can use -m without the CNG key.")


def cli_main():
    sys.stdout=SafeUnbuffered(sys.stdout)
    sys.stderr=SafeUnbuffered(sys.stderr)
    argv=unicode_argv("kindlekey.py")
    progname = os.path.basename(argv[0])
    print("{0} v{1}\nCopyright © 2010-2020 by some_updates, Apprentice Harper et al.".format(progname,__version__))

    try:
        opts, args = getopt.getopt(argv[1:], "hk:m:s:b:V:",
                                   ["master-key=", "salt-file=", "blob-file=", "dump-master=", "volume-serial="])
    except getopt.GetoptError as err:
        print("Error in options or arguments: {0}".format(err.args[0]))
        usage(progname)
        sys.exit(2)

    files = []
    master32 = saltFile = blobFile = dumpMaster = volumeSerial = None
    for o, a in opts:
        if o == "-h":
            usage(progname)
            sys.exit(0)
        if o == "-k":
            files = [a]
        if o in ("-m", "--master-key"):
            master32 = a
        if o in ("-s", "--salt-file"):
            saltFile = a
        if o in ("-b", "--blob-file"):
            blobFile = a
        if o == "--dump-master":
            dumpMaster = a
        if o in ("-V", "--volume-serial"):
            volumeSerial = a

    if len(args) > 1:
        usage(progname)
        sys.exit(2)

    if len(args) == 1:
        # save to the specified file or directory
        outpath = args[0]
        if not os.path.isabs(outpath):
           outpath = os.path.abspath(outpath)
    else:
        # save to the same directory as the script
        outpath = os.path.dirname(argv[0])

    # make sure the outpath is canonical
    outpath = os.path.realpath(os.path.normpath(outpath))

    if not getkey(outpath, files, master32, saltFile, blobFile, dumpMaster, volumeSerial):
        print("Could not retrieve Kindle for Mac/PC key.")
    return 0


def gui_main():
    try:
        import tkinter
        import tkinter.constants
        import tkinter.messagebox
        import traceback
    except:
        return cli_main()

    class ExceptionDialog(tkinter.Frame):
        def __init__(self, root, text):
            tkinter.Frame.__init__(self, root, border=5)
            label = tkinter.Label(self, text="Unexpected error:",
                                  anchor=tkinter.constants.W, justify=tkinter.constants.LEFT)
            label.pack(fill=tkinter.constants.X, expand=0)
            self.text = tkinter.Text(self)
            self.text.pack(fill=tkinter.constants.BOTH, expand=1)

            self.text.insert(tkinter.constants.END, text)


    argv=unicode_argv("kindlekey.py")
    root = tkinter.Tk()
    root.withdraw()
    progpath, progname = os.path.split(argv[0])
    success = False
    try:
        keys = kindlekeys()
        keycount = 0
        for key in keys:
            while True:
                keycount += 1
                outfile = os.path.join(progpath,"kindlekey{0:d}.k4i".format(keycount))
                if not os.path.exists(outfile):
                    break

            with open(outfile, 'w') as keyfileout:
                keyfileout.write(json.dumps(key))
            success = True
            tkinter.messagebox.showinfo(progname, "Key successfully retrieved to {0}".format(outfile))
    except DrmException as e:
        tkinter.messagebox.showerror(progname, "Error: {0}".format(str(e)))
    except Exception:
        root.wm_state('normal')
        root.title(progname)
        text = traceback.format_exc()
        ExceptionDialog(root, text).pack(fill=tkinter.constants.BOTH, expand=1)
        root.mainloop()
    if not success:
        return 1
    return 0

if __name__ == '__main__':
    if len(sys.argv) > 1:
        sys.exit(cli_main())
    sys.exit(gui_main())
