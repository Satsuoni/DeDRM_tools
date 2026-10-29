#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""ion.py: Decrypt Kindle KFX files.

Revision history:
  Pascal implementation by lulzkabulz.
  BinaryIon.pas + DrmIon.pas + IonSymbols.pas
  1.0   - Python translation by apprenticenaomi.
  1.1   - DeDRM integration by anon.
  1.2   - Added pylzma import fallback
  1.3   - Fixed lzma support for calibre 4.6+
  2.0   - VoucherEnvelope v2/v3 support by apprenticesakuya.
  3.0   - Added Python 3 compatibility for calibre 5.0

Copyright © 2013-2020 Apprentice Harper et al.
"""

import collections
import base64
import hashlib
import hmac
import os
import os.path
import re
import struct

from io import BytesIO

__license__ = 'GPL v3'
__version__ = '3.0'

#@@CALIBRE_COMPAT_CODE@@


try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.py3compat import bchr
except ImportError:
    from Crypto.Cipher import AES
    from Crypto.Util.py3compat import bchr

try:
    # lzma library from calibre 4.6.0 or later
    import calibre_lzma.lzma1 as calibre_lzma
except ImportError:
    calibre_lzma = None
    # lzma library from calibre 2.35.0 or later
    try:
        import lzma.lzma1 as calibre_lzma
    except ImportError:
        calibre_lzma = None
        try:
            import lzma
        except ImportError:
            # Need pip backports.lzma on Python <3.3
            try:
                from backports import lzma
            except ImportError:
                # Windows-friendly choice: pylzma wheels
                import pylzma as lzma
try:
 from .kfxtables import *
except:
 from kfxtables import *


def _stream_value(stream):
    """The bytes a one-shot stream holds, or None when there is no stream.

    Snapshot at construction: the parser walks the same stream, so this is the last moment the
    bytes can be read.
    """
    getter = getattr(stream, 'getvalue', None)
    if getter is None:
        return None
    try:
        return bytes(getter())
    except Exception:  # noqa: BLE001 - an unreadable stream simply disables the fallback
        return None


def _operand_text(value):
    if isinstance(value, bytes):
        try:
            return value.decode('ASCII')
        except Exception:
            return None
    if isinstance(value, str):
        return value or None
    return None

TID_NULL = 0
TID_BOOLEAN = 1
TID_POSINT = 2
TID_NEGINT = 3
TID_FLOAT = 4
TID_DECIMAL = 5
TID_TIMESTAMP = 6
TID_SYMBOL = 7
TID_STRING = 8
TID_CLOB = 9
TID_BLOB = 0xA
TID_LIST = 0xB
TID_SEXP = 0xC
TID_STRUCT = 0xD
TID_TYPEDECL = 0xE
TID_UNUSED = 0xF


SID_UNKNOWN = -1
SID_ION = 1
SID_ION_1_0 = 2
SID_ION_SYMBOL_TABLE = 3
SID_NAME = 4
SID_VERSION = 5
SID_IMPORTS = 6
SID_SYMBOLS = 7
SID_MAX_ID = 8
SID_ION_SHARED_SYMBOL_TABLE = 9
SID_ION_1_0_MAX = 10


LEN_IS_VAR_LEN = 0xE
LEN_IS_NULL = 0xF


VERSION_MARKER = [b"\x01", b"\x00", b"\xEA"]


# asserts must always raise exceptions for proper functioning
def _assert(test, msg="Exception"):
    if not test:
        raise Exception(msg)


class SystemSymbols(object):
    ION = '$ion'
    ION_1_0 = '$ion_1_0'
    ION_SYMBOL_TABLE = '$ion_symbol_table'
    NAME = 'name'
    VERSION = 'version'
    IMPORTS = 'imports'
    SYMBOLS = 'symbols'
    MAX_ID = 'max_id'
    ION_SHARED_SYMBOL_TABLE = '$ion_shared_symbol_table'


class IonCatalogItem(object):
    name = ""
    version = 0
    symnames = []

    def __init__(self, name, version, symnames):
        self.name = name
        self.version = version
        self.symnames = symnames


class SymbolToken(object):
    text = ""
    sid = 0

    def __init__(self, text, sid):
        if text == "" and sid == 0:
            raise ValueError("Symbol token must have Text or SID")

        self.text = text
        self.sid = sid


class SymbolTable(object):
    table = None

    def __init__(self):
        self.table = [None] * SID_ION_1_0_MAX
        self.table[SID_ION] = SystemSymbols.ION
        self.table[SID_ION_1_0] = SystemSymbols.ION_1_0
        self.table[SID_ION_SYMBOL_TABLE] = SystemSymbols.ION_SYMBOL_TABLE
        self.table[SID_NAME] = SystemSymbols.NAME
        self.table[SID_VERSION] = SystemSymbols.VERSION
        self.table[SID_IMPORTS] = SystemSymbols.IMPORTS
        self.table[SID_SYMBOLS] = SystemSymbols.SYMBOLS
        self.table[SID_MAX_ID] = SystemSymbols.MAX_ID
        self.table[SID_ION_SHARED_SYMBOL_TABLE] = SystemSymbols.ION_SHARED_SYMBOL_TABLE

    def findbyid(self, sid):
        if sid < 1:
            raise ValueError("Invalid symbol id")

        if sid < len(self.table):
            return self.table[sid]
        else:
            return ""

    def import_(self, table, maxid):
        for i in range(maxid):
            self.table.append(table.symnames[i])

    def importunknown(self, name, maxid):
        for i in range(maxid):
            self.table.append("%s#%d" % (name, i + 1))


class ParserState:
    Invalid,BeforeField,BeforeTID,BeforeValue,AfterValue,EOF = 1,2,3,4,5,6

ContainerRec = collections.namedtuple("ContainerRec", "nextpos, tid, remaining")


class BinaryIonParser(object):
    eof = False
    state = None
    localremaining = 0
    needhasnext = False
    isinstruct = False
    valuetid = 0
    valuefieldid = 0
    parenttid = 0
    valuelen = 0
    valueisnull = False
    valueistrue = False
    value = None
    didimports = False

    def __init__(self, stream):
        self.annotations = []
        self.catalog = []

        self.stream = stream
        self.initpos = stream.tell()
        self.reset()
        self.symbols = SymbolTable()

    def reset(self):
        self.state = ParserState.BeforeTID
        self.needhasnext = True
        self.localremaining = -1
        self.eof = False
        self.isinstruct = False
        self.containerstack = []
        self.stream.seek(self.initpos)

    def addtocatalog(self, name, version, symbols):
        self.catalog.append(IonCatalogItem(name, version, symbols))

    def hasnext(self):
        while self.needhasnext and not self.eof:
            self.hasnextraw()
            if len(self.containerstack) == 0 and not self.valueisnull:
                if self.valuetid == TID_SYMBOL:
                    if self.value == SID_ION_1_0:
                        self.needhasnext = True
                elif self.valuetid == TID_STRUCT:
                    for a in self.annotations:
                        if a == SID_ION_SYMBOL_TABLE:
                            self.parsesymboltable()
                            self.needhasnext = True
                            break
        return not self.eof

    def hasnextraw(self):
        self.clearvalue()
        while self.valuetid == -1 and not self.eof:
            self.needhasnext = False
            if self.state == ParserState.BeforeField:
                _assert(self.valuefieldid == SID_UNKNOWN)

                self.valuefieldid = self.readfieldid()
                if self.valuefieldid != SID_UNKNOWN:
                    self.state = ParserState.BeforeTID
                else:
                    self.eof = True

            elif self.state == ParserState.BeforeTID:
                self.state = ParserState.BeforeValue
                self.valuetid = self.readtypeid()
                if self.valuetid == -1:
                    self.state = ParserState.EOF
                    self.eof = True
                    break

                if self.valuetid == TID_TYPEDECL:
                    if self.valuelen == 0:
                        self.checkversionmarker()
                    else:
                        self.loadannotations()

            elif self.state == ParserState.BeforeValue:
                self.skip(self.valuelen)
                self.state = ParserState.AfterValue

            elif self.state == ParserState.AfterValue:
                if self.isinstruct:
                    self.state = ParserState.BeforeField
                else:
                    self.state = ParserState.BeforeTID

            else:
                _assert(self.state == ParserState.EOF)

    def next(self):
        if self.hasnext():
            self.needhasnext = True
            return self.valuetid
        else:
            return -1

    def push(self, typeid, nextposition, nextremaining):
        self.containerstack.append(ContainerRec(nextpos=nextposition, tid=typeid, remaining=nextremaining))

    def stepin(self):
        _assert(self.valuetid in [TID_STRUCT, TID_LIST, TID_SEXP] and not self.eof,
                "valuetid=%s eof=%s" % (self.valuetid, self.eof))
        _assert((not self.valueisnull or self.state == ParserState.AfterValue) and
               (self.valueisnull or self.state == ParserState.BeforeValue))

        nextrem = self.localremaining
        if nextrem != -1:
            nextrem -= self.valuelen
            if nextrem < 0:
                nextrem = 0
        self.push(self.parenttid, self.stream.tell() + self.valuelen, nextrem)

        self.isinstruct = (self.valuetid == TID_STRUCT)
        if self.isinstruct:
            self.state = ParserState.BeforeField
        else:
            self.state = ParserState.BeforeTID

        self.localremaining = self.valuelen
        self.parenttid = self.valuetid
        self.clearvalue()
        self.needhasnext = True

    def stepout(self):
        rec = self.containerstack.pop()

        self.eof = False
        self.parenttid = rec.tid
        if self.parenttid == TID_STRUCT:
            self.isinstruct = True
            self.state = ParserState.BeforeField
        else:
            self.isinstruct = False
            self.state = ParserState.BeforeTID
        self.needhasnext = True

        self.clearvalue()
        curpos = self.stream.tell()
        if rec.nextpos > curpos:
            self.skip(rec.nextpos - curpos)
        else:
            _assert(rec.nextpos == curpos)

        self.localremaining = rec.remaining

    def read(self, count=1):
        if self.localremaining != -1:
            self.localremaining -= count
            _assert(self.localremaining >= 0)

        result = self.stream.read(count)
        if len(result) == 0:
            raise EOFError()
        return result

    def readfieldid(self):
        if self.localremaining != -1 and self.localremaining < 1:
            return -1

        try:
            return self.readvaruint()
        except EOFError:
            return -1

    def readtypeid(self):
        if self.localremaining != -1:
            if self.localremaining < 1:
                return -1
            self.localremaining -= 1

        b = self.stream.read(1)
        if len(b) < 1:
            return -1
        b = ord(b)
        result = b >> 4
        ln = b & 0xF

        if ln == LEN_IS_VAR_LEN:
            ln = self.readvaruint()
        elif ln == LEN_IS_NULL:
            ln = 0
            self.state = ParserState.AfterValue
        elif result == TID_NULL:
            # Must have LEN_IS_NULL
            _assert(False)
        elif result == TID_BOOLEAN:
            _assert(ln <= 1)
            self.valueistrue = (ln == 1)
            ln = 0
            self.state = ParserState.AfterValue
        elif result == TID_STRUCT:
            if ln == 1:
                ln = self.readvaruint()

        self.valuelen = ln
        return result

    def readvarint(self):
        b = ord(self.read())
        negative = ((b & 0x40) != 0)
        result = (b & 0x3F)

        i = 0
        while (b & 0x80) == 0 and i < 4:
            b = ord(self.read())
            result = (result << 7) | (b & 0x7F)
            i += 1

        _assert(i < 4 or (b & 0x80) != 0, "int overflow")

        if negative:
            return -result
        return result

    def readvaruint(self):
        b = ord(self.read())
        result = (b & 0x7F)

        i = 0
        while (b & 0x80) == 0 and i < 4:
            b = ord(self.read())
            result = (result << 7) | (b & 0x7F)
            i += 1

        _assert(i < 4 or (b & 0x80) != 0, "int overflow")

        return result

    def readdecimal(self):
        if self.valuelen == 0:
            return 0.

        rem = self.localremaining - self.valuelen
        self.localremaining = self.valuelen
        exponent = self.readvarint()

        _assert(self.localremaining > 0, "Only exponent in ReadDecimal")
        _assert(self.localremaining <= 8, "Decimal overflow")

        signed = False
        b = [ord(x) for x in self.read(self.localremaining)]
        if (b[0] & 0x80) != 0:
            b[0] = b[0] & 0x7F
            signed = True

        # Convert variably sized network order integer into 64-bit little endian
        j = 0
        vb = [0] * 8
        for i in range(len(b), -1, -1):
            vb[i] = b[j]
            j += 1

        v = struct.unpack("<Q", b"".join(bchr(x) for x in vb))[0]

        result = v * (10 ** exponent)
        if signed:
            result = -result

        self.localremaining = rem
        return result

    def skip(self, count):
        if self.localremaining != -1:
            self.localremaining -= count
            if self.localremaining < 0:
                raise EOFError()

        self.stream.seek(count, os.SEEK_CUR)

    def parsesymboltable(self):
        self.next() # shouldn't do anything?

        _assert(self.valuetid == TID_STRUCT)

        if self.didimports:
            return

        self.stepin()

        fieldtype = self.next()
        while fieldtype != -1:
            if not self.valueisnull:
                _assert(self.valuefieldid == SID_IMPORTS, "Unsupported symbol table field id")

                if fieldtype == TID_LIST:
                    self.gatherimports()

            fieldtype = self.next()

        self.stepout()
        self.didimports = True

    def gatherimports(self):
        self.stepin()

        t = self.next()
        while t != -1:
            if not self.valueisnull and t == TID_STRUCT:
                self.readimport()

            t = self.next()

        self.stepout()

    def readimport(self):
        version = -1
        maxid = -1
        name = ""

        self.stepin()

        t = self.next()
        while t != -1:
            if not self.valueisnull and self.valuefieldid != SID_UNKNOWN:
                if self.valuefieldid == SID_NAME:
                    name = self.stringvalue()
                elif self.valuefieldid == SID_VERSION:
                    version = self.intvalue()
                elif self.valuefieldid == SID_MAX_ID:
                    maxid = self.intvalue()

            t = self.next()

        self.stepout()

        if name == "" or name == SystemSymbols.ION:
            return

        if version < 1:
            version = 1

        table = self.findcatalogitem(name)
        if maxid < 0:
            _assert(table is not None and version == table.version, "Import %s lacks maxid" % name)
            maxid = len(table.symnames)

        if table is not None:
            self.symbols.import_(table, min(maxid, len(table.symnames)))
            if len(table.symnames) < maxid:
                self.symbols.importunknown(name + "-unknown", maxid - len(table.symnames))
        else:
            self.symbols.importunknown(name, maxid)

    def intvalue(self):
        _assert(self.valuetid in [TID_POSINT, TID_NEGINT], "Not an int")

        self.preparevalue()
        return self.value

    def stringvalue(self):
        _assert(self.valuetid == TID_STRING, "Not a string")

        if self.valueisnull:
            return ""

        self.preparevalue()
        return self.value

    def symbolvalue(self):
        _assert(self.valuetid == TID_SYMBOL, "Not a symbol")

        self.preparevalue()
        result = self.symbols.findbyid(self.value)
        if result == "":
            result = "SYMBOL#%d" % self.value
        return result

    def lobvalue(self):
        _assert(self.valuetid in [TID_CLOB, TID_BLOB], "Not a LOB type: %s" % self.getfieldname())

        if self.valueisnull:
            return None

        result = self.read(self.valuelen)
        self.state = ParserState.AfterValue
        return result

    def decimalvalue(self):
        _assert(self.valuetid == TID_DECIMAL, "Not a decimal")

        self.preparevalue()
        return self.value

    def preparevalue(self):
        if self.value is None:
            self.loadscalarvalue()

    def loadscalarvalue(self):
        if self.valuetid not in [TID_NULL, TID_BOOLEAN, TID_POSINT, TID_NEGINT,
                                 TID_FLOAT, TID_DECIMAL, TID_TIMESTAMP,
                                 TID_SYMBOL, TID_STRING]:
            return

        if self.valueisnull:
            self.value = None
            return

        if self.valuetid == TID_STRING:
            self.value = self.read(self.valuelen).decode("UTF-8")

        elif self.valuetid in (TID_POSINT, TID_NEGINT, TID_SYMBOL):
            if self.valuelen == 0:
                self.value = 0
            else:
                _assert(self.valuelen <= 4, "int too long: %d" % self.valuelen)
                v = 0
                for i in range(self.valuelen - 1, -1, -1):
                    v = (v | (ord(self.read()) << (i * 8)))

                if self.valuetid == TID_NEGINT:
                    self.value = -v
                else:
                    self.value = v

        elif self.valuetid == TID_DECIMAL:
            self.value = self.readdecimal()

        #else:
        #    _assert(False, "Unhandled scalar type %d" % self.valuetid)

        self.state = ParserState.AfterValue

    def clearvalue(self):
        self.valuetid = -1
        self.value = None
        self.valueisnull = False
        self.valuefieldid = SID_UNKNOWN
        self.annotations = []

    def loadannotations(self):
        ln = self.readvaruint()
        maxpos = self.stream.tell() + ln
        while self.stream.tell() < maxpos:
            self.annotations.append(self.readvaruint())
        self.valuetid = self.readtypeid()

    def checkversionmarker(self):
        for i in VERSION_MARKER:
            _assert(self.read() == i, "Unknown version marker")

        self.valuelen = 0
        self.valuetid = TID_SYMBOL
        self.value = SID_ION_1_0
        self.valueisnull = False
        self.valuefieldid = SID_UNKNOWN
        self.state = ParserState.AfterValue

    def findcatalogitem(self, name):
        for result in self.catalog:
            if result.name == name:
                return result

    def forceimport(self, symbols):
        item = IonCatalogItem("Forced", 1, symbols)
        self.symbols.import_(item, len(symbols))

    def getfieldname(self):
        if self.valuefieldid == SID_UNKNOWN:
            return ""
        return self.symbols.findbyid(self.valuefieldid)

    def getfieldnamesymbol(self):
        return SymbolToken(self.getfieldname(), self.valuefieldid)

    def gettypename(self):
        if len(self.annotations) == 0:
            return ""

        return self.symbols.findbyid(self.annotations[0])

    @staticmethod
    def printlob(b):
        if b is None:
            return "null"

        result = ""
        for i in b:
            result += ("%02x " % ord(i))

        if len(result) > 0:
            result = result[:-1]
        return result

    def ionwalk(self, supert, indent, lst):
        while self.hasnext():
            if supert == TID_STRUCT:
                L = self.getfieldname() + ":"
            else:
                L = ""

            t = self.next()
            if t in [TID_STRUCT, TID_LIST]:
                if L != "":
                    lst.append(indent + L)
                L = self.gettypename()
                if L != "":
                    lst.append(indent + L + "::")
                if t == TID_STRUCT:
                    lst.append(indent + "{")
                else:
                    lst.append(indent + "[")

                self.stepin()
                self.ionwalk(t, indent + "  ", lst)
                self.stepout()

                if t == TID_STRUCT:
                    lst.append(indent + "}")
                else:
                    lst.append(indent + "]")

            else:
                if t == TID_STRING:
                    L += ('"%s"' % self.stringvalue())
                elif t in [TID_CLOB, TID_BLOB]:
                    L += ("{%s}" % self.printlob(self.lobvalue()))
                elif t == TID_POSINT:
                    L += str(self.intvalue())
                elif t == TID_SYMBOL:
                    tn = self.gettypename()
                    if tn != "":
                        tn += "::"
                    L += tn + self.symbolvalue()
                elif t == TID_DECIMAL:
                    L += str(self.decimalvalue())
                else:
                    L += ("TID %d" % t)
                lst.append(indent + L)

    def print_(self, lst):
        self.reset()
        self.ionwalk(-1, "", lst)


SYM_NAMES = [ 'com.amazon.drm.Envelope@1.0',
              'com.amazon.drm.EnvelopeMetadata@1.0', 'size', 'page_size',
              'encryption_key', 'encryption_transformation',
              'encryption_voucher', 'signing_key', 'signing_algorithm',
              'signing_voucher', 'com.amazon.drm.EncryptedPage@1.0',
              'cipher_text', 'cipher_iv', 'com.amazon.drm.Signature@1.0',
              'data', 'com.amazon.drm.EnvelopeIndexTable@1.0', 'length',
              'offset', 'algorithm', 'encoded', 'encryption_algorithm',
              'hashing_algorithm', 'expires', 'format', 'id',
              'lock_parameters', 'strategy', 'com.amazon.drm.Key@1.0',
              'com.amazon.drm.KeySet@1.0', 'com.amazon.drm.PIDv3@1.0',
              'com.amazon.drm.PlainTextPage@1.0',
              'com.amazon.drm.PlainText@1.0', 'com.amazon.drm.PrivateKey@1.0',
              'com.amazon.drm.PublicKey@1.0', 'com.amazon.drm.SecretKey@1.0',
              'com.amazon.drm.Voucher@1.0', 'public_key', 'private_key',
              'com.amazon.drm.KeyPair@1.0', 'com.amazon.drm.ProtectedData@1.0',
              'doctype', 'com.amazon.drm.EnvelopeIndexTableOffset@1.0',
              'enddoc', 'license_type', 'license', 'watermark', 'key', 'value',
              'com.amazon.drm.License@1.0', 'category', 'metadata',
              'categorized_metadata', 'com.amazon.drm.CategorizedMetadata@1.0',
              'com.amazon.drm.VoucherEnvelope@1.0', 'mac', 'voucher',
              'com.amazon.drm.ProtectedData@2.0',
              'com.amazon.drm.Envelope@2.0',
              'com.amazon.drm.EnvelopeMetadata@2.0',
              'com.amazon.drm.EncryptedPage@2.0',
              'com.amazon.drm.PlainText@2.0', 'compression_algorithm',
              'com.amazon.drm.Compressed@1.0', 'page_index_table',
              ] + ['com.amazon.drm.VoucherEnvelope@%d.0' % n
                   for n in list(range(2, 29)) + [
                                   9708, 1031, 2069, 9041, 3646,
                                   6052, 9479, 9888, 4648, 5683,7384,2746,3332]+list(range(10001,11111))] #this assumes there are no new types added aside from voucher envelopes. So far it was largely correct
                                   


def addprottable(ion):
    ion.addtocatalog("ProtectedData", 1, SYM_NAMES)


def pkcs7pad(msg, blocklen):
    paddinglen = blocklen - len(msg) % blocklen
    padding = bchr(paddinglen) * paddinglen
    return msg + padding


def pkcs7unpad(msg, blocklen):
    _assert(len(msg) % blocklen == 0)

    paddinglen = msg[-1]

    _assert(paddinglen > 0 and paddinglen <= blocklen, "Incorrect padding - Wrong key")
    _assert(msg[-paddinglen:] == bchr(paddinglen) * paddinglen, "Incorrect padding - Wrong key")

    return msg[:-paddinglen]





# The versions below all come from one table, but "every version has a word" is wrong: it covers
# 2..28, 9708, 1031, 2069, 9041, 3646, 6052, 9479, 9888, 4648 and 5683 only.  There is no entry for
# 10001 and up -- or for 7384, 2746 and 3332 -- so a voucher version absent from this table gets no
# obfuscation at all.  See tools/kindle-re/README.md for the emulated lookup that shows this.
OBFUSCATION_TABLE = {
    "V1":    (0x00, None),
    "V2":    (0x05, b'Antidisestablishmentarianism'),
    "V3":    (0x08, b'Floccinaucinihilipilification'),
    "V4":    (0x07, b'>\x14\x0c\x12\x10-\x13&\x18U\x1d\x05Rlt\x03!\x19\x1b\x13\x04]Y\x19,\t\x1b'),
    "V5":    (0x06, b'~\x18~\x16J\\\x18\x10\x05\x0b\x07\t\x0cZ\r|\x1c\x15\x1d\x11>,\x1b\x0e\x03"4\x1b\x01'),
    "V6":    (0x09, b'3h\x055\x03[^>\x19\x1c\x08\x1b\rtm4\x02Rp\x0c\x16B\n'),
    "V7":    (0x05, b'\x10\x1bJ\x18\nh!\x10"\x03>Z\'\r\x01]W\x06\x1c\x1e?\x0f\x13'),
    "V8":    (0x09, b"K\x0c6\x1d\x1a\x17pO}Rk\x1d'w1^\x1f$\x1c{C\x02Q\x06\x1d`"),
    "V9":    (0x05, b'X.\x0eW\x1c*K\x12\x12\t\n\n\x17Wx\x01\x02Yf\x0f\x18\x1bVXPi\x01'),
    "V10":   (0x07, b'z3\n\x039\x12\x13`\x06=v;\x02MTK\x1e%}L\x1c\x1f\x15\x0c\x11\x02\x0c\n8\x17p'),
    "V11":   (0x05, b'L=\nhVm\x07go\n6\x14\x06\x16L\r\x02\x0b\x0c\x1b\x04#p\t'),
    "V12":   (0x06, b';n\x1d\rl\x13\x1c\x13\x16p\x14\x07U\x0c\x1f\x19w\x16\x16\x1d5T'),
    "V13":   (0x07, b'I\x05\t\x08\x03r)\x01$N\x0fr3n\x0b062D\x0f\x13'),
    "V14":   (0x05, b"\x03\x02\x1c9\x19\x15\x15q\x1057\x08\x16\x0cF\x1b.Fw\x01\x12\x03\x13\x02\x17S'hk6"),
    "V15":   (0x0A, b'&,4B\x1dcI\x0bU\x03I\x07\x04\x1c\t\x05c\x07%ws\x0cj\t\x1a\x08\x0f'),
    "V16":   (0x0A, b'\x06\x18`h;b><\x06PqR\x02Zc\x034\n\x16\x1e\x18\x06#e'),
    "V17":   (0x07, b'y\r\x12\x08fw.[\x02\t\n\x13\x11\x0c\x11b\x1e8L\x10(\x13<Jx6c\x0f'),
    "V18":   (0x07, b'I\x0b\x0e;\x19\x1aIa\x10s\x19g\\\x1b\x11!\x18yf\x0f\t\x1d7[bSp\x03'),
    "V19":   (0x05, b'\n6>)N\x02\x188\x016s\x13\x14\x1b\x16jeN\n\x146\x04\x18\x1c\x0c\x19\x1f,\x02]'),
    "V20":   (0x08, b'_\r\x01\x12]\\\x14*\x17i\x14\r\t!\x1e;~hZ\x12jK\x17\x1e*1'),
    "V21":   (0x07, b'e\x1d\x19|\ty\x1di|N\x13\x0e\x04\x1bj<h\x13\x15k\x12\x08=\x1f\x16~\x13l'),
    "V22":   (0x08, b'?\x17yi$k7Pc\tEo\x0c\x07\x07\t\x1f,*i\x12\x0cI0\x10I\x1a?2\x04'),
    "V23":   (0x08, b'\x16+db\x13\x04\x18\rc%\x14\x17\x0f\x13F\x0c[\t9\x1ay\x01\x1eH'),
    "V24":   (0x06, b'|6\\\x1a\r\x10\nP\x07\x0fu\x1f\t;\rr`uv\\~55\x11]N'),
    "V25":   (0x09, b'\x07\x14w\x1e;^y\x01:\x08\x07\x1fr\tU#j\x16\x12\x1eB\x04\x16=\x06fZ\x07\x02\x06'),
    "V26":   (0x06, b'\x03IL\x1e"K\x1f\x0f\x1fp0\x01`X\x02z0`\x03\x0eN\x07'),
    "V27":   (0x07, b'Xk\x10y\x02\x18\x10\x17\x1d,\x0e\x05e\x10\x15"e\x0fh(\x06s\x1c\x08I\x0c\x1b\x0e'),
    "V28":   (0x0A, b'6P\x1bs\x0f\x06V.\x1cM\x14\x02\n\x1b\x07{P0:\x18zaU\x05'),
    "V9708": (0x05, b'\x1diIm\x08a\x17\x1e!am\x1d\x1aQ.\x16!\x06*\x04\x11\t\x06\x04?'),
    "V1031": (0x08, b'Antidisestablishmentarianism'),
    "V2069": (0x07, b'Floccinaucinihilipilification'),
    "V9041": (0x06, b'>\x14\x0c\x12\x10-\x13&\x18U\x1d\x05Rlt\x03!\x19\x1b\x13\x04]Y\x19,\t\x1b'),
    "V3646": (0x09, b'~\x18~\x16J\\\x18\x10\x05\x0b\x07\t\x0cZ\r|\x1c\x15\x1d\x11>,\x1b\x0e\x03"4\x1b\x01'),
    "V6052": (0x05, b'3h\x055\x03[^>\x19\x1c\x08\x1b\rtm4\x02Rp\x0c\x16B\n'),
    "V9479": (0x09, b'\x10\x1bJ\x18\nh!\x10"\x03>Z\'\r\x01]W\x06\x1c\x1e?\x0f\x13'),
    "V9888": (0x05, b"K\x0c6\x1d\x1a\x17pO}Rk\x1d'w1^\x1f$\x1c{C\x02Q\x06\x1d`"),
    "V4648": (0x07, b'X.\x0eW\x1c*K\x12\x12\t\n\n\x17Wx\x01\x02Yf\x0f\x18\x1bVXPi\x01'),
    "V5683": (0x05, b'z3\n\x039\x12\x13`\x06=v;\x02MTK\x1e%}L\x1c\x1f\x15\x0c\x11\x02\x0c\n8\x17p'),
}


#common str:  "PIDv3AESAES/CBC/PKCS5PaddingHmacSHA256"
class workspace(object):
  def __init__(self,initial_list):
    self.work=initial_list
  def shuffle(self,shuflist):
    ll=len(shuflist)
    rt=[]
    for i in range(ll):
      rt.append(self.work[shuflist[i]])
    self.work=rt
  def sbox(self,table,matrix,skplist=[]): #table is list of 4-byte integers
    nwork=[0]*16
    for col in range(4):
      wo=col*4
      toff=col*0x400
      uv=(
        table[toff+self.work[wo]]
        ^table[toff+0x100+self.work[wo+1]]
        ^table[toff+0x200+self.work[wo+2]]
        ^table[toff+0x300+self.work[wo+3]]
      )
      prev=0
      for lane in range(4):
        if lane not in skplist:
          prev=(uv>>(24-8*lane))&0xff
        nwork[wo+lane]=prev
    self.work=nwork
  def exlookup(self,ltable):
    lookoffs=0
    for a in range(len(self.work)):
      self.work[a]=ltable[self.work[a]+lookoffs]
      lookoffs+=0x100
  def mask(self, chunk):
    out=[]
    for a in range(len(chunk)):
      self.work[a]=self.work[a]^chunk[a]
      out.append(self.work[a])
    return out

_V4DIGIT_REPL = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]


def _run_v4digit(st, seed16, t_a, t_y, t_b, skplist, ops):
  ws = workspace(list(seed16))
  out = []
  for sto in range(0, len(st), 16):
    for op in ops:
      if op == "S":
        ws.shuffle(_V4DIGIT_REPL)
      else:
        ws.sbox(t_a if op == "A" else t_b, d0x6a0dab50, skplist)
    ws.exlookup(t_y)
    out += ws.mask(st[sto:sto + 16])
  return bytes(out)


#e9c457a7dae6aa24365e7ef219b934b17ed58ee7d5329343fc3aea7860ed51f9a73de14351c9
#d53efea7fdd0fda3e1e0ebbae87cad0e8f5ef413c471c3ae81f39222a9ec8b8ed582e045918c
#8e6196d754a304c9354e91b5d79f07b048026d31c7373a8691e513f2c802c706742731caa858
#11f7db074b24e560dfa6fae3252b383c3b936e51f6ded570dc936cb1da9f4fc4a97ec686e7d8
#d468aa362b44479282291983243b38197c4b4aa24c2c58e62c76ec4b81e08556ca0c54301664
#d683c8c4e4f46ae45812196f37e218eabce0fae08994f25fabb01d3e569b8bf3866b99d36f57
#925635db434bccd3f4791eb87b89d2dfc7c93be06e794744eb9de58e6d721e696980680ab551
#54c470723f8c105ba0186b6319050869de673ce31a5ec15d4439921d4cd05c5e860cb2a41fea
#705bd4cd8b61d4596ef4ca40774d68e71f1f846c6e94bd23fd26e5c127e0beaa650a50171f1b
#1f5af733423e5104afb9d5594e682ecf839a776257f33747c9beee671c57ab3f84943f69d8fd
_V4DIGIT_SPECS = (
  (9708, [0x11] * 16, d0x6a06ea70, d0x6a072a70, d0x6a073a70, [], "SABS"),
  (1031, OBFUSCATION_TABLE["V16"][1][:16], d0x6a0797c0, d0x6a07d7c0, d0x6a07e7c0, [3], "SABSAB"),
  (2069, OBFUSCATION_TABLE["V17"][1][:16], d0x6a084498, d0x6a088498, d0x6a089498, [2], "ASBBAS"),
  (9041, OBFUSCATION_TABLE["V18"][1][:16], d0x6a08f170, d0x6a093170, d0x6a094170, [1], "BSSAAB"),
  (3646, OBFUSCATION_TABLE["V19"][1][:16], d0x6a099e48, d0x6a09de48, d0x6a09ee48, [2, 3], "SABBSAASB"),
  (6052, OBFUSCATION_TABLE["V20"][1][:16], d0x6a0a4b20, d0x6a0a8b20, d0x6a0a9b20, [1, 3], "SASABSBBA"),
  (9479, OBFUSCATION_TABLE["V21"][1][:16], d0x6a0af7f8, d0x6a0b37f8, d0x6a0b47f8, [1, 2, 3], "AABASBSSB"),
  (9888, OBFUSCATION_TABLE["V22"][1][:16], d0x6a0ba4d0, d0x6a0be4d0, d0x6a0bf4d0, [1, 2], "ABBASSSBA"),
  (4648, OBFUSCATION_TABLE["V23"][1][:16], d0x6a0c51a8, d0x6a0c91a8, d0x6a0ca1a8, [1, 3], "BSBABAASS"),
  (5683, OBFUSCATION_TABLE["V24"][1][:16], d0x6a0cfe80, d0x6a0d3e80, d0x6a0d4e80, [], "BSABABSAS"),
)
_V4DIGIT_FUNCS = []
for _tag, *_spec in _V4DIGIT_SPECS:
  _fn = lambda st, _s=_spec: _run_v4digit(st, *_s)
  globals()["process_V%d" % _tag] = _fn
  _V4DIGIT_FUNCS.append(_fn)


# def a2hex(arr):
#   ax=[]
#   ha="0123456789abcdef"
#   for a in arr:
#     if a<0: a=256+a
#     ax.append(ha[(a>>4)]+ha[a%16])
#   return "".join(ax)
#
# def memhex(adr,sz):
#   emu=EmulatorHelper(currentProgram)
#   arr=emu.readMemory(getAddress(adr),sz)
#   return a2hex(arr)
#




def _obfuscate_common(secret, version, permute_fn, first_half=True):
    if version == 1:  # v1 does not use obfuscation
        return secret
    magic, word = OBFUSCATION_TABLE.get("V%d" % version, (1, b"unknown"))
    # extend secret so that its length is divisible by the magic number
    if len(secret) % magic != 0:
        secret = secret + b'\x00' * (magic - len(secret) % magic)
    digest = hashlib.sha256(word).digest()
    wordhash = digest[:16] if first_half else digest[16:]
    shuffled = permute_fn(bytearray(secret), magic)
    # shuffle secret and xor it with the first half of the word hash
    return bytearray(shuffled[i] ^ wordhash[i % 16] for i in range(len(shuffled)))


def _scramble1(st, magic):
    ret = bytearray(len(st))
    stride = len(st) // magic
    for i, b in enumerate(st):
        ret[i // stride + magic * (i % stride)] = b
    return ret


# obfuscate shared secret according to the VoucherEnvelope version
def obfuscate(secret, version):
    return _obfuscate_common(secret, version, _scramble1, True)


# scramble() and obfuscate2() from https://github.com/andrewc12/DeDRM_tools/commit/d9233d61f00d4484235863969919059f4d0b2057
def scramble(st, magic):
    ret = bytearray(len(st))
    padlen = len(st)
    for counter in range(padlen):
        ivar2 = (padlen // 2) - 2 * (counter % magic) + magic + counter - 1
        ret[ivar2 % padlen] = st[counter]
    return ret


def obfuscate2(secret, version):
    return _obfuscate_common(secret, version, scramble, False)


# scramble3() and obfuscate3() from https://github.com/Satsuoni/DeDRM_tools/commit/da6b6a0c911b6d45fe1b13042b690daebc1cc22f
def scramble3(st, magic):
    padlen = len(st)
    ret = bytearray(padlen)
    divs = padlen // magic
    cntr = 0
    for offset in range(magic - 1 + divs):
        if (offset & 1) == 0:
            r, c, dr, dc = min(offset, divs - 1), max(0, offset - divs + 1), -1, 1
        else:
            r, c, dr, dc = max(0, offset - magic + 1), min(offset, magic - 1), 1, -1
        while 0 <= r < divs and 0 <= c < magic:
            ret[padlen - 1 - cntr] = st[r * magic + c]
            r += dr
            c += dc
            cntr += 1
    return ret


#not sure if the third variant is used anywhere, but it is in Kindle, so I tried to add it
#secret = bytearray(secret)
#print(wordhash.hex())
#print(shuffled)
def obfuscate3(secret, version):
    return _obfuscate_common(secret, version, scramble3, True)


def obfuscate_legacy_xor(secret, version, first_half=True):
    """16-byte repeating SHA-256 pad, not permuted."""
    if not secret or version == 1:
        return secret
    _magic, word = OBFUSCATION_TABLE.get("V%d" % version, (1, None))
    if not word:
        return secret
    digest = hashlib.sha256(word).digest()
    pad = digest[:16] if first_half else digest[16:32]
    return bytes(byte ^ pad[index & 0x0F] for index, byte in enumerate(bytearray(secret)))


PLAINTEXT_TYPES = ("com.amazon.drm.PlainText@1.0", "com.amazon.drm.PlainText@2.0")
PLAINTEXT_SIDS = (0x29, 0x45, 0x46)
KEY_RECORD_TYPES = ("com.amazon.drm.SecretKey@1.0",) + PLAINTEXT_TYPES


def _is_plaintext_node(parser):
    return parser.gettypename() in PLAINTEXT_TYPES or any(
        ann in PLAINTEXT_SIDS for ann in getattr(parser, "annotations", ())
    )


def _extract_key_from_ion_bytes(raw_bytes, strict=False):
    # 16-byte content key out of a KeySet/SecretKey/PlainText@1.0|2.0 Ion stream
    if not raw_bytes or not isinstance(raw_bytes, (bytes, bytearray)):
        return None
    raw_bytes = bytes(raw_bytes)
    if not raw_bytes.startswith(b"\xe0\x01\x00\xea"):
        return None
    try:
        parser = BinaryIonParser(BytesIO(raw_bytes))
        addprottable(parser)
    except Exception:
        return None

    def _walk(in_key_record=False, in_keyset=False, in_secret_key=False):
        found = None
        while parser.hasnext():
            t = parser.next()
            tname = parser.gettypename()
            fname = parser.getfieldname()
            if in_secret_key and strict:
                if fname == "algorithm":
                    _assert(parser.stringvalue() == "AES", "Unknown cipher algorithm: %s" % parser.stringvalue())
                elif fname == "format":
                    _assert(parser.stringvalue() == "RAW", "Unknown key format: %s" % parser.stringvalue())
            is_secret_key = in_secret_key or (tname == "com.amazon.drm.SecretKey@1.0")
            is_key_node = in_key_record or is_secret_key or (tname in KEY_RECORD_TYPES) or _is_plaintext_node(parser)
            is_ks_node = in_keyset or (tname == "com.amazon.drm.KeySet@1.0")
            if t in (TID_BLOB, TID_CLOB):
                blob = parser.lobvalue()
                if not blob:
                    continue
                if blob.startswith(b"\xe0\x01\x00\xea"):
                    nested = _extract_key_from_ion_bytes(blob, strict=strict)
                    if nested is not None:
                        return nested
                if (len(blob) == 16 or (strict and is_key_node)) and (
                    is_key_node or (is_ks_node and fname in ("encoded", "data", "cipher_text"))
                ):
                    if in_secret_key and strict:
                        found = bytes(blob)
                    else:
                        return bytes(blob)
            elif t in (TID_STRUCT, TID_LIST, TID_SEXP):
                parser.stepin()
                sub = _walk(is_key_node, is_ks_node, is_secret_key)
                parser.stepout()
                if sub is not None:
                    return sub
        return found

    if strict:
        return _walk(False, False, False)
    try:
        return _walk(False, False, False)
    except Exception:
        return None

# VoucherEnvelope versions from 10001 on do not derive the voucher key by permuting the
# shared secret string. They hand the lock parameter values to a routine that returns both
# the HMAC key and the message, and for those versions the message is no longer the
# constant b"PIDv3" that the versions below use. The boundary here is the ION symbol range
# this plugin already accepts, not a verified property of every version in it.
NEW_KEY_DERIVATION_VERSIONS = range(10001, 11111)

# A voucher may declare only CLIENT_ID, which is what the 10014 vouchers on Kindles that
# never received an account secret do: that one has a client id to work from, so it is
# attempted with an empty secret rather than skipped. One that declares no lock parameters
# at all is read from its voucher id instead; see obfuscate4_voucher_id().
def needs_new_key_derivation(version, lockparams):
    """Whether this voucher's key comes from the lock parameter values.

    Versions from 10001 on derive the key and the message from those values rather than by
    permuting the shared secret string, but a voucher that declares none of them is derived
    from its voucher id instead, so this is false for it.
    """
    return version in NEW_KEY_DERIVATION_VERSIONS and bool(lockparams)

# The message builder reads the account secret, the client id and these fixed strings as
# one run of bytes, then maps each byte to MESSAGE_MULTIPLIERS[byte % 10] * byte. The key
# builder reads the account secret and the client id alone, with no fixed padding.
MESSAGE_PREFIX = b"hsrevf43is ds_"
MESSAGE_SUFFIX = b"-89kndeh83n303"
MESSAGE_ALPHABET = ".e7G270E7VaO8098SaAm8062wmmAm1SFOMAy"
MESSAGE_MULTIPLIERS = [28, 88, 28, 100, 35, 118, 271, 231, 184, 240,
                       40, 120, 105, 132, 290, 52, 60, 31, 171, 49]

# One of the library builds that arrived with the B00 serial vouchers opens its message
# vector with this run of characters instead. Its prefix, suffix and multiplier table are
# byte identical to MESSAGE_PREFIX, MESSAGE_SUFFIX and MESSAGE_MULTIPLIERS, so this is
# the only string that differs; the first 36 entries of the vector the device shuffles
# are the ords of this run rather than of MESSAGE_ALPHABET.
MESSAGE_ALPHABET_B = ".eDV5AD_4j.VoAB8H.OmoA35FmmOm1F9dOCx"

# The other two of those three vouchers open their message vector with a run of their own,
# so the three captures between them disagree on all three of the constants a build fixes
# and no two share a profile. Both runs below were recovered by inverting message4()'s
# shuffle and heap walk against the HMAC message the library emitted for its own voucher,
# and each reproduces that message byte for byte, as MESSAGE_ALPHABET_B does for
# B00I765ZEU. _shuffle is not one to one in the alphabet once the body is fixed, so what
# is pinned is a member of the class the capture admits rather than necessarily the run
# itself; the body is the account secret and the client id, so this is exact for the
# device these came from and would have to be re-derived for another serial.
MESSAGE_ALPHABET_C = ".Fe06z2J570N729.kz5z82f63zz5m1jijZ1i"
MESSAGE_ALPHABET_D = ".e-Jjh0RBjdJhjB1VdDuLj7iAnuDm1T6SECX"

# The message vector's opening run is not a constant of a build after all: the library
# picks its 36 characters out of a 64 character source it builds from the voucher's own
# id, so what a voucher opens with follows from the voucher rather than from the library
# that made it. MESSAGE_ALPHABET and its three variants stand in for what that rule
# builds when a voucher carries no id to build one from; where a run and the rule
# disagree, the run is a member of the class the inversion admitted rather than the run
# the library built, which is what the note above says of MESSAGE_ALPHABET_C and
# MESSAGE_ALPHABET_D.
#
# VOUCHER_ID_PREFIX heads every voucher id. SOURCE_SEED is the run the source starts as,
# permuted by SOURCE_ROUNDS swaps each driven by one byte of the id. MESSAGE_STREAM is a
# fixed 36 character run of the library's, holding next to the message builder's own
# fixed strings, whose 18 pairs decide which 36 of the source's positions are read.
# [the id laws take any non-empty id, so gating on the prefix would reject one the library reads]
VOUCHER_ID_PREFIX = b"amzn1.drm-voucher.v1."
SOURCE_SEED = b"0Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh-8Ii9JjKkLlMmNnOoPpQqR_rSsTtUuVvWwXxYyZz"
SOURCE_ROUNDS = 22
MESSAGE_STREAM = b"dhbi934l3irje98rjnfne949fdnfankANSDW"


def _voucher_id_bytes(voucher_id):
    """The id as bytes, or None when there is no id to read.

    Only an empty id is skipped. The library's id laws fold every character of any non-empty id
    and nothing in them distinguishes one spelling from another, so gating on the prefix this
    pipeline expects would build no alphabet and read no row count for an id it would have read.
    """
    if isinstance(voucher_id, str):
        voucher_id = voucher_id.encode('ASCII')
    if not isinstance(voucher_id, bytes) or not voucher_id:
        return None
    return voucher_id

# The device keeps the ACCOUNT_SECRET for its own DRM key derivation wrapped under this
# key, in a file called acsr. The wrapping key is a firmware constant, not per-device.
ACSR_WRAP_KEY = b"e35f5062f97cc8b1244f6f1a2414e31c"
ACSR_WRAP_KEYS = [ACSR_WRAP_KEY] #maybe one day...
# The two shapes an account secret has once it is out of its wrapping: the 40 character form
# the app stores, and the 30 bytes a base build's base64 decode turns that form into. The
# derivation accepts either.
ACCOUNT_SECRET_LENGTHS = (30, 40)

# Separators a device file or a credential list may put between rotations of one secret.
_SECRET_SEPARATOR = re.compile(br'[\s,;]+')


def drilldown(t):
  """
  take a list of byte-strings, split it further and b64decode until done
  """
  nxt=[]
  for val in t:
    if not val:
      continue
    if len(val)<=64:
      nxt.append(val) #should be one of the final values
      continue
    if b"," in val: #list of base64
      subs=val.split(b",")
      for s in subs:
        nxt.extend(drilldown([s]))
      continue
    #should be base64?
    try:
      deval=_b64decode_field(val)
      nxt.extend(drilldown([deval]))
    except Exception as e:
      print("Exception for value {} : {}".format(val,e))
  return nxt

def _is_secret_text(value):
  # one fixed key sometimes hits valid padding by chance, so check the text too
  if not value:
    return False
  return all(0x20 <= byte <= 0x7e for byte in value)

def _is_plain_secret(value):
  return len(value) in ACCOUNT_SECRET_LENGTHS and _is_secret_text(value)

def try_unwrap_value(val):
  """The account secret inside one wrapped value, or None when it is not wrapped.

  The wrapping is a 16 byte IV then AES-CBC ciphertext under the firmware's wrap key, the
  plaintext PKCS#7 padded. The unpadded result is checked as text too, because the padding
  alone is a weak check under one fixed key.
  """
  if len(val) < 32 or len(val)%16!=0:
    return None
  for key in ACSR_WRAP_KEYS:
    try:
      aes = AES.new(key, AES.MODE_CBC, val[:16])
      data=aes.decrypt(val[16:])
      plain = pkcs7unpad(data, 16)
    except Exception:
      continue
    if _is_secret_text(plain):
      return plain
  return None

def _secret_tokens(value):
  """The candidate tokens one acsr value holds.

  A value that reads as text is a list: one rotation per line, and the same separators turn up
  between values copied by hand. One that doesn't is a wrapped secret as it stands -- a 16 byte
  IV and its ciphertext hold bytes that look like separators -- so it's kept whole.
  """
  if not value:
    return []
  if _looks_like_text(value):
    return [token for token in _SECRET_SEPARATOR.split(value) if token]
  return [value]

def _looks_like_text(value):
  if not value:
    return False
  return all(0x20 <= byte <= 0x7e or byte in (0x09, 0x0a, 0x0d) for byte in value)

def _secrets_from_token(token):
  """Every account secret one token stands for, narrowest variant first.

  The value may be one the unwrap takes, may be the secret as it stands, or one base64 layer
  short of either. Undecoded before decoded: a bare hex secret is valid base64 too, and would
  decode into bytes that are neither. A wrapped 30 byte secret is 48 bytes, whose base64 form is
  exactly the length the splitter treats as final, so that layer comes off here.
  """
  for value in drilldown([token]):
    secret = try_unwrap_value(value)
    if secret is not None:
      yield secret
      continue
    if _is_plain_secret(value):
      yield value
      continue
    try:
      decoded = _b64decode_field(value)
    except Exception:
      continue
    if not decoded or decoded == value:
      continue
    secret = try_unwrap_value(decoded)
    if secret is not None:
      yield secret
    elif _is_plain_secret(decoded):
      yield decoded

def unwrap_account_secrets(acsr):
    """Recover the ACCOUNT_SECRET from the device's acsr file contents.

    acsr is base64 of base64 of a 16 byte IV followed by the AES-CBC ciphertext. Returns
    the account secret as bytes, ready to be passed to DrmIonVoucher as the secret.
    Odd fact: some acsr have more than one secret! separated by comma. ALso, not all versions have external base64 wrapping for.. reasons? PC one does not. 
    [the unwrap below also takes one base64 layer and an already unwrapped secret, and splits on
    whitespace and semicolon as well as comma]
    """
    if isinstance(acsr, (bytes, bytearray, str)):
        values = [acsr]
    else:
        values = list(acsr)

    tokens = []
    for value in values:
        if isinstance(value, str):
            value = value.encode('ASCII')
        tokens.extend(_secret_tokens(bytes(value)))

    secrets=[]
    for token in tokens:
        for secret in _secrets_from_token(token):
            if secret not in secrets:
                secrets.append(secret)
    return secrets
    #inner = _b64decode_field(acsr)
    #wrapped = _b64decode_field(inner)
    #_assert(len(wrapped) > 16 and len(wrapped) % 16 == 0,
    #        "acsr does not hold an IV and a whole number of cipher blocks")
    #aes = AES.new(ACSR_WRAP_KEY, AES.MODE_CBC, wrapped[:16])
    #return pkcs7unpad(aes.decrypt(wrapped[16:]), 16)


def _b64decode_field(value):
    """Decode a whole base64 field, ignoring only surrounding whitespace.

    Unlike _b64decode_whole_groups() this keeps the padding, because these fields stand
    alone rather than being a prefix of a longer string.
    """
    return base64.b64decode(b''.join(value.split()))


_HEX_CHARS = set("0123456789abcdefABCDEF")
SERIAL_PREFIX_LENGTHS = (16, 32, 40)


def is_serial_id(tok):
    return (len(tok) == 16 and tok.isalnum()) or (
        len(tok) in (32, 40) and all(ch in _HEX_CHARS for ch in tok)
    )


def unwrap_secret_token(text, allow_plain=False, unwrap_fn=None):
    if not text:
        return []
    if unwrap_fn is None:
        unwrap_fn = unwrap_account_secrets
    if (
        allow_plain
        and len(text) in ACCOUNT_SECRET_LENGTHS
        and all(0x20 <= ord(ch) <= 0x7E for ch in text)
        and not text.startswith("1+")
        and ":" not in text
        and "+" not in text
    ):
        return [text]
    tries = []
    if text.startswith("1+") and len(text) > 2:
        tries.append(text[2:])
    if allow_plain or (len(text) >= 44 and len(text) not in (46, 56, 62, 70, 72, 80)):
        tries.append(text)
    out = []
    for cand in tries:
        try:
            unwrapped = unwrap_fn(cand)
        except Exception:
            unwrapped = []
        for item in unwrapped:
            if isinstance(item, (bytes, bytearray)):
                try:
                    item = bytes(item).decode("ASCII")
                except Exception:
                    continue
            item = str(item).strip()
            if len(item) in ACCOUNT_SECRET_LENGTHS and item not in out:
                out.append(item)
        if out:
            break
    return out


def split_serial_secret(raw, check_serial=False, concat_plain=False, unwrap_fn=None):
    for prefix_len in SERIAL_PREFIX_LENGTHS:
        if len(raw) <= prefix_len:
            continue
        ser_part = raw[:prefix_len]
        if check_serial and not is_serial_id(ser_part):
            continue
        if len(raw) > prefix_len + 1 and raw[prefix_len] in (":", "+"):
            secs = unwrap_secret_token(raw[prefix_len + 1:], allow_plain=True, unwrap_fn=unwrap_fn)
            if secs:
                return ser_part, secs
        rest_part = raw[prefix_len:]
        if (
            rest_part.startswith("1+")
            or (concat_plain and len(rest_part) in ACCOUNT_SECRET_LENGTHS)
            or (len(rest_part) >= 44 and (concat_plain or len(raw) not in (46, 56, 62, 70, 72, 80)))
        ):
            secs = unwrap_secret_token(rest_part, allow_plain=concat_plain, unwrap_fn=unwrap_fn)
            if secs:
                return ser_part, secs
    return None, []

# The key builder flattens the same wrapped lock parameter values into a vector of
# ((byte << k) ^ xor) % 500, then walks the distinct values in ascending order as moduli.
# These are the PW4's xor and row count; which pair a build uses travels in
# DerivationProfile.
FLATTEN_XOR = 9
FLATTEN_ROWS = 9

# The row count is not fixed per build: captures from one build and one credential, with
# only the voucher id changed, produce keys of five different lengths, and each length
# belongs to exactly one (xor, rows) pair in which the two agree and range over these five.
# The device reads the count out of the voucher id; _voucher_rows() recomputes it, and
# these are the counts offered when there is no id to read.
FLATTEN_ROW_CANDIDATES = (1, 3, 5, 7, 9)
FACTOR_E = (2, 3, 5, 7)


class DerivationProfile(object):
    """One library build's constants for obfuscate4() and message4().

    A voucher carries its lock parameter values and its version, and says nothing about
    which build of the SDK produced it, so the properties builds have been observed to
    disagree on travel together as one profile:

    flatten_xor and flatten_rows shape the key builder's flatten vector,
    alphabet is the run of characters the message vector opens with when there is no
    voucher id to build one from, and
    passthrough_hex_secret says how a 40 character ACCOUNT_SECRET, the form
    unwrap_account_secret returns, is read: a build either uses it as it stands or
    base64 decodes it like any other encoded secret, which turns those 40 characters
    into the 30 bytes they spell.

    passthrough_hex_secret is a constant a build fixes; the alphabet is not one of them,
    and neither is the row count. message4() prefers the run _voucher_alphabet() builds
    from the voucher's id and reaches for profile.alphabet when the voucher does not carry
    an id it can read, and decryptvoucher() takes the row count from _voucher_rows() the
    same way, falling back to every FLATTEN_ROW_CANDIDATES count when there is no id.
    """

    def __init__(self, name, flatten_xor, flatten_rows, alphabet, passthrough_hex_secret):
        self.name = name
        self.flatten_xor = flatten_xor
        self.flatten_rows = flatten_rows
        self.alphabet = alphabet
        self.passthrough_hex_secret = passthrough_hex_secret

    def __repr__(self):
        return "DerivationProfile(%r)" % (self.name,)


# Every profile below was checked against output captured from the library it describes:
# "pw4" against the firmware's own HMAC key and message for the real credential, "pr135"
# against the key and message the library shipped in pr135-files.zip emitted for every
# lock parameter combination tried against it, and the three named for the voucher each was
# taken from against that voucher's own key and message. decryptvoucher() offers a
# candidate built under each, because nothing in the voucher says which library to use.
#
# The last three read the 40 character secret unwrap_account_secret returns as it stands,
# which is the form the plugin holds: under that reading each reproduces the key and the
# message in its capture. pr135 and b00i765zeu agree on MESSAGE_ALPHABET_B and on the
# flatten pair and still are not one build: pr135 base64 decodes the secret its own
# harness handed it, and the capture behind b00i765zeu does not.
DERIVATION_PROFILES = (
    DerivationProfile("pw4", FLATTEN_XOR, FLATTEN_ROWS, MESSAGE_ALPHABET, True),
    DerivationProfile("pr135", 3, 3, MESSAGE_ALPHABET_B, False),
    DerivationProfile("b00i765zeu", 3, 3, MESSAGE_ALPHABET_B, True),
    DerivationProfile("b00cvs2j80", 9, 9, MESSAGE_ALPHABET_C, True),
    DerivationProfile("b00spvpx2g", 1, 1, MESSAGE_ALPHABET_D, True),
)


def _derivation_profile(profile):
    """The profile to derive under, defaulting to the first one tried."""
    return DERIVATION_PROFILES[0] if profile is None else profile


def obfuscate4(lockparamvalues, version, profile=None):
    """HMAC key for a VoucherEnvelope version in NEW_KEY_DERIVATION_VERSIONS.

    Unlike obfuscate()/obfuscate2()/obfuscate3(), which permute one shared secret string,
    these versions read the lock parameter values themselves, so the result's length
    depends on the bytes of the ACCOUNT_SECRET and CLIENT_ID values rather than only on
    the length of the shared string.

    lockparamvalues maps the lock parameter name to its value as bytes: ACCOUNT_SECRET is
    the account secret and CLIENT_ID the device serial. Either may be absent, and is read
    as empty: a voucher can carry a client id with no account secret, which is what the
    versions on Kindles that were never given one look like. version selects the
    derivation, and is unused here because versions in this range share one. profile
    selects the library build to derive under, and defaults to the first of
    DERIVATION_PROFILES; see DerivationProfile for what differs between them.
    """
    profile = _derivation_profile(profile)
    body = _key_body(_decode_account_secret(lockparamvalues.get("ACCOUNT_SECRET", b""),
                                            profile),
                     lockparamvalues.get("CLIENT_ID", b""))
    return _emit(_modulus_runs(body, profile))


def _emit(runs):
    """Walk modulus runs into key material, the way the device's key builder does.

    Each modulus contributes its factors, then every round emits the whole accumulator
    under the modulus, except that the last round of the last modulus reaches only the
    loop exit and every last round into a new modulus emits under that new modulus.
    """
    out = bytearray()
    accumulator = []
    previous = 2
    for index, (modulus, rounds) in enumerate(runs):
        # k carries over from the previous modulus, starting at 2: a scan at k == 1 can
        # only return the modulus itself, and a run after a modulus of 0 starts at 0.
        for factor in _factors(modulus, previous):
            accumulator.append(factor)
            out.append(factor & 0xFF)
        last = index == len(runs) - 1
        following = modulus if last else runs[index + 1][0]
        for round_index in range(rounds - 1 if last else rounds):
            emit_modulus = following if round_index == rounds - 1 else modulus
            for i, value in enumerate(accumulator):
                out.append(((value * (emit_modulus + 1)) & 0xFFFF ^ (emit_modulus ^ i)) & 0xFF)
        previous = modulus
    return bytes(out)


def obfuscate4_voucher_id(voucher_id, version):
    """HMAC key for a 10001+ voucher that declares no lock parameters.

    Such a voucher leaves the key builder nothing to read from the lock parameters, so
    the device flattens the voucher id itself instead: ((byte & xor) * (byte | xor) *
    (byte ^ xor)) % 500 for every byte of the id, where xor is the row count the id also
    names, and then walks those values as moduli the same way obfuscate4() walks its
    body's. The result reads neither the account secret nor the client id, so a voucher
    locked this way decrypts without either. Returns None when there is no id to read.
    """
    voucher_id = _voucher_id_bytes(voucher_id)
    if voucher_id is None:
        return None
    xor = _voucher_rows(voucher_id)
    if xor is None:
        return None
    values = [((byte & xor) * (byte | xor) * (byte ^ xor)) % 500 for byte in voucher_id]
    return _emit(_runs_from_values(values))


def _modulus_runs(body, profile=None):
    """The distinct flatten values ascending, each with its multiplicity."""
    profile = _derivation_profile(profile)
    return _runs_from_values(_flatten(body, profile))


def _runs_from_values(values):
    """The distinct values ascending, each with its multiplicity."""
    runs = []
    for value in sorted(values):
        if runs and runs[-1][0] == value:
            runs[-1][1] += 1
        else:
            runs.append([value, 1])
    return [tuple(run) for run in runs]


def _flatten(body, profile=None):
    """The profile's flatten of every byte of the body: ((byte << k) ^ xor) % 500."""
    profile = _derivation_profile(profile)
    return [((byte << k) ^ profile.flatten_xor) % 500
            for k in range(profile.flatten_rows) for byte in body]


def _signed_remainder(a, b):
    """The remainder with the dividend's sign, as the device's integer division gives it.

    Python's % takes the divisor's sign, so it can't express this: -3 % 33 is 30 here and -3 on
    the device, and the factor scan depends on the difference.
    """
    remainder = abs(a) % abs(b)
    return -remainder if a < 0 else remainder


def _signed_gcd(a, b):
    """The factor scan's Euclidean loop, which can return a negative divisor.

    The device keeps whatever sign its remainder sequence lands on, so a negative result is
    common and the caller rejects it by testing against one. That rejection has to be
    reproduced, not repaired: the magnitude admits factors the device never accepts and
    reorders the rest.
    """
    if b == 0:
        return a
    previous, current = a, b
    while True:
        remainder = _signed_remainder(previous, current)
        previous = current
        if remainder == 0:
            return current
        current = remainder


def _factors(modulus, first_k):
    """The factors a modulus contributes, in the order the device accepts them.

    For each k ascending the device takes every e with k^2 == e^2 (mod modulus) whose
    gcd(k - e, modulus) is above one, in the order FACTOR_E lists them, and each distinct
    factor is accepted once per scan.
    The gcd is the signed one; see _signed_gcd for why the sign decides acceptance.
    """
    accepted = []
    for k in range(first_k, modulus):
        for e in FACTOR_E:
            if (k * k - e * e) % modulus:
                continue
            factor = _signed_gcd(k - e, modulus)
            if factor > 1 and factor not in accepted:
                accepted.append(factor)
    return accepted


def message4(lockparamvalues, version, profile=None, voucher_id=None):
    """HMAC message for a VoucherEnvelope version in NEW_KEY_DERIVATION_VERSIONS.

    Takes the same lockparamvalues argument as obfuscate4(), and the same profile: the
    message and the key are built under one library build's constants, not one of each.
    voucher_id is the envelope's voucher id when the caller has it, and it decides the 36
    characters the message opens with; profile.alphabet stands in when there is no id to
    build those characters from. Returns bytes.

    The message is the concatenation of the decimal renderings of a vector of 32 bit
    values, in the order a breadth first walk of an implicit binary heap visits them.
    """
    profile = _derivation_profile(profile)
    body = _message_body(_decode_account_secret(lockparamvalues.get("ACCOUNT_SECRET", b""),
                                                profile),
                         lockparamvalues.get("CLIENT_ID", b""))
    vector = _message_vector(body, profile, voucher_id)
    order = _heap_walk_order(len(vector))
    return ''.join(str(vector[i]) for i in order).encode('ASCII')


def _decode_account_secret(account_secret, profile=None):
    """The account secret as the device's key and message builders receive it, as bytes.

    The acsr file holds the secret base64 encoded, so it is decoded here. What differs
    between library builds is the unwrapped form: most of the profiles below use the 40
    hex characters unwrap_account_secret() returns as they stand, while pr135 base64
    decodes them like any other encoded secret, which turns those 40 characters into the
    30 bytes they spell. profile decides which reading applies; see DerivationProfile.
    """
    profile = _derivation_profile(profile)
    if isinstance(account_secret, str):
        account_secret = account_secret.encode('ASCII')
    if profile.passthrough_hex_secret and _is_account_secret(account_secret):
        return account_secret
    return _b64decode_whole_groups(account_secret)


def _is_account_secret(value):
    """Whether value is an already unwrapped account secret. value must be bytes.

    The unwrapped secret is 40 lowercase hex characters, and every one of them is also a
    base64 digit, so this shape alone does not say how the value is to be read: that is
    what DerivationProfile.passthrough_hex_secret decides.
    [the check below takes upper case digits too, so case is not part of the shape]
    """
    return (len(value) == 40
            and all(c in b'0123456789abcdefABCDEF' for c in value))


def _key_body(account_secret, client_id):
    """The bytes the HMAC key is built from: the account secret then the client id."""
    return account_secret + client_id


def _message_body(account_secret, client_id):
    """The bytes the HMAC message is built from: the key body inside fixed padding."""
    return MESSAGE_PREFIX + _key_body(account_secret, client_id) + MESSAGE_SUFFIX


def _b64decode_whole_groups(value):
    """Decode the account secret the way the device does.

    The device decodes as many whole 4 character groups as the string holds and ignores
    any remainder, so a 5 character secret decodes to the same bytes as its first 4.
    """
    return base64.b64decode(value[:(len(value) // 4) * 4])


def _voucher_alphabet(voucher_id):
    """The 36 characters the message vector opens with for this voucher, or None.

    voucher_id is the envelope's voucher id, the string VOUCHER_ID_PREFIX heads. An id
    of any other shape builds nothing, so None tells the caller to fall back to the run
    the profile carries.
    [any non-empty id builds a run too]
    """
    voucher_id = _voucher_id_bytes(voucher_id)
    if voucher_id is None:
        return None
    source = _voucher_source(voucher_id)
    return bytes(source[i] for i in _message_picks(source)).decode('ASCII')


def _voucher_rows(voucher_id):
    """The row count the key builder flattens over, read out of the voucher id, or None.

    The device starts an accumulator at ten and folds every character of the id through
    acc = ((c << (c & 1)) ^ acc) % 10, replacing a zero with three; the result is the count.
    An id of any other shape reads no count, so None tells the caller to fall back to the
    counts FLATTEN_ROW_CANDIDATES names.
    [any non-empty id reads a count]
    """
    voucher_id = _voucher_id_bytes(voucher_id)
    if voucher_id is None:
        return None
    acc = 10
    for byte in voucher_id:
        acc = ((byte << (byte & 1)) ^ acc) % 10
        if acc == 0:
            acc = 3
    return acc


def _voucher_source(voucher_id):
    """The 64 character run the message vector's opening 36 are picked out of.

    SOURCE_SEED is swapped SOURCE_ROUNDS times, each swap driven by the next byte of the
    id and the byte of the seed it lands on. The id's characters in first appearance
    order are then written in front of the seed's characters the id does not hold, and
    the run is cut back to the seed's length.
    """
    seed = bytearray(SOURCE_SEED)
    acc = 1
    for k in range(SOURCE_ROUNDS):
        i = 3 * k
        acc ^= voucher_id[i % len(voucher_id)] ^ seed[i]
        j = (i ^ acc) & 0x3f
        seed[i], seed[j] = seed[j], seed[i]
    head = []
    seen = set()
    for byte in voucher_id:
        if byte not in seen:
            seen.add(byte)
            head.append(byte)
    tail = [byte for byte in seed if byte not in seen]
    return bytes((head + tail)[:len(SOURCE_SEED)])


def _message_picks(source):
    """The 36 positions in source the message vector's opening run reads, in order."""
    picks = []
    """
    source is read as an 8 by 8 grid. MESSAGE_STREAM holds 18 character pairs, and for
    each pair the library walks the grid in row order until it has met both of the pair's
    characters, taking the first of each. Those two positions are then mixed into the
    two picks: characters found on one row have their columns stepped forward, characters
    found in one column have their rows stepped forward, and otherwise the picks cross.

    A character the grid does not hold has no position to be found, so the walk runs off
    the end of the grid and both positions fall back to ones read out of the pair's own
    bytes instead.
    """
    for k in range(0, len(MESSAGE_STREAM), 2):
        first, second = MESSAGE_STREAM[k], MESSAGE_STREAM[k + 1]
        rowa, cola, rowb, colb = _find_pair(source, first, second)
        if rowa == rowb:
            picks += [rowa * 8 + ((cola + 1) & 7), rowb * 8 + ((colb + 1) & 7)]
        elif cola == colb:
            picks += [((rowa + 1) & 7) * 8 + cola, ((rowb + 1) & 7) * 8 + colb]
        else:
            picks += [rowa * 8 + colb, rowb * 8 + cola]
    return picks


def _find_pair(source, first, second):
    """Where the two characters sit in source, as four row/column values.

    Returns them as (row, column) of first then of second, or the positions the pair's
    own bytes name when either character is missing from the grid: first's low bit and
    second's low two bits for the first position, second modulo six and first's low three
    bits for the second.
    """
    positions = [None, None]
    for i, byte in enumerate(source):
        if positions[0] is None and byte == first:
            positions[0] = (i >> 3, i & 7)
        if positions[1] is None and byte == second:
            positions[1] = (i >> 3, i & 7)
        if positions[0] is not None and positions[1] is not None:
            return positions[0] + positions[1]
    return first & 1, second & 3, second % 6, first & 7


def _message_vector(body, profile=None, voucher_id=None):
    """The vector the message is rendered from, given the wrapped lock parameter values."""
    profile = _derivation_profile(profile)
    alphabet = _voucher_alphabet(voucher_id)
    if alphabet is None:
        alphabet = profile.alphabet
    values = [ord(c) for c in alphabet]
    values += [MESSAGE_MULTIPLIERS[c % 10] * c for c in body]
    _shuffle(values)
    return values + _trickle(values)


def _shuffle(values):
    """Swap each entry with a data dependent partner, in place.

    Position k is swapped values[k] % 10 times, re-read after every swap, and the partner
    is (k << (n % 3)) % len(values) for the decreasing counter n.
    """
    length = len(values)
    for k in range(length):
        n = values[k] % 10
        while n:
            j = (k << (n % 3)) % length
            values[k], values[j] = values[j], values[k]
            n -= 1


def _trickle(values):
    """The appended part: a monotonic stack over the vector, emitting differences."""
    stack = []
    out = []
    j = 0
    while j < len(values):
        if stack and values[stack[-1]] < values[j]:
            popped = values[stack.pop()]
            if stack:
                top = stack[-1]
                out.append((min(values[j], values[top]) - popped) * (j - top - 1))
        else:
            stack.append(j)
            j += 1
    return out


def _heap_walk_order(n):
    """Breadth first walk of an implicit binary heap from its middle, without repeats."""
    queue = collections.deque([n // 2])
    seen = [False] * n
    order = []
    while queue:
        i = queue.popleft()
        if seen[i]:
            continue
        seen[i] = True
        order.append(i)
        for j in (2 * i + 1, 2 * i + 2, (i - 1) >> 1 if i else -1):
            if 0 <= j < n and not seen[j]:
                queue.append(j)
    return order


class SKeyList(object):
    def __init__(self, skeyfile):
      self.keycandidates={}
      self.secretkeys={} #let us hope there is one key per voucher...
      if skeyfile is None: return
      if os.path.isfile(skeyfile):
          with open(skeyfile,"r",encoding="utf8") as fl:
              for line in fl:
                  sline=line.strip()
                  if len(sline)<32: continue 
                  lst=sline.split("$")
                  if len(lst)<2: continue 
                  voucherid=lst[0]
                  for key in lst[1:]:
                      skey=key.split(":")
                      if skey[0]=="secret_key":
                          self.secretkeys[voucherid]=bytes.fromhex(skey[1])
                      elif skey[0]=="shared_key":
                          curlist=self.keycandidates.get(voucherid,[])
                          curlist.append(bytes.fromhex(skey[1]))
                          self.keycandidates[voucherid]=curlist
                          
class DrmIonVoucher(object):
    envelope = None
    version = None
    voucher = None
    drmkey = None
    license_type = "Unknown"

    encalgorithm = ""
    enctransformation = ""
    hashalgorithm = ""

    lockparams = None

    ciphertext = b""
    cipheriv = b""
    secretkey = b""

    def __init__(self, voucherenv, dsn, secret,skeylist=None,quiet=False,stage_fallback=True):
        self.dsn, self.secret = dsn, secret
        # Set by a caller that tries several PIDs in a row and prints one summary
        # itself, so that a failure is not reported once per PID.
        self.quiet = quiet
        # Whether the stages may answer once every candidate this module can build has been
        # refused. A caller that already ran them, and checked against a page, turns this off.
        self.stage_fallback = stage_fallback
        # kept: kfx_stages.classify() reads these bytes, and the parser walks the same stream
        self.envelope_bytes = _stream_value(voucherenv)

        if isinstance(dsn, str):
            self.dsn = dsn.encode('ASCII')

        if isinstance(secret, str):
            self.secret = secret.encode('ASCII')

        self.lockparams = []
        self.lockparamvalues = {}
        self.keycandidates=[]
        self.secretkeycandidate=None
        self.skeylist=skeylist
        self.voucher_id=""
        self.license_type="unknown"
        self.is_plaintext=False
        self.voucher_bytes=b""
        self.envelope = BinaryIonParser(voucherenv)
        addprottable(self.envelope)

    def decryptvoucher(self):
        if getattr(self, "is_plaintext", False) or _extract_key_from_ion_bytes(self.ciphertext) is not None:
            pt_key = _extract_key_from_ion_bytes(self.ciphertext)
            if pt_key is None and getattr(self, "is_plaintext", False):
                if self.ciphertext and len(self.ciphertext) == 16:
                    pt_key = bytes(self.ciphertext)
                else:
                    pt_key = _extract_key_from_ion_bytes(getattr(self, "voucher_bytes", b""))
            if pt_key is not None:
                self.secretkey = pt_key
                if self.ciphertext and self.ciphertext.startswith(b"\xe0\x01\x00\xea"):
                    self.drmkey = BinaryIonParser(BytesIO(self.ciphertext))
                    addprottable(self.drmkey)
                return

        prefix = ("PIDv3" + self.encalgorithm + self.enctransformation + self.hashalgorithm).encode('ASCII')

        raw_lockparams = list(self.lockparams)
        self.lockparams.sort()
        print("Lock parameters used: {}".format(self.lockparams))
        # Rebuilt rather than appended to, so that a second call cannot double the values.
        self.lockparamvalues = {}
        for param in self.lockparams:
            if param == "ACCOUNT_SECRET":
                value = self.secret
            elif param == "CLIENT_ID":
                value = self.dsn
            else:
                _assert(False, "Unknown lock parameter: %s" % param)
            self.lockparamvalues[param] = value

        sorted_lockparams = list(self.lockparams)
        lockparam_orders = [sorted_lockparams]
        if len(self.lockparams) > 1:
            if raw_lockparams not in lockparam_orders:
                lockparam_orders.append(raw_lockparams)
            rev_lockparams = list(reversed(sorted_lockparams))
            if rev_lockparams not in lockparam_orders:
                lockparam_orders.append(rev_lockparams)

        # i know that version maps to scramble pretty much 1 to 1, but there was precendent where they changed it, so...
        sharedsecrets = []
        seen_secrets = set()
        for param_order in lockparam_orders:
            shared = prefix
            for param in param_order:
                shared += param.encode('ASCII') + self.lockparamvalues[param]
            for cand in (
                obfuscate(shared, self.version),
                obfuscate2(shared, self.version),
                obfuscate3(shared, self.version),
                obfuscate_legacy_xor(shared, self.version, first_half=True),
                obfuscate_legacy_xor(shared, self.version, first_half=False),
                shared,
                *(fn(shared) for fn in _V4DIGIT_FUNCS),
            ):
                cand_bytes = bytes(cand)
                if cand_bytes not in seen_secrets:
                    seen_secrets.add(cand_bytes)
                    sharedsecrets.append(cand_bytes)

        decrypted=False
        lastexception = None # type: Exception | None
        keycandidates=list(self.keycandidates)
        for hmac_msg in (b"PIDv3", b"PIDv3\x00"):
            for sharedsecret in sharedsecrets:
                keycandidates.append(hmac.new(sharedsecret, hmac_msg, digestmod=hashlib.sha256).digest())
        if self.version in NEW_KEY_DERIVATION_VERSIONS:
            # Not one of the shared-secret permutations above: the key and the message both
            # come from the version's own routine rather than the shared string assembled
            # here, and the voucher does not say which library build it was made for.
            if self.lockparams:
                # The routine reads the lock parameter values, so one candidate is built
                # under each profile; the row count its key builder flattens over comes out
                # of the voucher id, and every count a capture has shown is offered when
                # there is no id to read it from.
                rows = _voucher_rows(self.voucher_id)
                row_counts = (rows,) if rows is not None else FLATTEN_ROW_CANDIDATES
                for profile in DERIVATION_PROFILES:
                    for row_count in row_counts:
                        candidate = (profile if row_count == profile.flatten_rows
                                     else DerivationProfile(profile.name, row_count, row_count,
                                                            profile.alphabet,
                                                            profile.passthrough_hex_secret))
                        keycandidates.append(hmac.new(
                            obfuscate4(self.lockparamvalues, self.version, candidate),
                            message4(self.lockparamvalues, self.version, candidate,
                                     self.voucher_id),
                            digestmod=hashlib.sha256).digest())
            else:
                # No lock parameters to read: the key builder flattens the voucher id
                # itself, so the key and the message read neither the account secret nor
                # the client id and the voucher decrypts without either. The message is
                # still built from the empty body, which is what makes its opening run the
                # voucher id's.
                voucher_key = obfuscate4_voucher_id(self.voucher_id, self.version)
                if voucher_key is not None:
                    keycandidates.append(hmac.new(
                        voucher_key,
                        message4(self.lockparamvalues, self.version, None, self.voucher_id),
                        digestmod=hashlib.sha256).digest())
        for index, key in enumerate(keycandidates, 1):
            aes = AES.new(key[:32], AES.MODE_CBC, self.cipheriv[:16])
            try:
                b = aes.decrypt(self.ciphertext)
                b = pkcs7unpad(b, 16)
                self.drmkey = BinaryIonParser(BytesIO(b))
                addprottable(self.drmkey)

                _assert(self.drmkey.hasnext() and self.drmkey.next() == TID_LIST and self.drmkey.gettypename() == "com.amazon.drm.KeySet@1.0",
                    "Expected KeySet, got %s" % self.drmkey.gettypename())
                decrypted=True

                print("Decryption succeeded with candidate {0} of {1}".format(
                    index, len(keycandidates)))
                break
            except Exception as ex:
                lastexception = ex
        if not decrypted:
            stage_key = self._stage_content_key()
            if stage_key is not None:
                # A page key, not a decrypted key set: recorded where the page reader looks,
                # confirmed by the caller's page walk
                print("The migrated derivation stages produced this voucher's content key")
                self.secretkey = stage_key
                self.drmkey = None
                return
            if self.quiet:
                raise lastexception
            print("Tried {0} key candidates for voucher version {1}, none of them worked. "
                  "The last one failed with: {2}".format(len(keycandidates), self.version, lastexception))
            if self.secretkeycandidate is None:
              raise lastexception
            else:
                print("Failed all decryption attempts but we have a key candidate")
                self.secretkey =self.secretkeycandidate
                self.drmkey=None
                return
                 

        self.secretkey = _extract_key_from_ion_bytes(b, strict=True) or b""

    def _stage_content_key(self):
        """The content key the stages compute for this envelope, or None.

        Only called once every candidate this module can build has been refused. The import is
        guarded and happens at call time, so a host without the stage tree behaves as before. An
        envelope no family claims answers None at once.

        A voucher envelope carries no pages, so there's no page oracle here -- the caller's page
        reader confirms the key. Empty lock class first, then this voucher's operands.
        """
        if not self.stage_fallback or not self.envelope_bytes:
            return None
        try:
            import kfx_stages
        except Exception:  # noqa: BLE001 - absent stage tree is a supported configuration
            return None
        try:
            family = kfx_stages.classify(self.envelope_bytes)
        except Exception:  # noqa: BLE001 - unparseable means "no engine here"
            return None
        if family is None:
            return None
        print("The voucher envelope belongs to the {0} derivation family".format(family))
        candidates = [{}]
        credentials = {}
        client_id = _operand_text(self.dsn)
        secret = _operand_text(self.secret)
        if client_id:
            credentials['client_id'] = [client_id]
        if secret:
            credentials['account_secret'] = [secret]
        if credentials:
            candidates.append(credentials)
        for credential_map in candidates:
            try:
                key = kfx_stages.derive(family, self.envelope_bytes, credential_map)
            except Exception:
                # A law refusing these operands is one answer among several: the next
                # assignment gets its turn, then the caller's failure handling
                continue
            if key and len(key) == 16:
                return bytes(key)
        return None

    def parse(self):
        self.envelope.reset()
        _assert(self.envelope.hasnext(), "Envelope is empty")
        tn=self.envelope.gettypename()
        _assert(self.envelope.next() == TID_STRUCT and str.startswith(tn, "com.amazon.drm.VoucherEnvelope@"),
                "Unknown type encountered in envelope, expected VoucherEnvelope")
        print(f"Envelope version {tn}")
        self.version = int(self.envelope.gettypename().split('@')[1][:-2])

        self.envelope.stepin()
        while self.envelope.hasnext():
            self.envelope.next()
            field = self.envelope.getfieldname()
            if field == "voucher":
                self.voucher_bytes = self.envelope.lobvalue()
                self.voucher = BinaryIonParser(BytesIO(self.voucher_bytes))
                addprottable(self.voucher)
                continue
            elif field != "strategy":
                continue

            strategy_type = self.envelope.gettypename()
            is_pt_strategy = _is_plaintext_node(self.envelope)
            _assert(strategy_type == "com.amazon.drm.PIDv3@1.0" or is_pt_strategy,
                    "Unknown strategy: %s" % strategy_type)
            if is_pt_strategy:
                self.is_plaintext = True

            if self.envelope.valuetid == TID_STRUCT:
                self.envelope.stepin()
                while self.envelope.hasnext():
                    self.envelope.next()
                    field = self.envelope.getfieldname()
                    if field == "encryption_algorithm":
                        self.encalgorithm = self.envelope.stringvalue()
                    elif field == "encryption_transformation":
                        self.enctransformation = self.envelope.stringvalue()
                    elif field == "hashing_algorithm":
                        self.hashalgorithm = self.envelope.stringvalue()
                    elif field == "lock_parameters":
                        self.envelope.stepin()
                        while self.envelope.hasnext():
                            _assert(self.envelope.next() == TID_STRING, "Expected string list for lock_parameters")
                            self.lockparams.append(self.envelope.stringvalue())
                        self.envelope.stepout()

                self.envelope.stepout()

        self.parsevoucher()
        if self.skeylist is not None:
            self.keycandidates=self.skeylist.keycandidates.get(self.voucher_id,[])
            print(f"Got {len(self.keycandidates)} shared key candidates {self.skeylist.keycandidates} {self.voucher_id}")
            self.secretkeycandidate=self.skeylist.secretkeys.get(self.voucher_id,None)
            if self.secretkeycandidate is not None:
                print(f"Got secret key candidate from file: {self.secretkeycandidate.hex()}")
           
    def parsevoucher(self):
        _assert(self.voucher.hasnext(), "Voucher is empty")
        root_tid = self.voucher.next()
        root_type = self.voucher.gettypename()
        if _is_plaintext_node(self.voucher):
            self.is_plaintext = True
            if root_tid in (TID_BLOB, TID_CLOB):
                self.ciphertext = self.voucher.lobvalue() or b""
                return
            _assert(root_tid == TID_STRUCT, "Unknown type, expected Voucher")
        else:
            _assert(root_tid == TID_STRUCT and root_type == "com.amazon.drm.Voucher@1.0",
                    "Unknown type, expected Voucher")

        self.voucher.stepin()
        while self.voucher.hasnext():
            field_tid = self.voucher.next()
            field_name = self.voucher.getfieldname()
            field_type = self.voucher.gettypename()
            is_pt_field = _is_plaintext_node(self.voucher) or field_name in PLAINTEXT_TYPES

            if field_name == "cipher_iv":
                self.cipheriv = self.voucher.lobvalue()
            elif field_name in ("cipher_text", "data", "encoded"):
                if field_name in ("data", "encoded") or is_pt_field:
                    self.is_plaintext = True
                self.ciphertext = self.voucher.lobvalue()
            elif field_name == "id":
                self.voucher_id = self.voucher.stringvalue()
            elif field_name == "lock_parameters":
                if not self.lockparams:
                    self.voucher.stepin()
                    while self.voucher.hasnext():
                        _assert(self.voucher.next() == TID_STRING, "Expected string list for lock_parameters")
                        self.lockparams.append(self.voucher.stringvalue())
                    self.voucher.stepout()
            elif field_name == "license":
                if (self.voucher.gettypename() != "com.amazon.drm.License@1.0"):
                  print("Unknown license: %s" % self.voucher.gettypename())
                  continue
                self.voucher.stepin()
                while self.voucher.hasnext():
                    self.voucher.next()
                    if self.voucher.getfieldname() == "license_type":
                        self.license_type = self.voucher.stringvalue()
                self.voucher.stepout()
            elif is_pt_field:
                self.is_plaintext = True
                if field_tid in (TID_BLOB, TID_CLOB):
                    if not self.ciphertext:
                        self.ciphertext = self.voucher.lobvalue()
                elif field_tid == TID_STRUCT:
                    self.voucher.stepin()
                    while self.voucher.hasnext():
                        sub_tid = self.voucher.next()
                        sub_name = self.voucher.getfieldname()
                        if sub_tid in (TID_BLOB, TID_CLOB) and sub_name in ("data", "encoded", "cipher_text", ""):
                            blob = self.voucher.lobvalue()
                            if blob and not self.ciphertext:
                                self.ciphertext = blob
                    self.voucher.stepout()

    def printenvelope(self, lst):
        self.envelope.print_(lst)

    def printkey(self, lst):
        if self.voucher is None:
            self.parse()
        if self.drmkey is None:
            self.decryptvoucher()
        if self.drmkey is None:
            # A key candidate answered, or the stages did: both leave the key set unopened, so
            # there's no document to print
            print("No decrypted key set is available for this voucher; the content key was "
                  "taken from a key candidate.")
            return
        self.drmkey.print_(lst)

    def printvoucher(self, lst):
        if self.voucher is None:
            self.parse()

        self.voucher.print_(lst)

    def getlicensetype(self):
        return self.license_type


class DrmIon(object):
    ion = None
    voucher = None
    vouchername = ""
    key = b""
    onvoucherrequired = None

    def __init__(self, ionstream, onvoucherrequired,skeylist=None):
        self.ion = BinaryIonParser(ionstream)
        addprottable(self.ion)
        self.onvoucherrequired = onvoucherrequired
        self.skeylist = skeylist
    def parse(self, outpages):
        self.ion.reset()

        _assert(self.ion.hasnext(), "DRMION envelope is empty")
        _assert(self.ion.next() == TID_SYMBOL and self.ion.gettypename() == "doctype", "Expected doctype symbol")
        _assert(self.ion.next() == TID_LIST and self.ion.gettypename() in ["com.amazon.drm.Envelope@1.0", "com.amazon.drm.Envelope@2.0"],
                "Unknown type encountered in DRMION envelope, expected Envelope, got %s" % self.ion.gettypename())

        while True:
            if self.ion.gettypename() == "enddoc":
                break

            self.ion.stepin()
            while self.ion.hasnext():
                self.ion.next()

                if self.ion.gettypename() in ["com.amazon.drm.EnvelopeMetadata@1.0", "com.amazon.drm.EnvelopeMetadata@2.0"]:
                    self.ion.stepin()
                    while self.ion.hasnext():
                        self.ion.next()
                        fname=self.ion.getfieldname()
                        if self.key is None or len(self.key)==0:
                            if fname=="encryption_key":
                                keyname=self.ion.stringvalue()
                                if self.skeylist is not None:
                                    self.key=self.skeylist.secretkeys.get(keyname,self.key) # i know they are supposed to be voucher ids, but it is easier to dump them all into one file, their UIDs are distinct anyway
                                    if self.key is not None and len(self.key)>10:
                                        print("Obtained secret key from list: {}".format(self.key.hex()))
                                    else:
                                      print("No key id {} in skeylist".format(keyname))
                        if  fname != "encryption_voucher":
                            continue

                        if self.vouchername == "":
                            self.vouchername = self.ion.stringvalue()
                            self.voucher = self.onvoucherrequired(self.vouchername)
                            if self.voucher is not None and self.voucher.secretkey is not None and len(self.voucher.secretkey)>0:
                                self.key = self.voucher.secretkey
                                _assert(self.key is not None, "Unable to obtain secret key from voucher")
                                
                        else:
                            _assert(self.vouchername == self.ion.stringvalue(),
                                    "Unexpected: Different vouchers required for same file?")

                    self.ion.stepout()

                elif self.ion.gettypename() in ["com.amazon.drm.EncryptedPage@1.0", "com.amazon.drm.EncryptedPage@2.0"]:
                    decompress = False
                    decrypt = True
                    ct = None
                    civ = None
                    self.ion.stepin()
                    while self.ion.hasnext():
                        self.ion.next()
                        if self.ion.gettypename() == "com.amazon.drm.Compressed@1.0":
                            decompress = True
                        if self.ion.getfieldname() == "cipher_text":
                            ct = self.ion.lobvalue()
                        elif self.ion.getfieldname() == "cipher_iv":
                            civ = self.ion.lobvalue()
                    _assert(self.key is not None and len(self.key) > 0, "Unable to obtain secret key from voucher or keylist")
                    if ct is not None and civ is not None:
                        self.processpage(ct, civ, outpages, decompress, decrypt)
                    self.ion.stepout()

                elif self.ion.gettypename() in ["com.amazon.drm.PlainText@1.0", "com.amazon.drm.PlainText@2.0"]:
                    decompress = False
                    decrypt = False
                    plaintext = None
                    self.ion.stepin()
                    while self.ion.hasnext():
                        self.ion.next()
                        if self.ion.gettypename() == "com.amazon.drm.Compressed@1.0":
                            decompress = True
                        if self.ion.getfieldname() == "data":
                            plaintext = self.ion.lobvalue()

                    if plaintext is not None:
                        self.processpage(plaintext, None, outpages, decompress, decrypt)
                    self.ion.stepout()

            self.ion.stepout()
            if not self.ion.hasnext():
                break
            self.ion.next()

    def print_(self, lst):
        self.ion.print_(lst)

    def processpage(self, ct, civ, outpages, decompress, decrypt):
        if decrypt:
            aes = AES.new(self.key[:16], AES.MODE_CBC, civ[:16])
            msg = pkcs7unpad(aes.decrypt(ct), 16)
        else:
            msg = ct

        if not decompress:
            outpages.write(msg)
            return

        _assert(msg[0] == 0, "LZMA UseFilter not supported")

        if calibre_lzma is not None:
            with calibre_lzma.decompress(msg[1:], bufsize=0x1000000) as f:
                f.seek(0)
                outpages.write(f.read())
            return

        decomp = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        while not decomp.eof:
            segment = decomp.decompress(msg[1:])
            msg = b"" # Contents were internally buffered after the first call
            outpages.write(segment)
