import frida
import argparse
from io import BytesIO
import collections 
from frida_tools.reactor import Reactor
import threading
import sys
import signal
import numbers
import zipfile 
import lzma
import os
import json
##Usage:
# Install Windows subsystem for Android or another android emulator, might also work on rooted Android device
# install kindle for Android on device/emulator
# install and run frida server on the device/emulator
# install frida for python that matches the version on the device 
# install Android platform tools and connect to device/emulator
# copy this python scrtipt and compiled_agent.js into the same folder
# run Kindle on Android, and download the books you want to convert from your library 
# adb pull /sdcard/Android/data/com.amazon.kindle/
# make output folder, like output
# run script, for example `python kindleFridaDecrypt.py -f "com.amazon.kindle/files/" -o output`
# if  KRFNotInitializedException appears - open any KFX book in the app and try again
# hope for the best

# note: compiled_agent.js is compiled from agent.js by npx frida-compile agent.js -o compiled_agent.js
# npm install frida-java-bridge and npm install --save-dev frida-compile 
##copied out from ion.py and subtly modified
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.py3compat import bchr
except ImportError:
    from Crypto.Cipher import AES
    from Crypto.Util.py3compat import bchr


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
                try:
                  self.valuetid = self.readtypeid()
                except:
                    self.valuetid =-1
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
            try:
             result += ("%02x " % ord(i)) 
            except:
             result += ("%02x " % i) 

        if len(result) > 0:
            result = result[:-1]
        result+=(" ->%05x"%len(b))
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
                                   6052, 9479, 9888, 4648, 5683,100001,100002,100003,100004,100005,100006,100007,100008,100009,]]+["mystery_data"]+['com.amazon.drm.VoucherEnvelope@V100011'] +[
                                   'com.amazon.drm.VoucherEnvelope@%d.0' % n for n in list(range(100109, 100209))]
def addprottable(ion):
    ion.addtocatalog("ProtectedData", 1, SYM_NAMES)

def pkcs7unpad(msg, blocklen):
    _assert(len(msg) % blocklen == 0)

    paddinglen = msg[-1]

    _assert(paddinglen > 0 and paddinglen <= blocklen, "Incorrect padding - Wrong key")
    _assert(msg[-paddinglen:] == bchr(paddinglen) * paddinglen, "Incorrect padding - Wrong key")

    return msg[:-paddinglen]
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
        self.key=None
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
                        if  fname != "encryption_voucher":
                            continue

                        if self.vouchername == "":
                            self.vouchername = self.ion.stringvalue()
                            self.voucher = self.onvoucherrequired(self.vouchername)
                                
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
                    if ct is not None and civ is not None:
                        if self.key is not None:
                          self.processpage(ct, civ, outpages, decompress, decrypt,self.key)
                        else:
                          if self.skeylist is not None:
                            done=0
                            lkey=None
                            for key in self.skeylist:
                              try:
                                self.processpage(ct, civ, outpages, decompress, decrypt,key)
                                done+=1
                                lkey=key
                                print(f"Got key candidate {key.hex()}")
                                #break
                              except Exception as e:
                                #print(e)
                                continue
                            if done>1:
                              done=0
                              lkey=None
                              for key in self.skeylist:
                                try:
                                  self.processpage(ct, civ, outpages, decompress, decrypt,key,True)
                                  done+=1
                                  lkey=key
                                  print(f"Got dedup key candidate {key.hex()}")
                                  #break
                                except Exception as e:
                                  #print(e)
                                  continue
                            _assert(done==1, f"Could not find key in list of {len(self.skeylist)} keys or duplicate keys ({done})")
                            self.key=lkey
                          else:
                            _assert(self.key is not None, "Book key not in candidates")
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

    def processpage(self, ct, civ, outpages, decompress, decrypt,key=None,cont_check=False):
        if decrypt:
            aes = AES.new(key[:16], AES.MODE_CBC, civ[:16])
            msg = pkcs7unpad(aes.decrypt(ct), 16)
        else:
            msg = ct

        if not decompress:
            if cont_check:
              _assert(msg[:4] == b"CONT", "CONT check failed ")
            outpages.write(msg)
            return

        _assert(msg[0] == 0, "LZMA UseFilter not supported")

        decomp = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        while not decomp.eof:
            segment = decomp.decompress(msg[1:])
            if cont_check:
              _assert(segment[:4] == b"CONT", "CONT check failed ")
            msg = b"" # Contents were internally buffered after the first call
            outpages.write(segment)
            cont_check=False

def processBook(bookfilelist, keylist,bookid):
  with zipfile.ZipFile(os.path.join(args.out_dir,f'{bookid}.kfx-zip'), 'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as zip_ref:
    for filename,outfilename in bookfilelist:
      with open(filename,"rb") as fh:
        data = fh.read(8)
        if data != b'\xeaDRMION\xee':
            zip_ref.writestr(outfilename, data+fh.read())
            continue
        data += fh.read()
        print("Decrypting KFX DRMION: {0}".format(filename))
        outfile = BytesIO()
        DrmIon(BytesIO(data[8:-8]), lambda name: name,keylist).parse(outfile)
        zip_ref.writestr(outfilename, outfile.getvalue())
    print("Book processing complete")

## end copy from ion.py


def create_target_parser(target_type):
    def parse_target(value):
        if target_type == "file":
            return (target_type, [value])
        if target_type == "gated":
            return (target_type, re.compile(value))
        if target_type == "pid":
            return (target_type, int(value))
        return (target_type, value)

    return parse_target
    
parser = argparse.ArgumentParser(
        prog='kindleInstrument',
        formatter_class=argparse.RawDescriptionHelpFormatter)
#parser.add_argument('-p','--process', default="com.amazon.kindle", help='the Kindle process you are trying to instrument')
parser.add_argument(
            "-n",
            "--attach-name",
            help="attach to NAME",
            metavar="NAME",
            dest="target",
            type=create_target_parser("name"),
        )
parser.add_argument(
            "-N",
            "--attach-identifier",
            help="attach to IDENTIFIER",
            metavar="IDENTIFIER",
            dest="target",
            type=create_target_parser("identifier"),
        )
parser.add_argument(
            "-p", "--attach-pid", help="attach to PID", metavar="PID", dest="target", type=create_target_parser("pid")
        )
def dir_path(string):
    if os.path.isdir(string):
        return string
    else:
        raise NotADirectoryError(string)
parser.add_argument(
            "-f", "--scan-folder", help="scan folder for Android Kindle book folders", metavar="book_folder", dest="scan_dir",default=".", type=dir_path )
parser.add_argument(
            "-o", "--output-folder", help="output folder for generated kfx-zips", metavar="output_folder", dest="out_dir", default=".", type=dir_path )
#usb by default
parser.add_argument('-H', '--host', type=str,
                        help='device connected over IP, or use \'local\' for local connection')
args = parser.parse_args()



#console.log(hex(p.readByteArray(ln)))

script_text=open("compiled_agent.js","r",encoding="utf8").read()

def find_device(device_type):
    for device in frida.enumerate_devices():
        if device.type == device_type:
            return device
    return None
    
class MiniReactor(object):
    def __init__(self,host,target,scr,on_message):
        self._reactor= Reactor(self._process_input, self._on_stop)
        self._device =None
        self._ready = threading.Event()
        self._stopping = threading.Event()
        if host is None or len(host)==0:
            self._device_type="usb"
            self._host=None
        else:
            if host=="local":
                self._host=None
                self._device_type=None#"local"
            else:
                self._host=host
                self._device_type="remote"
        self._device_id=None
        self._keepalive_interval=None
        self._schedule_on_output = lambda pid, fd, data: self._reactor.schedule(lambda: self._on_output(pid, fd, data))
        self._schedule_on_device_lost = lambda: self._reactor.schedule(self._on_device_lost)
        self._started = False
        self._target=target
        self._session = None
        self._schedule_on_session_detached = lambda reason, crash: self._reactor.schedule( lambda: self._on_session_detached(reason, crash))
        self._session_transport = "multiplexed"
        self._runtime="qjs"
        self._realm="native"
        self._script_text=scr
        self._script=None
        self._exit_on_error=True
        self._on_message_custom=on_message
    def _try_load_script(self) -> None:
        try:
            self._load_script()
        except Exception as e:
            self._print(f"Failed to load script: {e}")
    def _on_stop(self):
        self._stopping.set()
        
    def _try_start(self) -> None:
        if self._device is not None:
            return
        if self._device_id is not None:
            try:
                self._device = frida.get_device(self._device_id)
            except:
                self._update_status(f"Device '{self._device_id}' not found")
                self._exit(1)
                return
        elif (self._host is not None) or (self._device_type == "remote"):
            host = self._host
            print("remote")
            options = {}
            if self._keepalive_interval is not None:
                options["keepalive_interval"] = self._keepalive_interval

            if host is None and len(options) == 0:
                self._device = frida.get_remote_device()
            else:
                self._device = frida.get_device_manager().add_remote_device(
                    host if host is not None else "127.0.0.1", **options
                )
        elif self._device_type is not None:
            self._device = find_device(self._device_type)
            if self._device is None:
                return
        else:
            self._device = frida.get_local_device()
        self._device.on("output", self._schedule_on_output)
        self._device.on("lost", self._schedule_on_device_lost)
        self._attach_and_instrument()
    def _log(self, level: str, text: str):
        if level == "info":
            self._print(text)
        else:
            if level == "error":
                self._print(text, file=sys.stderr)
            else:
                self._print(text)
    def _unload_script(self):
        if self._script is None:
            return
        try:
            self._script.unload()
        except:
            pass
        self._script = None
    def _on_sigterm(self, n, f):
        self._reactor.cancel_io()
        self._exit(0)
    def _process_message(self, message ,data) -> None:
        #print("processing message")
        #print(message)
        message_type = message["type"]
        if message_type == "error":
            text = message.get("stack", message["description"])
            self._log("error", text)
            if self._exit_on_error:
                self._exit(1)
        else:
            self._on_message_custom(message["payload"],data,self)

    def _load_script(self) -> None:
        is_first_load = self._script is None

        assert self._session is not None
        script = self._session.create_script(name="kndl", source=self._script_text, runtime=self._runtime)
        script.set_log_handler(self._log)
        self._unload_script()
        self._script = script

        def on_message(message, data):
            if self.try_handle_bridge_request(message, self._script):
                return
            self._reactor.schedule(lambda: self._process_message(message, data))

        script.on("message", on_message)
        self._on_script_created(script)
        script.load()
    def try_handle_bridge_request(self, message, script):
        #print(message)
        if message["type"] != "send":
            return False

        payload = message.get("payload")
        if not isinstance(payload, dict):
            return False
        #print(payload)
        t = payload.get("type")
        if t != "frida:load-bridge":
            return False

        stem = payload["name"].lower()
        bridge = next(p for p in (Path(__file__).parent / "bridges").glob("*.js") if p.stem == stem)
        print("bridge posted")
        script.post(
            {
                "type": "frida:bridge-loaded",
                "filename": bridge.name,
                "source": bridge.read_text(encoding="utf-8"),
            }
        )

        return True
    def _perform_on_background_thread(self, f, timeout=None):
        result = [None, None]

        def work() -> None:
            with self._reactor.io_cancellable:
                try:
                    result[0] = f()
                except Exception as e:
                    result[1] = e

        worker = threading.Thread(target=work)
        worker.start()

        try:
            worker.join(timeout)
        except KeyboardInterrupt:
            self._reactor.cancel_io()

        if timeout is not None and worker.is_alive():
            self._reactor.cancel_io()
            while worker.is_alive():
                try:
                    worker.join()
                except KeyboardInterrupt:
                    pass

        error = result[1]
        if error is not None:
            raise error

        return result[0]
    def _attach_and_instrument(self):
        if self._target is None:
            print("Needs target")
            self._exit(1)
        if self._target is not None:
            target_type, target_value = self._target

            spawning = True
            try:
                if target_type == "identifier":
                    spawning = False
                    app_list = self._device.enumerate_applications()
                    app_identifier_lc = target_value.lower()
                    matching = [app for app in app_list if app.identifier.lower() == app_identifier_lc]
                    if len(matching) == 1 and matching[0].pid != 0:
                        attach_target = matching[0].pid
                    elif len(matching) > 1:
                        raise frida.ProcessNotFoundError(
                            "ambiguous identifier; it matches: %s"
                            % ", ".join([f"{process.identifier} (pid: {process.pid})" for process in matching])
                        )
                    else:
                        raise frida.ProcessNotFoundError("unable to find process with identifier '%s'" % target_value)
                elif target_type == "file":
                    argv = target_value
                    if not self._quiet:
                        self._update_status(f"Spawning `{' '.join(argv)}`...")

                    aux_kwargs = {}
                    if self._aux is not None:
                        aux_kwargs = dict([parse_aux_option(o) for o in self._aux])

                    self._spawned_pid = self._device.spawn(argv, stdio=self._stdio, **aux_kwargs)
                    self._spawned_argv = argv
                    attach_target = self._spawned_pid
                else:
                    attach_target = target_value
                    if not isinstance(attach_target, numbers.Number):
                        attach_target = self._device.get_process(attach_target).pid
                spawning = False
                self._attach(attach_target)
            except frida.OperationCancelledError:
                self._exit(0)
                return
            except Exception as e:
                if spawning:
                    self._update_status(f"Failed to spawn: {e}")
                else:
                    self._update_status(f"Failed to attach: {e}")
                self._exit(1)
                return
        self._start()
        self._started = True
    def _on_script_created(self, script: frida.core.Script):
        return 
    def _attach(self, pid: int) -> None:

        self._target_pid = pid
        assert self._device is not None
        self._session = self._device.attach(pid, realm=self._realm)
        self._session.on("detached", self._schedule_on_session_detached)

    def _start(self) -> None:
        self._load_script()
        assert self._script is not None
        self._ready.set()
        """
        override this method with the logic of your command, it will run after
        the class is fully initialized with a connected device/target if you
        required one.
        """
    def _stop(self) -> None:
        self._unload_script()

    def _print(self, *args, **kwargs):
        encoded_args = []
        encoding = sys.stdout.encoding or "UTF-8"
        if encoding == "UTF-8":
            encoded_args = list(args)
        else:
            for arg in args:
                if isinstance(arg, str):
                    encoded_args.append(arg.encode(encoding, errors="backslashreplace").decode(encoding))
                else:
                    encoded_args.append(arg)
        print(*encoded_args, **kwargs)
    def _show_message_if_no_device(self) -> None:
        if self._device is None:
            self._print("Waiting for USB device to appear...")
    def run(self):
        mgr = frida.get_device_manager()

        on_devices_changed = lambda: self._reactor.schedule(self._try_start)
        mgr.on("changed", on_devices_changed)

        self._reactor.schedule(self._try_start)
        self._reactor.schedule(self._show_message_if_no_device, delay=1)

        signal.signal(signal.SIGTERM, self._on_sigterm)

        self._reactor.run()

        if self._started:
            try:
                self._perform_on_background_thread(self._stop)
            except frida.OperationCancelledError:
                pass

        if self._session is not None:
            self._session.off("detached", self._schedule_on_session_detached)
            try:
                self._perform_on_background_thread(self._session.detach)
            except frida.OperationCancelledError:
                pass
            self._session = None

        if self._device is not None:
            self._device.off("output", self._schedule_on_output)
            self._device.off("lost", self._schedule_on_device_lost)

        mgr.off("changed", on_devices_changed)

        frida.shutdown()
        sys.exit(0)
    def _update_status(self, message) -> None:
            print( message )
    def _exit(self, exit_status: int) -> None:
        self._exit_status = exit_status
        self._reactor.stop()
    def _process_input(self, reactor: Reactor) -> None:
        try:
            while self._ready.wait(0.5) != True:
                if not reactor.is_running():
                    return
        except KeyboardInterrupt:
            self._reactor.cancel_io()
            return

        while True:
            try:
                if self._stopping.wait(1):
                    break
            except KeyboardInterrupt:
                self._reactor.cancel_io()
                return
    def _on_session_detached(self, reason: str, crash) -> None:
        if crash is None:
            message = reason[0].upper() + reason[1:].replace("-", " ")
        else:
            message = "Process crashed: " + crash.summary
        self._print( message)
        if crash is not None:
            self._print("\n***\n{}\n***".format(crash.report.rstrip("\n")))
        self._exit(1)


prev_maybe_key=False
prev_maybe_key_value=b""
ready_to_book=False
processing_book=False
key_set=set([])
scandir_iterator=None
cur_book=None
def process_metadata(bookid,mpath,bpath):
  ret={}
  with open(mpath,"rb") as fl:
    dat=json.load(fl)

  if dat["mimeType"]!="application/x-kfx-ebook":
    print(f"{bookid} is not kfx")
    raise ValueError("unsupported format")
  mani=dat["manifest"]
  manifest=json.loads(mani)
  bases = [item["id"] for item in manifest["resources"] if item["type"] == "KINDLE_MAIN_BASE"]
  attachables=[item["id"] for item in manifest["resources"] if item["type"] == "KINDLE_MAIN_ATTACHABLE" or item["type"] == "KINDLE_MAIN_METADATA"] #kfx
  vouchers=[item["id"] for item in manifest["resources"] if item["type"] == "DRM_VOUCHER"] #ast
  if len(bases)>1:
    print(f"Unusual book at {mpath} with several entry points, using first one")
  ret["bookFile"]=f"{bookid}/{bases[0]}.kfx"
  ret["vouchers"]=[]
  for vch in vouchers:
    ret["vouchers"].append(f"{bookid}/{vch}.ast")
  ret["resources"]=[]
  for b in bases:
    fname=os.path.join(bpath,f"{b}.kfx")
    if not os.path.isfile(fname):
      print(f"File {fname} is in manifest but does not exist!")
      continue
    ret["resources"].append((fname,f"{b}.azw"))
  for b in attachables:
    fname=os.path.join(bpath,f"{b}.kfx")
    if not os.path.isfile(fname):
      print(f"File {fname} is in manifest but does not exist!")
      continue
    ret["resources"].append((fname,f"{b}.res"))
  return ret
def move_next():
  global scandir_iterator
  while True:
    try:
      entry=next(scandir_iterator)
      if entry.is_dir():
        bookid=entry.name
        metapath=os.path.join(entry.path,".metadata")
        if os.path.isfile(metapath):
          try:
            flists=process_metadata(bookid,metapath,entry.path)
          except Exception as e:
            print(e)
            continue
          flists["bookid"]=bookid
          return flists
    except StopIteration:
      return None
def send_next_book(app):
  global processing_book,key_set,cur_book
  nxt=move_next()
  if nxt is None:
    app._exit(0)
    return
  print(f"Starting work on {nxt["bookid"]}")
  cur_book=nxt
  app._script.post({"type": "book","bookFile":nxt["bookFile"],"vouchers":nxt["vouchers"]})
  processing_book=True
  key_set=set([])
def on_message(payload, data,app):
    global ready_to_book,processing_book,key_set,scandir_iterator,cur_book
    if payload=="mem":
      if not ready_to_book: return
      if not processing_book: return 
      #print(data)
      #print(data.hex())
      if len(data)==16 :
        #print("Maybe key")
        key_set.add(data)
      return
    elif payload=="done":
      processing_book=False
      #for k in key_set:
      #  print(k.hex())
      print(cur_book["resources"])
      processBook(cur_book["resources"], list(key_set),cur_book["bookid"])
      send_next_book(app)
    else:
      print("[on_message] message:", payload, "data:", data)
      if isinstance(payload,dict):
        if payload["msg"]=="ready":
          ready_to_book=True
          print(f"DSN: {payload["dsn"]} secrets: {payload["secrets"]}")
          scandir_iterator=os.scandir(args.scan_dir)
          send_next_book(app)
          
def main():
    global script_text
    targ=args.target
    if targ is None:
        targ=("identifier","com.amazon.kindle")
    app = MiniReactor(args.host,targ,script_text,on_message)
    app.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
