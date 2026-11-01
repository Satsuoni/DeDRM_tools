#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# kgenpids.py
# Copyright © 2008-2020 Apprentice Harper et al.

__license__ = 'GPL v3'
__version__ = '3.0'

# Revision history:
#  2.0   - Fix for non-ascii Windows user names
#  2.1   - Actual fix for non-ascii WIndows user names.
#  2.2   - Return information needed for KFX decryption
#  3.0   - Python 3 for calibre 5.0


import sys
import os, csv
import binascii
import zlib
import re
from struct import pack, unpack, unpack_from
import traceback

class DrmException(Exception):
    pass

global charMap1
global charMap3
global charMap4


charMap1 = b'n5Pr6St7Uv8Wx9YzAb0Cd1Ef2Gh3Jk4M'
charMap3 = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
charMap4 = b'ABCDEFGHIJKLMNPQRSTUVWXYZ123456789'

# crypto digestroutines
import hashlib

def MD5(message):
    ctx = hashlib.md5()
    ctx.update(message)
    return ctx.digest()

def SHA1(message):
    ctx = hashlib.sha1()
    ctx.update(message)
    return ctx.digest()


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
    result = ''
    for i in range (0,len(data)-1,2):
        high = map.find(data[i])
        low = map.find(data[i+1])
        if (high == -1) or (low == -1) :
            break
        value = (((high * len(map)) ^ 0x80) & 0xFF) + low
        result += pack('B',value)
    return result

#
# PID generation routines
#

# Returns two bit at offset from a bit field
def getTwoBitsFromBitField(bitField,offset):
    byteNumber = offset // 4
    bitPosition = 6 - 2*(offset % 4)
    if sys.version_info[0] == 2:
        return ord(bitField[byteNumber]) >> bitPosition & 3
    else:
        return bitField[byteNumber] >> bitPosition & 3
    
# Returns the six bits at offset from a bit field
def getSixBitsFromBitField(bitField,offset):
    offset *= 3
    value = (getTwoBitsFromBitField(bitField,offset) <<4) + (getTwoBitsFromBitField(bitField,offset+1) << 2) +getTwoBitsFromBitField(bitField,offset+2)
    return value

# 8 bits to six bits encoding from hash to generate PID string
def encodePID(hash):
    global charMap3
    PID = b''
    for position in range (0,8):
        PID += bytes(bytearray([charMap3[getSixBitsFromBitField(hash,position)]]))
        
    return PID

# Encryption table used to generate the device PID
def generatePidEncryptionTable() :
    table = []
    for counter1 in range (0,0x100):
        value = counter1
        for counter2 in range (0,8):
            if (value & 1 == 0) :
                value = value >> 1
            else :
                value = value >> 1
                value = value ^ 0xEDB88320
        table.append(value)
    return table

# Seed value used to generate the device PID
def generatePidSeed(table,dsn) :
    value = 0
    for counter in range (0,4) :
        index = (dsn[counter] ^ value) & 0xFF
        value = (value >> 8) ^ table[index]
    return value

# Generate the device PID
def generateDevicePID(table,dsn,nbRoll):
    global charMap4
    seed = generatePidSeed(table,dsn)
    pidAscii = b''
    pid = [(seed >>24) &0xFF,(seed >> 16) &0xff,(seed >> 8) &0xFF,(seed) & 0xFF,(seed>>24) & 0xFF,(seed >> 16) &0xff,(seed >> 8) &0xFF,(seed) & 0xFF]
    index = 0
    for counter in range (0,nbRoll):
        pid[index] = pid[index] ^ dsn[counter]
        index = (index+1) %8
    for counter in range (0,8):
        index = ((((pid[counter] >>5) & 3) ^ pid[counter]) & 0x1f) + (pid[counter] >> 7)
        pidAscii += bytes(bytearray([charMap4[index]]))
    return pidAscii

def crc32(s):
    return (~binascii.crc32(s,-1))&0xFFFFFFFF

# convert from 8 digit PID to 10 digit PID with checksum
def checksumPid(s):
    global charMap4
    crc = crc32(s)
    crc = crc ^ (crc >> 16)
    res = s
    l = len(charMap4)
    for i in (0,1):
        b = crc & 0xff
        pos = (b // l) ^ (b % l)
        res += bytes(bytearray([charMap4[pos%l]]))
        crc >>= 8
    return res


# old kindle serial number to fixed pid
def pidFromSerial(s, l):
    global charMap4
    crc = crc32(s)
    arr1 = [0]*l
    for i in range(len(s)):
        if sys.version_info[0] == 2:
            arr1[i%l] ^= ord(s[i])
        else: 
            arr1[i%l] ^= s[i]
    crc_bytes = [crc >> 24 & 0xff, crc >> 16 & 0xff, crc >> 8 & 0xff, crc & 0xff]
    for i in range(l):
        arr1[i] ^= crc_bytes[i&3]
    pid = b""
    for i in range(l):
        b = arr1[i] & 0xff
        pid += bytes(bytearray([charMap4[(b >> 7) + ((b >> 5 & 3) ^ (b & 0x1f))]]))
    return pid


_COMBINED_SPLIT_LENGTHS = (
    (16, 40),
    (32, 40),
    (40, 40),
    (16, 30),
    (32, 30),
    (40, 30),
)


def _to_bytes(val):
    if isinstance(val, bytes):
        return val
    if isinstance(val, bytearray):
        return bytes(val)
    if isinstance(val, str):
        return val.encode("utf-8")
    return bytes(val)


def _unhex_variants(raw_bytes):
    raw = _to_bytes(raw_bytes).strip()
    if not raw:
        return []
    out = [raw]
    if len(raw) % 2 == 0:
        try:
            unhex = bytes.fromhex(raw.decode("ascii"))
            if unhex and unhex not in out:
                out.append(unhex)
        except (UnicodeDecodeError, ValueError):
            pass
    return out


def _serial_variants(raw_bytes):
    raw = _to_bytes(raw_bytes).strip()
    if not raw:
        return []
    out = [raw]
    for v in (raw.upper(), raw.lower(), *_unhex_variants(raw)):
        if v not in out:
            out.append(v)
    return out


def _book_pid(material, rec209, token):
    return checksumPid(encodePID(SHA1(material + rec209 + token)))


def _emit_dsn_pids(_add, table, d, rec209, token, sec_vars=(), device_first=False):
    if device_first and len(d) >= 4:
        _add(checksumPid(generateDevicePID(table, d, 4)))
    if device_first:
        if len(d) == 16:
            _add(checksumPid(pidFromSerial(d, 7) + b"*"))
        _add(checksumPid(pidFromSerial(d, 8)))
        for s in sec_vars:
            _add(_book_pid(d + s, rec209, token))
            _add(_book_pid(s, rec209, token))
        _add(_book_pid(d, rec209, token))
        return
    for s in sec_vars:
        _add(_book_pid(d + s, rec209, token))
    for s in sec_vars:
        _add(_book_pid(s, rec209, token))
    _add(_book_pid(d, rec209, token))
    if len(d) == 16:
        _add(checksumPid(pidFromSerial(d, 7) + b"*"))
    _add(checksumPid(pidFromSerial(d, 8)))
    if len(d) >= 4:
        _add(checksumPid(generateDevicePID(table, d, 4)))


# Parse the EXTH header records and use the Kindle serial number to calculate the book pid.
def getKindlePids(rec209, token, serialnum):
    if isinstance(serialnum,str):
        serialnum = serialnum.encode('utf-8')
    elif isinstance(serialnum, bytearray):
        serialnum = bytes(serialnum)

    if sys.version_info[0] == 2:
        if isinstance(serialnum,unicode):
            serialnum = serialnum.encode('utf-8')

    if rec209 is None:
        return [serialnum]

    pids=[]
    seen=set()

    def _add(pid10):
        pid_bytes = bytes(pid10)
        if pid_bytes not in seen:
            seen.add(pid_bytes)
            pids.append(pid_bytes)

    if len(serialnum) in (8, 10):
        _add(checksumPid(serialnum[:8]))
        if len(serialnum) == 10:
            _add(serialnum)
        return pids

    table = generatePidEncryptionTable()

    for dsn_len, sec_len in _COMBINED_SPLIT_LENGTHS:
        if len(serialnum) == dsn_len + sec_len:
            dsn_vars = _serial_variants(serialnum[:dsn_len])
            sec_vars = _unhex_variants(serialnum[dsn_len:])
            for d in dsn_vars:
                _emit_dsn_pids(_add, table, d, rec209, token, sec_vars)
            return pids

    # Compute book PID
    _add(_book_pid(serialnum, rec209, token))

    # compute fixed pid for old pre 2.5 firmware update pid as well
    _add(checksumPid(pidFromSerial(serialnum, 7) + b"*"))

    if len(serialnum) in (30, 40):
        for s in _unhex_variants(serialnum):
            _add(_book_pid(s, rec209, token))

    for v in _serial_variants(serialnum):
        _emit_dsn_pids(_add, table, v, rec209, token)

    return pids


# parse the Kindleinfo file to calculate the book pid.

keynames = ['kindle.account.tokens','kindle.cookie.item','eulaVersionAccepted','login_date','kindle.token.item','login','kindle.key.item','kindle.name.info','kindle.device.info', 'MazamaRandomNumber']
def maybeUnhex(dat):
  if isinstance(dat, (bytes, bytearray)):
    try:
      return bytearray.fromhex(dat.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
      return bytearray(dat)
  try:
    return bytearray.fromhex(dat)
  except ValueError:
    return bytearray(dat.encode("utf8"))
def getK4Pids(rec209, token, kindleDatabase):
    global charMap1
    pids = []
    #print(f"Entering getK4Pids with token {token} and kindleDatabase {kindleDatabase}")
    try:
        # Get the kindle account token, if present
        kindleAccountToken = maybeUnhex((kindleDatabase[1])['kindle.account.tokens'])

    except KeyError:
        kindleAccountToken = b''
        pass
    extraKindleTokens=kindleDatabase[1].get('kindle.account.secrets',[])
    extraKindleTokens=[maybeUnhex(f) for f in extraKindleTokens]
    extraKindleTokens.append(kindleAccountToken)
    #extraKindleTokens=list(set(extraKindleTokens))
    try:
        # Get the DSN token, if present
        DSN = maybeUnhex((kindleDatabase[1])['DSN'])
        print("Got DSN key from database {0}".format(kindleDatabase[0]))
    except KeyError:
        # See if we have the info to generate the DSN
        try:
            # Get the Mazama Random number
            MazamaRandomNumber = maybeUnhex((kindleDatabase[1])['MazamaRandomNumber'])
            #print "Got MazamaRandomNumber from database {0}".format(kindleDatabase[0])

            try:
                # Get the SerialNumber token, if present
                IDString = maybeUnhex((kindleDatabase[1])['SerialNumber'])
                print("Got SerialNumber from database {0}".format(kindleDatabase[0]))
            except KeyError:
                 # Get the IDString we added
                IDString = maybeUnhex((kindleDatabase[1])['IDString'])

            try:
                # Get the UsernameHash token, if present
                encodedUsername = maybeUnhex((kindleDatabase[1])['UsernameHash'])
                print("Got UsernameHash from database {0}".format(kindleDatabase[0]))
            except KeyError:
                # Get the UserName we added
                UserName = maybeUnhex((kindleDatabase[1])['UserName'])
                # encode it
                encodedUsername = encodeHash(UserName,charMap1)
                #print "encodedUsername",encodedUsername.encode('hex')
        except KeyError:
            print("Keys not found in the database {0}.".format(kindleDatabase[0]))
            return pids

        # Get the ID string used
        encodedIDString = encodeHash(IDString,charMap1)
        #print "encodedIDString",encodedIDString.encode('hex')

        # concat, hash and encode to calculate the DSN
        DSN = encode(SHA1(MazamaRandomNumber+encodedIDString+encodedUsername),charMap1)
        #print "DSN",DSN.encode('hex')
        pass
    extraDSNs=kindleDatabase[1].get('extra.dsns',[])
    extraDSNs=[maybeUnhex(f) for f in extraDSNs]
    extraDSNs.append(DSN)
    if rec209 is None:
        for DSN in extraDSNs:
          for accToken in extraKindleTokens:
            pids.append(DSN+accToken)
        return pids

    seen = set()

    def _add(pid10):
        pid_bytes = bytes(pid10)
        if pid_bytes not in seen:
            seen.add(pid_bytes)
            pids.append(pid_bytes)

    def _collect_variants(initial, raw_items, expand_fn, allow_empty=False):
        out = []
        for item in initial:
            b = bytes(item)
            if (allow_empty or b) and b not in out:
                out.append(b)
        for item in raw_items:
            if item:
                for v in expand_fn(item):
                    if v not in out:
                        out.append(v)
        return out

    db_rec = kindleDatabase[1]
    raw_tokens = [db_rec['kindle.account.tokens']] if db_rec.get('kindle.account.tokens') is not None else []
    raw_tokens += db_rec.get('kindle.account.secrets', []) + db_rec.get('kindle.account.clear_old_secrets', [])
    token_variants = _collect_variants(extraKindleTokens, raw_tokens, _unhex_variants, allow_empty=True)

    raw_dsns = [db_rec[k] for k in ('DSN', 'DSN_clear') if db_rec.get(k) is not None]
    raw_dsns += db_rec.get('extra.dsns', []) + db_rec.get('extra.dsns_clear', [])
    dsn_variants = _collect_variants(extraDSNs, raw_dsns, _serial_variants)

    # Compute the device PID (for which I can tell, is used for nothing).
    # Compute book PIDs
    table = generatePidEncryptionTable()
    for DSN in dsn_variants:
        _emit_dsn_pids(_add, table, DSN, rec209, token, token_variants, device_first=True)

    return pids

def getPidList(md1, md2, serials=[], kDatabases=[]):
    pidlst = []

    if kDatabases is None:
        kDatabases = []
    if serials is None:
        serials = []

    for kDatabase in kDatabases:
        try:
            pidlst.extend(map(bytes,getK4Pids(md1, md2, kDatabase)))
        except Exception as e:
            print("Error getting PIDs from database {0}: {1}".format(kDatabase[0],e.args[0]))
            traceback.print_exc()

    for serialnum in serials:
        try:
            pidlst.extend(map(bytes,getKindlePids(md1, md2, serialnum)))
        except Exception as e:
            print("Error getting PIDs from serial number {0}: {1}".format(serialnum ,e.args[0]))
            traceback.print_exc()

    return pidlst
