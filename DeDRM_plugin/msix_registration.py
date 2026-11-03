"""Read the Kindle MSIX client ID from the local Windows registration_data file.

The Kindle MSIX installation stores registration_data beside Classic/. Unlike the
.kinf2024 records, this file is a Base64-encoded Windows DPAPI blob. Recovery
must run under the Windows user who registered Kindle. Nothing is written back
to disk, and no plaintext identifiers are logged.
"""

import base64
import binascii
import ctypes
import json
import os
from ctypes import wintypes


def _unprotect_windows_dpapi(ciphertext):
    """Return decrypted DPAPI bytes or None, without displaying the result."""
    if os.name != "nt" or not ciphertext:
        return None

    class DataBlob(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ]

    buf = (ctypes.c_ubyte * len(ciphertext)).from_buffer_copy(ciphertext)
    encrypted = DataBlob(len(ciphertext), buf)
    plaintext = DataBlob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    unprotect = crypt32.CryptUnprotectData
    unprotect.argtypes = [
        ctypes.POINTER(DataBlob), ctypes.c_void_p, ctypes.POINTER(DataBlob),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(DataBlob),
    ]
    unprotect.restype = wintypes.BOOL

    if not unprotect(ctypes.byref(encrypted), None, None, None, None, 1,
                     ctypes.byref(plaintext)):
        return None
    try:
        return ctypes.string_at(plaintext.pbData, plaintext.cbData)
    finally:
        free = ctypes.WinDLL("kernel32", use_last_error=True).LocalFree
        free.argtypes = [ctypes.c_void_p]
        free.restype = ctypes.c_void_p
        free(ctypes.cast(plaintext.pbData, ctypes.c_void_p))


def recover_registration_dsn(kinfo_file, unprotect=None):
    """Return the local Kindle MSIX DSN as ASCII bytes, or None.

    kinfo_file is the .kinf2024 location, normally
    LocalState/Classic/Data/storage/.kinf2024.
    The DPAPI-protected registration_data is in LocalState/.
    """
    if os.path.basename(kinfo_file).lower() != ".kinf2024":
        return None
    if unprotect is None:
        unprotect = _unprotect_windows_dpapi

    registration = os.path.normpath(os.path.join(
        os.path.dirname(os.path.abspath(kinfo_file)),
        "..", "..", "..", "registration_data"))
    try:
        with open(registration, "rb") as fh:
            encoded = fh.read()
        if not encoded or len(encoded) > 1024 * 1024:
            return None
        encrypted = base64.b64decode(encoded)
        decoded = unprotect(encrypted)
        if not decoded:
            return None
        details = json.loads(decoded.decode("utf-8-sig"))
        dsn = details.get("dsn")
        if not isinstance(dsn, str) or len(dsn) not in (16, 32, 40):
            return None
        return dsn.encode("ascii")
    except (OSError, ValueError, TypeError, UnicodeError, binascii.Error):
        return None
