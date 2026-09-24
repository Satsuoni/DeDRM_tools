#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Engine to remove drm from Kindle KFX ebooks

#  2.0   - Python 3 for calibre 5.0
#  2.1   - Some fixes for debugging
#  2.1.1 - Whitespace!


import os, sys
import shutil
import traceback
import zipfile

from io import BytesIO


#@@CALIBRE_COMPAT_CODE@@


from ion import (DrmIon, DrmIonVoucher, SKeyList, needs_new_key_derivation,
                 unwrap_account_secret)
import kindlekey



__license__ = 'GPL v3'
__version__ = '2.0'


class KFXZipBook:
    def __init__(self, infile,skeyfile=None,serials=None):
        self.infile = infile
        # A snapshot: the caller goes on to extend its serial list with Android dbs.
        self.serials = list(serials or [])
        if skeyfile is not None:
          self.skeylist=SKeyList(skeyfile)
        else:
          self.skeylist=None
        self.voucher = None
        self.decrypted = {}

    def getPIDMetaInfo(self):
        return (None, None)

    def processBook(self, totalpids):
        with zipfile.ZipFile(self.infile, 'r') as zf:
            for filename in zf.namelist():
                with zf.open(filename) as fh:
                    data = fh.read(8)
                    if data != b'\xeaDRMION\xee':
                        continue
                    data += fh.read()
                    if self.voucher is None:
                        self.decrypt_voucher(totalpids)
                    print("Decrypting KFX DRMION: {0}".format(filename))
                    outfile = BytesIO()
                    DrmIon(BytesIO(data[8:-8]), lambda name: self.voucher,self.skeylist).parse(outfile)
                    self.decrypted[filename] = outfile.getvalue()

        if not self.decrypted:
            print("The .kfx-zip archive does not contain an encrypted DRMION file")

    def voucher_needs_account_secret(self, data):
        """Whether the voucher in this archive derives its key from the account secret.

        A new-style version is not enough on its own. The derivation reads the lock
        parameter values, and a voucher that declares no ACCOUNT_SECRET uses the serial
        alone, so asking the user for a secret would send them after a credential this
        voucher never consumes. The 10014 vouchers on Kindles that were never given one
        are exactly that shape.

        Returns None when the envelope cannot be read at all, so a caller can tell a
        voucher this build does not understand from one that does not need the secret.
        """
        try:
            voucher = DrmIonVoucher(BytesIO(data), '', '', self.skeylist)
            voucher.parse()
        except Exception as ex:
            print("Could not read the KFX voucher envelope: {0}: {1}".format(type(ex).__name__, ex))
            return None
        return ("ACCOUNT_SECRET" in voucher.lockparams
                and needs_new_key_derivation(voucher.version, voucher.lockparams))

    def account_secret_pids(self):
        """PIDs built from the account secret, for voucher versions that need it.

        A voucher keyed on the account secret is derived from the device serial followed
        by the secret, which is the PID shape the caller's split loop expects.

        The secret is read from a connected Kindle: acsr holds it wrapped, and
        account_secret holds it plain. Problems with the files are reported here; a total
        absence is not, because the caller reports that together with the other
        prerequisites.
        """
        secrets = []
        for name in ('acsr', 'account_secret'):
            value = kindlekey.get_device_setting(name)
            if not value:
                continue
            try:
                if name == 'acsr':
                    value = unwrap_account_secret(value)
            except Exception as ex:
                print("Could not read the {0} file on the device: {1}".format(name, ex))
                continue
            if isinstance(value, bytes):
                value = value.decode('ASCII')
            if len(value) != 40:
                print("The {0} file on the device does not hold a 40 character account "
                      "secret (it is {1} characters).".format(name, len(value)))
                continue
            secrets.append(value)
        return [serial + secret
                for serial in self.serials for secret in secrets]

    def decrypt_voucher(self, totalpids):
        with zipfile.ZipFile(self.infile, 'r') as zf:
            for info in zf.infolist():
                with zf.open(info.filename) as fh:
                    data = fh.read(4)
                    if data != b'\xe0\x01\x00\xea':
                        continue

                    data += fh.read()
                    if b'ProtectedData' in data:
                        break   # found DRM voucher
            else:
                #raise Exception("The .kfx-zip archive contains an encrypted DRMION file without a DRM voucher")
                print("The .kfx-zip archive contains an encrypted DRMION file without a DRM voucher. Just in case it is a rare decrypted KFX, we continue")
                self.voucher = None
                return
        print("Decrypting KFX DRM voucher: {0}".format(info.filename))

        # Voucher versions from 10001 on need the account secret and the device serial
        # rather than a serial-derived PID. A serial-derived PID on its own cannot
        # decrypt one of these, so the account secret pair is tried first rather than
        # only when nothing else was supplied.
        needs_secret = self.voucher_needs_account_secret(data)
        secret_pids = self.account_secret_pids() if needs_secret else []
        pids = secret_pids + [''] + totalpids

        voucher = None
        lastexception = None
        for pid in pids:
            # Belt and braces. PIDs should be unicode strings, but just in case...
            if isinstance(pid, bytes):
                pid = pid.decode('ascii')
            for dsn_len,secret_len in [(0,0), (16,0), (16,40), (32,0), (32,40), (40,0), (40,40)]:
                if len(pid) == dsn_len + secret_len:
                    break       # split pid into DSN and account secret
            else:
                continue

            try:
                candidate = DrmIonVoucher(BytesIO(data), pid[:dsn_len], pid[dsn_len:],self.skeylist,
                                          quiet=True)
                candidate.parse()
                candidate.decryptvoucher()
            except Exception as ex:
                # A wrong candidate. The reason is kept so that a total failure can
                # report why the last attempt did not work.
                lastexception = ex
                continue
            voucher = candidate
            break

        if voucher is None:
            self.voucher = None
            if needs_secret is None:
                print("The KFX DRM voucher could not be read at all.")
            elif needs_secret and not secret_pids:
                print("This KFX DRM voucher is keyed on the device account secret, which "
                      "is not available. It needs the Kindle's serial number in the "
                      "plugin's settings, and its acsr file in a de-drm-secrets folder on "
                      "the mounted Kindle; see Other_Tools/Kindle_Account_Secret/ for how "
                      "to get that file.")
            else:
                print("Failed to decrypt the KFX DRM voucher with any key.")
                if lastexception is not None:
                    print("The last key tried was rejected: {0}: {1}".format(
                        type(lastexception).__name__, lastexception))
                print("Check that the serial number and account secret belong to the device "
                      "this book was downloaded for.")
            return

        print("KFX DRM voucher successfully decrypted")

        license_type = voucher.getlicensetype()
        if license_type != "Purchase":
            #raise Exception(("This book is licensed as {0}. "
            #        'These tools are intended for use on purchased books.').format(license_type))
            print("Warning: This book is licensed as {0}. "
                    "These tools are intended for use on purchased books. Continuing ...".format(license_type))

        self.voucher = voucher

    def getBookTitle(self):
        return os.path.splitext(os.path.split(self.infile)[1])[0]

    def getBookExtension(self):
        return '.kfx-zip'

    def getBookType(self):
        return 'KFX-ZIP'

    def cleanup(self):
        pass

    def getFile(self, outpath):
        if not self.decrypted:
            shutil.copyfile(self.infile, outpath)
        else:
            with zipfile.ZipFile(self.infile, 'r') as zif:
                with zipfile.ZipFile(outpath, 'w') as zof:
                    for info in zif.infolist():
                        zof.writestr(info, self.decrypted.get(info.filename, zif.read(info.filename)))
