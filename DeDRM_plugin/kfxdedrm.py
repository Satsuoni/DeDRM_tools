#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Engine to remove drm from Kindle KFX ebooks

#  2.0   - Python 3 for calibre 5.0
#  2.1   - Some fixes for debugging
#  2.1.1 - Whitespace!


import os, sys
import shutil
import tempfile
import zipfile

from io import BytesIO


#@@CALIBRE_COMPAT_CODE@@


from ion import (DrmIon, DrmIonVoucher, SKeyList, needs_new_key_derivation,
                 unwrap_account_secrets,
                 ACCOUNT_SECRET_LENGTHS, SERIAL_PREFIX_LENGTHS,
                 unwrap_secret_token, split_serial_secret)
from utilities import RELATIONAL_CONTAINER_MAGIC, is_relational_container  # noqa: F401
import kindlekey



__license__ = 'GPL v3'
__version__ = '2.0'


# 40 characters in the app's form, 30 bytes after a base build's base64 decode. The
# derivation takes either, and the unwrapper shares this tuple.
ACCEPTED_SECRET_LENGTHS = ACCOUNT_SECRET_LENGTHS


# (serial length, secret length). The first pair whose lengths add up to the
# candidate's wins. Shapes older than the 30 character secret stay first, so the
# same PID reads the same way.
PID_SPLIT_LENGTHS = ((0, 0), (16, 0), (16, 40), (32, 0), (32, 40), (40, 0), (40, 40),
                     (16, 30), (32, 30), (40, 30), (0, 30))

# voucher magic (Ion envelope), then the DRMION magic
VOUCHER_MAGIC = b'\xe0\x01\x00\xea'
DRMION_MAGIC = b'\xeaDRMION\xee'

# delivery component suffixes: the container and what ships beside it
DELIVERY_COMPONENT_SUFFIXES = ('.azw8', '.azw9', '.md', '.res')

# the largest file read as a component -- a fragment database or a page envelope
MAX_DELIVERY_COMPONENT_BYTES = 512 * 1024 * 1024


def _same_file(path_a, path_b):
    if os.path.abspath(path_a) == os.path.abspath(path_b):
        return True
    try:
        return (
            os.path.exists(path_a)
            and os.path.exists(path_b)
            and os.path.samefile(path_a, path_b)
        )
    except OSError:
        return False


def _unwrap_pid_secrets(text, unwrap_fn=None):
    return unwrap_secret_token(text, allow_plain=False, unwrap_fn=unwrap_fn)


def _decode_str(val):
    if isinstance(val, (bytes, bytearray)):
        try:
            val = bytes(val).decode('utf-8', 'ignore')
        except Exception:
            return None
    return val.strip() if isinstance(val, str) else None


def _expand_totalpids(totalpids, serials=None, unwrap_fn=None):
    clean_serials = []
    for s in (serials or []):
        s = _decode_str(s)
        if s and s not in clean_serials:
            clean_serials.append(s)
    expanded = []
    bare_secrets = []
    for item in (totalpids or []):
        raw = _decode_str(item)
        if raw is None:
            continue
        if not raw:
            if '' not in expanded:
                expanded.append('')
            continue
        direct_secrets = _unwrap_pid_secrets(raw, unwrap_fn=unwrap_fn)
        if direct_secrets:
            for sec in direct_secrets:
                if sec not in expanded:
                    expanded.append(sec)
                if sec not in bare_secrets:
                    bare_secrets.append(sec)
            continue
        ser_part, rest_secrets = split_serial_secret(raw, unwrap_fn=unwrap_fn)
        if ser_part is not None:
            if ser_part not in clean_serials:
                clean_serials.append(ser_part)
            for sec in rest_secrets:
                comb = ser_part + sec
                if comb not in expanded:
                    expanded.append(comb)
                if sec not in bare_secrets:
                    bare_secrets.append(sec)
            continue
        if raw not in expanded:
            expanded.append(raw)
        if len(raw) in ACCEPTED_SECRET_LENGTHS and not raw.startswith('1+') and raw not in bare_secrets:
            bare_secrets.append(raw)
    for ser in clean_serials:
        if len(ser) in SERIAL_PREFIX_LENGTHS:
            for sec in bare_secrets:
                if ser != sec and (ser + sec) not in expanded:
                    expanded.append(ser + sec)
    return expanded


def _is_delivery_component(name, data):
    # the voucher isn't one: it's the key document, and it comes out decrypted. A
    # renamed component is caught by its magic.
    if data[:4] == VOUCHER_MAGIC:
        return False
    if name.lower().endswith(DELIVERY_COMPONENT_SUFFIXES):
        return True
    return data.startswith(DRMION_MAGIC) or data.startswith(RELATIONAL_CONTAINER_MAGIC)


def _sibling_delivery_components(infile):
    """(name, document) for each component beside infile, source excluded.

    Siblings of an unpacked delivery. Read once, not walked, sorted so the output
    archive comes out the same twice.
    """
    directory = os.path.dirname(os.path.abspath(infile))
    base = os.path.basename(os.path.abspath(infile))
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return []
    components = []
    for name in names:
        if name == base or name.startswith('.'):
            continue
        path = os.path.join(directory, name)
        try:
            if not os.path.isfile(path):
                continue
            if os.path.getsize(path) > MAX_DELIVERY_COMPONENT_BYTES:
                continue
            with open(path, 'rb') as component_file:
                data = component_file.read()
        except OSError:
            continue
        if _is_delivery_component(name, data):
            components.append((name, data))
    return components


def _open_delivery_component(data, content_key, key_holder, skeylist=None):
    # the image, or None when there's nothing to open -- the caller carries the bytes
    # through unchanged
    if data.startswith(DRMION_MAGIC):
        try:
            plain_envelope = _is_plain_envelope_component(data)
        except Exception:  # noqa: BLE001 - no kfx_stages
            plain_envelope = False
        if not plain_envelope:
            if key_holder is None:
                return None
            outfile = BytesIO()
            DrmIon(BytesIO(data[8:-8]), key_holder, skeylist).parse(outfile)
            return outfile.getvalue()
    return _open_relational_component(data, content_key)


def _stage_ladder():
    """kfx_stages, or None on a host that doesn't have it.

    Imported here, not at the top: Python 3 only, and a host without it should still
    run the plain sweep.
    """
    try:
        import kfx_stages
        return kfx_stages
    except Exception as ex:  # noqa: BLE001 - no kfx_stages
        print("The migrated derivation stages are not available on this host ({0}); using "
              "the built-in candidate sweep only.".format(type(ex).__name__))
        return None


def _stage_credential_maps(candidate_strings):
    """Credential maps for kfx_stages, from the plugin's candidates.

    A candidate is serial then secret, split by the sweep's matrix. A bare secret gets
    an entry too, or the matrix reads it as a serial and loses it.
    """
    maps = [{}]
    seen = set()
    for candidate in candidate_strings:
        if isinstance(candidate, bytes):
            try:
                candidate = candidate.decode('ascii')
            except Exception:
                continue
        if not candidate:
            continue
        pairs = []
        for dsn_len, secret_len in PID_SPLIT_LENGTHS:
            if len(candidate) == dsn_len + secret_len:
                if dsn_len or secret_len:
                    pairs.append((candidate[:dsn_len], candidate[dsn_len:]))
                break
        if len(candidate) in ACCEPTED_SECRET_LENGTHS:
            # bare secret: no matrix pair fits, so it gets an empty serial
            pairs.append(('', candidate))
        for pair in pairs:
            if pair in seen:
                continue
            seen.add(pair)
            credentials = {}
            if pair[0]:
                credentials['client_id'] = [pair[0]]
            if pair[1]:
                credentials['account_secret'] = [pair[1]]
            maps.append(credentials)
    return maps


def _key_passes_oracle(key, oracle_source):
    """Only an explicit REJECTED verdict fails; no oracle at all passes."""
    if oracle_source is None or not key or len(key) != 16:
        return True
    stages = _stage_ladder()
    if stages is None:
        return True
    try:
        verdict = stages.verify_page(oracle_source, key)
    except Exception:  # noqa: BLE001 - unreadable, no page to check
        return True
    return not (verdict is not None and verdict.get('verdict') == 'REJECTED')


def _stage_key(envelope, candidate_strings, oracle_source=None):
    """The 16-byte content key for one envelope, from kfx_stages, or None.

    None when no family claims the envelope, the credentials derive nothing, or the key
    doesn't open the first encrypted page (00 5d). The caller's sweep runs as before.
    """
    if not envelope:
        return None
    stages = _stage_ladder()
    if stages is None:
        return None
    try:
        family = stages.classify(envelope)
    except Exception as ex:  # noqa: BLE001 - unparseable envelope
        print("The voucher envelope could not be classified ({0}).".format(type(ex).__name__))
        return None
    if family is None:
        return None
    print("The voucher envelope belongs to the {0} derivation family".format(family))
    for credentials in _stage_credential_maps(candidate_strings):
        try:
            key = stages.derive(family, envelope, credentials)
        except Exception:
            # a refusal here is normal, not a failed run -- the sweep goes on
            continue
        if not key or len(key) != 16:
            continue
        if not _key_passes_oracle(key, oracle_source):
            print("A stage-derived key did not open the first encrypted page")
            continue
        return bytes(key)
    return None


def _is_plain_envelope_component(data):
    """True for a plain encrypted envelope, not a DRMION document.

    Both start with the same eight magic bytes, so the first token decides: a DRMION
    carries a doctype, a plain component its page pair. An unreadable token counts as
    not-a-doctype; with no pages, the DRMION path takes it and reports its own error.
    """
    if not data.startswith(DRMION_MAGIC):
        return False
    if _stage_ladder() is None:
        return False
    try:
        from kfx_stages import _envelope, _ion
    except Exception:  # noqa: BLE001 - no kfx_stages
        return False

    try:
        first = _ion.IonReader(data[8:]).read_value()
    except Exception:  # noqa: BLE001 - unparseable, not a doctype
        first = None
    if first is not None and (
        first.text == "doctype"
        or first.sid == 50
        or 50 in first.annotations
    ):
        return False
    return bool(_envelope.envelope_pages(data))


def _open_relational_component(data, content_key):
    # the image, or None if this isn't a relational container -- the caller leaves it alone
    stages = _stage_ladder()
    if stages is None or not data:
        return None
    try:
        from kfx_stages import _envelope
    except Exception:  # noqa: BLE001 - no kfx_stages
        return None

    kind = _envelope.payload_kind(data)
    if kind == 'relational':
        return stages.decrypt_relational(data, content_key)
    if kind != 'envelope':
        return None
    pages = _envelope.envelope_pages(data)
    if not pages:
        return None
    if any(iv is not None for iv, _ct in pages):
        inner = _envelope.decrypt_component(data, content_key)
    else:
        inner = _envelope.expand_plain_envelope(data)
    if not _envelope.is_relational_container(inner):
        return None
    return stages.decrypt_relational(inner, content_key)


def _content_key_from_voucher(voucher):
    secret = getattr(voucher, 'secretkey', None)
    if isinstance(secret, (bytes, bytearray)) and len(secret) >= 16:
        return bytes(secret[:16])
    return None


def _sibling_voucher_documents(infile):
    """(label, document) for each voucher beside a standalone container file.

    A container out of a delivery lost the archive that carried its voucher, so look
    beside it: same-stem vouchers first, then other vouchers, then archives with the same
    base name, then the rest. Dedup by content, in that order. Read once; nothing outside
    the directory is opened.
    """
    abspath = os.path.abspath(infile)
    directory = os.path.dirname(abspath)
    source_name = os.path.basename(abspath)
    base = os.path.splitext(source_name)[0]
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return

    def _prioritize_by_stem(items):
        out = [n for n in items if os.path.splitext(n)[0] == base]
        out += [n for n in items if n.startswith(base) and n not in out]
        out += [n for n in items if n not in out]
        return out

    seen = set()
    direct_files = [
        name for name in names
        if name != source_name and not name.startswith('.')
        and not name.lower().endswith(('.kfx-zip', '.zip'))
    ]
    voucher_named = [name for name in direct_files if name.lower().endswith(('.voucher', '.ion'))]
    ordered_direct = _prioritize_by_stem(voucher_named)
    ordered_direct += [name for name in direct_files if name not in ordered_direct]

    for name in ordered_direct:
        path = os.path.join(directory, name)
        try:
            if not os.path.isfile(path):
                continue
            if os.path.getsize(path) > MAX_DELIVERY_COMPONENT_BYTES:
                continue
            with open(path, 'rb') as document_file:
                head = document_file.read(4)
                if head != VOUCHER_MAGIC:
                    continue
                document = head + document_file.read()
        except OSError:
            continue
        if b'ProtectedData' in document and document not in seen:
            seen.add(document)
            yield (name, document)

    archives = [
        name for name in names
        if name != source_name and name.lower().endswith(('.kfx-zip', '.zip'))
    ]
    for name in _prioritize_by_stem(archives):
        path = os.path.join(directory, name)
        try:
            with zipfile.ZipFile(path, 'r') as zf:
                for entry in zf.namelist():
                    document = zf.read(entry)
                    if (document[:4] == VOUCHER_MAGIC
                            and b'ProtectedData' in document
                            and document not in seen):
                        seen.add(document)
                        yield ("{0}:{1}".format(name, entry), document)
        except (zipfile.BadZipFile, OSError, RuntimeError):
            continue


class _DerivedKeyVoucher(object):
    """A voucher shape around a key derived by kfx_stages, not a decrypted envelope.

    The page reader takes one field from what it's handed, so a 16-byte key is all it
    needs.
    """

    license_type = ""

    def __init__(self, content_key):
        self.secretkey = bytes(content_key)


class KFXZipBook:
    def __init__(self, infile,skeyfile=None,serials=None,original_path=None):
        self.infile = infile
        # A snapshot: the caller goes on to extend its serial list with Android dbs.
        self.serials = list(serials or [])
        if skeyfile is not None:
          self.skeylist=SKeyList(skeyfile)
        else:
          self.skeylist=None
        self.voucher = None
        # a key from kfx_stages, if the sweep found no voucher
        self.derived_key = None
        # the 16 bytes the page cipher uses, whatever produced them
        self.content_key = None
        self.oracle_source = self.infile
        self.decrypted = {}
        # components found beside the source, not inside it
        self.external_components = {}
        self.delivery_components = {}
        self.delivery_bundle = False
        self.original_path=original_path
        if(self.original_path is None):
          self.original_path=self.infile
    def getPIDMetaInfo(self):
        return (None, None)

    def _key_holder(self, name):
        if self.voucher is not None:
            return self.voucher
        if self.derived_key is not None:
            return _DerivedKeyVoucher(self.derived_key)
        return None

    def _open_relational_components(self, zf, totalpids):
        # a component that refuses the key goes through untouched, not half decrypted
        if _stage_ladder() is None:
            return
        try:
            from kfx_stages import _envelope
        except Exception:  # noqa: BLE001 - no kfx_stages
            return

        pending = []
        for info in zf.infolist():
            if info.filename in self.decrypted:
                continue
            data = zf.read(info.filename)
            if _envelope.payload_kind(data) in ('relational', 'envelope'):
                pending.append((info.filename, data))
        if not pending:
            return
        if self.content_key is None:
            # its voucher is beside it, not in a DRMION entry
            self._ensure_content_key(totalpids)
        if self.content_key is None:
            return
        for filename, data in pending:
            try:
                opened = _open_relational_component(data, self.content_key)
            except Exception as ex:  # noqa: BLE001 - reported
                print("A relational container component could not be opened ({0}: {1}); it "
                      "is passed through unchanged.".format(type(ex).__name__, ex))
                continue
            if opened is None:
                continue
            print("Decrypted relational container: {0}".format(filename))
            self.decrypted[filename] = opened

    def _add_sibling_delivery_components(self, zf, totalpids):
        # a partial bundle needs its siblings, or the format step never sees every
        # fragment. Ones the archive already carries are skipped; one that refuses the
        # key, or holds nothing to open, goes through unchanged rather than corrupted.
        known = set(zf.namelist())
        siblings = [(name, data) for name, data in _sibling_delivery_components(self.original_path or self.infile)
                    if name not in known]
        if not siblings:
            return
        if self.content_key is None:
            self._ensure_content_key(totalpids)
        opened_count = 0
        for name, data in siblings:
            opened = None
            if self.content_key is not None:
                try:
                    opened = _open_delivery_component(data, self.content_key, self._key_holder,
                                                      self.skeylist)
                except Exception as ex:  # noqa: BLE001 - reported, and carried unchanged
                    print("A delivery component beside the archive could not be opened ({0}: "
                          "{1}); it is carried through unchanged.".format(type(ex).__name__, ex))
            if opened is None:
                opened = data
            else:
                opened_count += 1
            self.external_components[name] = opened
        print("Packaged {0:d} delivery component(s) found beside the archive; {1:d} opened."
              .format(len(siblings), opened_count))

    def processBook(self, totalpids):
        totalpids = _expand_totalpids(totalpids, self.serials)
        with zipfile.ZipFile(self.infile, 'r') as zf:
            for filename in zf.namelist():
                with zf.open(filename) as fh:
                    data = fh.read(8)
                    if data != DRMION_MAGIC:
                        continue
                    data += fh.read()
                    if _is_plain_envelope_component(data):
                        # an encrypted component, not a DRMION. The container pass below
                        # opens wrapped relational ones.
                        continue
                    if self.voucher is None and self.derived_key is None:
                        self.decrypt_voucher(totalpids)
                    print("Decrypting KFX DRMION: {0}".format(filename))
                    outfile = BytesIO()
                    DrmIon(BytesIO(data[8:-8]), self._key_holder,self.skeylist).parse(outfile)
                    self.decrypted[filename] = outfile.getvalue()

            self._open_relational_components(zf, totalpids)
            self._add_sibling_delivery_components(zf, totalpids)

        if not self.decrypted:
            print("The .kfx-zip archive does not contain an encrypted DRMION file")

    def voucher_needs_account_secret(self, data):
        """Whether the voucher in this archive derives its key from the account secret.

        A new-style version is not enough on its own. The derivation reads the lock
        parameter values, and a voucher that declares no ACCOUNT_SECRET does not consume
        one, so asking the user for a secret would send them after a credential it never
        uses. The 10014 vouchers on Kindles that were never given one carry a client id
        alone, and a voucher that declares no lock parameters at all is derived from its
        voucher id.

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
                and (needs_new_key_derivation(voucher.version, voucher.lockparams)
                     or voucher.version in (7384, 2746, 3332)))

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
            #print("Original path to file (presumed): {}".format(self.original_path))
            values=[]
            value = kindlekey.get_device_setting(name,os.path.dirname(self.original_path))
            if not value:
                continue
            try:
                if name == 'acsr':
                    values = unwrap_account_secrets(value)
                    print("Got {} values from secrets file: {}".format(len(values),values))
                else:
                    if isinstance(value, bytes):
                      value = value.decode('ASCII')
                    values=value.split(",")
            except Exception as ex:
                print("Could not read the {0} file on the device: {1}".format(name, ex))
                continue
            for value in values:
              if isinstance(value, bytes):
                try:
                  value = value.decode('ASCII')
                except Exception as e:
                  print("Invalid value: {}".format(e))
                  continue
              if len(value) not in ACCEPTED_SECRET_LENGTHS:
                  print("The {0} file on the device does not hold a 30 or 40 character "
                        "account secret (it is {1} characters).".format(name, len(value)))
                  continue
              if value not in secrets:
                  secrets.append(value)
        candidates = [serial + secret
                      for serial in self.serials for secret in secrets]
        for secret in secrets:
            if secret not in candidates:
                candidates.append(secret)
        return candidates

    def _voucher_document(self):
        with zipfile.ZipFile(self.infile, 'r') as zf:
            for info in zf.infolist():
                with zf.open(info.filename) as fh:
                    data = fh.read(4)
                    if data != VOUCHER_MAGIC:
                        continue
                    data += fh.read()
                    if b'ProtectedData' in data:
                        return data, info.filename
        return None, None

    def _voucher_documents(self):
        data, label = self._voucher_document()
        if data is not None:
            yield data, label

    def _no_voucher_message(self):
        #raise Exception("The .kfx-zip archive contains an encrypted DRMION file without a DRM voucher")
        return ("The .kfx-zip archive contains an encrypted DRMION file without a DRM "
                "voucher. Just in case it is a rare decrypted KFX, we continue")

    def decrypt_voucher(self, totalpids):
        if not self._ensure_content_key(totalpids, check_voucher=True):
            print(self._no_voucher_message())
            self.voucher = None

    def _ensure_content_key(self, totalpids, check_voucher=False):
        if not check_voucher and self.content_key is not None:
            return self.content_key
        found = False
        for data, voucher_label in self._voucher_documents():
            found = True
            print("Decrypting KFX DRM voucher: {0}".format(voucher_label))
            self._apply_derivation(data, totalpids)
            if self.content_key is not None or (check_voucher and self.voucher is not None):
                break
        return found if check_voucher else self.content_key

    def _apply_derivation(self, data, totalpids):
        voucher, derived_key = self._derive_voucher(data, totalpids)
        if voucher is not None:
            self.voucher = voucher
            self.content_key = _content_key_from_voucher(voucher)
            return
        if derived_key is not None:
            # kfx_stages verified a key but opened no envelope we can read -- the page
            # reader gets a stand-in
            self.voucher = None
            self.derived_key = derived_key
            self.content_key = derived_key
            return
        self.voucher = None

    def _derive_voucher(self, data, totalpids):
        """(voucher, derived key) for one voucher document; at most one is set.

        kfx_stages first, then the candidate sweep -- which covers every family with no
        stage engine, and stands in when kfx_stages is missing, can't classify, or
        derives nothing.
        """
        # Voucher versions from 10001 on need the account secret and the device serial
        # rather than a serial-derived PID. A serial-derived PID on its own cannot
        # decrypt one of these, so the account secret pair is tried first rather than
        # only when nothing else was supplied.
        #
        # reading the secret probes the mounted device (and the MTP cache), so the scan
        # runs up front only when the derivation says it consumes one. Others try the
        # credentials in hand first, the device only if none worked.
        needs_secret = self.voucher_needs_account_secret(data)
        secret_pids = self.account_secret_pids() if needs_secret else []
        candidates = secret_pids + [''] + list(totalpids)

        derived_key = _stage_key(data, candidates, oracle_source=self.oracle_source)
        if derived_key is not None:
            print("The KFX DRM voucher key was derived and verified by the migrated stages")
            return None, derived_key

        voucher = None
        lastexception = None

        def try_pids(pids):
            nonlocal lastexception
            for pid in pids:
                # Belt and braces. PIDs should be unicode strings, but just in case...
                if isinstance(pid, bytes):
                    pid = pid.decode('ascii')
                for dsn_len,secret_len in PID_SPLIT_LENGTHS:
                    if len(pid) == dsn_len + secret_len:
                        break       # split pid into DSN and account secret
                else:
                    continue

                try:
                    candidate = DrmIonVoucher(BytesIO(data), pid[:dsn_len], pid[dsn_len:],self.skeylist,
                                              quiet=True, stage_fallback=False)
                    candidate.parse()
                    candidate.decryptvoucher()
                except Exception as ex:
                    # A wrong candidate. The reason is kept so that a total failure can
                    # report why the last attempt did not work.
                    lastexception = ex
                    continue
                return candidate
            return None

        voucher = try_pids(candidates)
        if voucher is None and needs_secret is not True:
            # nothing supplied worked and no secret is declared, so try the device
            secret_pids = self.account_secret_pids()
            if secret_pids:
                derived_key = _stage_key(data, secret_pids, oracle_source=self.oracle_source)
                if derived_key is not None:
                    print("The KFX DRM voucher key was derived and verified by the migrated stages")
                    return None, derived_key
                voucher = try_pids(secret_pids + [''])

        if voucher is None:
            if needs_secret is None:
                print("The KFX DRM voucher could not be read at all.")
            elif needs_secret and not secret_pids:
                print("This KFX DRM voucher is keyed on the device account secret, which "
                      "is not available. It needs the Kindle's serial number in the "
                      "plugin's settings, and its acsr file in a de-drm-secrets folder on "
                      "the mounted Kindle; see Other_Tools/Kindle_Account_Secret/ for how "
                      "to get that file. Decryption will probably not work.")
            else:
                print("Failed to decrypt the KFX DRM voucher with any key.")
                if lastexception is not None:
                    print("The last key tried was rejected: {0}: {1}".format(
                        type(lastexception).__name__, lastexception))
                print("Check that the serial number and account secret belong to the device "
                      "this book was downloaded for.")
            return None, None

        print("KFX DRM voucher successfully decrypted")

        license_type = voucher.getlicensetype()
        if license_type != "Purchase":
            #raise Exception(("This book is licensed as {0}. "
            #        'These tools are intended for use on purchased books.').format(license_type))
            print("Warning: This book is licensed as {0}. "
                    "These tools are intended for use on purchased books. Continuing ...".format(license_type))

        return voucher, None

    def getBookTitle(self):
        return os.path.splitext(os.path.split(self.infile)[1])[0]

    def getBookExtension(self):
        return '.kfx-zip'

    def getBookType(self):
        return 'KFX-ZIP'

    def cleanup(self):
        pass

    def getFile(self, outpath):
        if not self.decrypted and not self.external_components:
            if not _same_file(self.infile, outpath):
                shutil.copyfile(self.infile, outpath)
            return

        def _write_zip(tmp_path):
            with zipfile.ZipFile(self.infile, 'r') as zif, zipfile.ZipFile(tmp_path, 'w') as zof:
                written = set()
                for info in zif.infolist():
                    zof.writestr(info, self.decrypted.get(info.filename, zif.read(info.filename)))
                    written.add(info.filename)
                for name, data in self.external_components.items():
                    if name not in written:
                        zof.writestr(name, data)

        _atomic_replace(outpath, _write_zip)


def _atomic_replace(outpath, write_fn):
    outdir = os.path.dirname(os.path.abspath(outpath)) or "."
    fd, tmp_path = tempfile.mkstemp(
        prefix=os.path.basename(outpath) + ".",
        suffix=".part",
        dir=outdir,
    )
    os.close(fd)
    try:
        write_fn(tmp_path)
        os.replace(tmp_path, outpath)
    except Exception:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        raise


class KFXContainerBook(KFXZipBook):
    """A bare relational container file, opened with a voucher from beside it.

    Exporting a delivery drops the archive that carried the voucher, so look beside it.
    Nothing outside that directory is read, and the output never replaces the source.
    Any key has to verify against the container's own first encrypted page; an
    unencrypted file goes out with its fingerprints stripped.
    """

    def _voucher_documents(self):
        if '_voucher_document' in self.__dict__:
            data, label = self._voucher_document()
            if data is not None:
                yield data, label
            return
        for label, document in _sibling_voucher_documents(self.original_path or self.infile):
            yield document, label

    def _voucher_document(self):
        for label, document in _sibling_voucher_documents(self.original_path or self.infile):
            return document, label
        return None, None

    def _apply_derivation(self, data, totalpids):
        super()._apply_derivation(data, totalpids)
        if self.content_key is not None and not _key_passes_oracle(
            self.content_key, self.oracle_source
        ):
            self.voucher = None
            self.derived_key = None
            self.content_key = None

    def _no_voucher_message(self):
        return ("No DRM voucher was found for this container. Put the container beside the "
                ".kfx-zip archive it came from, or a voucher document, and try again. "
                "Passing the file back unchanged.")

    def processBook(self, totalpids):
        totalpids = _expand_totalpids(totalpids, self.serials)
        with open(self.infile, 'rb') as container_file:
            data = container_file.read()
        if not data.startswith(RELATIONAL_CONTAINER_MAGIC):
            print("This file is not a relational container. Passing it back unchanged.")
            return
        # the oracle reads the container's own first page, so it gets the image, not a path
        self.oracle_source = data
        self.decrypt_voucher(totalpids)
        siblings = _sibling_delivery_components(self.original_path or self.infile)
        if siblings:
            # an imported component, not a lone container: the rest of the delivery is
            # beside it
            self._package_delivery_bundle(data, siblings)
            return
        if self.content_key is None:
            return
        try:
            opened = _open_relational_component(data, self.content_key)
        except Exception as ex:  # noqa: BLE001 - reported, source untouched
            print("The container could not be opened with the derived key ({0}: {1}).".format(
                type(ex).__name__, ex))
            return
        if opened is None:
            print("The container holds no rows this build can open.")
            return
        print("Decrypted relational container: {0}".format(os.path.basename(self.infile)))
        self.decrypted[self.infile] = opened

    def _package_delivery_bundle(self, primary, siblings):
        entries = [(os.path.basename(self.original_path or self.infile), primary)] + list(siblings)
        opened_count = 0
        for name, component in entries:
            opened = None
            if self.content_key is not None:
                try:
                    opened = _open_delivery_component(component, self.content_key,
                                                      self._key_holder, self.skeylist)
                except Exception as ex:  # noqa: BLE001 - reported, carried through unchanged
                    print("A delivery component could not be opened ({0}: {1}); it is carried "
                          "through unchanged.".format(type(ex).__name__, ex))
            if opened is None:
                opened = component
            else:
                opened_count += 1
            self.delivery_components[name] = opened
        self.delivery_bundle = True
        print("Packaged a delivery bundle of {0:d} component(s); {1:d} opened.".format(
            len(entries), opened_count))

    def getBookExtension(self):
        return '.kfx-zip' if self.delivery_bundle else '.kfx'

    def getBookType(self):
        return 'KFX delivery bundle' if self.delivery_bundle else 'KFX container'

    def getFile(self, outpath):
        if self.delivery_bundle:
            def _write_bundle(tmp_path):
                with zipfile.ZipFile(tmp_path, 'w') as zof:
                    for name, data in self.delivery_components.items():
                        zof.writestr(name, data)
            _atomic_replace(outpath, _write_bundle)
            return
        if not self.decrypted:
            if not _same_file(self.infile, outpath):
                shutil.copyfile(self.infile, outpath)
            return
        image = next(iter(self.decrypted.values()))
        def _write_image(tmp_path):
            with open(tmp_path, 'wb') as outfile:
                outfile.write(image)
        _atomic_replace(outpath, _write_image)
