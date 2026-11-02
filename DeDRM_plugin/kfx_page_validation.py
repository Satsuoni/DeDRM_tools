"""Format-aware validation for compressed and uncompressed DRMION components. Provided by @Jadehawk

A compressed candidate is ALWAYS handled by the preexisting LZMA oracle.
An uncompressed candidate is accepted only when a minimum of three separated,
independently encrypted pages exhibit valid PKCS#7 padding under the same key.
No content or credentials are logged; failed or ambiguous checks reject.
"""
import zipfile
from collections import Counter

def _nodes(node, depth=0):
    if depth > 25:
        return
    yield node
    for children in node.fields.values():
        for child in children:
            yield from _nodes(child, depth+1)
    for child in node.items:
        yield from _nodes(child, depth+1)


def page_classes(raw):
    """Return per-container classification, without using any secret/key.

    An encrypted page's compressed bit is determined by the presence of the
    Compressed@1.0 annotation inside the EncryptedPage node; not inferred
    from ciphertext or the first-page oracle.
    """
    from kfx_stages import _envelope, _ion
    result = Counter()
    if not raw.startswith(_envelope.ENVELOPE_MAGIC):
        return result
    reader = _ion.IonReader(raw[len(_envelope.ENVELOPE_MAGIC):])
    while reader.pos < len(reader.data):
        try:
            node = reader.read_value()
        except Exception:
            result["parser_stopped"] += 1
            break
        if node is None:
            continue
        for subnode in _nodes(node):
            names = tuple(_ion.symbol_name(sid) or "" for sid in subnode.annotations)
            if any("com.amazon.drm.EncryptedPage@" in name for name in names):
                descendant_compressed = any(
                    "com.amazon.drm.Compressed@1.0" in (_ion.symbol_name(sid) or "")
                    for descendant in _nodes(subnode)
                    for sid in descendant.annotations
                )
                result["encrypted_pages"] += 1
                result["compressed" if descendant_compressed else "uncompressed"] += 1
    return result



MIN_SAMPLES = 3
MAX_SAMPLES = 5
MAX_COMPONENT_BYTES = 2 * 1024 * 1024


def _sample_indices(count):
    if count < MIN_SAMPLES:
        return ()
    k = min(count, MAX_SAMPLES)
    return tuple((i * (count - 1)) // (k - 1) for i in range(k))


def _valid_tail_padding(key, iv, ciphertext):
    """Validate only one decrypted CBC tail block, never return plaintext."""
    from kfx_stages import _aes
    ct = bytes(ciphertext)
    iv = bytes(iv)
    if len(key) != 16 or len(iv) != 16 or not ct or len(ct) % 16:
        return False
    # CBC tail decryption only needs the preceding ciphertext block as IV.
    tail_iv = ct[-32:-16] if len(ct) >= 32 else iv
    block = _aes.AES.new(key, _aes.AES.MODE_CBC, tail_iv).decrypt(ct[-16:])
    pad = block[-1]
    return 1 <= pad <= 16 and block[-pad:] == bytes((pad,)) * pad


def check_uncompressed(source, key):
    """Return (True/False/None, sample_count): None means not an eligible format.

    Only the first encrypted envelope is considered, matching the original
    first-encrypted-page oracle. Missing, unreadable, mixed, compressed, or
    sparse content never yields a positive verdict.
    """
    from kfx_stages import _envelope

    try:
        with zipfile.ZipFile(source) as archive:
            for entry in archive.infolist():
                if not 8 <= entry.file_size <= MAX_COMPONENT_BYTES:
                    continue
                with archive.open(entry) as stream:
                    if stream.read(8) != _envelope.ENVELOPE_MAGIC:
                        continue
                    raw = _envelope.ENVELOPE_MAGIC + stream.read()
                classes = page_classes(raw)
                n_encrypted = classes.get("encrypted_pages", 0)
                if not n_encrypted:
                    continue
                # No uncompressed allowance when annotations are mixed, unknown,
                # incomplete, or the original LZMA/Compressed path is applicable.
                if classes.get("compressed", 0) or classes.get("uncompressed", 0) != n_encrypted:
                    return None, 0
                pages = [(iv, ct) for iv, ct in _envelope.envelope_pages(raw) if iv is not None]
                if len(pages) != n_encrypted:
                    return None, 0
                indices = _sample_indices(len(pages))
                if not indices:
                    return None, 0
                try:
                    verdicts = [
                        _valid_tail_padding(key, pages[i][0], pages[i][1])
                        for i in indices
                    ]
                except Exception:
                    return False, len(indices)
                return all(verdicts), len(indices)
    except (OSError, ValueError, TypeError, zipfile.BadZipFile):
        return None, 0
    return None, 0
