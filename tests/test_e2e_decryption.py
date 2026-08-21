"""End-to-end decryption of genuinely DRM-encrypted books.

Unlike the rest of the suite these build real ciphertext and run the real
decryptors over it, so a regression in the crypto or container handling shows
up as a failure to recover the plaintext rather than as a changed code path.
"""
import os
import zipfile

import pytest

import ineptepub
import k4mobidedrm
import mobidedrm
from conftest import PLUGIN_DIR
from drm_fixtures import ADEPT_CHAPTER, build_adept_epub, build_mobi

PAGES = [b'CANARY-PAGE-1 The quick brown fox.', b'CANARY-PAGE-2 Jumps over the lazy dog.']
ADEPT_CONTENT = b'<html><body><p>CANARY-ADEPT-CONTENT the quick brown fox</p></body></html>'


# Every Kindle extension DeDRM claims must reach the Mobipocket decryptor and
# actually decrypt. 'azw8' and 'kfx' are the regression guards for the dispatch
# bug where both were declared in file_types but ignored by run().
@pytest.mark.parametrize("ext", ["mobi", "prc", "azw", "azw1", "azw3", "azw4", "azw8", "kfx", "pobi"])
def test_encrypted_mobi_decrypts_under_every_kindle_extension(tmp_path, ext):
    book = tmp_path / ("book." + ext)
    build_mobi(str(book), PAGES)

    decrypted = k4mobidedrm.GetDecryptedBook(str(book), [], [], [], [])
    out = tmp_path / "out.mobi"
    decrypted.getFile(str(out))
    blob = out.read_bytes()

    for page in PAGES:
        assert page in blob, "page not recovered from %s" % ext
    decrypted.cleanup()


def test_encrypted_mobi_clears_the_encryption_flag(tmp_path):
    book = tmp_path / "book.azw3"
    build_mobi(str(book), PAGES)
    assert mobidedrm.MobiBook(str(book)).crypto_type == -1   # not parsed yet

    mb = mobidedrm.MobiBook(str(book))
    mb.processBook([])
    assert mb.crypto_type == 1
    out = tmp_path / "out.mobi"
    mb.getFile(str(out))

    # the decrypted copy must declare "no encryption" so readers accept it
    cleaned = mobidedrm.MobiBook(str(out))
    assert cleaned.sect[0x0C:0x0E] == b'\x00\x00'
    for page in PAGES:
        assert page in out.read_bytes()


def test_adept_epub_round_trip(tmp_path):
    book, out = tmp_path / "book.epub", tmp_path / "out.epub"
    userkey = build_adept_epub(str(book), ADEPT_CONTENT)

    assert ineptepub.adeptBook(str(book)) is True
    assert ineptepub.decryptBook(userkey, str(book), str(out)) == 0

    with zipfile.ZipFile(str(out)) as zf:
        names = zf.namelist()
        assert zf.read(ADEPT_CHAPTER) == ADEPT_CONTENT
        # DRM bookkeeping must be gone from the decrypted copy
        assert 'META-INF/rights.xml' not in names
        assert 'META-INF/encryption.xml' not in names
        # mimetype must stay first and stored, or readers reject the EPUB
        assert names[0] == 'mimetype'
        assert zf.getinfo('mimetype').compress_type == zipfile.ZIP_STORED


def test_adept_epub_rejects_the_wrong_key(tmp_path):
    book, out = tmp_path / "book.epub", tmp_path / "out.epub"
    build_adept_epub(str(book), ADEPT_CONTENT)
    other_key = build_adept_epub(str(tmp_path / "other.epub"), ADEPT_CONTENT)

    # 2 == "wrong key", distinct from 0 (success) and 1 (not an ADEPT book)
    assert ineptepub.decryptBook(other_key, str(book), str(out)) == 2


def test_drm_free_epub_is_reported_as_such(tmp_path):
    plain = tmp_path / "plain.epub"
    with zipfile.ZipFile(str(plain), 'w') as zf:
        zf.writestr(zipfile.ZipInfo('mimetype'), 'application/epub+zip', zipfile.ZIP_STORED)
        zf.writestr(ADEPT_CHAPTER, ADEPT_CONTENT)
    assert ineptepub.adeptBook(str(plain)) is False
    assert ineptepub.decryptBook(b'', str(plain), str(tmp_path / "o.epub")) == 1


class _NamedTempFile:
    """Minimal stand-in for calibre's FileTypePlugin.temporary_file."""

    def __init__(self, path):
        self.name = str(path)

    def close(self):
        pass


@pytest.mark.parametrize("ext", ["azw8", "kfx", "azw3", "mobi"])
def test_run_decrypts_end_to_end_without_calibre(tmp_path, ext, monkeypatch, restore_std_streams):
    """The full plugin entry point, from run() through to recovered plaintext.

    This is the regression guard for the dispatch bug: with 'azw8'/'kfx' missing
    from run()'s booktype list the file came back untouched and still encrypted.
    """
    import DeDRM_plugin as plugin
    import prefs as prefs_module
    from DeDRM_plugin.standalone.jsonconfig import JSONConfig

    # Keep the prefs reader inside tmp_path. Without calibre its base path is
    # "/", so an unpatched run would try to create /plugins.
    config_root = tmp_path / "config"
    config_root.mkdir()
    monkeypatch.setattr(prefs_module, "JSONConfig",
                        lambda rel: JSONConfig(rel, base_path=str(config_root)))

    book = tmp_path / ("book." + ext)
    build_mobi(str(book), PAGES)

    dedrm = plugin.DeDRM()
    dedrm.alfdir = PLUGIN_DIR          # calibre's initialize() normally sets this
    counter = {"n": 0}

    def temporary_file(suffix):
        counter["n"] += 1
        return _NamedTempFile(tmp_path / ("out%d%s" % (counter["n"], suffix)))

    dedrm.temporary_file = temporary_file

    result = dedrm.run(str(book))

    assert result is not None
    assert os.path.abspath(result) != os.path.abspath(str(book)), \
        "%s came back untouched - run() did not dispatch it" % ext
    blob = open(result, 'rb').read()
    for page in PAGES:
        assert page in blob
