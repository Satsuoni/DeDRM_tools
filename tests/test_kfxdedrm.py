"""KFX container handling: magic detection and actionable errors."""
import zipfile

import pytest

import k4mobidedrm
import kfxdedrm

DRMION_MAGIC = b"\xeaDRMION\xee"


def _kfx_zip(path, members):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return str(path)


def test_kfx_zip_without_drmion_is_left_alone(tmp_path):
    book = kfxdedrm.KFXZipBook(_kfx_zip(tmp_path / "b.kfx-zip", {"a.kfx": b"plain", "b.res": b"x"}))
    book.processBook([])
    assert book.decrypted == {}
    out = tmp_path / "out.kfx-zip"
    book.getFile(str(out))
    assert out.read_bytes() == (tmp_path / "b.kfx-zip").read_bytes()
    assert book.getBookType() == "KFX-ZIP" and book.getBookExtension() == ".kfx-zip"
    assert book.getBookTitle() == "b"


def test_kfx_zip_with_drmion_but_no_voucher_raises(tmp_path):
    book = kfxdedrm.KFXZipBook(_kfx_zip(tmp_path / "b.kfx-zip", {"book.kfx": DRMION_MAGIC + b"\x00" * 32}))
    with pytest.raises(Exception, match="without a DRM voucher"):
        book.processBook(["B0123456789ABCDE"])


def test_bare_drmion_kfx_gives_actionable_error(tmp_path):
    kfx = tmp_path / "book.kfx"
    kfx.write_bytes(DRMION_MAGIC + b"\x00" * 16)
    with pytest.raises(k4mobidedrm.DrmException, match="kfx-zip archive containing a DRM voucher"):
        k4mobidedrm.GetDecryptedBook(str(kfx), [], [], [], [])


def test_missing_input_file(tmp_path):
    with pytest.raises(k4mobidedrm.DrmException, match="does not exist"):
        k4mobidedrm.GetDecryptedBook(str(tmp_path / "nope.azw3"), [], [], [], [])
