"""DeDRM.run() must route every declared file type to a decryptor (A1)."""
import os

import pytest

import DeDRM_plugin as plugin

KINDLE_TYPES = {"prc", "mobi", "pobi", "azw", "azw1", "azw3", "azw4", "azw8", "tpz", "kfx", "kfx-zip"}
EXPECTED_HANDLER = dict(
    {t: "KindleMobiDecrypt" for t in KINDLE_TYPES},
    pdb="eReaderDecrypt", pdf="PDFDecrypt", epub="ePubDecrypt")


def _instrumented_plugin():
    dedrm = plugin.DeDRM()
    calls = []
    for handler in set(EXPECTED_HANDLER.values()):
        setattr(dedrm, handler, (lambda name: (lambda path: calls.append((name, path)) or "DECRYPTED:" + name))(handler))
    return dedrm, calls


def test_every_declared_file_type_has_a_handler():
    assert set(EXPECTED_HANDLER) == set(plugin.DeDRM.file_types)


@pytest.mark.parametrize("ext", sorted(plugin.DeDRM.file_types))
def test_run_dispatches(ext, tmp_path, restore_std_streams):
    book = tmp_path / ("book." + ext)
    book.write_bytes(b"")
    dedrm, calls = _instrumented_plugin()
    result = dedrm.run(str(book))
    assert calls == [(EXPECTED_HANDLER[ext], str(book))]
    assert result == "DECRYPTED:" + EXPECTED_HANDLER[ext]


def test_run_passes_unknown_types_back_unchanged(tmp_path, restore_std_streams):
    book = tmp_path / "book.txt"
    book.write_bytes(b"")
    dedrm, calls = _instrumented_plugin()
    assert dedrm.run(str(book)) == str(book)
    assert calls == []


def test_run_is_case_insensitive(tmp_path, restore_std_streams):
    book = tmp_path / "BOOK.KFX"
    book.write_bytes(b"")
    dedrm, calls = _instrumented_plugin()
    dedrm.run(str(book))
    assert calls == [("KindleMobiDecrypt", str(book))]
