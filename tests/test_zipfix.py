"""zipfix.repairBook: EPUB container rewrite round-trip."""
import os
import zipfile

import zipfix


def _build_epub(path):
    members = [
        ("OEBPS/content.opf", b"<package/>", zipfile.ZIP_DEFLATED),
        ("OEBPS/chäpter 1.xhtml", "<html>ü</html>".encode("utf-8"), zipfile.ZIP_DEFLATED),
        ("OEBPS/stored.bin", bytes(range(256)), zipfile.ZIP_STORED),
        ("OEBPS/large.bin", os.urandom(2 * 1024 * 1024), zipfile.ZIP_DEFLATED),
        ("mimetype", b"application/epub+zip", zipfile.ZIP_DEFLATED),   # wrong place, wrong method
    ]
    with zipfile.ZipFile(path, "w") as zf:
        for name, data, method in members:
            zf.writestr(name, data, compress_type=method)
    return {name: data for name, data, _ in members}


def test_repair_book_round_trip(tmp_path):
    src, dst = tmp_path / "in.epub", tmp_path / "out.epub"
    expected = _build_epub(src)
    assert zipfix.repairBook(str(src), str(dst)) == 0
    with zipfile.ZipFile(dst) as zf:
        assert zf.testzip() is None
        infos = zf.infolist()
        assert infos[0].filename == "mimetype"
        assert infos[0].compress_type == zipfile.ZIP_STORED
        assert {i.filename: zf.read(i) for i in infos} == expected
        assert zf.getinfo("OEBPS/chäpter 1.xhtml").flag_bits & 0x800


def test_repair_book_missing_input(tmp_path):
    assert zipfix.repairBook(str(tmp_path / "missing.epub"), str(tmp_path / "out.epub")) == 1
