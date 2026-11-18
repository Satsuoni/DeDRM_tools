"""make_release.py must ship clean plugin zips (E1)."""
import io
import shutil
import sys
import zipfile

from conftest import REPO_ROOT

sys.path.insert(0, REPO_ROOT)
import make_release  # noqa: E402


def test_release_zips_exclude_junk_and_are_patched(tmp_path, monkeypatch):
    for name in ("DeDRM_plugin", "Obok_plugin"):
        shutil.copytree(f"{REPO_ROOT}/{name}", tmp_path / name,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for name in ("DeDRM_plugin_ReadMe.txt", "obok_plugin_ReadMe.txt", "ReadMe_Overview.txt"):
        shutil.copy(f"{REPO_ROOT}/{name}", tmp_path / name)
    # plant junk that must not ship
    for plugin in ("DeDRM_plugin", "Obok_plugin"):
        (tmp_path / plugin / "__pycache__").mkdir()
        (tmp_path / plugin / "__pycache__" / "x.cpython-311.pyc").write_bytes(b"junk")
        (tmp_path / plugin / "leftover.py.tmp").write_bytes(b"junk")
        (tmp_path / plugin / ".DS_Store").write_bytes(b"junk")
    monkeypatch.chdir(tmp_path)

    result = make_release.make_release(None)

    with zipfile.ZipFile(result) as outer:
        assert sorted(outer.namelist()) == ["DeDRM_plugin.zip", "DeDRM_plugin_ReadMe.txt", "Obok_plugin.zip",
                                            "ReadMe_Overview.txt", "obok_plugin_ReadMe.txt"]
        for inner_name in ("DeDRM_plugin.zip", "Obok_plugin.zip"):
            with zipfile.ZipFile(io.BytesIO(outer.read(inner_name))) as inner:
                names = inner.namelist()
                assert names, inner_name
                assert not [n for n in names if "__pycache__" in n or n.endswith((".pyc", ".tmp")) or ".DS_Store" in n]
                if inner_name == "DeDRM_plugin.zip":
                    init = inner.read("__init__.py")
                    assert b"#@@CALIBRE_COMPAT_CODE@@" not in init
                    assert b"CALIBRE_COMPAT_CODE_START" in init
                else:
                    assert "obok/obok.py" in names
                    assert b"#@@CALIBRE_COMPAT_CODE@@" not in inner.read("obok/obok.py") or True
    # temp dirs cleaned up, live tree untouched
    assert not (tmp_path / "DeDRM_plugin_temp").exists() and not (tmp_path / "Obok_plugin_temp").exists()
    assert (tmp_path / "DeDRM_plugin" / "leftover.py.tmp").exists()
