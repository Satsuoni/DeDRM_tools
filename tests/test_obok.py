"""Obok (Kobo) helpers: Linux library autodetection (C2), redaction (C5), legacy key (C4)."""
import importlib.util
import os
import sys

import pytest

from conftest import OBOK_DIR


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(OBOK_DIR, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


obok = _load("obok")
legacy_obok = _load("legacy_obok")


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(obok, "KOBODIR_LINUX_ROOTS", ("~", str(tmp_path / "mnt")))
    return home


def test_find_kobodir_prefers_known_wine_layout_and_skips_caches(fake_home):
    wine = fake_home / ".wine/drive_c/users/u/AppData/Local/Kobo/Kobo Desktop Edition"
    wine.mkdir(parents=True)
    (wine / "Kobo.sqlite").write_bytes(b"")
    decoy = fake_home / ".cache/stuff"
    decoy.mkdir(parents=True)
    (decoy / "Kobo.sqlite").write_bytes(b"")
    assert obok.find_kobodir_linux() == str(wine)


def test_find_kobodir_falls_back_to_bounded_home_walk(fake_home):
    odd = fake_home / "Downloads/kobo-backup"
    odd.mkdir(parents=True)
    (odd / "Kobo.sqlite").write_bytes(b"")
    assert obok.find_kobodir_linux() == str(odd)
    # too deep -> not found
    (odd / "Kobo.sqlite").unlink()
    deep = fake_home.joinpath(*["d"] * (obok.KOBODIR_LINUX_WALK_MAX_DEPTH + 2))
    deep.mkdir(parents=True)
    (deep / "Kobo.sqlite").write_bytes(b"")
    assert obok.find_kobodir_linux() is None


def test_cached_kobodir_writes_refreshes_and_clears_cache(fake_home):
    cache = fake_home / ".config/calibre/kobo location"
    lib = fake_home / "Kobo/Kobo Desktop Edition"
    lib.mkdir(parents=True)
    (lib / "Kobo.sqlite").write_bytes(b"")
    assert obok.cached_kobodir_linux() == str(lib)
    assert cache.read_text() == str(lib)
    # stale cache is discarded and nothing is cached when the library is gone
    (lib / "Kobo.sqlite").unlink()
    assert obok.cached_kobodir_linux() is None
    assert not cache.exists()


def test_kobolibrary_does_not_share_a_mutable_default():
    assert obok.KoboLibrary.__init__.__defaults__[0] is None


def test_redact_key():
    assert obok.redact_key(bytes(range(16))) == "00010203... (16 bytes)"
    assert obok.redact_key(b"") == "... (0 bytes)"


def test_legacy_cookie_key_derivation(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    cookies = {"Browser.cookies": ["@ByteArray(wsuid=0123456789abcdef)", "pwsdid=fedcba9876543210"]}
    monkeypatch.setattr(legacy_obok.legacy_obok, "plist_to_dictionary", lambda self, filename: cookies)
    monkeypatch.setenv("HOME", "/nonexistent")
    import hashlib, binascii
    expected = binascii.a2b_hex(hashlib.sha256(b"fedcba98765432100123456789abcdef").hexdigest()[32:])
    assert legacy_obok.legacy_obok().get_legacy_cookie_id == expected
