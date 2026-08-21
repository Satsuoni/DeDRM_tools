"""Import smoke test and invalid-escape-sequence guard for every shipped module."""
import glob
import importlib
import io
import os
import sys
import warnings
from contextlib import redirect_stdout

import pytest

from conftest import PLUGIN_DIR, REPO_ROOT

OBOK_PLUGIN_DIR = os.path.join(REPO_ROOT, "Obok_plugin")

# Modules that legitimately need calibre, Qt, or a specific OS.
SKIP = {
    "config": "needs PyQt/calibre GUI",
    "adobekey_winreg_unicode": "Windows only (ctypes.windll)",
    "ignoblekeyWindowsStore": "Windows only (apsw / Windows Store)",
    "__main__": "CLI entry point, runs main()",
    "__calibre_compat_code": "source snippet spliced in at release time, not a module",
}

PLUGIN_MODULES = sorted(os.path.basename(f)[:-3] for f in glob.glob(os.path.join(PLUGIN_DIR, "*.py")))
STANDALONE_MODULES = sorted("standalone." + os.path.basename(f)[:-3]
                            for f in glob.glob(os.path.join(PLUGIN_DIR, "standalone", "*.py")))
OBOK_MODULES = ["obok", "legacy_obok"]


@pytest.mark.parametrize("name", PLUGIN_MODULES + STANDALONE_MODULES)
def test_dedrm_module_imports(name):
    if name.split(".")[-1] in SKIP:
        pytest.skip(SKIP[name.split(".")[-1]])
    with redirect_stdout(io.StringIO()):
        module = importlib.import_module("DeDRM_plugin." + name)
    assert module is not None


@pytest.mark.parametrize("name", OBOK_MODULES)
def test_obok_module_imports(name):
    with redirect_stdout(io.StringIO()):
        assert importlib.import_module(name) is not None


ALL_SOURCES = sorted(
    glob.glob(os.path.join(PLUGIN_DIR, "**", "*.py"), recursive=True)
    + glob.glob(os.path.join(OBOK_PLUGIN_DIR, "**", "*.py"), recursive=True)
    + [os.path.join(REPO_ROOT, "make_release.py")])


@pytest.mark.parametrize("path", ALL_SOURCES, ids=lambda p: os.path.relpath(p, REPO_ROOT))
def test_source_compiles_without_syntax_warnings(path):
    with open(path, "rb") as fh:
        source = fh.read()
    with warnings.catch_warnings():
        warnings.simplefilter("error", SyntaxWarning)
        warnings.simplefilter("error", DeprecationWarning)
        compile(source, path, "exec")
