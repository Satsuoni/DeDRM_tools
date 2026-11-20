"""
pytest configuration for the DeDRM_tools repository.

The plugin sources mix relative imports (``from .utilities import ...``) with
flat imports (``import prefs``, ``from ion import ...``). Inside calibre both
work because the release-time compat code sets ``__package__`` and calibre's
zip plugin loader resolves flat names against the plugin package. This
conftest reproduces that environment for the test run:

* the repository root is on ``sys.path`` so ``DeDRM_plugin`` imports as a
  package (relative imports work);
* a meta-path finder resolves a flat ``import <name>`` to the already
  package-qualified ``DeDRM_plugin.<name>`` module (one shared object);
* ``Obok_plugin/obok`` is on ``sys.path`` (its modules only use flat imports).

Run with an interpreter that has ``pytest`` and ``pycryptodomex`` installed,
e.g. ``python -m pytest`` from the repository root. calibre and Qt are not
required; modules that need them are skipped by the import smoke test.
"""
import importlib.abc
import importlib.machinery
import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN_DIR = os.path.join(REPO_ROOT, "DeDRM_plugin")
OBOK_DIR = os.path.join(REPO_ROOT, "Obok_plugin", "obok")

for _p in (REPO_ROOT, OBOK_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)


class _AliasLoader(importlib.abc.Loader):
    """Loader that hands back an already-imported module object."""

    def __init__(self, module):
        self.module = module

    def create_module(self, spec):
        return self.module

    def exec_module(self, module):
        pass


class _PluginFlatFinder(importlib.abc.MetaPathFinder):
    """Resolve a flat ``import <name>`` to the ``DeDRM_plugin.<name>`` module.

    The same module object is shared under both names, so relative imports
    inside it work and there is only ever one copy of each module.
    """

    def find_spec(self, fullname, path=None, target=None):
        if "." in fullname or path is not None:
            return None
        if fullname == "__init__":
            qualified = "DeDRM_plugin"
        elif (os.path.isfile(os.path.join(PLUGIN_DIR, fullname + ".py"))
              or os.path.isfile(os.path.join(PLUGIN_DIR, fullname, "__init__.py"))):
            qualified = "DeDRM_plugin." + fullname
        else:
            return None
        module = importlib.import_module(qualified)
        return importlib.util.spec_from_loader(fullname, _AliasLoader(module))


sys.meta_path.insert(0, _PluginFlatFinder())
sys.dont_write_bytecode = True


def import_plugin_module(name):
    """Import ``DeDRM_plugin.<name>`` and return the module."""
    return importlib.import_module("DeDRM_plugin." + name)


@pytest.fixture
def restore_std_streams():
    """DeDRM.run() wraps sys.stdout/stderr; make sure they are put back."""
    out, err = sys.stdout, sys.stderr
    yield
    sys.stdout, sys.stderr = out, err
