"""_aes.py -- AES-CBC backend selection for the stage subpackage.

The stages need one primitive: AES-CBC with a 16-byte IV, called as
AES.new(key, AES.MODE_CBC, iv).decrypt(ct).  With no backend importable the
module still imports; using the cipher raises AESUnavailable with the exact
remedy, so a missing optional dependency is never mistaken for a wrong key or a
corrupt table.
"""

from __future__ import annotations

__all__ = ["AES", "AESUnavailable", "aes_cbc_decrypt", "backend_name"]

_BACKEND = ""
_AES = None


class AESUnavailable(RuntimeError):
    """No AES-CBC provider is importable in this interpreter."""


# 1. Cryptodome (what the host app exposes today), 2. Crypto (the upstream
# pycryptodome name), 3. cryptography -- adapted to the same two-method surface
def _load_pycryptodome():
    try:
        from Cryptodome.Cipher import AES as _mod  # type: ignore[import-not-found]

        return _mod, "Cryptodome"
    except ImportError:
        pass
    try:
        from Crypto.Cipher import AES as _mod  # type: ignore[import-not-found]

        return _mod, "Crypto"
    except ImportError:
        return None, ""


class _CryptographyCipher:
    def __init__(self, key: bytes, iv: bytes) -> None:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        if len(key) not in (16, 24, 32):
            raise ValueError(f"AES key must be 16, 24 or 32 bytes, got {len(key)}")
        if len(iv) != 16:
            raise ValueError(f"AES-CBC IV must be 16 bytes, got {len(iv)}")
        self._cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    @staticmethod
    def _block_multiple(data: bytes, what: str) -> bytes:
        if len(data) % 16:
            raise ValueError(f"{what} must be a multiple of the 16-byte AES block, got {len(data)}")
        return bytes(data)

    def decrypt(self, data: bytes) -> bytes:
        ctx = self._cipher.decryptor()
        return ctx.update(self._block_multiple(data, "ciphertext")) + ctx.finalize()


class _CryptographyAES:
    MODE_CBC = 2

    @staticmethod
    def new(key: bytes, mode: int, iv: bytes | None = None):
        if mode != _CryptographyAES.MODE_CBC:
            raise ValueError(f"only AES-CBC is provided here, got mode {mode}")
        if iv is None:
            raise ValueError("AES-CBC needs a 16-byte IV")
        return _CryptographyCipher(bytes(key), bytes(iv))


def _load():
    global _AES, _BACKEND
    if _AES is not None:
        return _AES
    module, name = _load_pycryptodome()
    if module is not None:
        _AES, _BACKEND = module, name
        return _AES
    try:
        import cryptography  # noqa: F401  (probe only)
    except ImportError:
        raise AESUnavailable(
            "no AES-CBC provider is available: install pycryptodome (module 'Crypto' or "
            "'Cryptodome') or 'cryptography'; the derivation stages cannot open a page without it"
        ) from None
    _AES, _BACKEND = _CryptographyAES, "cryptography"
    return _AES


class _AESProxy:
    MODE_CBC = 2

    def new(self, *args, **kwargs):
        return _load().new(*args, **kwargs)

    def __getattr__(self, item: str):
        return getattr(_load(), item)

    def __repr__(self) -> str:  # pragma: no cover - display helper
        return f"<kfx_stages._aes proxy backend={_BACKEND or 'unresolved'}>"


AES = _AESProxy()


def backend_name() -> str:
    # "" while nothing is importable yet
    try:
        _load()
    except AESUnavailable:
        return ""
    return _BACKEND


def aes_cbc_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).decrypt(ct)

