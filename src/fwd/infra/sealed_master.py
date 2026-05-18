"""AESGCM envelope sealed master — Vault aes256-gcm96 replacement.

The master is 32 raw bytes loaded from a 0600 host file; ciphertext format is
``seal:v1:<b64(nonce12 || aesgcm_ct_tag)>``.  This is the v1.0.0a1 Vault
replacement (asset class: low-value Flare automation keys, host never public).

The async context-manager surface is identical to the retired VaultClient so
the three DI sites in app/dependencies.py change name only.
"""

from __future__ import annotations

import base64
import os
import stat
from typing import Self

from fwd.settings import get_settings


class SealError(Exception):
    """Sealed-master unavailable or ciphertext invalid."""


class SealedMaster:
    """Load a 32-byte AESGCM master key from a 0600 host file.

    Lifecycle: ``async with SealedMaster() as master:`` — the context-exit
    zeroizes the in-memory master key.
    """

    def __init__(self) -> None:
        s = get_settings()
        path = s.fwd_master_key_file

        if not os.path.isfile(path):
            raise SealError(f"master key file not found: {path}")

        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode != 0o600:
            raise SealError(f"master key file mode must be 0600 (got {oct(mode)}): {path}")

        if os.stat(path).st_uid != os.geteuid():
            raise SealError(f"master key file must be owned by the user running fwd: {path}")

        with open(path, "rb") as f:
            raw = f.read()

        if len(raw) != 32:
            raise SealError(f"master key file must be exactly 32 bytes (got {len(raw)}): {path}")

        # Wrap in bytearray — mutable so we can zeroize in __aexit__.
        # Mirror EnvelopeSigner's bytearray discipline: do NOT keep an
        # immutable bytes copy as an attribute.
        self._master = bytearray(raw)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        """Zeroize the master key in place on context exit."""
        for i in range(len(self._master)):
            self._master[i] = 0

    async def encrypt(self, plaintext: bytes) -> str:
        """Envelope-encrypt ``plaintext`` with AESGCM.

        Returns a ``seal:v1:<b64(nonce12 || ct_with_tag)>`` string —
        parallel to the retired Vault ``vault:v1:<...>`` format.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = os.urandom(12)
        ct = AESGCM(bytes(self._master)).encrypt(nonce, plaintext, None)
        return "seal:v1:" + base64.b64encode(nonce + ct).decode("ascii")

    async def decrypt(self, ciphertext: str) -> bytes:
        """Decrypt a ``seal:v1:...`` ciphertext.

        Raises ``SealError`` on prefix mismatch or authentication failure.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if not ciphertext.startswith("seal:v1:"):
            raise SealError(f"ciphertext must start with 'seal:v1:': {ciphertext[:16]!r}...")
        blob = base64.b64decode(ciphertext[len("seal:v1:") :])
        nonce, ct = blob[:12], blob[12:]
        try:
            return AESGCM(bytes(self._master)).decrypt(nonce, ct, None)
        except Exception as exc:
            raise SealError(f"sealed-master decrypt failed: {exc}") from exc
