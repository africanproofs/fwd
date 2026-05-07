"""Async Vault client wrapping the subset of Vault HTTP API fwd uses.

Per decisions.md D10:
- Login on first use (lazy); cache (client_token, lease_duration).
- Every Vault call sends X-Vault-Token: <client_token>.
- On 403 from any call, re-authenticate once and retry the same call.
- No background renewal task in v1.

Public surface used by EnvelopeSigner:
- async def encrypt(plaintext: bytes) -> str   # returns "vault:v1:<ciphertext>"
- async def decrypt(ciphertext: str) -> bytes  # raises VaultError on failure

Both wrap httpx errors and Vault errors into VaultError.
"""

from __future__ import annotations

import base64
from typing import Any, Self

import httpx
import structlog

from fwd.settings import get_settings

logger = structlog.get_logger(__name__)

MASTER_KEY = "fwd-master"


class VaultError(Exception):
    """Vault returned an error or was unreachable."""


class VaultClient:
    """Lifecycle: instantiate via 'async with VaultClient() as client:'.

    The token is cached for the lifetime of the instance. Login is lazy:
    the first Vault call triggers POST /v1/auth/approle/login. On 403,
    re-auth and retry once. On context exit, the httpx client is closed;
    the cached token is overwritten with empty bytes (best-effort zeroize).
    """

    def __init__(self) -> None:
        s = get_settings()
        self._addr = s.vault_addr.rstrip("/")
        self._role_id = s.fwd_vault_role_id
        self._secret_id = s.fwd_vault_secret_id
        if not self._role_id or not self._secret_id:
            raise VaultError(
                "FWD_VAULT_ROLE_ID and FWD_VAULT_SECRET_ID must be set "
                "(see docs/runbooks/vault-init.md)"
            )
        self._http = httpx.AsyncClient(timeout=10.0)
        self._token: str | None = None

    async def __aenter__(self) -> Self:
        # Login is lazy: first _request() call checks token and logs in if needed.
        # This matches D10 "login on first use" and keeps unit tests Vault-free.
        return self

    async def __aexit__(self, *exc: Any) -> None:
        # Best-effort token zeroize; httpx close.
        if self._token is not None:
            self._token = "0" * len(self._token)
            self._token = None
        await self._http.aclose()

    async def encrypt(self, plaintext: bytes) -> str:
        """Envelope-encrypt 'plaintext' via transit/encrypt/fwd-master.

        Returns the Vault-formatted ciphertext: "vault:v1:<base64-blob>".
        """
        b64 = base64.b64encode(plaintext).decode("ascii")
        body = {"plaintext": b64}
        r = await self._request("POST", f"/v1/transit/encrypt/{MASTER_KEY}", json=body)
        ciphertext = r.json()["data"]["ciphertext"]
        if not isinstance(ciphertext, str) or not ciphertext.startswith("vault:v1:"):
            raise VaultError(f"unexpected ciphertext shape from Vault: {ciphertext!r}")
        return ciphertext

    async def decrypt(self, ciphertext: str) -> bytes:
        """Decrypt a Vault envelope via transit/decrypt/fwd-master.

        Returns the plaintext bytes (caller must zeroize after use).
        """
        if not ciphertext.startswith("vault:v1:"):
            raise VaultError(f"ciphertext must start with 'vault:v1:': {ciphertext[:16]!r}...")
        body = {"ciphertext": ciphertext}
        r = await self._request("POST", f"/v1/transit/decrypt/{MASTER_KEY}", json=body)
        b64 = r.json()["data"]["plaintext"]
        try:
            return base64.b64decode(b64)
        except Exception as exc:
            raise VaultError(f"invalid base64 from Vault decrypt: {exc}") from exc

    async def _login(self) -> None:
        url = f"{self._addr}/v1/auth/approle/login"
        body = {"role_id": self._role_id, "secret_id": self._secret_id}
        try:
            r = await self._http.post(url, json=body)
        except httpx.HTTPError as exc:
            raise VaultError(f"vault unreachable: {exc}") from exc
        if r.status_code != 200:
            raise VaultError(f"approle login failed: {r.status_code} {r.text[:200]}")
        try:
            self._token = r.json()["auth"]["client_token"]
        except (KeyError, ValueError) as exc:
            raise VaultError(f"approle login response shape: {exc}") from exc
        logger.info("vault.login.success")

    async def _request(
        self, method: str, path: str, *, json: dict[str, Any] | None = None
    ) -> httpx.Response:
        """HTTP wrapper that auto-retries once on 403 (re-auth + retry).

        Per D10: 403 → re-auth → retry exactly once. If the second 403 fires,
        surface as VaultError (no infinite loop).
        """
        if self._token is None:
            await self._login()
        url = f"{self._addr}{path}"

        async def _send() -> httpx.Response:
            assert self._token is not None
            return await self._http.request(
                method, url, json=json, headers={"X-Vault-Token": self._token}
            )

        try:
            r = await _send()
        except httpx.HTTPError as exc:
            raise VaultError(f"vault {method} {path}: {exc}") from exc

        if r.status_code == 403:
            logger.warning("vault.403.reauth", path=path)
            await self._login()
            try:
                r = await _send()
            except httpx.HTTPError as exc:
                raise VaultError(f"vault {method} {path} (after reauth): {exc}") from exc
            if r.status_code == 403:
                raise VaultError(f"vault {method} {path}: 403 after reauth")

        if r.status_code >= 400:
            raise VaultError(f"vault {method} {path}: {r.status_code} {r.text[:200]}")
        return r
