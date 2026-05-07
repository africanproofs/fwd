"""FastAPI-style dependencies for the app layer.

Composition lives here so that api/ can depend only on app/ (and domain/).
The cm shape is a context manager that, when entered, yields a signer
backed by a freshly-opened Vault session and SQLite session. Both are
closed on exit.
"""
from __future__ import annotations

from fwd.app.wallet_create import VaultUnavailableError
from fwd.infra.db import session_scope
from fwd.infra.envelope_signer import EnvelopeSigner
from fwd.infra.vault_client import VaultClient, VaultError
from fwd.infra.wallet_repo import WalletRepo


class SignerCM:
    """Async context manager. `async with signer_cm as signer:` yields a wired EnvelopeSigner."""

    async def __aenter__(self) -> EnvelopeSigner:
        try:
            self._vault = VaultClient()
            self._vault_entered = await self._vault.__aenter__()
        except VaultError as exc:
            raise VaultUnavailableError(str(exc)) from exc
        self._session_cm = session_scope()
        self._session = await self._session_cm.__aenter__()
        repo = WalletRepo(self._session)
        return EnvelopeSigner(self._vault_entered, repo)

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        await self._session_cm.__aexit__(exc_type, exc, tb)
        await self._vault.__aexit__(exc_type, exc, tb)


def get_signer() -> SignerCM:
    return SignerCM()
