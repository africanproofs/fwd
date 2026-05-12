"""FastAPI-style dependencies for the app layer.

Composition lives here so api/ depends only on app/ (and domain/). Each
dependency yields a context-manager that opens infra resources and
closes them on exit.
"""

from __future__ import annotations

from fwd.app.wallet_create import VaultUnavailableError
from fwd.infra.caller_repo import Caller as Caller  # re-export for api/caller_auth.py
from fwd.infra.caller_repo import CallerRepo
from fwd.infra.db import session_scope
from fwd.infra.envelope_signer import EnvelopeSigner
from fwd.infra.nonce_repo import NonceRepo
from fwd.infra.rpc import RpcManager
from fwd.infra.transaction_repo import TransactionRepo
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


class RpcManagerCM:
    """Async context manager. Yields an RpcManager; closes httpx pool on exit."""

    async def __aenter__(self) -> RpcManager:
        self._mgr = RpcManager()
        return self._mgr

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        await self._mgr.aclose()


def get_signer() -> SignerCM:
    return SignerCM()


def get_rpc_manager() -> RpcManagerCM:
    return RpcManagerCM()


class CallerRepoCM:
    """Async context manager. Yields a CallerRepo backed by a session."""

    async def __aenter__(self) -> CallerRepo:
        self._session_cm = session_scope()
        self._session = await self._session_cm.__aenter__()
        return CallerRepo(self._session)

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        await self._session_cm.__aexit__(exc_type, exc, tb)


def get_caller_repo() -> CallerRepoCM:
    return CallerRepoCM()


class TransactionRepoCM:
    """Async context manager. Yields a TransactionRepo backed by a session."""

    async def __aenter__(self) -> TransactionRepo:
        self._session_cm = session_scope()
        self._session = await self._session_cm.__aenter__()
        return TransactionRepo(self._session)

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        await self._session_cm.__aexit__(exc_type, exc, tb)


def get_transaction_repo() -> TransactionRepoCM:
    return TransactionRepoCM()


class NonceRepoCM:
    """Async context manager. Yields a NonceRepo backed by a session."""

    async def __aenter__(self) -> NonceRepo:
        self._session_cm = session_scope()
        self._session = await self._session_cm.__aenter__()
        return NonceRepo(self._session)

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        await self._session_cm.__aexit__(exc_type, exc, tb)


def get_nonce_repo() -> NonceRepoCM:
    return NonceRepoCM()
