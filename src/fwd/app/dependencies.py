"""FastAPI-style dependencies for the app layer.

Composition lives here so api/ depends only on app/ (and domain/). Each
dependency yields a context-manager that opens infra resources and
closes them on exit.

v0.4.5 adds `RequestScopeCM` — the per-request/per-tick scope that shares
ONE session across signer/tx_repo/nonce_repo. The pre-v0.4.5 multi-CM
pattern (SignerCM + TransactionRepoCM + NonceRepoCM each opening their
own session_scope) caused writer-lock contention under our BEGIN IMMEDIATE
event handler: three concurrent sessions per request, each grabbing the
SQLite writer lock, manifested as "database is locked" in the Phase 5
GA drill. RequestScopeCM consolidates them onto a single session.
"""

from __future__ import annotations

from dataclasses import dataclass

from fwd.app.wallet_create import VaultUnavailableError
from fwd.infra.audit_repo import AuditRepo
from fwd.infra.caller_repo import Caller as Caller  # re-export for api/caller_auth.py
from fwd.infra.caller_repo import CallerRepo
from fwd.infra.db import session_scope
from fwd.infra.envelope_signer import EnvelopeSigner
from fwd.infra.nonce_repo import NonceRepo
from fwd.infra.rate_repo import RateRepo
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


class RateRepoCM:
    """Async context manager. Yields a RateRepo backed by a session."""

    async def __aenter__(self) -> RateRepo:
        self._session_cm = session_scope()
        self._session = await self._session_cm.__aenter__()
        return RateRepo(self._session)

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        await self._session_cm.__aexit__(exc_type, exc, tb)


def get_rate_repo() -> RateRepoCM:
    return RateRepoCM()


class AuditRepoCM:
    """Async context manager. Yields an AuditRepo backed by a session."""

    async def __aenter__(self) -> AuditRepo:
        self._session_cm = session_scope()
        self._session = await self._session_cm.__aenter__()
        return AuditRepo(self._session)

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        await self._session_cm.__aexit__(exc_type, exc, tb)


def get_audit_repo() -> AuditRepoCM:
    return AuditRepoCM()


class WalletRepoCM:
    """Async context manager. Yields a WalletRepo backed by a session.

    Used by the admin GET /v1/admin/wallets endpoint. SignerCM still owns
    its own WalletRepo for the signing path; this CM is dedicated to
    read-only admin listing.
    """

    async def __aenter__(self) -> WalletRepo:
        self._session_cm = session_scope()
        self._session = await self._session_cm.__aenter__()
        return WalletRepo(self._session)

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        await self._session_cm.__aexit__(exc_type, exc, tb)


def get_wallet_repo() -> WalletRepoCM:
    return WalletRepoCM()


@dataclass(frozen=True)
class RequestScope:
    """Bundle of components built atop a single session — see RequestScopeCM."""

    signer: EnvelopeSigner
    rpc_mgr: RpcManager
    tx_repo: TransactionRepo
    nonce_repo: NonceRepo


class RequestScopeCM:
    """Single-session scope for signing-flow operations.

    Opens ONE session_scope and constructs signer + tx_repo + nonce_repo
    against that shared session. Also opens Vault + RpcManager. Designed
    for api/sign.py and app/receipt_watcher.py — both flows need all
    four components, and pre-v0.4.5 each opened its own session_scope,
    causing SQLite writer-lock contention under our BEGIN IMMEDIATE
    event handler (each session.execute fires `begin` → BEGIN IMMEDIATE
    → contends with the other sessions' writer-lock attempts).

    Sharing one session means one BEGIN IMMEDIATE per request/tick.
    Reads and writes from the three repos cooperate cleanly.
    """

    async def __aenter__(self) -> RequestScope:
        try:
            self._vault = VaultClient()
            self._vault_entered = await self._vault.__aenter__()
        except VaultError as exc:
            raise VaultUnavailableError(str(exc)) from exc
        self._session_cm = session_scope()
        self._session = await self._session_cm.__aenter__()
        self._rpc_mgr = RpcManager()
        wallet_repo = WalletRepo(self._session)
        return RequestScope(
            signer=EnvelopeSigner(self._vault_entered, wallet_repo),
            rpc_mgr=self._rpc_mgr,
            tx_repo=TransactionRepo(self._session),
            nonce_repo=NonceRepo(self._session),
        )

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        # Close RPC manager first (no DB state); then session (commits/rolls
        # back the shared transaction); then Vault.
        await self._rpc_mgr.aclose()
        await self._session_cm.__aexit__(exc_type, exc, tb)
        await self._vault.__aexit__(exc_type, exc, tb)


def get_request_scope() -> RequestScopeCM:
    return RequestScopeCM()
