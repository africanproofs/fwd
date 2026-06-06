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
from fwd.infra.audit_repo import _canonical_json as _canonical_json  # re-export for api/
from fwd.infra.caller_repo import Caller as Caller  # re-export for api/caller_auth.py
from fwd.infra.caller_repo import CallerRepo
from fwd.infra.db import session_scope
from fwd.infra.envelope_signer import EnvelopeSigner
from fwd.infra.nonce_repo import NonceRepo
from fwd.infra.nonce_repo import (
    NonceWalletNotFoundError as NonceWalletNotFoundError,  # re-export for api/
)
from fwd.infra.policy_loader import policy_path_exists as policy_path_exists  # re-export for api/
from fwd.infra.rate_repo import RateRepo
from fwd.infra.sealed_master import SealedMaster, SealError
from fwd.infra.transaction_repo import TransactionAttemptRepo, TransactionRepo
from fwd.infra.wallet_repo import WalletRepo


class SignerCM:
    """Async context manager. `async with signer_cm as signer:` yields a wired EnvelopeSigner."""

    async def __aenter__(self) -> EnvelopeSigner:
        try:
            self._vault = SealedMaster()
            self._vault_entered = await self._vault.__aenter__()
        except SealError as exc:
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


class CallerRepoCM:
    """Async context manager. Yields a CallerRepo backed by a session.

    Uses read_only=True: the caller-auth path is a pure argon2 SELECT
    (no writes) — skipping BEGIN IMMEDIATE avoids contending on the
    SQLite writer lock during high-concurrency auth checks.
    """

    async def __aenter__(self) -> CallerRepo:
        self._session_cm = session_scope(read_only=True)
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
    """Bundle of components built atop a single session — see RequestScopeCM.

    v0.5.0a6 adds rate_repo, audit_repo, wallet_repo so the sign-transaction
    path shares ONE session for all DB mutations (nonce + tx + rate + audit)
    under the single BEGIN IMMEDIATE per D16 atomicity requirement.
    v1.1.0a9 removes rpc_mgr (zero-egress: no RPC calls from the daemon).
    v1.1.0a13 adds attempt_repo (TransactionAttemptRepo) for attempt recording.
    """

    signer: EnvelopeSigner
    tx_repo: TransactionRepo
    nonce_repo: NonceRepo
    rate_repo: RateRepo
    audit_repo: AuditRepo
    wallet_repo: WalletRepo
    attempt_repo: TransactionAttemptRepo


class RequestScopeCM:
    """Single-session scope for signing-flow operations.

    Opens ONE session_scope and constructs signer + tx_repo + nonce_repo
    + rate_repo + audit_repo + wallet_repo against that shared session.
    Also opens Vault. Designed for api/sign.py — all flows need all
    components, and pre-v0.4.5 each opened its own session_scope, causing
    SQLite writer-lock contention under our BEGIN IMMEDIATE event handler.

    Sharing one session means one BEGIN IMMEDIATE per request/tick.
    Reads and writes from all repos cooperate cleanly.
    """

    async def __aenter__(self) -> RequestScope:
        try:
            self._vault = SealedMaster()
            self._vault_entered = await self._vault.__aenter__()
        except SealError as exc:
            raise VaultUnavailableError(str(exc)) from exc
        self._session_cm = session_scope()
        self._session = await self._session_cm.__aenter__()
        wallet_repo = WalletRepo(self._session)
        return RequestScope(
            signer=EnvelopeSigner(self._vault_entered, wallet_repo),
            tx_repo=TransactionRepo(self._session),
            nonce_repo=NonceRepo(self._session),
            rate_repo=RateRepo(self._session),
            audit_repo=AuditRepo(self._session),
            wallet_repo=wallet_repo,
            attempt_repo=TransactionAttemptRepo(self._session),
        )

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        await self._session_cm.__aexit__(exc_type, exc, tb)
        await self._vault.__aexit__(exc_type, exc, tb)


def get_request_scope() -> RequestScopeCM:
    return RequestScopeCM()


@dataclass(frozen=True)
class AdminScope:
    """Bundle of components built atop a single session for admin operations.

    Mirrors RequestScope but omits RpcManager (admin actions don't touch chain).
    Provides signer + caller_repo + audit_repo + nonce_repo + tx_repo on ONE
    shared session so that admin-action mutations and the D16 audit row commit
    atomically under one BEGIN IMMEDIATE (per AdminScopeCM below).
    tx_repo is used by nonce-init to guard against force-overwriting in-flight nonces.
    """

    signer: EnvelopeSigner
    caller_repo: CallerRepo
    audit_repo: AuditRepo
    nonce_repo: NonceRepo
    tx_repo: TransactionRepo


class AdminScopeCM:
    """Single-session scope for admin write operations.

    Opens ONE session_scope and constructs signer (via WalletRepo) +
    caller_repo + audit_repo against the shared session. Also opens Vault.
    Does NOT open an RpcManager — admin actions never hit chain.

    The audit row commits atomically with the mutation (signer INSERT or
    caller_repo INSERT/UPDATE) under the shared BEGIN IMMEDIATE lock.
    """

    async def __aenter__(self) -> AdminScope:
        try:
            self._vault = SealedMaster()
            self._vault_entered = await self._vault.__aenter__()
        except SealError as exc:
            raise VaultUnavailableError(str(exc)) from exc
        self._session_cm = session_scope()
        self._session = await self._session_cm.__aenter__()
        wallet_repo = WalletRepo(self._session)
        return AdminScope(
            signer=EnvelopeSigner(self._vault_entered, wallet_repo),
            caller_repo=CallerRepo(self._session),
            audit_repo=AuditRepo(self._session),
            nonce_repo=NonceRepo(self._session),
            tx_repo=TransactionRepo(self._session),
        )

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        await self._session_cm.__aexit__(exc_type, exc, tb)
        await self._vault.__aexit__(exc_type, exc, tb)


def get_admin_scope() -> AdminScopeCM:
    return AdminScopeCM()


@dataclass(frozen=True)
class ReportScope:
    """tx_repo + nonce_repo + audit_repo on ONE shared session for the
    client report-back endpoints (broadcast-result, receipt). No Vault, no RPC —
    these paths never sign."""

    tx_repo: TransactionRepo
    nonce_repo: NonceRepo
    audit_repo: AuditRepo


class ReportScopeCM:
    async def __aenter__(self) -> ReportScope:
        self._session_cm = session_scope()
        self._session = await self._session_cm.__aenter__()
        return ReportScope(
            tx_repo=TransactionRepo(self._session),
            nonce_repo=NonceRepo(self._session),
            audit_repo=AuditRepo(self._session),
        )

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        await self._session_cm.__aexit__(exc_type, exc, tb)


def get_report_scope() -> ReportScopeCM:
    return ReportScopeCM()


@dataclass(frozen=True)
class ReplacementScope:
    """signer + tx_repo + attempt_repo + nonce_repo + audit_repo on ONE shared
    session for the sign-replacement endpoint (a13).

    Needs the Vault (signs a replacement tx); does not need rate_repo
    (replacement re-signs the same intent at the same nonce — no new rate tick).
    """

    signer: EnvelopeSigner
    tx_repo: TransactionRepo
    attempt_repo: TransactionAttemptRepo
    nonce_repo: NonceRepo
    audit_repo: AuditRepo


class ReplacementScopeCM:
    """Single-session scope for the sign-replacement path."""

    async def __aenter__(self) -> ReplacementScope:
        try:
            self._vault = SealedMaster()
            self._vault_entered = await self._vault.__aenter__()
        except SealError as exc:
            raise VaultUnavailableError(str(exc)) from exc
        self._session_cm = session_scope()
        self._session = await self._session_cm.__aenter__()
        wallet_repo = WalletRepo(self._session)
        return ReplacementScope(
            signer=EnvelopeSigner(self._vault_entered, wallet_repo),
            tx_repo=TransactionRepo(self._session),
            attempt_repo=TransactionAttemptRepo(self._session),
            nonce_repo=NonceRepo(self._session),
            audit_repo=AuditRepo(self._session),
        )

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        await self._session_cm.__aexit__(exc_type, exc, tb)
        await self._vault.__aexit__(exc_type, exc, tb)


def get_replacement_scope() -> ReplacementScopeCM:
    return ReplacementScopeCM()
