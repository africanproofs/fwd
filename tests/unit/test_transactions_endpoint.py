"""GET /v1/transactions/{tx_id} endpoint tests."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest  # noqa: TC002
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fwd import settings as settings_mod
from fwd.api.caller_auth import require_caller
from fwd.api.transactions import router
from fwd.app.dependencies import get_caller_repo, get_transaction_repo
from fwd.infra.caller_repo import Caller
from fwd.infra.transaction_repo import Transaction, TransactionHash


def _fake_caller(name: str = "test-caller") -> Caller:
    return Caller(
        name=name,
        api_key_hash="hash",
        api_key_prefix="abcd1234",
        policy_path="policies/test.yaml",
        created_at=datetime.now(UTC),
        revoked_at=None,
    )


def _fake_tx(tx_id: str, caller: str = "test-caller") -> Transaction:
    return Transaction(
        tx_id=tx_id,
        wallet="test-wallet",
        chain=114,
        caller=caller,
        nonce=0,
        contract_address="0x" + "11" * 20,
        method_name="0x",
        value_wei="0",
        idempotency_key=None,
        request_json='{"wallet":"test-wallet"}',
        signed_raw="0xdeadbeef",
        status="submitted",
        submitted_at=datetime.now(UTC),
        confirmed_at=None,
        receipt_json=None,
        created_at=datetime.now(UTC),
    )


def _fake_hash(tx_id: str, seq: int = 1) -> TransactionHash:
    return TransactionHash(
        tx_id=tx_id,
        sequence_num=seq,
        hash_hex="0x" + "ab" * 32,
        submitted_at=datetime.now(UTC),
    )


def _make_authed_client(
    caller: Caller,
    tx: Transaction | None,
    hashes: list[TransactionHash] | None = None,
) -> TestClient:
    """Client with require_caller and get_transaction_repo both overridden."""
    mock_repo = MagicMock()
    mock_repo.get_by_id = AsyncMock(return_value=tx)
    mock_repo.list_hashes_by_tx = AsyncMock(return_value=hashes or [])

    class _FakeRepoCM:
        async def __aenter__(self) -> MagicMock:
            return mock_repo

        async def __aexit__(self, *args: object) -> None:
            pass

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[require_caller] = lambda: caller
    app.dependency_overrides[get_transaction_repo] = lambda: _FakeRepoCM()
    return TestClient(app, raise_server_exceptions=False)


def _make_real_auth_client() -> TestClient:
    """Client with real require_caller but no matching callers in repo (simulates bad/admin token)."""
    mock_caller_repo = MagicMock()
    mock_caller_repo.list_by_prefix_active = AsyncMock(return_value=[])

    class _FakeCallerRepoCM:
        async def __aenter__(self) -> MagicMock:
            return mock_caller_repo

        async def __aexit__(self, *args: object) -> None:
            pass

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_caller_repo] = lambda: _FakeCallerRepoCM()
    return TestClient(app, raise_server_exceptions=False)


# --- Tests ---


def test_get_transaction_own_returns_200() -> None:
    tx_id = "018f1234-5678-7abc-8def-012345678901"
    caller = _fake_caller("test-caller")
    tx = _fake_tx(tx_id, caller="test-caller")
    hashes = [_fake_hash(tx_id)]
    client = _make_authed_client(caller, tx, hashes)
    r = client.get(
        f"/v1/transactions/{tx_id}",
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["tx_id"] == tx_id
    assert body["status"] == "submitted"
    assert body["wallet"] == "test-wallet"
    assert body["chain"] == 114
    assert len(body["hashes"]) == 1
    assert body["hashes"][0]["sequence_num"] == 1
    assert body["hashes"][0]["hash_hex"] == "0x" + "ab" * 32


def test_get_transaction_other_caller_returns_404() -> None:
    """Cross-caller isolation: tx owned by caller-a returns 404 for caller-b (not 403)."""
    tx_id = "018f1234-5678-7abc-8def-012345678902"
    caller_b = _fake_caller("caller-b")
    tx = _fake_tx(tx_id, caller="caller-a")  # tx belongs to caller-a
    client = _make_authed_client(caller_b, tx)  # caller-b is authenticated
    r = client.get(
        f"/v1/transactions/{tx_id}",
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 404


def test_get_transaction_missing_returns_404() -> None:
    tx_id = "018f1234-5678-7abc-8def-012345678903"
    caller = _fake_caller("test-caller")
    client = _make_authed_client(caller, tx=None)  # repo returns None → 404
    r = client.get(
        f"/v1/transactions/{tx_id}",
        headers={"Authorization": "Bearer fwd_live_x"},
    )
    assert r.status_code == 404


def test_get_transaction_no_auth_returns_401() -> None:
    client = _make_real_auth_client()
    r = client.get("/v1/transactions/some-tx-id")
    assert r.status_code == 401


def test_get_transaction_admin_token_returns_401(monkeypatch: pytest.MonkeyPatch) -> None:
    """D11 bright line: admin token on caller endpoint → 401."""
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-secret")
    settings_mod.get_settings.cache_clear()
    client = _make_real_auth_client()
    r = client.get(
        "/v1/transactions/some-tx-id",
        headers={"Authorization": "Bearer admin-secret"},
    )
    assert r.status_code == 401
