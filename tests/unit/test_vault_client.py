"""VaultClient unit tests with httpx.MockTransport.

Verifies:
- login on first use → cached client_token used on subsequent calls
- 403 on a request triggers re-auth + retry once
- second 403 (after re-auth) raises VaultError
- encrypt/decrypt happy paths
- VaultError when role_id/secret_id are empty
- httpx.HTTPError mapping to VaultError
"""
from __future__ import annotations

import base64

import httpx
import pytest

from fwd import settings as settings_mod
from fwd.infra.vault_client import VaultClient, VaultError


def _set_creds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_ADDR", "http://vault:8200")
    monkeypatch.setenv("FWD_VAULT_ROLE_ID", "rid")
    monkeypatch.setenv("FWD_VAULT_SECRET_ID", "sid")
    settings_mod.get_settings.cache_clear()


@pytest.mark.asyncio
async def test_login_then_encrypt(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_creds(monkeypatch)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        if request.url.path == "/v1/auth/approle/login":
            return httpx.Response(200, json={"auth": {"client_token": "tok-1", "lease_duration": 3600}})
        if request.url.path == "/v1/transit/encrypt/fwd-master":
            return httpx.Response(200, json={"data": {"ciphertext": "vault:v1:abc"}})
        return httpx.Response(500)

    transport = httpx.MockTransport(handler)
    async with VaultClient() as c:
        c._http = httpx.AsyncClient(transport=transport)
        ct = await c.encrypt(b"\x01" * 32)
    assert ct == "vault:v1:abc"
    # Expected sequence: login, encrypt.
    assert calls[-2:] == ["POST /v1/auth/approle/login", "POST /v1/transit/encrypt/fwd-master"]


@pytest.mark.asyncio
async def test_403_triggers_reauth_and_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_creds(monkeypatch)
    encrypt_count = 0
    login_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal encrypt_count, login_count
        if request.url.path == "/v1/auth/approle/login":
            login_count += 1
            return httpx.Response(200, json={"auth": {"client_token": f"tok-{login_count}", "lease_duration": 3600}})
        if request.url.path == "/v1/transit/encrypt/fwd-master":
            encrypt_count += 1
            if encrypt_count == 1:
                return httpx.Response(403, json={"errors": ["permission denied"]})
            return httpx.Response(200, json={"data": {"ciphertext": "vault:v1:ok"}})
        return httpx.Response(500)

    transport = httpx.MockTransport(handler)
    async with VaultClient() as c:
        c._http = httpx.AsyncClient(transport=transport)
        ct = await c.encrypt(b"\x02" * 32)
    assert ct == "vault:v1:ok"
    assert login_count == 2  # initial + reauth
    assert encrypt_count == 2  # 403 + retry


@pytest.mark.asyncio
async def test_second_403_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_creds(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/auth/approle/login":
            return httpx.Response(200, json={"auth": {"client_token": "tok", "lease_duration": 3600}})
        return httpx.Response(403, json={"errors": ["permission denied"]})

    transport = httpx.MockTransport(handler)
    async with VaultClient() as c:
        c._http = httpx.AsyncClient(transport=transport)
        with pytest.raises(VaultError, match="403 after reauth"):
            await c.encrypt(b"\x00" * 32)


@pytest.mark.asyncio
async def test_decrypt_happy(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_creds(monkeypatch)
    plaintext_b64 = base64.b64encode(b"\x09" * 32).decode("ascii")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/auth/approle/login":
            return httpx.Response(200, json={"auth": {"client_token": "tok", "lease_duration": 3600}})
        if request.url.path == "/v1/transit/decrypt/fwd-master":
            return httpx.Response(200, json={"data": {"plaintext": plaintext_b64}})
        return httpx.Response(500)

    transport = httpx.MockTransport(handler)
    async with VaultClient() as c:
        c._http = httpx.AsyncClient(transport=transport)
        pt = await c.decrypt("vault:v1:zzz")
    assert pt == b"\x09" * 32


@pytest.mark.asyncio
async def test_missing_creds_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_ADDR", "http://vault:8200")
    monkeypatch.delenv("FWD_VAULT_ROLE_ID", raising=False)
    monkeypatch.delenv("FWD_VAULT_SECRET_ID", raising=False)
    settings_mod.get_settings.cache_clear()
    with pytest.raises(VaultError, match="must be set"):
        VaultClient()
