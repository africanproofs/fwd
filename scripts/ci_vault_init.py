#!/usr/bin/env python3
"""CI Vault dev-mode initialization.

Run after the GitLab CI vault service starts and before
`pytest tests/integration/`. Initializes Transit + the fwd-app policy +
the fwd AppRole against the dev-mode Vault, then emits role_id +
secret_id as KEY=VALUE lines to stdout for shell sourcing.

Invocation:
    poetry run python scripts/ci_vault_init.py > vault.env
    set -a; . ./vault.env; set +a
    poetry run pytest tests/integration/ -v

Required env:
    VAULT_ADDR    — http URL, typically http://vault:8200 in CI.
    VAULT_TOKEN   — root token; in dev mode, this is the value passed to
                    `vault server -dev -dev-root-token-id=<value>`.

Idempotency: re-running this script against an already-initialized
Vault must succeed. "Already exists" (400 with "path is already in use"
or equivalent) is treated as success on enable/create operations.

This is a CI utility — not part of the fwd runtime. Lives under
scripts/ alongside vault-init.sh.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import httpx


def vault_addr() -> str:
    addr = os.environ.get("VAULT_ADDR", "").rstrip("/")
    if not addr:
        sys.exit("ERROR: VAULT_ADDR env var must be set (e.g. http://vault:8200)")
    return addr


def vault_token() -> str:
    token = os.environ.get("VAULT_TOKEN", "")
    if not token:
        sys.exit("ERROR: VAULT_TOKEN env var must be set (CI dev-mode root token)")
    return token


def wait_for_vault(addr: str, timeout_sec: int = 60) -> None:
    """Poll /v1/sys/health until Vault is initialized + unsealed + active.

    In dev mode this is essentially instantaneous, but we still need to
    wait for the service container to finish booting. 60s ceiling is
    generous; in practice it's <5s.
    """
    deadline = time.monotonic() + timeout_sec
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            r = httpx.get(f"{addr}/v1/sys/health", timeout=2.0)
            # 200 = initialized+unsealed+active. 429 = standby (irrelevant in dev).
            # 501 = not initialized. 503 = sealed.
            if r.status_code in (200, 429):
                return
            last_err = RuntimeError(f"unexpected status {r.status_code}: {r.text[:120]}")
        except Exception as exc:
            last_err = exc
        time.sleep(1.0)
    sys.exit(f"ERROR: vault not ready at {addr} after {timeout_sec}s: {last_err}")


def post(addr: str, token: str, path: str, body: dict | None = None) -> httpx.Response:
    return httpx.post(
        f"{addr}{path}",
        headers={"X-Vault-Token": token},
        json=body or {},
        timeout=5.0,
    )


def put(addr: str, token: str, path: str, body: dict) -> httpx.Response:
    return httpx.put(
        f"{addr}{path}",
        headers={"X-Vault-Token": token},
        json=body,
        timeout=5.0,
    )


def get(addr: str, token: str, path: str) -> httpx.Response:
    return httpx.get(
        f"{addr}{path}",
        headers={"X-Vault-Token": token},
        timeout=5.0,
    )


def accept_create_or_already_exists(r: httpx.Response, what: str) -> None:
    """Vault returns 2xx on success and 400 with a specific message when the
    resource already exists. Both are pass for idempotent create."""
    if r.status_code < 300:
        return
    if r.status_code == 400 and "already" in r.text.lower():
        return
    sys.exit(f"ERROR: {what} failed: HTTP {r.status_code} {r.text[:200]}")


def main() -> None:
    addr = vault_addr()
    token = vault_token()

    wait_for_vault(addr)

    # 1. Enable Transit secrets engine (idempotent).
    r = post(addr, token, "/v1/sys/mounts/transit", {"type": "transit"})
    accept_create_or_already_exists(r, "enable transit")

    # 2. Create fwd-master key.
    r = post(
        addr,
        token,
        "/v1/transit/keys/fwd-master",
        {"type": "aes256-gcm96", "exportable": False, "allow_plaintext_backup": False},
    )
    accept_create_or_already_exists(r, "create transit/keys/fwd-master")

    # 3. Write fwd-app policy.
    policy_path = Path(__file__).parent.parent / "config" / "vault" / "policies" / "fwd-app.hcl"
    policy_text = policy_path.read_text(encoding="utf-8")
    r = put(addr, token, "/v1/sys/policies/acl/fwd-app", {"policy": policy_text})
    if r.status_code >= 300:
        sys.exit(f"ERROR: write fwd-app policy failed: HTTP {r.status_code} {r.text[:200]}")

    # 4. Enable AppRole auth (idempotent).
    r = post(addr, token, "/v1/sys/auth/approle", {"type": "approle"})
    accept_create_or_already_exists(r, "enable approle")

    # 5. Create fwd role bound to fwd-app.
    r = post(
        addr,
        token,
        "/v1/auth/approle/role/fwd",
        {
            "token_policies": "fwd-app",
            "token_ttl": "24h",
            "token_max_ttl": "72h",
            "secret_id_ttl": "0",
            "secret_id_num_uses": "0",
        },
    )
    if r.status_code >= 300:
        sys.exit(f"ERROR: create fwd role failed: HTTP {r.status_code} {r.text[:200]}")

    # 6. Read role_id.
    r = get(addr, token, "/v1/auth/approle/role/fwd/role-id")
    if r.status_code >= 300:
        sys.exit(f"ERROR: read role-id failed: HTTP {r.status_code} {r.text[:200]}")
    role_id = r.json()["data"]["role_id"]

    # 7. Generate secret_id.
    r = post(addr, token, "/v1/auth/approle/role/fwd/secret-id")
    if r.status_code >= 300:
        sys.exit(f"ERROR: generate secret-id failed: HTTP {r.status_code} {r.text[:200]}")
    secret_id = r.json()["data"]["secret_id"]

    # 8. Emit env exports (KEY=VALUE on stdout; shell-sourceable with `set -a; . file; set +a`).
    print(f"FWD_VAULT_ROLE_ID={role_id}")
    print(f"FWD_VAULT_SECRET_ID={secret_id}")
    # VAULT_ADDR is already in the env; re-emit so a downstream `source` sees it.
    print(f"VAULT_ADDR={addr}")


if __name__ == "__main__":
    main()
