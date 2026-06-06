"""Smoke test for /healthz.

v1.0.0a1: response body shape replaced `vault` with `master`.
v1.1.0a9: `rpc` field removed (zero-egress). Shape is now
{"master": <str>, "sealed_master": <str>, "fwd": "ok"} on 200,
or {"status": "degraded", ...} on 503 when sealed master is unavailable.
"""

from __future__ import annotations

import os
import secrets
from typing import TYPE_CHECKING

from fastapi.testclient import TestClient

from fwd.main import app

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def test_healthz_returns_200_and_expected_shape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Provide a valid 0600 master key file so the sealed_master liveness
    # probe succeeds and /healthz returns 200.
    key_file = tmp_path / "master.key"
    key_file.write_bytes(secrets.token_bytes(32))
    os.chmod(key_file, 0o600)

    from fwd import settings as settings_mod  # noqa: PLC0415

    monkeypatch.setenv("FWD_MASTER_KEY_FILE", str(key_file))
    settings_mod.get_settings.cache_clear()

    client = TestClient(app)
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {"master", "sealed_master", "fwd"}
    assert body["fwd"] == "ok"
    assert body["master"] in ("ok", "unavailable")
    assert body["sealed_master"] in ("ok", "unavailable")
