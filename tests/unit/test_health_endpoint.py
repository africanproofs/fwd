"""Smoke test for /healthz.

v1.0.0a1: response body shape is exactly
{"master": <str>, "rpc": <str>, "fwd": "ok"} — the prior `vault` field
was retired with the Vault backend (replaced by the sealed-master
readiness probe).
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from fwd.main import app


def test_healthz_returns_200_and_expected_shape() -> None:
    client = TestClient(app)
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {"master", "rpc", "fwd"}
    assert body["fwd"] == "ok"
    assert body["rpc"] in ("ok", "unknown", "unreachable")
    assert body["master"] in ("ok", "unavailable")
