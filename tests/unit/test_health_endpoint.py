"""Smoke test for /healthz.

Phase 2 verification gate: response body shape is exactly
{"vault": <str>, "rpc": <str>, "fwd": "ok"}.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from fwd.main import app


def test_healthz_returns_200_and_expected_shape() -> None:
    client = TestClient(app)
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {"vault", "rpc", "fwd"}
    assert body["fwd"] == "ok"
    assert body["rpc"] in ("ok", "unknown", "unreachable")
    assert body["vault"] in ("ok", "sealed", "unreachable")
