"""Smoke test for /healthz.

v1.0.0a1: response body shape replaced `vault` with `master`.
v1.1.0a9: `rpc` field removed (zero-egress). Shape is now
{"master": <str>, "fwd": "ok"}.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from fwd.main import app


def test_healthz_returns_200_and_expected_shape() -> None:
    client = TestClient(app)
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {"master", "fwd"}
    assert body["fwd"] == "ok"
    assert body["master"] in ("ok", "unavailable")
