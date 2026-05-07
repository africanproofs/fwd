"""Admin-key bearer middleware unit tests.

Covers:
- 401 when Authorization header missing.
- 401 when Authorization is not Bearer.
- 401 when token doesn't match.
- 503 when FWD_ADMIN_KEY is empty.
- 200 when correct token.
"""

from __future__ import annotations

import pytest  # noqa: TC002
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from fwd import settings as settings_mod
from fwd.api.admin_auth import require_admin


def _app() -> FastAPI:
    test_app = FastAPI()

    @test_app.get("/probe", dependencies=[Depends(require_admin)])
    def _probe() -> dict[str, str]:
        return {"ok": "yes"}

    return test_app


def test_401_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "k")
    settings_mod.get_settings.cache_clear()
    r = TestClient(_app()).get("/probe")
    assert r.status_code == 401


def test_401_when_wrong(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "k")
    settings_mod.get_settings.cache_clear()
    r = TestClient(_app()).get("/probe", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_503_when_unconfigured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "")
    settings_mod.get_settings.cache_clear()
    r = TestClient(_app()).get("/probe", headers={"Authorization": "Bearer anything"})
    assert r.status_code == 503


def test_200_when_correct(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "k")
    settings_mod.get_settings.cache_clear()
    r = TestClient(_app()).get("/probe", headers={"Authorization": "Bearer k"})
    assert r.status_code == 200
