"""Settings parses env vars correctly and refuses to mutate post-cache."""

from __future__ import annotations

import pytest  # noqa: TC002

from fwd.settings import Settings, get_settings


def test_settings_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_MASTER_KEY_FILE", "/run/fwd/custom.key")
    monkeypatch.setenv("FWD_ADMIN_KEY", "ak-test")
    s = Settings()
    assert s.fwd_master_key_file == "/run/fwd/custom.key"
    assert s.fwd_admin_key == "ak-test"


def test_settings_defaults_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FWD_MASTER_KEY_FILE", raising=False)
    monkeypatch.delenv("FWD_ADMIN_KEY", raising=False)
    s = Settings()
    assert s.fwd_master_key_file == "/run/fwd/master.key"
    assert s.fwd_admin_key == ""


def test_get_settings_is_memoized() -> None:
    a = get_settings()
    b = get_settings()
    assert a is b


def test_settings_reads_rpc_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RPC_URL_FLARE", "http://flare:1")
    monkeypatch.setenv("RPC_URL_SONGBIRD", "http://songbird:2")
    monkeypatch.setenv("RPC_URL_COSTON2", "http://coston2:3")
    s = Settings()
    assert s.rpc_url_flare == "http://flare:1"
    assert s.rpc_url_songbird == "http://songbird:2"
    assert s.rpc_url_coston2 == "http://coston2:3"


def test_settings_rpc_url_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for k in ("RPC_URL_FLARE", "RPC_URL_SONGBIRD", "RPC_URL_COSTON2"):
        monkeypatch.delenv(k, raising=False)
    s = Settings()
    assert "flare-api.flare.network" in s.rpc_url_flare
    assert "songbird-api.flare.network" in s.rpc_url_songbird
    assert "coston2-api.flare.network" in s.rpc_url_coston2
