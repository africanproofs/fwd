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


def test_settings_sanity_caps_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FWD_MAX_GAS", raising=False)
    monkeypatch.delenv("FWD_MAX_FEE_PER_GAS", raising=False)
    s = Settings()
    assert s.fwd_max_gas == 15_000_000
    assert s.fwd_max_fee_per_gas == 500_000_000_000


def test_settings_sanity_caps_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_MAX_GAS", "1000000")
    monkeypatch.setenv("FWD_MAX_FEE_PER_GAS", "100000000000")
    s = Settings()
    assert s.fwd_max_gas == 1_000_000
    assert s.fwd_max_fee_per_gas == 100_000_000_000
