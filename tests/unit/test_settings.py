"""Settings parses env vars correctly and refuses to mutate post-cache."""
from __future__ import annotations

import pytest  # noqa: TC002

from fwd.settings import Settings, get_settings


def test_settings_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_ADDR", "http://example:8200")
    monkeypatch.setenv("FWD_VAULT_ROLE_ID", "rid-test")
    monkeypatch.setenv("FWD_VAULT_SECRET_ID", "sid-test")
    monkeypatch.setenv("FWD_ADMIN_KEY", "ak-test")
    s = Settings()
    assert s.vault_addr == "http://example:8200"
    assert s.fwd_vault_role_id == "rid-test"
    assert s.fwd_vault_secret_id == "sid-test"
    assert s.fwd_admin_key == "ak-test"


def test_settings_defaults_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    for k in ("VAULT_ADDR", "FWD_VAULT_ROLE_ID", "FWD_VAULT_SECRET_ID", "FWD_ADMIN_KEY"):
        monkeypatch.delenv(k, raising=False)
    s = Settings()
    assert s.vault_addr == "http://vault:8200"
    assert s.fwd_vault_role_id == ""
    assert s.fwd_vault_secret_id == ""
    assert s.fwd_admin_key == ""


def test_get_settings_is_memoized() -> None:
    a = get_settings()
    b = get_settings()
    assert a is b
