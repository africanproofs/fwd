"""Centralized environment-driven settings.

Reads from process env (and .env in dev via docker-compose). Public callers
of fwd.settings.get_settings() get a memoized Settings instance.

Per architecture.md § Layer boundaries, settings is infra-layer-adjacent
(it touches the environment) but lives at the package root because every
layer reads from it. The convention: domain code never imports settings;
infra/, app/, api/, cli/ may.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore", case_sensitive=False)

    # Vault
    vault_addr: str = Field(default="http://vault:8200")
    fwd_vault_role_id: str = Field(default="")
    fwd_vault_secret_id: str = Field(default="")

    # State
    database_url: str = Field(default="sqlite+aiosqlite:////data/state.db")

    # Phase 7 policy engine (v0.5.0a6).
    fwd_policy_path: str = Field(default="/etc/fwd/policy.yaml")
    fwd_abis_dir: str = Field(default="/app/config/abis")

    # RPC URLs (Phase 3c). Defaults match .env.example public Flare endpoints.
    # In production AP swaps these to ap-ftso-01 / ap-ftso-02 internal RPCs.
    rpc_url_flare: str = Field(default="https://flare-api.flare.network/ext/C/rpc")
    rpc_url_songbird: str = Field(default="https://songbird-api.flare.network/ext/C/rpc")
    rpc_url_coston2: str = Field(default="https://coston2-api.flare.network/ext/C/rpc")

    # Admin auth
    fwd_admin_key: str = Field(default="")

    # Logging
    fwd_log_level: str = Field(default="INFO")

    # Receipt watcher (v0.4.0a6). Gated by fwd_watcher_disabled so tests can
    # exercise the rest of the app without the background task running.
    fwd_watcher_disabled: bool = Field(default=False)
    fwd_watcher_poll_interval_sec: float = Field(default=2.0, ge=0.1)
    fwd_watcher_stuck_threshold_sec: float = Field(default=30.0, ge=1.0)
    fwd_watcher_max_retries: int = Field(default=5, ge=1, le=20)
    fwd_watcher_tip_multiplier: float = Field(default=1.125, gt=1.0, le=2.0)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
