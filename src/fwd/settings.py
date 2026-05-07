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

    # RPC URLs (Phase 3c). Defaults match .env.example public Flare endpoints.
    # In production AP swaps these to ap-ftso-01 / ap-ftso-02 internal RPCs.
    rpc_url_flare: str = Field(default="https://flare-api.flare.network/ext/C/rpc")
    rpc_url_songbird: str = Field(default="https://songbird-api.flare.network/ext/C/rpc")
    rpc_url_coston2: str = Field(default="https://coston2-api.flare.network/ext/C/rpc")

    # Admin auth
    fwd_admin_key: str = Field(default="")

    # Logging
    fwd_log_level: str = Field(default="INFO")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
