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

    # Sealed master (v1.0.0a1; replaces Vault)
    fwd_master_key_file: str = Field(default="/run/fwd/master.key")

    # State
    database_url: str = Field(default="sqlite+aiosqlite:////data/state.db")

    # Phase 7 policy engine (v0.5.0a6).
    fwd_policy_path: str = Field(default="/etc/fwd/policy.yaml")
    fwd_abis_dir: str = Field(default="/app/config/abis")

    # Admin auth
    fwd_admin_key: str = Field(default="")

    # Logging
    fwd_log_level: str = Field(default="INFO")

    # Zero-egress sanity caps (v1.1.0a9). Client supplies gas + fees; fwd bounds
    # them so a compromised/buggy client cannot drain a wallet via fee overspend.
    fwd_max_gas: int = Field(default=15_000_000, ge=21_000)
    fwd_max_fee_per_gas: int = Field(default=500_000_000_000, ge=1)  # 500 gwei


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
