"""Pydantic v2 policy schema — pure domain module.

Describes the shape of policy.yaml per decisions.md D13 and D14.
No fwd.* imports; domain is pure stdlib + third-party only.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RateLimit(BaseModel):
    """Per-caller or per-wallet rate-limit caps."""

    model_config = ConfigDict(extra="forbid")

    per_hour: int | None = Field(default=None, ge=1)
    per_day: int | None = Field(default=None, ge=1)


class MethodRule(BaseModel):
    """Policy rule for a single ABI method."""

    model_config = ConfigDict(extra="forbid")

    max_value_wei: str = "0"  # decimal string; coerced to int at evaluation
    arg_predicates: dict[str, Any] = Field(default_factory=dict)


class ContractRule(BaseModel):
    """Policy rule for a single contract address."""

    model_config = ConfigDict(extra="forbid")

    abi: str  # registry name (must match a loaded ABI)
    methods: dict[str, MethodRule]  # key = canonical method signature


class PermissionBlock(BaseModel):
    """Permissions block referenced by a caller binding's policy_path."""

    model_config = ConfigDict(extra="forbid")

    contracts: dict[str, ContractRule]  # key = contract address (lowercased)
    wallet_allowlist: list[str]
    rate: RateLimit | None = None


class WalletConstraint(BaseModel):
    """Per-wallet aggregate spend + rate constraints."""

    model_config = ConfigDict(extra="forbid")

    max_aggregate_value_wei_per_day: str | None = None  # decimal string
    rate: RateLimit | None = None


class CallerBinding(BaseModel):
    """Binds a caller name to a policy_path (→ PermissionBlock key)."""

    model_config = ConfigDict(extra="forbid")

    policy_path: str


class WalletBinding(BaseModel):
    """Binds a wallet name to a policy_path (→ WalletConstraint key)."""

    model_config = ConfigDict(extra="forbid")

    policy_path: str


class Policy(BaseModel):
    """Root policy.yaml schema per decisions.md D13/D14."""

    model_config = ConfigDict(extra="forbid")

    version: int
    callers: dict[str, CallerBinding] = Field(default_factory=dict)
    wallets: dict[str, WalletBinding] = Field(default_factory=dict)
    permissions: dict[str, PermissionBlock] = Field(default_factory=dict)
    wallet_constraints: dict[str, WalletConstraint] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        if self.version != 1:
            raise ValueError(f"policy version must be 1, got {self.version}")
