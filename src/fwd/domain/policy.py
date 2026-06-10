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
    # Fail-closed gate for non-scalar (array/tuple) top-level args: such args
    # are decoded but projected out of DecodedIntent.args (B1) and therefore
    # cannot be matched by arg_predicates. A method whose ABI has any such arg
    # is REFUSED unless the operator explicitly accepts that those args are
    # unconstrainable by setting this True. Default False = default-deny.
    allow_unconstrained_args: bool = False


class ContractRule(BaseModel):
    """Policy rule for a single contract address."""

    model_config = ConfigDict(extra="forbid")

    abi: str  # registry name (must match a loaded ABI)
    # Chain IDs on which this contract rule is valid. REQUIRED, non-empty:
    # a contract address is not chain-unique (Flare/Songbird/Coston2 system
    # contracts frequently share an address), so a signing request's chain
    # MUST match one of these or the request is denied (policy_engine step 2).
    # No default — a contract rule that does not declare its chains fails the
    # schema (startup fail-fast, D14) rather than signing on any chain.
    chains: list[int] = Field(min_length=1)
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


class FspPermissionBlock(BaseModel):
    """Permissions for the FSP structured-message signing endpoint.

    Caller-keyed (like PermissionBlock) but FSP-shaped: no contract/method/
    value — only the permitted message types + wallet allowlist + rate.
    """

    model_config = ConfigDict(extra="forbid")

    message_types: list[str]
    wallet_allowlist: list[str]
    chain_ids: list[int] = Field(default_factory=list)
    rate: RateLimit | None = None


class CallerBinding(BaseModel):
    """Binds a caller name to a policy_path (→ PermissionBlock key).

    `capability_id` (optional) is the consumer-namespaced
    `<consumer>/<network>/<role>` join key (ADR-0001 §3) — the immutable spine
    across spec → grant → import → reconcile. Optional for back-compat: a
    name-only grant carries none. When present it MUST be unique across all
    CallerBindings (the join's integrity — enforced in
    policy_loader.check_consistency).
    """

    model_config = ConfigDict(extra="forbid")

    policy_path: str
    capability_id: str | None = Field(
        default=None,
        max_length=128,
        pattern=r"^[a-z0-9][a-z0-9_-]*/[a-z0-9-]+/[a-z0-9-]+$",  # <consumer>/<network>/<role>
    )


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
    fsp_permissions: dict[str, FspPermissionBlock] = Field(default_factory=dict)
    # Wallet names explicitly authorized to be the FSP signing-policy wallet
    # (in an fsp_permissions allowlist) AND that same key's own Leg-2 tx
    # sender (in an EVM permissions allowlist) — the narrow "signer pays gas"
    # carve-out to the key-domain segmentation invariant. Empty by default:
    # absent this opt-in the segmentation fail-fast is unchanged. The carve-out
    # is only honoured under the strict constraint enforced in
    # policy_loader.check_consistency (FSM signUptimeVote/signRewards,
    # max_value_wei == "0", nothing else). v1.1.0a6.
    fsp_self_submit: list[str] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        if self.version != 1:
            raise ValueError(f"policy version must be 1, got {self.version}")
