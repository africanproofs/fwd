"""App-layer capability-grant tooling (CLI-facing) — ADR-0001 §3/§4.

fwd ingests a consumer's machine-readable capability request (`clif spec --json`,
the reference consumer; consumer-contract-v1 §2.1) at the custody gate, and
**re-renders the custody diff itself** (ADR Invariant #3 / locked decision D3 —
fwd never trusts the consumer's own rendered diff). The operator judges fwd's
independently-decoded diff and approves; fwd then instantiates the grant via its
own audited primitive (POST /v1/admin/callers, keyed by `capability_id`).

This module is pure parse + validate + render + plan-derivation:
  - `parse_spec(text)`  — JSON → validated ConsumerSpec (rejects malformed input;
    no partial application).
  - `render_custody_diff(spec)` — the ADR-§4 adjudicable diff, re-rendered from
    the parsed fields (never the consumer's text). Carries NAMES only — never a
    caller-token value.
  - `provisioning_plan(spec)` — per capability, the derived fwd caller name +
    policy_path (the canonical clif/onboard naming convention) the operator-gated
    mint uses.

cli -> app boundary: cli/capability.py calls these; this module imports no infra
and performs no I/O / custody mutation (Inv #6 — the consumer REQUESTS; the
human-gated fwd side instantiates).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

__all__ = [
    "CapabilitySpecError",
    "ConsumerSpec",
    "PlannedGrant",
    "SpecCapability",
    "parse_spec",
    "provisioning_plan",
    "render_custody_diff",
]

# The <consumer>/<network>/<role> join key shape (mirrors domain.CallerBinding
# and the api/callers.py 400 gate).
_CAPABILITY_ID_PATTERN = r"^[a-z0-9][a-z0-9_-]*/[a-z0-9-]+/[a-z0-9-]+$"

# The canonical clif/onboard naming convention (install/onboard +
# app/policy_init.generate_policy): role -> (caller-name template, policy_path
# template). The grant plan derives the fwd caller name + policy_path from the
# capability's role because `clif spec --json` carries the wallet NAME but not
# the fwd caller name / policy_path. A role outside this set cannot be derived
# (the operator maps it by hand) — provisioning_plan leaves it un-derived.
# ADR-0004 role taxonomy (<context>-<noun>-<verb>). FSP signing is split per message-type
# (least-privilege): a sign caller authorizes ONE message type, a submit caller ONE method.
_ROLE_CONVENTION: dict[str, tuple[str, str]] = {
    "ftso-reward-claim": ("claim-{net}", "perm/claim-{net}"),
    "uptime-vote-sign": ("uptime-vote-sign-{net}", "fsp/uptime-{net}"),
    "reward-distribution-sign": ("reward-distribution-sign-{net}", "fsp/reward-{net}"),
    "uptime-vote-submit": ("uptime-vote-submit-{net}", "perm/uptime-submit-{net}"),
    "reward-distribution-submit": ("reward-distribution-submit-{net}", "perm/reward-submit-{net}"),
    "signing-policy-sign": ("signing-policy-sign-{net}", "fsp/signing-policy-{net}"),
    "voter-registration-sign": ("voter-registration-sign-{net}", "fsp/voter-registration-{net}"),
    "protocol-message-sign": ("protocol-message-sign-{net}", "fsp/protocol-message-{net}"),
    # One FAST_UPDATE sign seat on the shared signing wallet (SIGNING_PK).
    "fastupdate-sign": ("fastupdate-sign-{net}", "fsp/fastupdate-sign-{net}"),
    # Three EVM-only submit seats for FastUpdater.submitUpdates (FAST_UPDATES_ACCOUNTS).
    "fastupdate-submit-1": ("fastupdate-submit-1-{net}", "perm/fastupdate-submit-1-{net}"),
    "fastupdate-submit-2": ("fastupdate-submit-2-{net}", "perm/fastupdate-submit-2-{net}"),
    "fastupdate-submit-3": ("fastupdate-submit-3-{net}", "perm/fastupdate-submit-3-{net}"),
    # EVM-only submit roles for Submission contract.
    "ftso-price-submit": ("ftso-price-submit-{net}", "perm/ftso-price-submit-{net}"),
    "ftso-signature-submit": ("ftso-signature-submit-{net}", "perm/ftso-signature-submit-{net}"),
    # Relay finalization submit on the shared fsp-signing wallet (carve-out).
    "relay-submit": ("relay-submit-{net}", "perm/relay-submit-{net}"),
}


class CapabilitySpecError(Exception):
    """Raised when the ingested spec is not a well-formed capability request."""


class SpecCapability(BaseModel):
    """One capability entry (consumer-contract-v1 §2.1). All 12 keys REQUIRED to
    be present; non-applicable keys carry null. extra keys tolerated (additive
    forward-compat — the compat tuple gates real version skew, not this schema).
    """

    model_config = ConfigDict(extra="ignore")

    capability_id: str = Field(pattern=_CAPABILITY_ID_PATTERN, max_length=128)
    role: str
    endpoint: str
    caller_token_env: str
    wallet_env: str
    wallet_name: str | None
    contract: str | None
    contract_name: str | None
    method: str | None
    value_wei: str | None
    recipient_pinned: str | None
    suggested_rate: str | None


class ConsumerSpec(BaseModel):
    """The top-level `<consumer> spec --json` payload (consumer-contract-v1 §2)."""

    model_config = ConfigDict(extra="ignore")

    consumer: str
    network: str
    compat: dict[str, str]
    capabilities: list[SpecCapability] = Field(min_length=1)

    @model_validator(mode="after")
    def _check_join_integrity(self) -> ConsumerSpec:
        # The capability_id is the immutable join key: it MUST equal
        # <consumer>/<network>/<role> from this same spec (ADR Inv #4). A spec
        # whose id does not match its own fields is non-conformant.
        for cap in self.capabilities:
            expected = f"{self.consumer}/{self.network}/{cap.role}"
            if cap.capability_id != expected:
                raise ValueError(
                    f"capability_id '{cap.capability_id}' does not match "
                    f"'{expected}' (consumer/network/role join mismatch)"
                )
        return self


@dataclass(frozen=True)
class PlannedGrant:
    """The per-capability grant the operator-gated mint instantiates.

    `caller_name`/`policy_path` are None when the role is outside the known
    clif/onboard convention (the operator maps those by hand).
    """

    capability_id: str
    role: str
    caller_token_env: str
    wallet_name: str | None
    caller_name: str | None
    policy_path: str | None


def parse_spec(text: str) -> ConsumerSpec:
    """Parse + validate a `<consumer> spec --json` payload. Reject malformed
    input (no partial application). Raises CapabilitySpecError.
    """
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CapabilitySpecError(f"spec is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise CapabilitySpecError("spec must be a JSON object")
    try:
        return ConsumerSpec.model_validate(raw)
    except ValidationError as exc:
        raise CapabilitySpecError(f"spec is not a well-formed capability request: {exc}") from exc


def provisioning_plan(spec: ConsumerSpec) -> list[PlannedGrant]:
    """Derive the per-capability fwd caller name + policy_path (the canonical
    clif/onboard convention). Pure derivation — no I/O, no mint.
    """
    plan: list[PlannedGrant] = []
    for cap in spec.capabilities:
        template = _ROLE_CONVENTION.get(cap.role)
        if template is None:
            caller_name = None
            policy_path = None
        else:
            name_tpl, path_tpl = template
            caller_name = name_tpl.format(net=spec.network)
            policy_path = path_tpl.format(net=spec.network)
        plan.append(
            PlannedGrant(
                capability_id=cap.capability_id,
                role=cap.role,
                caller_token_env=cap.caller_token_env,
                wallet_name=cap.wallet_name,
                caller_name=caller_name,
                policy_path=policy_path,
            )
        )
    return plan


def render_custody_diff(spec: ConsumerSpec) -> str:
    """Re-render the ADR-§4 adjudicable custody diff from the PARSED fields (D3 —
    fwd's own rendering, never the consumer's). NAMES only; never a token value.
    """
    lines: list[str] = [
        f"custody diff — consumer: {spec.consumer}   network: {spec.network}",
        (
            f"  (compat: clif={spec.compat.get('clif', '?')} "
            f"fwd_client={spec.compat.get('fwd_client', '?')} "
            f"fwd_contract_expected={spec.compat.get('fwd_contract_expected', '?')})"
        ),
        "",
    ]
    for cap in spec.capabilities:
        lines.append(f"### {cap.capability_id}  ({cap.role})")
        lines.append(f"- endpoint: {cap.endpoint}")
        wallet = cap.wallet_name if cap.wallet_name else f"<{cap.wallet_env} unset>"
        lines.append(f"- fwd wallet: {wallet}  (env {cap.wallet_env})")
        lines.append(
            f"- caller token: env {cap.caller_token_env} "
            "(granted by fwd; the value is never shown in this diff)"
        )
        if cap.contract:
            label = cap.contract_name or "contract"
            lines.append(f"- contract: {label} {cap.contract}")
        if cap.method:
            lines.append(f"- method: {cap.method}")
        if cap.value_wei is not None:
            lines.append(f"- value: {cap.value_wei}")
        if cap.role == "claim":
            recipient = cap.recipient_pinned or "<CLAIM_RECIPIENT_ADDRESS unset>"
            lines.append(f"- recipient pinned: {recipient}")
        if cap.suggested_rate is not None:
            lines.append(
                f"- suggested rate: {cap.suggested_rate}  "
                "(request only — fwd policy is authoritative)"
            )
        lines.append("- → approve / reject")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
