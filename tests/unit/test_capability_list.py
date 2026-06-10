"""Unit tests for app/capability_list.py — the doctor 'fwd=granted' join.

The granted set is read from the LIVE POLICY's CallerBindings (NOT the audit
log): a hand-added policy block with no grant audit STILL appears (the
ungoverned-grant case, §3). Joined with caller rows for status; sorted by
capability_id (R6).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from fwd.app.capability_list import list_capabilities
from fwd.domain.policy import Policy
from fwd.infra.caller_repo import Caller

_NOW = datetime(2026, 1, 1, tzinfo=UTC)
_LATER = datetime(2026, 1, 2, tzinfo=UTC)


class _FakeRepo:
    def __init__(self, callers: list[Caller]) -> None:
        self._callers = callers

    async def list_all(self, *, include_revoked: bool = True) -> list[Caller]:
        return self._callers


def _caller(name: str, *, revoked: bool = False) -> Caller:
    return Caller(
        name=name,
        api_key_hash="hash",
        api_key_prefix="prefix00",
        policy_path="p",
        created_at=_NOW,
        revoked_at=_LATER if revoked else None,
    )


def _policy(callers: dict) -> Policy:  # type: ignore[type-arg]
    return Policy.model_validate({"version": 1, "callers": callers})


@pytest.mark.asyncio
async def test_join_sorted_and_excludes_name_only() -> None:
    policy = _policy(
        {
            "fsp-sign-songbird": {
                "policy_path": "fsp/songbird",
                "capability_id": "clif/songbird/fsp-sign",
            },
            "claim-songbird": {
                "policy_path": "perm/claim-songbird",
                "capability_id": "clif/songbird/claim",
            },
            "legacy": {"policy_path": "p"},  # name-only — excluded
        }
    )
    repo = _FakeRepo([_caller("claim-songbird"), _caller("fsp-sign-songbird")])
    got = await list_capabilities(policy, repo)  # type: ignore[arg-type]
    # Sorted by capability_id; the name-only binding is not in the granted set.
    assert [g.capability_id for g in got] == ["clif/songbird/claim", "clif/songbird/fsp-sign"]
    assert all(g.status == "active" for g in got)
    assert got[0].caller_name == "claim-songbird"
    assert got[0].policy_path == "perm/claim-songbird"
    assert got[0].granted_at is not None


@pytest.mark.asyncio
async def test_revoked_caller_status_revoked() -> None:
    policy = _policy(
        {"claim-songbird": {"policy_path": "perm/claim-songbird", "capability_id": "clif/songbird/claim"}}
    )
    repo = _FakeRepo([_caller("claim-songbird", revoked=True)])
    got = await list_capabilities(policy, repo)  # type: ignore[arg-type]
    assert got[0].status == "revoked"
    assert got[0].revoked_at is not None


@pytest.mark.asyncio
async def test_hand_added_binding_with_no_caller_row_still_appears() -> None:
    """The ungoverned-grant case (§3): a capability_id in the live policy with no
    grant audit AND no caller row STILL appears — read from the policy, not the audit."""
    policy = _policy(
        {"hand-added": {"policy_path": "perm/x", "capability_id": "clif/songbird/claim"}}
    )
    repo = _FakeRepo([])  # no caller rows at all
    got = await list_capabilities(policy, repo)  # type: ignore[arg-type]
    assert len(got) == 1
    assert got[0].capability_id == "clif/songbird/claim"
    assert got[0].status == "active"
    assert got[0].granted_at is None  # None marks "no minted caller row"


@pytest.mark.asyncio
async def test_no_policy_returns_empty() -> None:
    assert await list_capabilities(None, _FakeRepo([])) == []  # type: ignore[arg-type]
