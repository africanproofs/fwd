"""CLI unit tests for clifwd audit verify | show | tail.

Strategy: monkeypatched walker functions.

The DB URL resolution path (`session_scope → get_engine → get_settings`) uses
`@lru_cache` on both `get_engine()` and `get_settings()`, so in-process env
override via `monkeypatch.setenv("DATABASE_URL", ...)` after import does NOT
redirect the engine to a tmp DB. Instead, we monkeypatch the walker functions
in `fwd.cli.audit` directly — the same pattern used by test_cli_callers.py
for httpx calls.

The audit_repo unit tests (`test_audit_repo.py`) provide full coverage of the
repo + walker logic; these tests cover the CLI translation layer: exit codes,
stdout/stderr routing, and the --from/--to/--num options.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from fwd.cli.main import app
from fwd.infra.audit_repo import AuditRow, VerifyResult

runner = CliRunner()

# ---------------------------------------------------------------------------
# Helpers to build fixture objects
# ---------------------------------------------------------------------------


def _make_row(seq: int = 1, action: str = "sign-and-send") -> AuditRow:
    return AuditRow(
        seq=seq,
        ts=datetime(2026, 5, 16, 12, 0, 0, 0, tzinfo=UTC),
        caller="test-caller",
        action=action,
        request_json='{"to":"0xabc"}',
        decision="approved",
        decision_reason=None,
        outcome=None,
        prev_hash="0" * 64,
        row_hash="a" * 64,
    )


# ---------------------------------------------------------------------------
# clifwd audit verify
# ---------------------------------------------------------------------------


def test_audit_verify_clean_chain_exits_0() -> None:
    result_ok = VerifyResult(
        ok=True, rows_checked=3, first_break_seq=None, detail="chain intact: 3 rows"
    )
    with patch("fwd.cli.audit.verify_chain", new=AsyncMock(return_value=result_ok)):
        result = runner.invoke(app, ["audit", "verify"])
    assert result.exit_code == 0
    assert "chain intact" in result.stdout


def test_audit_verify_broken_chain_exits_2_stderr() -> None:
    result_broken = VerifyResult(
        ok=False,
        rows_checked=2,
        first_break_seq=2,
        detail="recompute mismatch: stored row_hash='aaa', recomputed='bbb'",
    )
    with patch("fwd.cli.audit.verify_chain", new=AsyncMock(return_value=result_broken)):
        result = runner.invoke(app, ["audit", "verify"])
    assert result.exit_code == 2
    # Typer CliRunner mixes_stderr into output by default — check combined output.
    combined = (result.stdout or "") + (result.output or "")
    assert "CHAIN BROKEN" in combined


def test_audit_verify_with_from_to_options() -> None:
    result_ok = VerifyResult(
        ok=True, rows_checked=2, first_break_seq=None, detail="chain intact: 2 rows"
    )
    with patch("fwd.cli.audit.verify_chain", new=AsyncMock(return_value=result_ok)) as mock_vc:
        result = runner.invoke(app, ["audit", "verify", "--from", "3", "--to", "5"])
    assert result.exit_code == 0
    mock_vc.assert_awaited_once_with(from_seq=3, to_seq=5)


def test_audit_verify_empty_chain_exits_0() -> None:
    result_empty = VerifyResult(ok=True, rows_checked=0, first_break_seq=None, detail="empty chain")
    with patch("fwd.cli.audit.verify_chain", new=AsyncMock(return_value=result_empty)):
        result = runner.invoke(app, ["audit", "verify"])
    assert result.exit_code == 0
    assert "empty" in result.stdout


# ---------------------------------------------------------------------------
# clifwd audit show
# ---------------------------------------------------------------------------


def test_audit_show_existing_seq_exits_0() -> None:
    row = _make_row(seq=7)
    with patch("fwd.cli.audit.show_row", new=AsyncMock(return_value=row)):
        result = runner.invoke(app, ["audit", "show", "7"])
    assert result.exit_code == 0
    assert "sign-and-send" in result.stdout
    assert "approved" in result.stdout


def test_audit_show_missing_seq_exits_1() -> None:
    with patch("fwd.cli.audit.show_row", new=AsyncMock(return_value=None)):
        result = runner.invoke(app, ["audit", "show", "99999"])
    assert result.exit_code == 1
    # Error message appears somewhere in runner output.
    combined = (result.stdout or "") + (result.output or "")
    assert "no audit row" in combined


# ---------------------------------------------------------------------------
# clifwd audit tail
# ---------------------------------------------------------------------------


def test_audit_tail_exits_0_one_line_per_row() -> None:
    rows = [_make_row(seq=i, action="wallet-create") for i in range(1, 4)]
    with patch("fwd.cli.audit.tail_rows", new=AsyncMock(return_value=rows)):
        result = runner.invoke(app, ["audit", "tail"])
    assert result.exit_code == 0
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 3
    # Each line has tab-separated fields.
    for line in lines:
        assert "\t" in line


def test_audit_tail_custom_n_option() -> None:
    rows = [_make_row(seq=i) for i in range(1, 6)]
    with patch("fwd.cli.audit.tail_rows", new=AsyncMock(return_value=rows)) as mock_tr:
        result = runner.invoke(app, ["audit", "tail", "-n", "5"])
    assert result.exit_code == 0
    mock_tr.assert_awaited_once_with(5)
