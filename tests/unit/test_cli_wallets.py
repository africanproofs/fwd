"""CLI unit tests for clifwd wallets create | list | import.

Uses typer.testing.CliRunner. HTTP calls mocked via unittest.mock.patch
at the cli.wallets module's httpx attribute. The import command's terminal
use case (app.wallet_import.import_wallet) is mocked so tests don't need
to construct a real 0600 privkey file.

v0.5.0a7: import command switched from get_signer/SignerCM to
get_admin_scope/AdminScopeCM. Tests patch get_admin_scope and import_wallet.

Closes audit deferral F6.3 (CLI test coverage) for wallets commands.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest  # noqa: TC002
from typer.testing import CliRunner

from fwd.app.dependencies import AdminScope
from fwd.app.wallet_import import (
    PrivkeyFileBadMode,
    PrivkeyFileNotFound,
    WalletAddressMismatch,
    WalletNameTakenImport,
)
from fwd.cli.main import app
from fwd.infra.wallet_repo import Wallet

runner = CliRunner()


def _fake_wallet(name: str = "alice", address: str | None = None) -> Wallet:
    return Wallet(
        name=name,
        address=address or "0x" + "aa" * 20,
        privkey_ciphertext="vault:v1:abc",
        vault_master_key="fwd-master",
        policy_path="policies/test.yaml",
        created_at=datetime.now(UTC),
    )


def _fake_admin_scope() -> AdminScope:
    """Build an AdminScope backed by AsyncMock components (no Vault needed)."""
    signer = MagicMock()
    caller_repo = MagicMock()
    audit_repo = MagicMock()
    audit_repo.append = AsyncMock(return_value=None)
    nonce_repo = MagicMock()
    return AdminScope(signer=signer, caller_repo=caller_repo, audit_repo=audit_repo, nonce_repo=nonce_repo)


class _FakeAdminScopeCM:
    """Minimal async CM that yields a fake AdminScope.

    Tests that mock import_wallet at module scope don't actually exercise
    the signer/audit_repo, but cli/wallets.py does enter the CM. Vault env
    vars are NOT set in tests; we override get_admin_scope to bypass Vault.
    """

    async def __aenter__(self) -> AdminScope:
        return _fake_admin_scope()

    async def __aexit__(self, *args: object) -> None:
        pass


# ---------------------------------------------------------------------------
# clifwd wallets create
# ---------------------------------------------------------------------------


def test_wallets_create_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    monkeypatch.setenv("FWD_URL", "http://127.0.0.1:8080")
    fake = MagicMock(
        status_code=201,
        json=lambda: {"name": "alice", "address": "0x" + "aa" * 20},
    )
    with patch("fwd.cli.wallets.httpx.post", return_value=fake):
        result = runner.invoke(
            app,
            ["wallets", "create", "--name", "alice", "--policy", "policies/x.yaml"],
        )
    assert result.exit_code == 0
    assert "created: alice" in result.stdout


def test_wallets_create_missing_admin_key_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FWD_ADMIN_KEY", raising=False)
    result = runner.invoke(
        app,
        ["wallets", "create", "--name", "alice", "--policy", "policies/x.yaml"],
    )
    assert result.exit_code == 2


def test_wallets_create_409_exits_3(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    fake = MagicMock(status_code=409, text='{"error": "wallet_exists"}')
    with patch("fwd.cli.wallets.httpx.post", return_value=fake):
        result = runner.invoke(
            app,
            ["wallets", "create", "--name", "dup", "--policy", "policies/x.yaml"],
        )
    assert result.exit_code == 3


def test_wallets_create_unreachable_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    with patch(
        "fwd.cli.wallets.httpx.post",
        side_effect=httpx.ConnectError("nope"),
    ):
        result = runner.invoke(
            app,
            ["wallets", "create", "--name", "alice", "--policy", "policies/x.yaml"],
        )
    assert result.exit_code == 2


# ---------------------------------------------------------------------------
# clifwd wallets list
# ---------------------------------------------------------------------------


def test_wallets_list_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    monkeypatch.setenv("FWD_URL", "http://127.0.0.1:8080")
    fake = MagicMock(
        status_code=200,
        json=lambda: {
            "wallets": [
                {
                    "name": "alice",
                    "address": "0x" + "aa" * 20,
                    "policy_path": "policies/alice.yaml",
                    "created_at": "2026-05-12T00:00:00+00:00",
                },
                {
                    "name": "bob",
                    "address": "0x" + "bb" * 20,
                    "policy_path": "policies/bob.yaml",
                    "created_at": "2026-05-12T00:01:00+00:00",
                },
            ]
        },
    )
    with patch("fwd.cli.wallets.httpx.get", return_value=fake):
        result = runner.invoke(app, ["wallets", "list"])
    assert result.exit_code == 0
    assert "alice" in result.stdout
    assert "bob" in result.stdout
    assert "name" in result.stdout  # header


def test_wallets_list_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    fake = MagicMock(status_code=200, json=lambda: {"wallets": []})
    with patch("fwd.cli.wallets.httpx.get", return_value=fake):
        result = runner.invoke(app, ["wallets", "list"])
    assert result.exit_code == 0
    # "(no wallets)" goes to stderr per the spec; CliRunner mixes by default
    # only in older versions; new typer attaches stderr to result.stderr.
    combined = (result.stdout or "") + (result.stderr or "")
    assert "(no wallets)" in combined


def test_wallets_list_missing_admin_key_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FWD_ADMIN_KEY", raising=False)
    result = runner.invoke(app, ["wallets", "list"])
    assert result.exit_code == 2


def test_wallets_list_http_error_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    fake = MagicMock(status_code=500, text='{"error": "internal"}')
    with patch("fwd.cli.wallets.httpx.get", return_value=fake):
        result = runner.invoke(app, ["wallets", "list"])
    assert result.exit_code == 1


def test_wallets_list_unreachable_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FWD_ADMIN_KEY", "admin-key")
    with patch(
        "fwd.cli.wallets.httpx.get",
        side_effect=httpx.ConnectError("nope"),
    ):
        result = runner.invoke(app, ["wallets", "list"])
    assert result.exit_code == 2


# ---------------------------------------------------------------------------
# clifwd wallets import (mocks the use case so no real privkey file needed)
# ---------------------------------------------------------------------------


def test_wallets_import_success(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """import_wallet is mocked to return a Wallet; the on-disk privkey
    file is never read because the use case is mocked at module scope."""
    privkey_file = tmp_path / "privkey.hex"
    privkey_file.write_text("ab" * 32)

    with (
        patch("fwd.cli.wallets.get_admin_scope", return_value=_FakeAdminScopeCM()),
        patch(
            "fwd.cli.wallets.import_wallet",
            new=AsyncMock(return_value=_fake_wallet("alice")),
        ),
    ):
        result = runner.invoke(
            app,
            [
                "wallets",
                "import",
                "--name",
                "alice",
                "--policy",
                "policies/x.yaml",
                "--privkey-file",
                str(privkey_file),
            ],
        )
    assert result.exit_code == 0, result.stdout + (result.stderr or "")
    assert "imported: alice" in result.stdout


def test_wallets_import_bad_mode_exits_2(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The use case raises PrivkeyFileBadMode; the CLI exits 2."""
    privkey_file = tmp_path / "privkey.hex"
    privkey_file.write_text("ab" * 32)

    with (
        patch("fwd.cli.wallets.get_admin_scope", return_value=_FakeAdminScopeCM()),
        patch(
            "fwd.cli.wallets.import_wallet",
            new=AsyncMock(side_effect=PrivkeyFileBadMode("mode 0644 != 0600")),
        ),
    ):
        result = runner.invoke(
            app,
            [
                "wallets",
                "import",
                "--name",
                "alice",
                "--policy",
                "policies/x.yaml",
                "--privkey-file",
                str(privkey_file),
            ],
        )
    assert result.exit_code == 2


def test_wallets_import_not_found_exits_2(tmp_path) -> None:  # type: ignore[no-untyped-def]
    privkey_file = tmp_path / "privkey.hex"  # doesn't exist
    with (
        patch("fwd.cli.wallets.get_admin_scope", return_value=_FakeAdminScopeCM()),
        patch(
            "fwd.cli.wallets.import_wallet",
            new=AsyncMock(side_effect=PrivkeyFileNotFound(str(privkey_file))),
        ),
    ):
        result = runner.invoke(
            app,
            [
                "wallets",
                "import",
                "--name",
                "alice",
                "--policy",
                "policies/x.yaml",
                "--privkey-file",
                str(privkey_file),
            ],
        )
    assert result.exit_code == 2


def test_wallets_import_name_taken_exits_3(tmp_path) -> None:  # type: ignore[no-untyped-def]
    privkey_file = tmp_path / "privkey.hex"
    privkey_file.write_text("ab" * 32)
    with (
        patch("fwd.cli.wallets.get_admin_scope", return_value=_FakeAdminScopeCM()),
        patch(
            "fwd.cli.wallets.import_wallet",
            new=AsyncMock(side_effect=WalletNameTakenImport("alice")),
        ),
    ):
        result = runner.invoke(
            app,
            [
                "wallets",
                "import",
                "--name",
                "alice",
                "--policy",
                "policies/x.yaml",
                "--privkey-file",
                str(privkey_file),
            ],
        )
    assert result.exit_code == 3


def test_wallets_import_address_mismatch_exits_2(tmp_path) -> None:  # type: ignore[no-untyped-def]
    privkey_file = tmp_path / "privkey.hex"
    privkey_file.write_text("ab" * 32)
    with (
        patch("fwd.cli.wallets.get_admin_scope", return_value=_FakeAdminScopeCM()),
        patch(
            "fwd.cli.wallets.import_wallet",
            new=AsyncMock(
                side_effect=WalletAddressMismatch(
                    expected="0x" + "11" * 20,
                    derived="0x" + "22" * 20,
                )
            ),
        ),
    ):
        result = runner.invoke(
            app,
            [
                "wallets",
                "import",
                "--name",
                "alice",
                "--policy",
                "policies/x.yaml",
                "--privkey-file",
                str(privkey_file),
                "--expected-address",
                "0x" + "11" * 20,
            ],
        )
    assert result.exit_code == 2
