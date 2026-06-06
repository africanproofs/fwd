"""Wallet-import use case (CLI-only per D9 + D12).

Reads a privkey from a file (with refusal-table validation), passes it
to EnvelopeSigner.import_wallet for encrypt + persist, and optionally
shreds the source file.

The CLI (clifwd wallets import) opens AdminScopeCM and calls this use case.
The privkey never traverses HTTP.

v0.5.0a7 adds the hash-chained audit-log row (D16): one row per call
(success or known-failure). request_json carries name + policy_path +
source_file path only — NEVER the privkey bytes or hex content.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING

import structlog

from fwd.infra.audit_repo import _canonical_json
from fwd.infra.envelope_signer import (
    WalletAddressMismatch,
    WalletImportInvalidLength,
)
from fwd.infra.wallet_repo import WalletExistsError

if TYPE_CHECKING:
    from pathlib import Path

    from fwd.infra.audit_repo import AuditRepo
    from fwd.infra.envelope_signer import EnvelopeSigner
    from fwd.infra.wallet_repo import Wallet

# Re-export so cli/ can import WalletAddressMismatch from the app layer,
# satisfying the cli: {app, domain} layer-boundary rule.
__all__ = [
    "WalletAddressMismatch",
    "WalletImportInvalidLength",
    "WalletImportRequest",
    "PrivkeyFileNotFound",
    "PrivkeyFileBadMode",
    "PrivkeyFileBadOwner",
    "PrivkeyFileBadContent",
    "WalletNameTakenImport",
    "ShredSourceFailed",
    "import_wallet",
]

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class WalletImportRequest:
    name: str
    policy_path: str
    privkey_file: Path
    expected_address: str | None = None
    shred_source: bool = False


# --- App-layer exceptions for the refusal table (D9) -------------------


class PrivkeyFileNotFound(Exception):  # noqa: N818
    """exit code 2: --privkey-file does not exist."""


class PrivkeyFileBadMode(Exception):  # noqa: N818
    """exit code 2: file mode is not exactly 0600."""

    def __init__(self, mode_octal: str) -> None:
        self.mode_octal = mode_octal
        super().__init__(f"privkey-file mode must be 0600 (got {mode_octal})")


class PrivkeyFileBadOwner(Exception):  # noqa: N818
    """exit code 2: file owner uid doesn't match the user running clifwd."""

    def __init__(self, file_owner: int, current_user: int) -> None:
        self.file_owner = file_owner
        self.current_user = current_user
        super().__init__(
            f"privkey-file must be owned by the user running clifwd "
            f"(file_owner={file_owner}, current_user={current_user})"
        )


class PrivkeyFileBadContent(Exception):  # noqa: N818
    """exit code 2: file content doesn't decode to 32 bytes hex."""

    def __init__(self, length: int) -> None:
        self.length = length
        super().__init__(
            f"privkey-file must contain a 32-byte hex-encoded secp256k1 "
            f"private key (got {length} bytes)"
        )


class WalletNameTakenImport(Exception):  # noqa: N818
    """exit code 3: wallet name already exists."""


class ShredSourceFailed(Exception):  # noqa: N818
    """warning: --shred-source requested but `shred` not on PATH or failed."""


# --- The use case --------------------------------------------------------


async def import_wallet(
    request: WalletImportRequest,
    signer: EnvelopeSigner,
    *,
    audit_repo: AuditRepo,
) -> Wallet:
    """Import a wallet from a host file. Per D12 in-process; per D9 CLI-only.

    Refusal table is enforced here. On any refusal, raises a specific
    exception that the CLI maps to exit code + message.

    D16: one audit row per call (success or known-failure). request_json
    carries name + policy_path + source_file path only — NEVER privkey bytes
    or hex content.
    """
    path = request.privkey_file
    _request_json = _canonical_json(
        {
            "name": request.name,
            "policy_path": request.policy_path,
            "source_file": str(path),
        }
    )

    # 1. File exists.
    if not path.exists():
        exc = PrivkeyFileNotFound(str(path))
        await audit_repo.append(
            action="wallet-import",
            decision="error",
            caller=None,
            request_json=_request_json,
            decision_reason=f"{type(exc).__name__}: {exc}",
        )
        await audit_repo.commit()
        raise exc

    # 2. File mode is 0600.
    st = path.stat()
    mode = stat.S_IMODE(st.st_mode)
    if mode != 0o600:
        exc_mode = PrivkeyFileBadMode(f"{mode:04o}")
        await audit_repo.append(
            action="wallet-import",
            decision="error",
            caller=None,
            request_json=_request_json,
            decision_reason=f"{type(exc_mode).__name__}: {exc_mode}",
        )
        await audit_repo.commit()
        raise exc_mode

    # 3. File owner matches current uid.
    if st.st_uid != os.getuid():
        exc_owner = PrivkeyFileBadOwner(file_owner=st.st_uid, current_user=os.getuid())
        await audit_repo.append(
            action="wallet-import",
            decision="error",
            caller=None,
            request_json=_request_json,
            decision_reason=f"{type(exc_owner).__name__}: {exc_owner}",
        )
        await audit_repo.commit()
        raise exc_owner

    # 4. Read content; decode to 32 bytes.
    content = path.read_text(encoding="ascii").strip()
    try:
        privkey_bytes = bytes.fromhex(content)
    except ValueError as hex_exc:
        exc_content = PrivkeyFileBadContent(length=len(content))
        await audit_repo.append(
            action="wallet-import",
            decision="error",
            caller=None,
            request_json=_request_json,
            decision_reason=f"{type(exc_content).__name__}: {exc_content}",
        )
        await audit_repo.commit()
        raise exc_content from hex_exc
    if len(privkey_bytes) != 32:
        exc_content = PrivkeyFileBadContent(length=len(privkey_bytes))
        await audit_repo.append(
            action="wallet-import",
            decision="error",
            caller=None,
            request_json=_request_json,
            decision_reason=f"{type(exc_content).__name__}: {exc_content}",
        )
        await audit_repo.commit()
        raise exc_content

    # 5. Wrap in bytearray (hazard #2). The use case owns the buffer's
    #    lifetime up to the EnvelopeSigner.import_wallet call; after that,
    #    EnvelopeSigner zeroizes in its own finally (per D12).
    privkey_buf = bytearray(privkey_bytes)
    privkey_bytes = b""  # noqa: F841

    try:
        wallet = await signer.import_wallet(
            name=request.name,
            privkey_buf=privkey_buf,
            policy_path=request.policy_path,
            expected_address=request.expected_address,
        )
    except WalletExistsError as exc:
        exc_taken = WalletNameTakenImport(request.name)
        await audit_repo.append(
            action="wallet-import",
            decision="error",
            caller=None,
            request_json=_request_json,
            decision_reason=f"{type(exc).__name__}: {exc}",
        )
        await audit_repo.commit()
        raise exc_taken from exc
    except WalletImportInvalidLength:
        # Already enforced above; defensive re-raise.
        exc_inv = PrivkeyFileBadContent(length=len(privkey_buf))
        await audit_repo.append(
            action="wallet-import",
            decision="error",
            caller=None,
            request_json=_request_json,
            decision_reason=f"WalletImportInvalidLength: buffer length {len(privkey_buf)}",
        )
        await audit_repo.commit()
        raise exc_inv from None
    except WalletAddressMismatch as exc:
        # WalletAddressMismatch surfaces directly to the CLI (its message is
        # already user-facing per its __init__).
        await audit_repo.append(
            action="wallet-import",
            decision="error",
            caller=None,
            request_json=_request_json,
            decision_reason=f"{type(exc).__name__}: {exc}",
        )
        await audit_repo.commit()
        raise

    # 6. Optional shred of the source file. NOT a refusal — shredding is
    #    operator hygiene, not a security barrier.
    if request.shred_source:
        try:
            _shred_file(path)
        except Exception as exc:  # noqa: BLE001
            logger.warning("wallet.import.shred_failed", path=str(path), error=str(exc))
            raise ShredSourceFailed(str(path)) from exc

    # Audit approved row.
    await audit_repo.append(
        action="wallet-import",
        decision="approved",
        caller=None,
        request_json=_request_json,
        outcome=_canonical_json({"address": wallet.address}),
    )

    logger.info(
        "wallet.import.ok",
        name=wallet.name,
        address=wallet.address,
        policy_path=wallet.policy_path,
        source_file_path=str(path),
        source_file_mode=f"{mode:04o}",
        source_file_owner=st.st_uid,
        shredded=request.shred_source,
    )

    return wallet


def _shred_file(path: Path) -> None:
    """Run `shred -u <path>` (overwrites, then unlinks).

    Per architecture.md § Wallet provisioning § Import: "exit non-zero with
    a warning if shred fails — the wallet is provisioned but the source
    file remains on disk for the operator to handle." This means a missing
    `shred` binary is a hard failure, NOT a silent fall-through to plain
    `path.unlink()`. Plain unlink does NOT overwrite — recoverable on most
    filesystems (especially copy-on-write) — and would silently violate the
    operator's `--shred-source` contract.

    Closes audit F1.2 (v0.4.0a1 audit). Caller (`import_wallet` use case)
    catches the raised exception and translates to `ShredSourceFailed`,
    which the CLI maps to a non-zero exit code with an explicit message;
    the wallet is still persisted; the source file remains on disk.
    """
    if shutil.which("shred") is None:
        raise RuntimeError(
            "shred command not found on PATH; source file remains on disk. "
            "Install GNU coreutils (or comparable) and re-run; or shred manually."
        )
    result = subprocess.run(
        ["shred", "-u", str(path)],
        capture_output=True,
        text=True,
        timeout=10.0,
    )
    if result.returncode != 0:
        raise RuntimeError(f"shred exit {result.returncode}: {result.stderr.strip()}")
