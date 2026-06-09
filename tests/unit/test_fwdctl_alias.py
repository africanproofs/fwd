"""Part A: `fwdctl` is an additive invocation alias of `clifwd`.

The alias lives at the host-wrapper + in-container-shim + installer layer. The
Typer program name stays `clifwd` by design — the full ~250-occurrence rename
is DEFERRED (ADR-0002). These tests assert only the additive alias plumbing:

  - install/fwdctl is a byte-faithful copy of install/clifwd, differing ONLY in
    the header lead and the final delegation token (the FWD_DIR / FWD_CONTAINER /
    COMPOSE_PROJECT_NAME / CLIF_ENV_DIR exports + the onboard routing block are
    preserved verbatim, so fwdctl behaves identically to clifwd);
  - the Dockerfile wires /usr/local/bin/fwdctl to the same in-container app as
    clifwd (a symlink to the shared shim);
  - install.sh installs the fwdctl wrapper alongside clifwd (clifwd untouched).
"""

from __future__ import annotations

import stat
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_CLIFWD = _REPO / "install" / "clifwd"
_FWDCTL = _REPO / "install" / "fwdctl"
_DOCKERFILE = _REPO / "Dockerfile"
_INSTALL_SH = _REPO / "install" / "install.sh"

_ONBOARD_BLOCK = (
    'if [ "${1:-}" = "onboard" ]; then\n'
    "  shift\n"
    '  exec "$FWD_DIR/install/onboard" "$@"\n'
    "fi\n"
)


def _export_lines(p: Path) -> list[str]:
    return [ln for ln in p.read_text().splitlines() if ln.startswith("export ")]


def test_fwdctl_wrapper_exists_and_executable() -> None:
    assert _FWDCTL.is_file()
    assert _FWDCTL.stat().st_mode & stat.S_IXUSR


def test_fwdctl_exports_block_byte_identical_to_clifwd() -> None:
    # The 4 export lines carry the runbook contract and MUST be verbatim.
    exports = _export_lines(_FWDCTL)
    assert exports == _export_lines(_CLIFWD)
    assert len(exports) == 4


def test_fwdctl_onboard_routing_byte_identical_to_clifwd() -> None:
    assert _ONBOARD_BLOCK in _CLIFWD.read_text()
    assert _ONBOARD_BLOCK in _FWDCTL.read_text()


def test_fwdctl_delegation_targets_fwdctl_in_container() -> None:
    assert 'exec docker exec "${FWD_CONTAINER:-fwd}" clifwd "$@"' in _CLIFWD.read_text()
    assert 'exec docker exec "${FWD_CONTAINER:-fwd}" fwdctl "$@"' in _FWDCTL.read_text()


def test_fwdctl_header_leads_with_fwdctl() -> None:
    # Line 0 is the shebang; line 1 is the leading wrapper-identifying comment.
    assert "fwdctl" in _FWDCTL.read_text().splitlines()[1]


def test_dockerfile_wires_fwdctl_alias_to_same_app() -> None:
    df = _DOCKERFILE.read_text()
    # The clifwd shim is still created verbatim ...
    assert "> /usr/local/bin/clifwd" in df
    # ... and fwdctl is symlinked to it, so both exec the identical app.
    assert "ln -s clifwd /usr/local/bin/fwdctl" in df


def test_install_sh_installs_fwdctl_alongside_clifwd() -> None:
    sh = _INSTALL_SH.read_text()
    assert 'install -m 0755 "$SRC/install/fwdctl" "$FWD_BIN_DIR/fwdctl"' in sh
    # clifwd install is unchanged (no bulk rename).
    assert 'install -m 0755 "$SRC/install/clifwd" "$FWD_BIN_DIR/clifwd"' in sh
    # fwdctl participates in the FWD_DIR/FWD_CONTAINER/CLIF_ENV_DIR baking loops.
    assert "for _w in fwd clifwd fwdctl; do" in sh
