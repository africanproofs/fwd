"""Cross-artifact drift test for the version anchor.

Per Core invariant #13 (linear-forward versioning): every ship bumps the next
linear patch number in BOTH pyproject.toml and src/fwd/version.py. This test
fails the build if the two drift apart.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from fwd.version import __version__

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_pyproject_version_matches_version_module() -> None:
    pyproject_path = REPO_ROOT / "pyproject.toml"
    pyproject = tomllib.loads(pyproject_path.read_text())
    pyproject_version = pyproject["tool"]["poetry"]["version"]
    assert pyproject_version == __version__, (
        f"pyproject.toml version '{pyproject_version}' != "
        f"src/fwd/version.py __version__ '{__version__}'"
    )
