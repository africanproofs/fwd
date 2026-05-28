"""Single source of truth for fwd's version string.

Asserted equal to pyproject.toml's [tool.poetry.version] by
tests/unit/test_version_consistency.py — Core invariant #13 (linear-forward
versioning) drift detection.
"""

__version__ = "1.1.0a28"
