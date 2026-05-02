"""Layer-boundary import-graph test.

Per architecture.md § Layer boundaries — Enforcement: this test walks every
.py file under src/fwd/<layer>/ and asserts it does not import from a layer
it is not allowed to import from.

Allowed cross-layer imports:
  domain  → (none — domain imports nothing from other fwd layers)
  app     → domain, infra
  infra   → domain
  api     → app, domain
  cli     → app, domain

Forbidden imports:
  any layer → cli       (cli is interface; nothing else depends on it)
  domain    → infra/app/api  (domain is pure)
  infra     → app/api        (infra is below app)
  api       → infra          (interface goes through app, not infra directly)
  cli       → infra          (same as api)
"""

from __future__ import annotations

import ast
from pathlib import Path

LAYERS: tuple[str, ...] = ("domain", "app", "infra", "api", "cli")

# Allowed targets per source layer.
ALLOWED: dict[str, set[str]] = {
    "domain": set(),
    "app": {"domain", "infra"},
    "infra": {"domain"},
    "api": {"app", "domain"},
    "cli": {"app", "domain"},
}

SRC_FWD = Path(__file__).resolve().parents[2] / "src" / "fwd"


def _layer_of_module(module: str | None) -> str | None:
    """Return the fwd layer for an import target, or None if not an fwd layer."""
    if module is None:
        return None
    parts = module.split(".")
    if len(parts) >= 2 and parts[0] == "fwd" and parts[1] in LAYERS:
        return parts[1]
    return None


def _layer_of_file(path: Path) -> str | None:
    """Return the layer a file belongs to, or None if it's a top-level fwd/ file."""
    rel = path.relative_to(SRC_FWD)
    if rel.parts and rel.parts[0] in LAYERS:
        return rel.parts[0]
    return None


def test_layer_boundaries() -> None:
    violations: list[str] = []
    for path in SRC_FWD.rglob("*.py"):
        source_layer = _layer_of_file(path)
        if source_layer is None:
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            target_modules: list[str | None] = []
            if isinstance(node, ast.Import):
                target_modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                target_modules.append(node.module)
            for tm in target_modules:
                target_layer = _layer_of_module(tm)
                if target_layer is None or target_layer == source_layer:
                    continue
                if target_layer not in ALLOWED[source_layer]:
                    violations.append(
                        f"{path.relative_to(SRC_FWD.parent.parent)}: "
                        f"{source_layer}/ imports from {target_layer}/ ({tm})"
                    )
    assert not violations, "Layer boundary violations:\n  " + "\n  ".join(violations)
