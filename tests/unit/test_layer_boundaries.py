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

Top-level (non-layer) modules under fwd/:
  fwd.version          (constant; any layer may import)
  fwd.settings         (env reader; domain MUST NOT import — F3.1 / v0.3.2)
  fwd.main             (ASGI entry point; not a layer member; no rules apply)

Audit-finding F3.1 (v0.3.1 audit) — a future domain module could import
fwd.settings without any test catching it. The FORBIDDEN_TOP_LEVEL map
below extends boundary enforcement to top-level fwd modules.
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

# Top-level fwd modules each layer is forbidden from importing.
# Domain code must remain pure: no env, no I/O, no settings.
FORBIDDEN_TOP_LEVEL: dict[str, set[str]] = {
    "domain": {"settings", "main"},
    "app": {"main"},
    "infra": {"main"},
    "api": {"main"},
    "cli": {"main"},
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


def _top_level_fwd_module(module: str | None) -> str | None:
    """Return fwd.<X> where <X> is a top-level (non-layer) module, else None."""
    if module is None:
        return None
    parts = module.split(".")
    if len(parts) >= 2 and parts[0] == "fwd" and parts[1] not in LAYERS:
        return parts[1]
    return None


def _layer_of_file(path: Path) -> str | None:
    """Return the layer a file belongs to, or None if it's a top-level fwd/ file."""
    rel = path.relative_to(SRC_FWD)
    if rel.parts and rel.parts[0] in LAYERS:
        return rel.parts[0]
    return None


def _expand_import_targets(node: ast.AST) -> list[str]:
    """Yield every fully-qualified module path an Import/ImportFrom touches.

    Critically, `from fwd import settings` resolves the target to
    `fwd.settings` (combining `node.module` with `alias.name`), not just
    `fwd`. Without this expansion the FORBIDDEN_TOP_LEVEL rule misses
    that idiom — a real bug surfaced by the v0.3.2 layer-boundary
    meta-test.
    """
    targets: list[str] = []
    if isinstance(node, ast.Import):
        targets.extend(alias.name for alias in node.names)
    elif isinstance(node, ast.ImportFrom):
        if node.module is None:
            # Relative import (`from . import ...`); not an fwd-target.
            return targets
        targets.append(node.module)
        # Also check `from <module> import <name>` — the imported name
        # may itself be a submodule (e.g., `from fwd import settings`
        # resolves to fwd.settings).
        for alias in node.names:
            targets.append(f"{node.module}.{alias.name}")
    return targets


def test_layer_boundaries() -> None:
    violations: list[str] = []
    for path in SRC_FWD.rglob("*.py"):
        source_layer = _layer_of_file(path)
        if source_layer is None:
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            for tm in _expand_import_targets(node):
                target_layer = _layer_of_module(tm)
                if (
                    target_layer is not None
                    and target_layer != source_layer
                    and target_layer not in ALLOWED[source_layer]
                ):
                    violations.append(
                        f"{path.relative_to(SRC_FWD.parent.parent)}: "
                        f"{source_layer}/ imports from {target_layer}/ ({tm})"
                    )
                top_level = _top_level_fwd_module(tm)
                if top_level is not None and top_level in FORBIDDEN_TOP_LEVEL.get(
                    source_layer, set()
                ):
                    violations.append(
                        f"{path.relative_to(SRC_FWD.parent.parent)}: "
                        f"{source_layer}/ imports forbidden top-level fwd.{top_level} ({tm})"
                    )
    assert not violations, "Layer boundary violations:\n  " + "\n  ".join(violations)
