"""ABI registry loader — infra module.

Loads and indexes ABI function entries from a config/abis/ directory per
decisions.md D15 and architecture.md § Intent decoder.

The registry is keyed by (abi_name, selector_hex); it is address-agnostic —
address→abi-name binding lives in policy.yaml (a later ship).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path  # noqa: TC003
from typing import Any

import yaml

from fwd.domain.intent import canonical_signature, canonical_type, selector_of


class AbiRegistryError(Exception):
    """Raised on any malformed ABI registry config — a boot-time error."""


@dataclass(frozen=True)
class AbiMethod:
    """A single indexed ABI function entry."""

    method_signature: str
    canonical_input_types: tuple[str, ...]
    abi_fn_entry: dict[str, Any]


class AbiRegistry:
    """Registry of ABI function entries, indexed by (abi_name, selector_hex).

    Only state-changing functions (stateMutability in nonpayable/payable) are
    indexed. View/pure functions are excluded because fwd only signs
    state-changing calls.
    """

    # internal: dict[str, dict[str, AbiMethod]] = abi_name -> selector_hex -> AbiMethod
    def __init__(self) -> None:
        self._data: dict[str, dict[str, AbiMethod]] = {}

    @classmethod
    def load(cls, abis_dir: Path) -> AbiRegistry:
        """Load and index all ABIs declared in abis_dir/registry.yaml.

        Raises AbiRegistryError on any configuration problem so callers can
        fail fast at boot time rather than silently skipping ABIs.
        """
        registry_path = abis_dir / "registry.yaml"
        if not registry_path.exists():
            raise AbiRegistryError(f"registry.yaml not found at {registry_path}")

        raw = yaml.safe_load(registry_path.read_text())
        if not isinstance(raw, dict):
            raise AbiRegistryError(
                f"registry.yaml must be a YAML mapping, got {type(raw).__name__}"
            )
        if raw.get("version") != 1:
            raise AbiRegistryError(f"registry.yaml version must be 1, got {raw.get('version')!r}")
        abis_map = raw.get("abis")
        if not isinstance(abis_map, dict):
            raise AbiRegistryError(
                f"registry.yaml must contain an 'abis' mapping, got {abis_map!r}"
            )

        instance = cls()

        for abi_name, filename in abis_map.items():
            if not isinstance(filename, str):
                raise AbiRegistryError(
                    f"registry.yaml abis.{abi_name}: filename must be a string, got {filename!r}"
                )
            # Path-traversal defense
            if "/" in filename or "\\" in filename or ".." in filename:
                raise AbiRegistryError(
                    f"registry.yaml abis.{abi_name}: filename {filename!r} contains "
                    f"path traversal characters"
                )

            path = abis_dir / filename
            if not path.is_file():
                raise AbiRegistryError(f"registry.yaml abis.{abi_name}: file {path} does not exist")

            try:
                parsed = json.loads(path.read_text())
            except json.JSONDecodeError as exc:
                raise AbiRegistryError(
                    f"Failed to parse JSON for {abi_name} ({filename}): {exc}"
                ) from exc

            # Normalize: Hardhat artifact or bare array
            if isinstance(parsed, dict) and isinstance(parsed.get("abi"), list):
                abi_entries: list[Any] = parsed["abi"]
            elif isinstance(parsed, list):
                abi_entries = parsed
            else:
                raise AbiRegistryError(
                    f"{abi_name} ({filename}): expected a JSON array or a Hardhat artifact "
                    f"dict with an 'abi' key, got {type(parsed).__name__}"
                )

            submap: dict[str, AbiMethod] = {}
            for entry in abi_entries:
                if not isinstance(entry, dict):
                    continue
                if entry.get("type") != "function":
                    continue
                if entry.get("stateMutability") not in ("nonpayable", "payable"):
                    continue

                sel = selector_of(entry)
                sig = canonical_signature(entry)
                types = tuple(canonical_type(i) for i in entry.get("inputs", []))

                if sel in submap:
                    raise AbiRegistryError(
                        f"Duplicate selector {sel} in ABI '{abi_name}': "
                        f"'{submap[sel].method_signature}' and '{sig}'"
                    )
                submap[sel] = AbiMethod(
                    method_signature=sig,
                    canonical_input_types=types,
                    abi_fn_entry=entry,
                )

            instance._data[abi_name] = submap

        return instance

    def lookup(self, abi_name: str, selector_hex: str) -> AbiMethod | None:
        """Return the AbiMethod for (abi_name, selector_hex), or None if unknown.

        selector_hex is normalized to lowercase before lookup.
        """
        submap = self._data.get(abi_name)
        if submap is None:
            return None
        return submap.get(selector_hex.lower())

    def abi_names(self) -> frozenset[str]:
        """Return the frozenset of loaded ABI names."""
        return frozenset(self._data.keys())

    def signatures_for(self, abi_name: str) -> frozenset[str]:
        """Return the frozenset of method_signatures indexed for *abi_name*.

        Empty frozenset if the abi_name is unknown. Used by
        policy_loader check 3 (per-signature orphan detection).
        """
        submap = self._data.get(abi_name)
        if submap is None:
            return frozenset()
        return frozenset(m.method_signature for m in submap.values())
