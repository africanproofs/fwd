"""ABI intent decoder — pure domain module.

Implements the decode_intent() function per decisions.md D15 and
architecture.md § Intent decoder.

Top-level arguments whose ABI type is outside the predicatable-scalar set
are decoded but omitted from `.args`; they remain visible in
`method_signature`. The decoder returns None only on decode failure, never
merely because a non-scalar arg is present.

B1 rule: non-scalar top-level args (arrays, tuples, dynamic bytes arrays) are
decoded but projected out of DecodedIntent.args. Policy predicates can only
match scalar values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import eth_abi
from eth_utils import function_abi_to_4byte_selector  # type: ignore[attr-defined]

# Compiled regex for _is_predicatable_scalar.
# Matches:
#   address | bool | string | bytes (bare)
#   uint / uint8..256 (step 8) | int / int8..256 (step 8)
#   bytes1..bytes32
_SCALAR_RE = re.compile(
    r"^("
    r"address"
    r"|bool"
    r"|string"
    r"|bytes"
    r"|uint(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?"
    r"|int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?"
    r"|bytes([1-9]|[12][0-9]|3[0-2])"
    r")$"
)


@dataclass(frozen=True)
class DecodedIntent:
    """The decoded, human-readable interpretation of an EVM calldata payload."""

    contract: str  # lowercased 0x-hex address
    method_signature: str  # canonical, e.g. "transfer(address,uint256)"
    selector: str  # "0x" + 8 lowercase hex chars
    args: dict[str, Any]  # ONLY predicatable-scalar top-level args (B1)


def canonical_type(abi_input: dict[str, Any]) -> str:
    """Return the canonical Solidity type string for an ABI input entry.

    For tuple types (tuple, tuple[], tuple[N]), recursively expands
    components into the canonical parenthesised form required for
    selector/signature computation.
    """
    t: str = abi_input["type"]
    if not t.startswith("tuple"):
        return t
    # Recursive expansion for tuple, tuple[], tuple[N]
    components: list[dict[str, Any]] = abi_input["components"]
    inner = "(" + ",".join(canonical_type(c) for c in components) + ")"
    suffix = t[len("tuple") :]  # one of "", "[]", "[N]"
    return inner + suffix


def canonical_signature(abi_fn_entry: dict[str, Any]) -> str:
    """Return the canonical function signature, e.g. 'transfer(address,uint256)'."""
    inputs: list[dict[str, Any]] = abi_fn_entry.get("inputs", [])
    name: str = abi_fn_entry["name"]
    return name + "(" + ",".join(canonical_type(i) for i in inputs) + ")"


def selector_of(abi_fn_entry: dict[str, Any]) -> str:
    """Return '0x' + 8 lowercase hex chars for the 4-byte function selector."""
    return "0x" + function_abi_to_4byte_selector(abi_fn_entry).hex()  # type: ignore[arg-type]


def _is_predicatable_scalar(abi_type: str) -> bool:
    """Return True iff abi_type is a scalar type suitable for policy predicates.

    Scalars: address, bool, string, bytes (bare), uint/uint<N>, int/int<N>,
    bytes<N> (N in 1..32).
    Non-scalars (arrays, tuples, dynamic types with "["/"(") return False.
    """
    # Fast path: any array or tuple-like type is not scalar
    if "[" in abi_type or "(" in abi_type or abi_type.startswith("tuple"):
        return False
    if abi_type.startswith("function"):
        return False
    return bool(_SCALAR_RE.match(abi_type))


def _normalize(ctype: str, value: Any) -> Any:
    """Normalize a decoded value to a JSON-serializable form.

    bytes and bytes<N> → "0x" + hex string.
    Everything else (address, string, bool, uint*, int*) → pass through unchanged.
    eth_abi 5.x already returns lowercase 0x-hex str for address, Python int
    for uint/int, bool, and str for string — no further transformation needed.
    """
    if ctype == "bytes" or (ctype.startswith("bytes") and ctype != "bytes" and "[" not in ctype):
        # bytes or bytesN: eth_abi returns Python bytes
        assert isinstance(value, bytes)
        return "0x" + value.hex()
    return value


def decode_intent(
    contract: str,
    calldata: bytes,
    abi_fn_entry: dict[str, Any],
) -> DecodedIntent | None:
    """Decode EVM calldata against a single ABI function entry.

    Returns a DecodedIntent on success, or None on any failure (selector
    mismatch, truncated data, decode error, etc.). Never raises.

    Per B1: non-scalar top-level args (arrays, tuples) are decoded by
    eth_abi but omitted from DecodedIntent.args. The caller should
    treat None as default-deny.
    """
    try:
        if len(calldata) < 4:
            return None

        sel = selector_of(abi_fn_entry)
        if "0x" + calldata[:4].hex() != sel:
            return None

        inputs: list[dict[str, Any]] = abi_fn_entry.get("inputs", [])
        types = [canonical_type(inp) for inp in inputs]

        # Build names list — fall back to "arg<i>" for unnamed inputs
        names = [(inp.get("name") or f"arg{i}") for i, inp in enumerate(inputs)]

        # Decode full calldata (eth_abi handles nested tuples/arrays)
        decoded = eth_abi.decode(types, calldata[4:])  # type: ignore[attr-defined]

        # Projection (B1): only include scalar args in .args
        args: dict[str, Any] = {}
        for inp, name, value in zip(inputs, names, decoded, strict=False):
            ctype = canonical_type(inp)
            if _is_predicatable_scalar(ctype):
                args[name] = _normalize(ctype, value)
            # Non-scalar args are silently omitted per B1

        return DecodedIntent(
            contract=contract.lower(),
            method_signature=canonical_signature(abi_fn_entry),
            selector=sel,
            args=args,
        )
    except Exception:  # noqa: BLE001
        return None
