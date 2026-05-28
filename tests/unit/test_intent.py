"""Unit tests for fwd.domain.intent (ABI intent decoder).

Per decisions.md D15. All tests are synchronous (plain def).
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import eth_abi
import pytest
from eth_utils import function_abi_to_4byte_selector

from fwd.domain.intent import (
    DecodedIntent,
    canonical_type,
    decode_intent,
    has_nonscalar_args,
)

# ---------------------------------------------------------------------------
# Path to the real ABI files (config/abis/ relative to repo root)
# ---------------------------------------------------------------------------
_ABIS_DIR = Path(__file__).resolve().parents[2] / "config" / "abis"


def _load_abi(name: str) -> list[dict[str, Any]]:
    data = json.loads((_ABIS_DIR / f"{name}.json").read_text())
    if isinstance(data, list):
        return data
    # Hardhat artifact
    return data["abi"]  # type: ignore[return-value]


def _fn_entry(abi: list[dict[str, Any]], fn_name: str) -> dict[str, Any]:
    return next(e for e in abi if e.get("name") == fn_name)


# ---------------------------------------------------------------------------
# Helper: build valid calldata from an ABI function entry + values
# ---------------------------------------------------------------------------
def _calldata(fn_entry: dict[str, Any], values: list[Any]) -> bytes:
    return function_abi_to_4byte_selector(fn_entry) + eth_abi.encode(
        [canonical_type(i) for i in fn_entry.get("inputs", [])], values
    )


# ---------------------------------------------------------------------------
# ABI fixtures (loaded once)
# ---------------------------------------------------------------------------
_ERC20 = _load_abi("erc20")
_PR = _load_abi("participant_register")
_RM = _load_abi("reward_manager")

_ERC20_TRANSFER = _fn_entry(_ERC20, "transfer")
_PR_REGISTER = _fn_entry(_PR, "register")
_PR_UNREGISTER = _fn_entry(_PR, "unregister")
_RM_CLAIM = _fn_entry(_RM, "claim")
_RM_AUTOCLAIM = _fn_entry(_RM, "autoClaim")
_RM_INIT = _fn_entry(_RM, "initialiseWeightBasedClaims")

_CONTRACT = "0xabcdef1234567890abcdef1234567890abcdef12"
_ADDR_LOWER = "0x" + "aa" * 20


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


def test_has_nonscalar_args_scalar_only_is_false() -> None:
    # transfer(address,uint256) — both args scalar.
    assert has_nonscalar_args(_ERC20_TRANSFER) is False


def test_has_nonscalar_args_with_tuple_array_is_true() -> None:
    # claim(...,(...)[]) — the _proofs tuple[] is non-scalar.
    assert has_nonscalar_args(_RM_CLAIM) is True
    # autoClaim has an address[] — also non-scalar.
    assert has_nonscalar_args(_RM_AUTOCLAIM) is True


def test_erc20_transfer_happy_path() -> None:
    """Test 1: erc20 transfer decodes to correct args, signature, and selector."""
    amount = 1_000
    cd = _calldata(_ERC20_TRANSFER, [_ADDR_LOWER, amount])
    result = decode_intent(_CONTRACT, cd, _ERC20_TRANSFER)
    assert result is not None
    assert result.args == {"to": _ADDR_LOWER, "amount": amount}
    assert result.method_signature == "transfer(address,uint256)"
    assert result.selector.startswith("0x")
    assert len(result.selector) == 10  # "0x" + 8 hex chars
    # Verify selector matches the known keccak value
    assert result.selector == "0x" + function_abi_to_4byte_selector(_ERC20_TRANSFER).hex()


def test_erc20_transfer_address_already_lowercase_from_eth_abi() -> None:
    """Test 2: doctrine-correction #2 regression guard.

    eth_abi 5.x already returns lowercase 0x-hex str for address — the decoder
    must NOT strip/re-lowercase, just pass through. A checksummed address passed
    in encodes to the same 32-byte ABI word; eth_abi decodes it as lowercase.
    """
    # Build calldata with a checksummed (mixed-case) 'to' address
    checksummed_to = "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"
    cd = _calldata(_ERC20_TRANSFER, [checksummed_to, 42])
    result = decode_intent(_CONTRACT, cd, _ERC20_TRANSFER)
    assert result is not None
    # eth_abi 5.x returns the address in all-lowercase hex
    to_addr: str = result.args["to"]
    assert to_addr == to_addr.lower(), "Address must be all-lowercase from eth_abi 5.x"
    assert to_addr.startswith("0x")


def test_participant_register_register_happy_path() -> None:
    """Test 3: ParticipantRegister register(uint8,string) decodes correctly."""
    cd = _calldata(_PR_REGISTER, [1, "https://proofs.africa"])
    result = decode_intent(_CONTRACT, cd, _PR_REGISTER)
    assert result is not None
    assert result.method_signature == "register(uint8,string)"
    assert result.args["participantType"] == 1
    assert result.args["infoURI"] == "https://proofs.africa"
    # uint8 (enum) decodes as int
    assert isinstance(result.args["participantType"], int)
    # string decodes as str
    assert isinstance(result.args["infoURI"], str)


def test_participant_register_unregister_empty_args() -> None:
    """Test 4: ParticipantRegister unregister() has no args."""
    cd = _calldata(_PR_UNREGISTER, [])
    result = decode_intent(_CONTRACT, cd, _PR_UNREGISTER)
    assert result is not None
    assert result.args == {}
    assert result.method_signature == "unregister()"
    expected_sel = "0x" + function_abi_to_4byte_selector(_PR_UNREGISTER).hex()
    assert result.selector == expected_sel


def test_reward_manager_claim_scalars_only_proof_array_absent() -> None:
    """Test 5: RewardManager claim — only 4 scalar args; proof array omitted (B1).

    method_signature must end with '(bytes32[],(uint24,bytes20,uint120,uint8))[])'.
    """
    proofs_val = [([b"\x00" * 32], (1, b"\x00" * 20, 1, 0))]
    cd = _calldata(
        _RM_CLAIM,
        ["0x" + "11" * 20, "0x" + "22" * 20, 5, True, proofs_val],
    )
    result = decode_intent(_CONTRACT, cd, _RM_CLAIM)
    assert result is not None
    # Exactly 4 scalar keys; _proofs (tuple[]) must be absent
    assert set(result.args.keys()) == {"_rewardOwner", "_recipient", "_rewardEpochId", "_wrap"}
    # Type assertions
    assert isinstance(result.args["_rewardOwner"], str)  # address
    assert isinstance(result.args["_recipient"], str)  # address
    assert isinstance(result.args["_rewardEpochId"], int)  # uint24
    assert isinstance(result.args["_wrap"], bool)  # bool
    assert result.args["_rewardEpochId"] == 5
    assert result.args["_wrap"] is True
    # Signature ends with the full tuple expansion
    assert result.method_signature.endswith("(bytes32[],(uint24,bytes20,uint120,uint8))[])")


def test_reward_manager_claim_empty_proofs_array() -> None:
    """Test 6: RewardManager claim with empty proofs list still decodes."""
    cd = _calldata(
        _RM_CLAIM,
        ["0x" + "aa" * 20, "0x" + "bb" * 20, 7, False, []],
    )
    result = decode_intent(_CONTRACT, cd, _RM_CLAIM)
    assert result is not None
    assert set(result.args.keys()) == {"_rewardOwner", "_recipient", "_rewardEpochId", "_wrap"}
    assert result.args["_rewardEpochId"] == 7
    assert result.args["_wrap"] is False


def test_reward_manager_autoclaim_address_array_omitted() -> None:
    """Test 7: RewardManager autoClaim — address[] first arg is omitted; only uint24 scalar."""
    owners = ["0x" + "11" * 20, "0x" + "22" * 20]
    proofs_val = [([b"\x00" * 32], (1, b"\x00" * 20, 1, 0))]
    cd = _calldata(_RM_AUTOCLAIM, [owners, 3, proofs_val])
    result = decode_intent(_CONTRACT, cd, _RM_AUTOCLAIM)
    assert result is not None
    # Only _rewardEpochId (uint24) is scalar; _rewardOwners (address[]) and _proofs (tuple[]) omitted
    assert set(result.args.keys()) == {"_rewardEpochId"}
    assert result.args["_rewardEpochId"] == 3


def test_reward_manager_initialise_weight_based_claims_all_omitted() -> None:
    """Test 8: RewardManager initialiseWeightBasedClaims — sole input is tuple[]; args == {}."""
    proofs_val = [([b"\x00" * 32], (1, b"\x00" * 20, 1, 0))]
    cd = _calldata(_RM_INIT, [proofs_val])
    result = decode_intent(_CONTRACT, cd, _RM_INIT)
    assert result is not None
    assert result.args == {}
    # Selector is valid
    expected_sel = "0x" + function_abi_to_4byte_selector(_RM_INIT).hex()
    assert result.selector == expected_sel
    # Signature includes the full nested type
    assert "initialiseWeightBasedClaims" in result.method_signature


def test_decode_intent_selector_mismatch_returns_none() -> None:
    """Test 9: selector mismatch → None."""
    # Build calldata for transfer, but try to decode against approve
    erc20_approve = _fn_entry(_ERC20, "approve")
    cd = _calldata(_ERC20_TRANSFER, [_ADDR_LOWER, 100])
    # Decode against the wrong entry (approve != transfer selector)
    result = decode_intent(_CONTRACT, cd, erc20_approve)
    assert result is None


def test_decode_intent_truncated_calldata_returns_none() -> None:
    """Test 10: valid selector + too-few bytes → None (truncated ABI payload)."""
    sel = function_abi_to_4byte_selector(_ERC20_TRANSFER)
    # Provide only the selector (no argument bytes)
    result = decode_intent(_CONTRACT, bytes(sel), _ERC20_TRANSFER)
    assert result is None


def test_decode_intent_empty_calldata_returns_none() -> None:
    """Test 11: empty calldata → None."""
    result = decode_intent(_CONTRACT, b"", _ERC20_TRANSFER)
    assert result is None


def test_decode_intent_less_than_4_bytes_returns_none() -> None:
    """Test 12: calldata shorter than 4 bytes → None."""
    result = decode_intent(_CONTRACT, b"\x01\x02", _ERC20_TRANSFER)
    assert result is None


def test_decode_intent_dynamic_bytes_arg_hex_normalized() -> None:
    """Test 13: dynamic bytes arg → args["x"] is '0x'+hex string."""
    fn_entry: dict[str, Any] = {
        "name": "f",
        "type": "function",
        "stateMutability": "nonpayable",
        "inputs": [{"name": "x", "type": "bytes"}],
        "outputs": [],
    }
    payload = b"\xde\xad\xbe\xef"
    cd = function_abi_to_4byte_selector(fn_entry) + eth_abi.encode(["bytes"], [payload])
    result = decode_intent(_CONTRACT, cd, fn_entry)
    assert result is not None
    assert result.args["x"] == "0x" + payload.hex()
    assert isinstance(result.args["x"], str)


def test_decode_intent_bytes32_arg_hex_normalized() -> None:
    """Test 14: bytes32 arg → args["x"] is '0x' + 64 lowercase hex chars."""
    fn_entry: dict[str, Any] = {
        "name": "g",
        "type": "function",
        "stateMutability": "nonpayable",
        "inputs": [{"name": "x", "type": "bytes32"}],
        "outputs": [],
    }
    payload = b"\xab" * 32
    cd = function_abi_to_4byte_selector(fn_entry) + eth_abi.encode(["bytes32"], [payload])
    result = decode_intent(_CONTRACT, cd, fn_entry)
    assert result is not None
    assert result.args["x"] == "0x" + payload.hex()
    assert len(result.args["x"]) == 66  # "0x" + 64 hex chars


def test_decode_intent_negative_int256() -> None:
    """Test 15: negative int256 value decodes as negative Python int."""
    fn_entry: dict[str, Any] = {
        "name": "f",
        "type": "function",
        "stateMutability": "nonpayable",
        "inputs": [{"name": "x", "type": "int256"}],
        "outputs": [],
    }
    cd = function_abi_to_4byte_selector(fn_entry) + eth_abi.encode(["int256"], [-5])
    result = decode_intent(_CONTRACT, cd, fn_entry)
    assert result is not None
    assert result.args["x"] == -5
    assert isinstance(result.args["x"], int)


def test_decode_intent_trailing_junk_bytes_succeeds() -> None:
    """Test 16: eth_abi tolerates trailing bytes; decoder returns valid DecodedIntent."""
    cd = _calldata(_ERC20_TRANSFER, [_ADDR_LOWER, 999]) + b"\xff" * 16
    result = decode_intent(_CONTRACT, cd, _ERC20_TRANSFER)
    # eth_abi 5.x is lenient about trailing bytes — decoder must not return None
    assert result is not None
    assert result.args["amount"] == 999
    assert result.args["to"] == _ADDR_LOWER


def test_decode_intent_never_raises() -> None:
    """Test 17: decode_intent returns None (never raises) for garbage inputs."""
    fn_entry: dict[str, Any] = {
        "name": "f",
        "type": "function",
        "stateMutability": "nonpayable",
        "inputs": [{"name": "x", "type": "uint256"}],
        "outputs": [],
    }
    bad_inputs = [
        b"",
        b"\x00",
        b"\x01\x02\x03",
        b"\xff" * 100,
        b"\x00" * 4,
        b"\xde\xad\xbe\xef",
        # Wrong-shaped entry (missing name key)
    ]
    for blob in bad_inputs:
        result = decode_intent(_CONTRACT, blob, fn_entry)
        assert result is None, f"Expected None for blob {blob!r}, got {result!r}"

    # Also try a wrong-shaped entry dict — should not raise
    bad_entry: dict[str, Any] = {"name": "broken", "inputs": [{"type": "NOTATYPE"}]}
    result2 = decode_intent(_CONTRACT, b"\x00" * 100, bad_entry)
    assert result2 is None


def test_decoded_intent_is_frozen() -> None:
    """Test 18: DecodedIntent is a frozen dataclass — attribute assignment raises."""
    intent = DecodedIntent(
        contract=_CONTRACT,
        method_signature="transfer(address,uint256)",
        selector="0xa9059cbb",
        args={"to": _ADDR_LOWER, "amount": 1000},
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        intent.contract = "0x" + "00" * 20  # type: ignore[misc]
