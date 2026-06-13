"""FSP message preimage builder — pure domain module.

The Flare signing-tool (github.com/flare-foundation/signing-tool, src/sign.ts)
builds a 32-byte FSP messageHash, then EIP-191 personal-signs it. This module
reconstructs that messageHash from typed, validated fields — the FSP analogue
of decode_intent() (decisions.md D15). The caller never supplies a raw digest
or an opaque component hash; fwd builds the entire preimage.

Byte-verified against signing-tool@838b87f (v1.2.1):
  UPTIME              keccak256( epoch_be32 || keccak256(0x00 * 32) )
  REWARD_DISTRIBUTION keccak256( epoch_be32
                        || keccak256(abi.encode('(uint256,uint256)[]',
                                                [[chain_id, n]]))
                        || rewards_hash_32 )
epoch_be32 = rewardEpochId as a 32-byte big-endian uint256.

Byte-verified against flare-system-client@29d2c78:
  VOTER_REGISTRATION  legacy:      keccak256(abi.encode(['uint32','address'],[epoch,addr]))
                      chain_scoped: keccak256(abi.encode(['uint256','uint32','address'],[chain_id,epoch,addr]))
  SIGNING_POLICY      SigningPolicyHash(policy_bytes) — iterative keccak chain over 32-byte chunks
  PROTOCOL_PAYLOAD    keccak256(payload_bytes)

Byte-verified against fast-updates@go-client/updates/updates.go (PrepareUpdates):
  FAST_UPDATE         sha256( abi.encode(['uint256','uint256','uint256','uint256','uint256','uint256','bytes'],
                                         [block_number, replicate, gamma_x, gamma_y, c, s, deltas]) )
  The Go client then applies EIP-191 (crypto.Sign(keccak256(prefix||sha256_digest), key))
  which equals sign_fsp_eip191(sha256_digest) — signer reused unchanged.

Returns None on any malformed input (default-deny; mirrors decode_intent).
Pure: stdlib + eth_utils + eth_abi + hashlib only; NO fwd.* imports.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

import eth_abi
from eth_utils import keccak  # type: ignore[attr-defined]

UPTIME = "UPTIME"
REWARD_DISTRIBUTION = "REWARD_DISTRIBUTION"
SIGNING_POLICY = "SIGNING_POLICY"
VOTER_REGISTRATION = "VOTER_REGISTRATION"
PROTOCOL_PAYLOAD = "PROTOCOL_PAYLOAD"
FAST_UPDATE = "FAST_UPDATE"
_MESSAGE_TYPES = frozenset({UPTIME, REWARD_DISTRIBUTION, SIGNING_POLICY, VOTER_REGISTRATION, PROTOCOL_PAYLOAD, FAST_UPDATE})
_MAX_UINT24 = 16_777_215  # signing-tool parseRewardEpochId range (defense-in-depth)
_MAX_PAYLOAD_BYTES = 4096
_MAX_DELTAS_BYTES = 4096
_MAX_UINT256 = 2**256 - 1
_HEX_ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")


@dataclass(frozen=True)
class FspMessage:
    """The reconstructed FSP identity + the 32-byte body to EIP-191-sign."""

    message_type: str
    reward_epoch_id: int
    message_hash: bytes  # exactly 32 bytes


def _decode_hex(hex_str: str | None) -> bytes | None:
    """Decode a 0x-prefixed hex string to bytes. Returns None on any error."""
    if not isinstance(hex_str, str) or not hex_str.startswith("0x"):
        return None
    try:
        return bytes.fromhex(hex_str[2:])
    except ValueError:
        return None


def _signing_policy_hash(policy_bytes: bytes) -> bytes:
    """Compute SigningPolicyHash per flare-system-client system_manager_utils.go.

    Right-pads policy_bytes to multiple of 32, then iteratively keccak-chains
    the 32-byte chunks: h = keccak(chunk0 || chunk1), then for each subsequent
    chunk: h = keccak(h || chunk_i). Requires >= 64 bytes after padding.
    """
    if len(policy_bytes) % 32 != 0:
        policy_bytes = policy_bytes + b"\x00" * (32 - len(policy_bytes) % 32)
    if len(policy_bytes) < 64:
        raise ValueError("SigningPolicyHash requires >= 64 bytes after padding")
    h = keccak(policy_bytes[0:32] + policy_bytes[32:64])
    for i in range(2, len(policy_bytes) // 32):
        h = keccak(h + policy_bytes[i * 32 : (i + 1) * 32])
    return h


def build_fsp_message(
    message_type: str,
    reward_epoch_id: int,
    *,
    chain_id: int | None = None,
    no_of_weight_based_claims: int | None = None,
    rewards_hash: str | None = None,
    address: str | None = None,
    signing_policy: str | None = None,
    payload: str | None = None,
    protocol_id: int | None = None,
    registration_variant: str | None = None,
    block_number: int | None = None,
    replicate: int | None = None,
    gamma_x: int | None = None,
    gamma_y: int | None = None,
    c: int | None = None,
    s: int | None = None,
    deltas: str | None = None,
) -> FspMessage | None:
    """Reconstruct the FSP messageHash. None on ANY malformed input."""
    try:
        if message_type not in _MESSAGE_TYPES:
            return None
        if not isinstance(reward_epoch_id, int) or isinstance(reward_epoch_id, bool):
            return None
        if reward_epoch_id < 0 or reward_epoch_id > _MAX_UINT24:
            return None
        epoch_be32 = reward_epoch_id.to_bytes(32, "big")  # noqa: F841 — used by UPTIME/REWARD

        if message_type == UPTIME:
            if (
                chain_id is not None
                or no_of_weight_based_claims is not None
                or rewards_hash is not None
                or address is not None
                or signing_policy is not None
                or payload is not None
                or protocol_id is not None
                or registration_variant is not None
                or block_number is not None
                or replicate is not None
                or gamma_x is not None
                or gamma_y is not None
                or c is not None
                or s is not None
                or deltas is not None
            ):
                return None
            second = keccak(b"\x00" * 32)
            message = epoch_be32 + second
            message_hash = keccak(message)

        elif message_type == REWARD_DISTRIBUTION:
            if (
                address is not None
                or signing_policy is not None
                or payload is not None
                or protocol_id is not None
                or registration_variant is not None
                or block_number is not None
                or replicate is not None
                or gamma_x is not None
                or gamma_y is not None
                or c is not None
                or s is not None
                or deltas is not None
            ):
                return None
            if not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id <= 0:
                return None
            if (
                not isinstance(no_of_weight_based_claims, int)
                or isinstance(no_of_weight_based_claims, bool)
                or no_of_weight_based_claims < 0
            ):
                return None
            if (
                not isinstance(rewards_hash, str)
                or not rewards_hash.startswith("0x")
                or len(rewards_hash) != 66
            ):
                return None
            try:
                rewards_hash_bytes = bytes.fromhex(rewards_hash[2:])
            except ValueError:
                return None
            if len(rewards_hash_bytes) != 32:
                return None
            nowbc_encoded = eth_abi.encode(  # type: ignore[attr-defined]
                ["(uint256,uint256)[]"],
                [[(chain_id, no_of_weight_based_claims)]],
            )
            second = keccak(nowbc_encoded)
            message = epoch_be32 + second + rewards_hash_bytes
            message_hash = keccak(message)

        elif message_type == VOTER_REGISTRATION:
            # Foreign fields forbidden
            if (
                no_of_weight_based_claims is not None
                or rewards_hash is not None
                or signing_policy is not None
                or payload is not None
                or protocol_id is not None
                or block_number is not None
                or replicate is not None
                or gamma_x is not None
                or gamma_y is not None
                or c is not None
                or s is not None
                or deltas is not None
            ):
                return None
            # address required and must be valid 0x + 40 hex
            if not isinstance(address, str) or not _HEX_ADDR.match(address):
                return None
            # registration_variant required
            if registration_variant not in ("legacy", "chain_scoped"):
                return None
            addr_lower = address.lower()
            if registration_variant == "legacy":
                # chain_id must NOT be present in the hash; caller passes None
                if chain_id is not None:
                    return None
                encoded = eth_abi.encode(  # type: ignore[attr-defined]
                    ["uint32", "address"],
                    [reward_epoch_id, addr_lower],
                )
            else:  # chain_scoped
                if not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id <= 0:
                    return None
                encoded = eth_abi.encode(  # type: ignore[attr-defined]
                    ["uint256", "uint32", "address"],
                    [chain_id, reward_epoch_id, addr_lower],
                )
            message_hash = keccak(encoded)

        elif message_type == SIGNING_POLICY:
            # Foreign fields forbidden (chain_id not in the hash; carried at gate only)
            if (
                chain_id is not None
                or address is not None
                or no_of_weight_based_claims is not None
                or rewards_hash is not None
                or payload is not None
                or protocol_id is not None
                or registration_variant is not None
                or block_number is not None
                or replicate is not None
                or gamma_x is not None
                or gamma_y is not None
                or c is not None
                or s is not None
                or deltas is not None
            ):
                return None
            policy_bytes = _decode_hex(signing_policy)
            if policy_bytes is None:
                return None
            if len(policy_bytes) == 0:
                return None
            message_hash = _signing_policy_hash(policy_bytes)

        elif message_type == PROTOCOL_PAYLOAD:
            # Foreign fields forbidden
            if (
                address is not None
                or no_of_weight_based_claims is not None
                or rewards_hash is not None
                or signing_policy is not None
                or registration_variant is not None
                or block_number is not None
                or replicate is not None
                or gamma_x is not None
                or gamma_y is not None
                or c is not None
                or s is not None
                or deltas is not None
            ):
                return None
            payload_bytes = _decode_hex(payload)
            if payload_bytes is None or len(payload_bytes) == 0:
                return None
            if len(payload_bytes) > _MAX_PAYLOAD_BYTES:
                return None
            # protocol_id and chain_id are audit-only; not in the hash
            message_hash = keccak(payload_bytes)

        else:  # FAST_UPDATE
            # Foreign fields forbidden
            if (
                no_of_weight_based_claims is not None
                or rewards_hash is not None
                or address is not None
                or signing_policy is not None
                or payload is not None
                or protocol_id is not None
                or registration_variant is not None
            ):
                return None
            # All six ints required; must be non-bool ints in [0, 2**256-1]
            for _val in (block_number, replicate, gamma_x, gamma_y, c, s):
                if not isinstance(_val, int) or isinstance(_val, bool):
                    return None
                if _val < 0 or _val > _MAX_UINT256:
                    return None
            # deltas: required 0x-hex, decoded, length bound <= 4096 bytes
            deltas_bytes = _decode_hex(deltas)
            if deltas_bytes is None:
                return None
            if len(deltas_bytes) > _MAX_DELTAS_BYTES:
                return None
            # chain_id is gate-scoping only; NOT in the hash
            packed = eth_abi.encode(  # type: ignore[attr-defined]
                ["uint256", "uint256", "uint256", "uint256", "uint256", "uint256", "bytes"],
                [block_number, replicate, gamma_x, gamma_y, c, s, deltas_bytes],
            )
            message_hash = hashlib.sha256(packed).digest()

        return FspMessage(
            message_type=message_type,
            reward_epoch_id=reward_epoch_id,
            message_hash=message_hash,
        )
    except Exception:  # noqa: BLE001 — default-deny: any failure -> None
        return None
