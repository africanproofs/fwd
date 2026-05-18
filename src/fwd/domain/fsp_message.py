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

Returns None on any malformed input (default-deny; mirrors decode_intent).
Pure: stdlib + eth_utils + eth_abi only; NO fwd.* imports.
"""

from __future__ import annotations

from dataclasses import dataclass

import eth_abi
from eth_utils import keccak  # type: ignore[attr-defined]

UPTIME = "UPTIME"
REWARD_DISTRIBUTION = "REWARD_DISTRIBUTION"
_MESSAGE_TYPES = frozenset({UPTIME, REWARD_DISTRIBUTION})
_MAX_UINT24 = 16_777_215  # signing-tool parseRewardEpochId range (defense-in-depth)


@dataclass(frozen=True)
class FspMessage:
    """The reconstructed FSP identity + the 32-byte body to EIP-191-sign."""

    message_type: str
    reward_epoch_id: int
    message_hash: bytes  # exactly 32 bytes


def build_fsp_message(
    message_type: str,
    reward_epoch_id: int,
    *,
    chain_id: int | None = None,
    no_of_weight_based_claims: int | None = None,
    rewards_hash: str | None = None,
) -> FspMessage | None:
    """Reconstruct the FSP messageHash. None on ANY malformed input."""
    try:
        if message_type not in _MESSAGE_TYPES:
            return None
        if not isinstance(reward_epoch_id, int) or isinstance(reward_epoch_id, bool):
            return None
        if reward_epoch_id < 0 or reward_epoch_id > _MAX_UINT24:
            return None
        epoch_be32 = reward_epoch_id.to_bytes(32, "big")

        if message_type == UPTIME:
            if (
                chain_id is not None
                or no_of_weight_based_claims is not None
                or rewards_hash is not None
            ):
                return None
            second = keccak(b"\x00" * 32)
            message = epoch_be32 + second
        else:  # REWARD_DISTRIBUTION
            if (
                not isinstance(chain_id, int)
                or isinstance(chain_id, bool)
                or chain_id <= 0
            ):
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
        return FspMessage(
            message_type=message_type,
            reward_epoch_id=reward_epoch_id,
            message_hash=message_hash,
        )
    except Exception:  # noqa: BLE001 — default-deny: any failure -> None
        return None
