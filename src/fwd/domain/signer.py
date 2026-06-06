"""Signer protocol — the only forward-compatibility abstraction in fwd.

Per architecture.md § The signer interface, this Protocol is what the
application layer depends on. v1 ships one implementation: EnvelopeSigner
(infra/envelope_signer.py). A future YubiHsmSigner (Phase 10, optional)
plugs in via the same protocol.

Phase 3b ships address() and a placeholder sign_transaction() that raises
NotImplementedError. Phase 3c implements sign_transaction.
"""

from __future__ import annotations

from typing import Any, NamedTuple, Protocol


class SignedTransaction(NamedTuple):
    raw_transaction: bytes
    hash: bytes
    r: int
    s: int
    v: int


class SignedDigest(NamedTuple):
    """Result of an EIP-191 personal_sign over a fwd-reconstructed 32-byte
    FSP messageHash. NOT a transaction, NOT a raw eth_sign digest."""

    message_hash: bytes  # the 32-byte body that was EIP-191-wrapped
    r: int
    s: int
    v: int
    signature: bytes  # 65-byte r||s||v


class Signer(Protocol):
    async def address(self, wallet_name: str) -> str: ...

    async def sign_transaction(
        self, wallet_name: str, tx_dict: dict[str, Any]
    ) -> SignedTransaction: ...

    async def sign_fsp_eip191(self, wallet_name: str, message_hash_32: bytes) -> SignedDigest: ...
