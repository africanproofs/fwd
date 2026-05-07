"""EnvelopeSigner — Vault-Transit envelope-encryption Signer implementation.

Per architecture.md § Signing flow + § The signer interface:
- Phase 3b ships address() and a generate_and_store() helper for wallet
  creation; sign_transaction() raises NotImplementedError until Phase 3c.

The wallet-create flow is:
  1. Account.create() generates a fresh secp256k1 privkey.
  2. Wrap as bytearray immediately (per architecture.md § Implementation
     hazards #2: bytearray, not bytes).
  3. Vault encrypt(plaintext_bytes) → "vault:v1:<...>".
  4. WalletRepo.create(name, address, privkey_ciphertext, ...).
  5. Zeroize the bytearray in-place.

The cardinal rule: the privkey lives in process memory only between
steps 1 and 5. No instance attribute holds plaintext past return.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from eth_account import Account
from eth_utils import to_checksum_address  # type: ignore[attr-defined]

if TYPE_CHECKING:
    from fwd.domain.signer import SignedTransaction
    from fwd.infra.vault_client import VaultClient
    from fwd.infra.wallet_repo import Wallet, WalletRepo


def _zeroize(buf: bytearray) -> None:
    """Overwrite a bytearray in-place. Per architecture.md hazard #2."""
    for i in range(len(buf)):
        buf[i] = 0


class EnvelopeSigner:
    def __init__(self, vault: VaultClient, repo: WalletRepo) -> None:
        self._vault = vault
        self._repo = repo

    async def address(self, wallet_name: str) -> str:
        wallet = await self._repo.get_by_name(wallet_name)
        assert wallet is not None  # raises WalletNotFoundError otherwise
        return wallet.address

    async def sign_transaction(
        self, wallet_name: str, tx_dict: dict[str, Any]
    ) -> SignedTransaction:
        # Phase 3c lands the real signing path (decrypt → sign → zeroize).
        # The placeholder enforces "Phase 3b doesn't sign yet" at call time.
        raise NotImplementedError("sign_transaction lands in Phase 3c (v0.3.0)")

    async def create_wallet(
        self,
        *,
        name: str,
        policy_path: str,
    ) -> Wallet:
        """Generate a fresh wallet, encrypt the privkey, persist.

        Returns the persisted Wallet. Plaintext privkey is zeroized before
        return.
        """
        # 1. Generate.
        account = Account.create()
        privkey_buf = bytearray(account.key)  # immutable-bytes -> mutable bytearray
        try:
            # 2. Encrypt.
            ciphertext = await self._vault.encrypt(bytes(privkey_buf))
            # 3. Address (eth-account already gives this; checksum for storage).
            address = to_checksum_address(account.address)
            # 4. Persist.
            wallet = await self._repo.create(
                name=name,
                address=address,
                privkey_ciphertext=ciphertext,
                vault_master_key="fwd-master",
                policy_path=policy_path,
            )
            return wallet
        finally:
            # 5. Always zeroize, even on raise.
            _zeroize(privkey_buf)
