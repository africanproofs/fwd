"""EnvelopeSigner — Vault-Transit envelope-encryption Signer implementation.

Per architecture.md § Signing flow + § The signer interface:
- Phase 3b ships address() and create_wallet() for wallet provisioning.
- Phase 3c implements sign_transaction() (decrypt → sign → zeroize).

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

from fwd.domain.signer import SignedTransaction

if TYPE_CHECKING:
    from fwd.infra.sealed_master import SealedMaster
    from fwd.infra.wallet_repo import Wallet, WalletRepo


def _zeroize(buf: bytearray) -> None:
    """Overwrite a bytearray in-place. Per architecture.md hazard #2."""
    for i in range(len(buf)):
        buf[i] = 0


class WalletImportInvalidLength(Exception):  # noqa: N818
    """Raised when the supplied privkey is not exactly 32 bytes."""


class WalletAddressMismatch(Exception):  # noqa: N818
    """Raised when --expected-address doesn't match the derived address."""

    def __init__(self, *, expected: str, derived: str) -> None:
        self.expected = expected
        self.derived = derived
        super().__init__(f"derived address {derived} does not match --expected-address {expected}")


class EnvelopeSigner:
    def __init__(self, vault: SealedMaster, repo: WalletRepo) -> None:
        self._vault = vault
        self._repo = repo

    async def address(self, wallet_name: str) -> str:
        wallet = await self._repo.get_by_name(wallet_name)
        assert wallet is not None  # raises WalletNotFoundError otherwise
        return wallet.address

    async def sign_transaction(
        self, wallet_name: str, tx_dict: dict[str, Any]
    ) -> SignedTransaction:
        """Sign an EIP-1559 transaction dict with the wallet's privkey.

        Per architecture.md § Signing flow steps 9-12 + § Implementation hazards #2:
          1. Fetch privkey_ciphertext from wallets table.
          2. Vault decrypt -> bytes plaintext.
          3. Wrap as bytearray (mutable -> in-place zeroize possible).
          4. Account.from_key(bytes(buf)).sign_transaction(tx_dict).
          5. Zeroize the bytearray in finally.

        Caveat (architecture.md hazards #2): the bytes returned from
        vault.decrypt() are immutable. Wrapping as bytearray creates a copy;
        the original immutable bytes are subject to GC, not in-place
        overwrite. Phase 10 with ctypes is the canonical fix. v1 accepts.
        """
        wallet = await self._repo.get_by_name(wallet_name)
        assert wallet is not None  # raises WalletNotFoundError when missing_ok=False
        plaintext_bytes = await self._vault.decrypt(wallet.privkey_ciphertext)
        privkey_buf = bytearray(plaintext_bytes)
        try:
            signed = Account.from_key(bytes(privkey_buf)).sign_transaction(tx_dict)
            return SignedTransaction(
                raw_transaction=bytes(signed.raw_transaction),
                hash=bytes(signed.hash),
                r=int(signed.r),
                s=int(signed.s),
                v=int(signed.v),
            )
        finally:
            _zeroize(privkey_buf)

    async def import_wallet(
        self,
        *,
        name: str,
        privkey_buf: bytearray,
        policy_path: str,
        expected_address: str | None = None,
    ) -> Wallet:
        """Like create_wallet but with externally-provided privkey.

        Per D12: the caller (app/wallet_import.py) supplies the privkey as
        a bytearray that this method will zeroize in finally. Caller is
        responsible for NOT retaining a reference to the buffer after this
        returns; the bytearray identity is preserved (in-place overwrite).

        Validates the privkey length (32 bytes) and optionally the derived
        EIP-55 address against `expected_address`. Raises:
          - WalletImportInvalidLength: privkey_buf is not 32 bytes.
          - WalletAddressMismatch: derived address ≠ expected_address.
          - WalletExistsError: name PK collision.
        """
        if len(privkey_buf) != 32:
            _zeroize(privkey_buf)
            raise WalletImportInvalidLength(len(privkey_buf))

        try:
            # 1. Derive address.
            account = Account.from_key(bytes(privkey_buf))
            derived_address = to_checksum_address(account.address)
            if expected_address is not None and derived_address.lower() != expected_address.lower():
                raise WalletAddressMismatch(expected=expected_address, derived=derived_address)
            # 2. Encrypt.
            ciphertext = await self._vault.encrypt(bytes(privkey_buf))
            # 3. Persist.
            wallet = await self._repo.create(
                name=name,
                address=derived_address,
                privkey_ciphertext=ciphertext,
                vault_master_key="local:v1",
                policy_path=policy_path,
            )
            return wallet
        finally:
            _zeroize(privkey_buf)

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
                vault_master_key="local:v1",
                policy_path=policy_path,
            )
            return wallet
        finally:
            # 5. Always zeroize, even on raise.
            _zeroize(privkey_buf)
