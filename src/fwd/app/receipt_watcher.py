"""Receipt watcher (Phase 5a6).

Background asyncio task: every poll_interval_sec, walks all transactions
in status='submitted', checks each tx's hash history against on-chain
receipts, transitions to terminal status on mining, replaces stuck txs
with bumped fees.

Per docs/architecture.md § Signing flow step 16 + § Failure modes +
implementation-plan.md:122-123:
- Polls eth_getTransactionReceipt for each pending tx's hashes.
- On receipt: status='mined' (status=0x1) or 'failed' (status=0x0);
  calls nonce_repo.mark_confirmed on successful mining.
- On stuck (now - submitted_at > stuck_threshold_sec): bumped-tip resubmit
  inserts a new transaction_hashes row at sequence_num+1.
- After max_retries hashes with no receipt: status='failed'.

Doctrine (architecture.md § Failure modes step 13):
- Broadcast failures during replacement do NOT roll back the new hash row.
- The tx may still land on-chain via the previous hash; watcher reconciles
  next tick.

Status semantics (v0.4.0a6): only submitted -> mined and submitted -> failed
are valid transitions here. The logical tx is one tx_id with multiple
transaction_hashes rows; status stays 'submitted' through ALL retries.
External-nonce-consumption detection (replaced / dropped) defers to Phase 7.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog

from fwd.app.dependencies import RequestScopeCM
from fwd.app.sign_and_send import _DEFAULT_TIP_WEI, _GAS_ESTIMATE_BUFFER
from fwd.infra.rpc import RpcError, RpcUnavailable
from fwd.infra.sealed_master import SealError

if TYPE_CHECKING:
    from fwd.infra.envelope_signer import EnvelopeSigner
    from fwd.infra.nonce_repo import NonceRepo
    from fwd.infra.rpc import RpcClient, RpcManager
    from fwd.infra.transaction_repo import Transaction, TransactionHash, TransactionRepo

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class WatcherConfig:
    poll_interval_sec: float
    stuck_threshold_sec: float
    max_retries: int
    tip_multiplier: float  # 1.125 per architecture.md
    enabled: bool


async def watch_receipts(config: WatcherConfig) -> None:
    """Top-level watcher loop. Opens fresh CMs per tick.

    Cancellation: CancelledError propagates cleanly to the caller (lifespan).
    Per-tick exceptions are logged and swallowed -- the loop continues.
    """
    logger.info(
        "receipt_watcher.started",
        poll_interval_sec=config.poll_interval_sec,
        stuck_threshold_sec=config.stuck_threshold_sec,
        max_retries=config.max_retries,
    )
    try:
        while True:
            try:
                await _tick(config)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("receipt_watcher.tick_failed", error=str(exc))
            await asyncio.sleep(config.poll_interval_sec)
    except asyncio.CancelledError:
        logger.info("receipt_watcher.cancelled")
        raise


async def _tick(config: WatcherConfig) -> None:
    """One pass over pending txs. Opens a single RequestScope per tick.

    v0.4.5: replaces the pre-fix multi-CM pattern (SignerCM + RpcManagerCM +
    TransactionRepoCM + NonceRepoCM) that opened 4 concurrent session_scopes
    per tick, each grabbing the SQLite writer lock via our BEGIN IMMEDIATE
    event handler. RequestScopeCM consolidates the three DB repos onto one
    shared session — one writer-lock per tick.
    """
    async with RequestScopeCM() as scope:
        pending = await scope.tx_repo.list_by_status("submitted")
        for tx in pending:
            try:
                await _process_tx(
                    tx, config, scope.signer, scope.rpc_mgr, scope.tx_repo, scope.nonce_repo
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Per-tx errors do not break the tick -- log and continue.
                logger.warning(
                    "receipt_watcher.tx_failed",
                    tx_id=tx.tx_id,
                    error=str(exc),
                )


async def _process_tx(
    tx: Transaction,
    config: WatcherConfig,
    signer: EnvelopeSigner,
    rpc_mgr: RpcManager,
    tx_repo: TransactionRepo,
    nonce_repo: NonceRepo,
) -> None:
    """Inspect one pending tx: check receipts, replace if stuck, fail if exhausted."""
    rpc = rpc_mgr.for_chain(tx.chain)
    hashes = await tx_repo.list_hashes_by_tx(tx.tx_id)

    # 1. Check receipts across all known hashes.
    for h in hashes:
        try:
            receipt = await rpc.transaction_receipt(h.hash_hex)
        except (RpcUnavailable, RpcError) as exc:
            logger.warning(
                "receipt_watcher.receipt_fetch_failed",
                tx_id=tx.tx_id,
                hash_hex=h.hash_hex,
                error=str(exc),
            )
            return  # try again next tick

        if receipt is None:
            continue  # still pending; try next hash or fall through

        # Receipt found -- terminal transition.
        receipt_status = receipt.get("status")
        new_status = "mined" if receipt_status == "0x1" else "failed"

        await tx_repo.update_status(
            tx.tx_id,
            new_status,
            confirmed_at=datetime.now(UTC),
            receipt_json=json.dumps(receipt),
        )
        if new_status == "mined":
            await nonce_repo.mark_confirmed(tx.wallet, tx.chain, tx.nonce)
        logger.info(
            "receipt_watcher.terminal",
            tx_id=tx.tx_id,
            status=new_status,
            tx_hash=h.hash_hex,
            block_number=receipt.get("blockNumber"),
        )
        return

    # 2. No hash mined. Check if stuck.
    if tx.submitted_at is None:
        return  # shouldn't happen for status='submitted'; skip defensively
    # SQLite drops tzinfo on round-trip even for DateTime(timezone=True) columns
    # (aiosqlite + sqlalchemy 2.x behaviour). The watcher writes aware UTC
    # datetimes but reads back naive ones; normalize to aware-UTC before the
    # subtraction to avoid `can't subtract offset-naive and offset-aware
    # datetimes`. Phase 7 may centralize this in the repo layer; v0.4.0a6
    # bounds the fix to the comparison call sites that need it.
    submitted_at = tx.submitted_at
    if submitted_at.tzinfo is None:
        submitted_at = submitted_at.replace(tzinfo=UTC)
    age_sec = (datetime.now(UTC) - submitted_at).total_seconds()
    if age_sec < config.stuck_threshold_sec:
        return  # not yet stuck

    # 3. Stuck. Check retry cap.
    if len(hashes) >= config.max_retries:
        await tx_repo.update_status(
            tx.tx_id,
            "failed",
            confirmed_at=datetime.now(UTC),
        )
        logger.warning(
            "receipt_watcher.retries_exhausted",
            tx_id=tx.tx_id,
            attempts=len(hashes),
            max_retries=config.max_retries,
        )
        return

    # 4. Replace.
    await _replace(tx, hashes, config, signer, rpc, tx_repo)


async def _replace(
    tx: Transaction,
    hashes: list[TransactionHash],
    config: WatcherConfig,
    signer: EnvelopeSigner,
    rpc: RpcClient,
    tx_repo: TransactionRepo,
) -> None:
    """Replacement: bump tip by multiplier**new_seq, re-sign, re-broadcast,
    insert a new transaction_hashes row at sequence_num=new_seq.

    Doctrine (architecture.md hazards #2 + Core invariant #16): the re-sign
    decrypts the wallet's privkey through EnvelopeSigner, which zeroizes the
    plaintext buffer in finally. No plaintext caching between replacements.
    """
    new_seq = len(hashes) + 1
    original = json.loads(tx.request_json)

    # Fetch current fee market.
    try:
        fee = await rpc.fee_history(blocks=5)
    except (RpcUnavailable, RpcError) as exc:
        logger.warning(
            "receipt_watcher.replace_fee_failed",
            tx_id=tx.tx_id,
            error=str(exc),
        )
        return  # try again next tick

    try:
        base_fee = int(fee["baseFeePerGas"][-1], 16)
    except (KeyError, ValueError, IndexError, TypeError) as exc:
        logger.warning(
            "receipt_watcher.replace_fee_shape",
            tx_id=tx.tx_id,
            error=str(exc),
        )
        return

    new_tip = int(_DEFAULT_TIP_WEI * (config.tip_multiplier**new_seq))
    new_max_fee = base_fee * 2 + new_tip

    # Re-estimate gas (chain state may have moved). Fall back to the original
    # gas if the caller specified it explicitly.
    original_gas = original.get("gas")
    if original_gas is not None:
        gas = int(original_gas)
    else:
        # eth_estimateGas requires a 0x-prefixed checksum address in the `from`
        # field — passing the wallet *name* (e.g., "primary") causes geth/erigon
        # to either reject the call or estimate against the zero address.
        # Resolve the wallet name to its on-chain address via the signer.
        try:
            from_address = await signer.address(tx.wallet)
        except Exception as exc:
            logger.warning(
                "receipt_watcher.replace_address_failed",
                tx_id=tx.tx_id,
                error=str(exc),
            )
            return
        try:
            estimated = await rpc.estimate_gas(
                {
                    "from": from_address,
                    "to": original["to"],
                    "value": hex(int(original["value_wei"])),
                    "data": original["data"],
                }
            )
        except (RpcUnavailable, RpcError) as exc:
            logger.warning(
                "receipt_watcher.replace_estimate_failed",
                tx_id=tx.tx_id,
                error=str(exc),
            )
            return
        gas = int(estimated * _GAS_ESTIMATE_BUFFER)

    tx_dict = {
        "type": 2,
        "chainId": tx.chain,
        "nonce": tx.nonce,
        "to": original["to"],
        "value": int(original["value_wei"]),
        "data": original["data"],
        "gas": gas,
        "maxFeePerGas": new_max_fee,
        "maxPriorityFeePerGas": new_tip,
    }

    try:
        signed = await signer.sign_transaction(tx.wallet, tx_dict)
    except SealError as exc:
        logger.warning(
            "receipt_watcher.replace_sign_failed",
            tx_id=tx.tx_id,
            error=str(exc),
        )
        return

    try:
        new_hash = await rpc.send_raw_transaction(signed.raw_transaction)
    except (RpcUnavailable, RpcError) as exc:
        logger.warning(
            "receipt_watcher.replace_broadcast_failed",
            tx_id=tx.tx_id,
            error=str(exc),
        )
        return

    # Persist the new attempt. Status stays 'submitted'; we record the new
    # signed_raw + submitted_at so the stuck-clock resets for this attempt.
    new_signed_raw = "0x" + signed.raw_transaction.hex()
    await tx_repo.update_status(
        tx.tx_id,
        "submitted",
        signed_raw=new_signed_raw,
        submitted_at=datetime.now(UTC),
    )
    await tx_repo.add_hash(tx.tx_id, new_hash, sequence_num=new_seq)

    logger.info(
        "receipt_watcher.replaced",
        tx_id=tx.tx_id,
        new_seq=new_seq,
        new_hash=new_hash,
        new_tip_wei=new_tip,
        new_max_fee_wei=new_max_fee,
    )
