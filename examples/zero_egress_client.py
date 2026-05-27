"""Zero-egress demo client for fwd.

Demonstrates that fwd signs with ZERO network egress — the CLIENT broadcasts.

Usage:
    python examples/zero_egress_client.py

Environment variables (or edit defaults below):
    FWD_URL          fwd base URL (default: http://127.0.0.1:8099)
    FWD_CALLER_KEY   Caller bearer key minted by 'clifwd callers create'
    DEMO_WALLET      Wallet name in fwd (default: demo-wallet)
    DEMO_WALLET_ADDR On-chain address returned at wallet create time
    DEMO_TOKEN_ADDR  ERC-20 contract address on Coston2 (default: WC2FLR)
"""

from __future__ import annotations

import json
import os
import sys
import time

import httpx
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_utils import to_checksum_address

# ---------------------------------------------------------------------------
# Configuration (env overrides or set literals here)
# ---------------------------------------------------------------------------

FWD_URL = os.environ.get("FWD_URL", "http://127.0.0.1:8099")
CALLER_KEY = os.environ.get("FWD_CALLER_KEY", "")
WALLET_NAME = os.environ.get("DEMO_WALLET", "demo-wallet")
WALLET_ADDR = os.environ.get("DEMO_WALLET_ADDR", "")
TOKEN_ADDR = os.environ.get("DEMO_TOKEN_ADDR", "0x5db27d33e5c0f1375c5b53f0ba5c3fa684c1e0c7")
# fwd policy stores addresses lowercase; eth_account needs EIP-55 checksum for the tx
TOKEN_ADDR_CHECKSUMMED = to_checksum_address(TOKEN_ADDR)

COSTON2_RPC = "https://coston2-api.flare.network/ext/C/rpc"

# ERC-20 transfer(address,uint256) selector: keccak256("transfer(address,uint256)")[:4]
# = 0xa9059cbb
TRANSFER_SELECTOR = bytes.fromhex("a9059cbb")

# Arbitrary recipient + zero-amount for the demo (no real transfer needed)
RECIPIENT = "0x000000000000000000000000000000000000dEaD"
AMOUNT = 0


def build_transfer_calldata(recipient: str, amount: int) -> str:
    """Build transfer(address,uint256) calldata as 0x-prefixed hex."""
    # ABI-encode the arguments
    encoded_args = abi_encode(["address", "uint256"], [recipient, amount])
    calldata = TRANSFER_SELECTOR + encoded_args
    return "0x" + calldata.hex()


def rpc_call(method: str, params: list) -> dict:
    """Send a single JSON-RPC call to Coston2 and return the parsed response."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }
    resp = httpx.post(COSTON2_RPC, json=payload, timeout=15)
    resp.raise_for_status()
    return resp.json()


def main() -> None:
    # ------------------------------------------------------------------
    # Validate config
    # ------------------------------------------------------------------
    if not CALLER_KEY:
        print("ERROR: FWD_CALLER_KEY is not set. Set it to the key from 'clifwd callers create'.")
        sys.exit(1)
    if not WALLET_ADDR:
        print("ERROR: DEMO_WALLET_ADDR is not set. Set it to the address from 'clifwd wallets create'.")
        sys.exit(1)

    caller_headers = {"Authorization": f"Bearer {CALLER_KEY}"}

    print("=" * 70)
    print("STEP 1 — Build transfer calldata (client-side, zero network)")
    print("=" * 70)
    calldata = build_transfer_calldata(RECIPIENT, AMOUNT)
    print(f"  Token address   : {TOKEN_ADDR}")
    print(f"  Recipient       : {RECIPIENT}")
    print(f"  Amount          : {AMOUNT}")
    print(f"  Calldata        : {calldata[:18]}...{calldata[-8:]}")
    print(f"  Selector        : {calldata[:10]} (transfer == 0xa9059cbb)")

    print()
    print("=" * 70)
    print("STEP 2 — POST /v1/sign-transaction (fwd signs, ZERO egress from fwd)")
    print("=" * 70)

    sign_body = {
        "wallet": WALLET_NAME,
        "chain": 114,  # Coston2
        # fwd passes 'to' verbatim to eth_account which requires EIP-55 checksum
        "to": TOKEN_ADDR_CHECKSUMMED,
        "value_wei": "0",
        "data": calldata,
        "gas": 120_000,
        "max_fee_per_gas": 50_000_000_000,       # 50 gwei
        "max_priority_fee_per_gas": 1_000_000_000,  # 1 gwei
    }

    with httpx.Client(base_url=FWD_URL) as client:
        resp = client.post("/v1/sign-transaction", json=sign_body, headers=caller_headers, timeout=15)

    if resp.status_code != 200:
        print(f"ERROR: sign-transaction returned {resp.status_code}: {resp.text}")
        sys.exit(1)

    sign_result = resp.json()
    tx_id = sign_result["tx_id"]
    tx_hash = sign_result["hash"]
    signed_raw_tx = sign_result["signed_raw_tx"]
    nonce = sign_result["nonce"]

    print(f"  tx_id           : {tx_id}")
    print(f"  hash            : {tx_hash}")
    print(f"  nonce           : {nonce}")
    print(f"  signed_raw_tx   : {signed_raw_tx[:20]}...{signed_raw_tx[-8:]}")

    print()
    print("=" * 70)
    print("STEP 3 — Verify signer locally (eth_account, ZERO network, fwd not involved)")
    print("=" * 70)

    raw_bytes = bytes.fromhex(signed_raw_tx[2:] if signed_raw_tx.startswith("0x") else signed_raw_tx)
    recovered = Account.recover_transaction(raw_bytes)

    print(f"  Expected wallet : {WALLET_ADDR}")
    print(f"  Recovered signer: {recovered}")

    if recovered.lower() == WALLET_ADDR.lower():
        print("  RECOVERED SIGNER == WALLET ✓")
    else:
        print("  ERROR: signer mismatch — signing is broken!")
        sys.exit(1)

    print()
    print("=" * 70)
    print("STEP 4 — CLIENT broadcasts to Coston2 (fwd never touches the RPC)")
    print("=" * 70)
    print(f"  Broadcasting to: {COSTON2_RPC}")

    broadcast_result = rpc_call("eth_sendRawTransaction", [signed_raw_tx])
    print(f"  JSON-RPC result : {json.dumps(broadcast_result, indent=4)}")

    broadcast_tx_hash: str | None = None
    broadcast_error: str | None = None
    broadcast_outcome: str

    if "error" in broadcast_result:
        err = broadcast_result["error"]
        err_msg = err.get("message", str(err))
        broadcast_error = err_msg[:128]
        broadcast_outcome = "rejected_releaseable"
        broadcast_tx_hash = tx_hash  # use fwd's locally-computed hash for report-back
        print(f"  Broadcast failed (expected for unfunded wallet): {err_msg}")
    else:
        broadcast_tx_hash = broadcast_result["result"]
        broadcast_outcome = "accepted"
        print(f"  Broadcast accepted. Chain tx hash: {broadcast_tx_hash}")

    print()
    print("=" * 70)
    print("STEP 5 — Report broadcast result back to fwd")
    print("=" * 70)

    report_body: dict = {
        "tx_hash": broadcast_tx_hash,
        "outcome": broadcast_outcome,
    }
    if broadcast_error:
        report_body["error_class"] = broadcast_error

    with httpx.Client(base_url=FWD_URL) as client:
        report_resp = client.post(
            f"/v1/transactions/{tx_id}/broadcast-result",
            json=report_body,
            headers=caller_headers,
            timeout=15,
        )

    print(f"  POST /v1/transactions/{tx_id}/broadcast-result")
    print(f"  Status: {report_resp.status_code}  Body: {report_resp.json()}")

    # ------------------------------------------------------------------
    # On-chain receipt polling (only if broadcast was accepted)
    # ------------------------------------------------------------------
    if broadcast_outcome == "accepted":
        print()
        print("=" * 70)
        print("STEP 6 — Poll Coston2 for receipt (client-side egress only)")
        print("=" * 70)

        receipt = None
        for attempt in range(1, 7):
            print(f"  Attempt {attempt}/6 — eth_getTransactionReceipt({broadcast_tx_hash[:18]}...)")
            receipt_result = rpc_call("eth_getTransactionReceipt", [broadcast_tx_hash])
            if receipt_result.get("result") is not None:
                receipt = receipt_result["result"]
                break
            time.sleep(3)

        if receipt:
            status_int = int(receipt["status"], 16)
            block_number = int(receipt["blockNumber"], 16)
            outcome = "mined_success" if status_int == 1 else "mined_reverted"
            print(f"  Receipt found: block={block_number}, status={status_int} → {outcome}")

            receipt_body = {
                "tx_hash": broadcast_tx_hash,
                "outcome": outcome,
                "block_number": block_number,
            }
            with httpx.Client(base_url=FWD_URL) as client:
                rec_resp = client.post(
                    f"/v1/transactions/{tx_id}/receipt",
                    json=receipt_body,
                    headers=caller_headers,
                    timeout=15,
                )
            print(f"  POST /v1/transactions/{tx_id}/receipt → {rec_resp.status_code} {rec_resp.json()}")
        else:
            print("  Receipt not found after 6 attempts (normal for low-gwei on testnet).")

    print()
    print("=" * 70)
    print("STEP 7 — GET final fwd-side tx status")
    print("=" * 70)

    with httpx.Client(base_url=FWD_URL) as client:
        status_resp = client.get(
            f"/v1/transactions/{tx_id}",
            headers=caller_headers,
            timeout=15,
        )

    final = status_resp.json()
    print(f"  Status  : {final['status']}")
    print(f"  Wallet  : {final['wallet']}")
    print(f"  Chain   : {final['chain']}")
    print(f"  Nonce   : {final['nonce']}")
    print(f"  Method  : {final['method_name']}")
    print(f"  Hashes  : {[h['hash_hex'] for h in final.get('hashes', [])]}")

    print()
    print("=" * 70)
    print("DEMO COMPLETE")
    print("  - fwd signed the EIP-1559 tx locally (no RPC, no network).")
    print("  - The client recovered the signer independently (eth_account).")
    print("  - The client broadcast to Coston2 (all egress is client-side).")
    print("  - The client reported the result back to fwd (audit trail).")
    print("=" * 70)


if __name__ == "__main__":
    main()
