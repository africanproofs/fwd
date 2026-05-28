# Sign-and-send verification — manual operator gate (v0.3.0)

> ⚠️ **SUPERSEDED (pre-zero-egress) — historical.** The endpoint `/v1/sign-and-send`
> was renamed `/v1/sign-transaction` and made sign-only (no broadcast) at v1.1.0a9;
> custody moved off Vault at v1.0.0a1. The current sealed-master sign gate is
> `v1.0.0a1-sealed-master-verification.md`, and the live client↔fwd↔chain path is
> proven by the v1.1.0a12 Coston2 + epoch-400 mainnet drills. Kept as honest history.

> Phase 3c verification: send a real Coston2 transaction via fwd's
> `POST /v1/sign-and-send`. This is the operator-driven equivalent of the
> v0.2.0 spike, but as a real service.
>
> Per Core invariant #14: real-RPC verification is the validation. Mocks
> lie. This runbook is mandatory before tagging v0.3.0 as shipped.

## Prerequisites

- `docker compose ps` shows `fwd`, `fwd-vault`, `fwd-litestream` all up.
- `fwd-vault` is unsealed (`docker exec fwd-vault vault status` -> `Sealed: false`).
- `.env` has populated `FWD_VAULT_ROLE_ID`, `FWD_VAULT_SECRET_ID`, `FWD_ADMIN_KEY`.
- `RPC_URL_COSTON2` in `.env` points at a reachable Coston2 RPC (default: `https://coston2-api.flare.network/ext/C/rpc`).

## Steps

### 1. Create a wallet for testing.

```sh
KEY=$(grep -E '^FWD_ADMIN_KEY=' .env | cut -d= -f2-)
curl -sf -X POST http://127.0.0.1:8080/v1/admin/wallets \
    -H "Authorization: Bearer $KEY" \
    -H 'Content-Type: application/json' \
    -d '{"name":"sign-verify-coston2","policy_path":"sign-verify"}' | python3 -m json.tool
```

Capture the returned `address` from the response.

### 2. Fund the wallet from the Coston2 faucet.

Visit https://faucet.flare.network/coston2 and submit the address from step 1. Wait ~10 seconds for the faucet tx to confirm.

Verify funding:

```sh
ADDR=<address-from-step-1>
curl -s -X POST https://coston2-api.flare.network/ext/C/rpc \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$ADDR\",\"latest\"],\"id\":1}"
```

Expect a non-zero balance (typically 50e18 wei from the faucet).

### 3. Send a self-transfer via fwd.

A self-transfer (value=0, to=own_address, data=0x) is the cheapest verifiable signing path.

```sh
KEY=$(grep -E '^FWD_ADMIN_KEY=' .env | cut -d= -f2-)
ADDR=<address-from-step-1>
curl -sf -X POST http://127.0.0.1:8080/v1/sign-and-send \
    -H "Authorization: Bearer $KEY" \
    -H 'Content-Type: application/json' \
    -d "{
        \"wallet\": \"sign-verify-coston2\",
        \"chain\": 114,
        \"to\": \"$ADDR\",
        \"value_wei\": \"0\",
        \"data\": \"0x\",
        \"gas\": 21000
    }" | python3 -m json.tool
```

Expected response:

```json
{
    "hash": "0x<64-char hex>",
    "nonce": 0
}
```

If the response is 502 `rpc_unreachable`: confirm `RPC_URL_COSTON2` is set in `.env` and reachable.
If 503 `vault_unavailable`: `fwd-vault` is sealed; unseal it.
If 400 `chain_not_allowed`: chain id is wrong (must be 114 in v0.3.0).
If 404 `wallet_not_found`: step 1's wallet name does not match the request.

### 4. Verify the transaction on-chain.

```sh
HASH=<hash-from-step-3>
curl -s -X POST https://coston2-api.flare.network/ext/C/rpc \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByHash\",\"params\":[\"$HASH\"],\"id\":1}" \
    | python3 -m json.tool
```

Expect `result.from` to equal the wallet's address from step 1 (case-insensitive). `result.to` should match. `result.blockNumber` is null until mined; re-poll after ~5 seconds.

```sh
curl -s -X POST https://coston2-api.flare.network/ext/C/rpc \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$HASH\"],\"id\":1}" \
    | python3 -m json.tool
```

Expect `result.status == "0x1"` (success). `result.from` matches the wallet address.

You can also view it on a Coston2 block explorer (e.g., https://coston2-explorer.flare.network/tx/<hash>).

### 5. Negative test: chain_not_allowed.

```sh
curl -sf -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8080/v1/sign-and-send \
    -H "Authorization: Bearer $KEY" \
    -H 'Content-Type: application/json' \
    -d '{"wallet":"sign-verify-coston2","chain":14,"to":"0x0000000000000000000000000000000000000000","value_wei":"0","data":"0x","gas":21000}'
```

Expect: `400`.

### 6. Negative test: wallet_not_found.

```sh
curl -sf -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8080/v1/sign-and-send \
    -H "Authorization: Bearer $KEY" \
    -H 'Content-Type: application/json' \
    -d '{"wallet":"does-not-exist","chain":114,"to":"0x0000000000000000000000000000000000000000","value_wei":"0","data":"0x","gas":21000}'
```

Expect: `404`.

### 7. Negative test: 401 without admin auth.

```sh
curl -sf -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8080/v1/sign-and-send \
    -H 'Content-Type: application/json' \
    -d '{"wallet":"sign-verify-coston2","chain":114,"to":"0x0000000000000000000000000000000000000000","value_wei":"0","data":"0x","gas":21000}'
```

Expect: `401`.

## Verification gate

All seven steps must pass for v0.3.0 to be considered shipped:

1. Wallet created, address returned.
2. Wallet funded on Coston2 (non-zero balance).
3. Self-transfer succeeds (200 with hash + nonce).
4. On-chain receipt confirms `from = wallet.address`, `status = 0x1`.
5. Flare chain rejected (400).
6. Unknown wallet rejected (404).
7. Unauthenticated request rejected (401).

Surface results to the Reviewer for inclusion in the v0.3.0 commit message.

## What this runbook does NOT cover

- Songbird / Flare mainnet — Phase 7 lifts the chain restriction.
- Caller authentication (currently admin-key only) — Phase 4.
- Idempotency-Key handling — Phase 5.
- Receipt watcher / replacement-on-stuck — Phase 5.
- Hash-chained audit log — Phase 7.
