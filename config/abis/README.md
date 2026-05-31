# config/abis — ABI registry for the intent decoder

Per `decisions.md` D15 and `architecture.md` § Intent decoder.

## What lives here

Pinned, in-repo, source-controlled JSON ABIs of the contracts fwd is
permitted to construct signatures for. The intent decoder
(`src/fwd/domain/intent.py`) loads these at startup
and uses them to convert opaque calldata bytes into a typed
`DecodedIntent` against which the policy engine evaluates argument
predicates.

ABIs are public information — they describe the open contract interface
that anyone can call. Committing them is consistent with Core
invariant #12 ("Public repo, private config" — policy.yaml is private;
ABIs are public).

## Layout

```
config/abis/
  README.md                      # this file
  registry.yaml                  # name → file mapping (loaded at startup)
  reward_manager.json            # FTSO RewardManager
  participant_register.json      # apregister (Coston2 + future Flare)
  erc20.json                     # canonical ERC-20 (transfer, approve)
  flare_systems_manager.json     # FlareSystemsManager (FSP Leg-2 submit)
```

`registry.yaml` shape:

```yaml
version: 1
abis:
  reward_manager: reward_manager.json
  participant_register: participant_register.json
  erc20: erc20.json
  flare_systems_manager: flare_systems_manager.json
```

The policy.yaml's `permissions.<path>.contracts.<addr>.abi` field
references a name from `registry.yaml`.

## Adding a new ABI

When a new AP backend needs to sign against a new contract:

1. Fetch the ABI JSON (block-explorer download, contract source repo, or
   `forge inspect`).
2. Drop the JSON in this directory: `config/abis/<name>.json`.
3. Add a registry.yaml entry mapping the name to the file.
4. Reference the name from the operator's `policy.yaml` in the
   `permissions.<path>.contracts.<addr>.abi` field for the new contract.
5. `docker compose restart fwd` — the new ABI loads at startup.

No code changes. The decoder is type-driven by the loaded ABI.

## Type-support scope (per D15)

Supported (decoder returns typed value):

- `address` — lowercased 0x-hex string
- `uint8`/`uint16`/`uint32`/`uint64`/`uint128`/`uint256` — Python `int`
- `int8`...`int256` — Python `int`
- `bool` — Python `bool`
- `bytesN` (N ≤ 32) — 0x-hex string
- `bytes` (dynamic) — 0x-hex string of the raw bytes
- `string` (dynamic) — Python `str` (UTF-8 decoded)

Complex top-level types — decoded by `eth_abi` for the full signature
but **omitted from `DecodedIntent.args`** per the **B1 projection
rule** (decisions.md D15):

- Dynamic arrays of any element type
- Fixed-size arrays (`address[3]`, `uint256[N]`, etc.)
- Tuples (Solidity structs encoded as tuples)
- Function-selector arguments (`function` type)

These do **NOT** make the decoder return `None`. `decode_intent`
(`src/fwd/domain/intent.py`) decodes the FULL calldata via `eth_abi`,
retains the complete canonical type in `method_signature` (so policy
method-matching still works), and projects only predicatable scalars
into `.args`; complex args are simply not exposed for `arg_predicates`.
`decode_intent` returns `None` **only** on a decode *failure* —
selector mismatch, truncated/garbage calldata, codec error — never
merely because an in-scope complex arg is present.

`string` and `bytes` support ParticipantRegister's registration
metadata fields (which use `string` for name / URL / description /
etc.); without them the participant_register ABI could not be
policy-evaluated.

Deep dotted-path predicate projection for complex types (B3) is a
Phase 10 follow-up scoped to whatever real consumer demands it (per
"What FWD Deliberately IS NOT" — no speculative scope).

## Why these

- **`reward_manager.json`** — the FTSO RewardManager; fwd signs FTSO
  `claim` calls for the reward claimer (`clif`).
- **`flare_systems_manager.json`** — the FlareSystemsManager; fwd signs
  the FSP Leg-2 submit transactions (`signUptimeVote` / `signRewards`)
  that broadcast a caller's signed FSP vote (`clif`).
- **`participant_register.json`** — apregister's ParticipantRegister,
  for the `apregister/` Coston2 signing path (contract
  `0x09f15b14D16BA645661c576348E4d4C201242bF2`).
- **`erc20.json`** — the default-deny verification vector: the live
  default-deny test matrix (ERC-20 `transfer` calldata) is built on this
  ABI, so it is load-bearing for that gate. Also the token-wallet shape
  (`transfer` / `approve`).

## What this directory deliberately is NOT

- A general ABI library. We pin only the contracts AP signs for.
- An on-chain ABI fetcher. fwd does not depend on a block explorer at
  startup (per D15 rejected alternative).
- A policy file. The policy is in `policy.yaml` (operator-controlled,
  gitignored); the ABIs are in this directory (committed, public).
