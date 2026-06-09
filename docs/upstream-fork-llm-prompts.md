# Upstream Fork LLM Prompts

Canonical prompts for work on the AfricanProofs forks of Flare Foundation
clients that need `fwd` integration.

The non-negotiable fork rule: keep upstream history easy to audit. In each fork,
`main` should track the Flare Foundation upstream with no AfricanProofs-only
commits. Put AfricanProofs work on an integration branch such as
`ap/fwd-integration`, and regularly merge or rebase from upstream with the
upstream base commit recorded in PRs and handoffs.

## Shared Fork Discipline

Use these remotes inside the matching local checkout.

For `flare-system-client`:

```sh
git remote add upstream https://github.com/flare-foundation/flare-system-client.git
git remote set-url origin https://github.com/africanproofs/flare-system-client.git
```

For `fast-updates`:

```sh
git remote add upstream https://github.com/flare-foundation/fast-updates.git
git remote set-url origin https://github.com/africanproofs/fast-updates.git
```

For every work session:

```sh
git fetch --all --prune
git status --short
git rev-parse --short HEAD
git log --oneline --decorate --left-right --cherry-pick origin/main...upstream/main
```

Before changing code, identify:

- upstream base commit currently targeted
- AfricanProofs branch name
- exact signing path being changed
- config/env compatibility impact
- tests that prove upstream behavior still works

Preferred fork layout:

- `main`: upstream-clean mirror
- `ap/fwd-integration`: long-lived AfricanProofs integration branch
- `ap/<short-task>`: short-lived task branches from `ap/fwd-integration`
- `docs/africanproofs-fork.md`: fork notes, upstream base, integration deltas

Do not remove upstream private-key mode unless explicitly instructed. Add `fwd`
mode as an opt-in path so upstream changes remain mergeable and regression tests
can still exercise stock behavior.

## Prompt: flare-system-client

```text
You are working in the AfricanProofs fork of:

upstream: https://github.com/flare-foundation/flare-system-client.git
origin:   https://github.com/africanproofs/flare-system-client.git

Objective:
Integrate fwd as an optional zero-egress signing backend for flare-system-client
while preserving upstream behavior and keeping future upstream merges low-risk.

Hard requirements:
1. Preserve upstream private-key configuration as the default unless explicitly
   told otherwise.
2. Add fwd mode as an opt-in backend selected by config/env, using wallet names
   and caller tokens instead of raw private keys.
3. Keep fwd zero-egress: this client retains RPC access, gas estimation,
   broadcasting, receipt polling, and FSP data fetching. fwd signs only.
4. Do not add raw digest signing to fwd integration. If a signing operation is
   not currently representable by fwd, define a typed request shape and identify
   the matching fwd endpoint/policy work required.
5. Keep upstream tracking explicit: fetch upstream first, record upstream base
   commit, and avoid broad refactors that increase merge conflicts.

Before edits:
- Run `git fetch --all --prune`, `git status --short`, and record `git rev-parse --short HEAD`.
- Compare the fork branch to `upstream/main`.
- Inspect the current signing paths:
  - `config/config.go` private-key loading
  - `client/protocol/protocol_context.go`
  - `client/protocol/submitter.go`
  - `client/epoch/epoch_client.go`
  - `client/epoch/registry_utils.go`
  - `client/epoch/system_manager_utils.go`
  - `utils/chain/client.go`
  - `utils/chain/tx_utils.go`

Implementation direction:
- Introduce a narrow signer interface rather than threading fwd HTTP calls
  through business logic.
- Support at least these roles explicitly:
  - system client sender: register/pre-register/sign-new-policy transaction sender
  - signing policy key: FSP/FSM detached signatures and voter registration signatures
  - protocol submit key: submit1/submit2/submit3 tx sender
  - protocol submit-signatures key: submitSignatures tx sender
- For EVM transactions, have the client construct intent, ask fwd to sign,
  broadcast the returned raw transaction, then report broadcast/receipt outcome
  back to fwd.
- For detached signatures, use typed fwd requests. Existing fwd supports
  UPTIME and REWARD_DISTRIBUTION, but full flare-system-client may also require
  typed support for signing-policy and voter-registration preimages.
- Keep nonce ownership clear. If fwd signs an EVM tx, fwd owns nonce allocation
  for that wallet and the client must report accepted/rejected/mined/reverted.

Policy and fwd-side gaps to surface:
- Submission ABI and methods: submit1, submit2, submit3, submitSignatures.
- VoterRegistry / VoterPreRegistry register methods.
- FlareSystemsManager methods beyond current fwd policy generation:
  signNewSigningPolicy, signUptimeVote, signRewards.
- Any typed detached-signature endpoint not already present in fwd.

Tests:
- Existing upstream tests must continue to pass in private-key mode.
- Add unit tests for config selection and signer backend selection.
- Add tests with a fake fwd server covering sign-transaction, broadcast result,
  receipt reporting, and typed detached signature requests.
- Add at least one integration or simulation test path before live Coston2.

Deliverables:
- Minimal code changes scoped to signing abstractions and config.
- Updated fork notes documenting upstream base commit and AfricanProofs deltas.
- A migration note showing which env vars are replaced by fwd wallet/caller
  config in fwd mode.
- Explicit list of fwd policy/API gaps that must be implemented in the fwd repo.
```

## Prompt: fast-updates

```text
You are working in the AfricanProofs fork of:

upstream: https://github.com/flare-foundation/fast-updates.git
origin:   https://github.com/africanproofs/fast-updates.git

Objective:
Integrate fwd as an optional zero-egress signing backend for the Fast Updates
Go client while preserving upstream behavior and keeping future upstream merges
low-risk.

Hard requirements:
1. Preserve upstream raw private-key configuration as the default unless
   explicitly told otherwise.
2. Add fwd mode as an opt-in backend selected by config/env, using wallet names
   and caller tokens instead of raw EVM private keys.
3. Keep fwd zero-egress: this client keeps RPC access, value-provider access,
   gas calculation, transaction broadcasting, and receipt polling. fwd signs only.
4. Treat the sortition key separately. Current fwd is an EVM/secp256k1 signer;
   the Fast Updates sortition key is not automatically in scope. Do not move it
   into fwd unless the fwd repo has first added an explicit sortition-key
   custody model and typed operations.
5. Keep upstream tracking explicit: fetch upstream first, record upstream base
   commit, and avoid broad refactors that increase merge conflicts.

Before edits:
- Run `git fetch --all --prune`, `git status --short`, and record `git rev-parse --short HEAD`.
- Compare the fork branch to `upstream/main`.
- Inspect the current signing paths:
  - `go-client/config/config.go`
  - `go-client/client/client.go`
  - `go-client/client/transaction_queue.go`
  - `go-client/client/client_requests.go`
  - `go-client/updates/updates.go`
  - `go-client/sortition/sortition.go`

Recommended scope:
- Phase 1: fwd custody for EVM keys only.
  - Replace `SIGNING_PRIVATE_KEY` and `ACCOUNTS` with fwd wallet/caller config
    in fwd mode.
  - Leave `SORTITION_PRIVATE_KEY` in the Fast Updates client config.
  - Add typed fwd signing for the update payload signature if needed.
  - Use fwd for transaction signing, while the client broadcasts and reports
    outcomes.
- Phase 2: sortition custody only after explicit fwd support exists.

Implementation direction:
- Introduce a narrow signer/broadcaster adapter around the existing transaction
  queue, not a cross-cutting rewrite.
- Replace `bind.NewKeyedTransactorWithChainID` in fwd mode with construction of
  transaction intent, fwd signing, local broadcast, and outcome reporting.
- Keep direct private-key mode untouched for upstream parity and tests.
- Preserve timing behavior. Fast Updates is block-window-sensitive, so fwd calls
  need tight timeouts, clear retries, and metrics/logging for missed windows.

Policy and fwd-side gaps to surface:
- FastUpdater ABI and method: submitUpdates.
- Submission ABI and method: submitAndPass, when the client submits through the
  Submission contract.
- A typed endpoint for Fast Updates payload signatures, unless this can be
  represented by an existing fwd typed-signing primitive without raw digests.
- Rate limits high enough for block-latency submissions across all configured
  transaction accounts.

Tests:
- Existing upstream tests must continue to pass in private-key mode.
- Add unit tests for config selection and signer backend selection.
- Add tests with a fake fwd server covering transaction signing, broadcast
  reporting, receipt reporting, and update payload signing.
- Add timing/regression tests around `TransactionQueue` so fwd mode does not
  miss submission windows under normal latency.

Deliverables:
- Minimal code changes scoped to signer abstraction, config, and transaction
  queue integration.
- Updated fork notes documenting upstream base commit and AfricanProofs deltas.
- A migration note showing which env vars are replaced by fwd wallet/caller
  config in fwd mode and which secrets remain local, especially sortition key.
- Explicit list of fwd policy/API gaps that must be implemented in the fwd repo.
```
