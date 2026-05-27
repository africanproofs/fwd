# D20 — zero-egress constitutional amendment (DRAFT — awaiting operator authorization)

> **STATUS: DRAFT. NOT APPLIED.** Per `CLAUDE.md` § Linear-forward versioning, a
> **constitutional-amendment ship is NEVER a Reviewer self-grant — it must be
> explicitly operator-authorized.** This file is the prepared proposal, written
> during the 2026-05-27 autonomous window; the Core-invariant / IS-NOT /
> threat-model edits below are **not made** until you authorize. Reviewing it costs
> you one read; authorizing turns it into one bounded amendment ship.

## Why this is needed (Core #18 — drift, marked-deferred)

Ships v1.1.0a9–a12 made fwd a **zero-egress sign-only signer**. Core invariants
#4, #11, #14 and the "What FWD IS NOT" list still describe the **retired**
sign-and-broadcast behaviour (receipt watcher, startup RPC reconcile, fwd-side
broadcast/replacement, "real-RPC verification"). That is drift. It is currently
*marked-deferred* (the § Scope current-state line, the architecture doc, and the
a9–a12 history files all point here), so it is #18-compliant — but it must be
reconciled. This is that reconciliation.

## Operator decision made on your behalf (the reclaim mechanic)

You delegated the open §10 reclaim-mechanic question. **Decision: same-intent
replacement + operator-alarm; NEVER cross-intent auto-reissue.** An orphaned nonce
reservation (client got a signed tx, then died before broadcasting) is only ever
(a) re-driven for the *exact recorded intent* via `sign-replacement`, or (b) a
deliberate operator-gated rescue/gap-fill, or (c) surfaced to the operator as an
unresolved hole. fwd never hands a reserved nonce to a *different* intent (that
would be the cross-client race the architecture doc §5 rejected). `nonce-sync` is
admin-only and bounded. This decision governs the Core #4/#11 reword below and the
future a13 ship.

## Proposed amendments (apply on authorization)

### Core #4 — "One nonce manager per (wallet, chain)"
Reword the tail. **From:** "...Nonce release on confirmed-or-dropped,
reconciliation on startup." **To:** "fwd remains the single nonce *reservation*
authority — `reserve_next` under `BEGIN IMMEDIATE` is the only nonce operation fwd
performs, and it is purely local (no network). fwd does **not** seed or reconcile
nonces from chain (it has no egress); the initial seed is the admin `nonce-init`
endpoint (v1.1.0a8) and reconciliation is client-fed chain-truth via the admin
`nonce-sync` endpoint (a13). A reserved nonce is released on a client-reported
releaseable broadcast rejection (tail-only; non-tail gaps surface as operator-visible
drift), kept on a `nonce_too_low` rejection (chain ahead → nonce-sync), and confirmed
on a client-reported receipt." *(code in a8/a9/a10 makes the local-reservation +
nonce-init + report-back parts true; the `nonce-sync` clause is deferred to a13.)*

### Core #11 — "Replacement, not retry-from-zero"
Reword. **To:** "Stuck transactions are resubmitted with the same nonce and bumped
`maxPriorityFeePerGas` (×1.125, ≤5 retries) — but the trigger is now the **client**
(fwd has no receipt watcher and no egress): the client detects a stuck tx and calls
`sign-replacement` (a13), which re-signs the same nonce at a higher tip. A reserved
nonce is never silently abandoned: it confirms (client `receipt`), replaces (client
`sign-replacement`), is released (client `broadcast-result rejected_releaseable`,
tail-only), or surfaces to the operator as an unresolved hole." *(report-back in a10
makes the confirm/release parts true; `sign-replacement` is deferred to a13.)*

### Core #14 — "Real-RPC verification is the validation"
Reword. **To:** "fwd's own code no longer makes any RPC call, so the validation
boundary moves to the **client↔fwd↔chain integration**: a signing-path change is
proven by a client broadcasting an fwd-signed tx on real Coston2 and the
report-back driving fwd's state to match the on-chain effect. The v1.1.0a12 funded
live drill (tx `0x14440b…95cbd`, Coston2 block 31,028,196, status 1 → fwd `mined`)
is the canonical instance; it caught a real defect (the non-checksummed-`to`
TypeError nonce-wedge) invisible to mocked tests — the proof that mocks lie remains
exactly as #14 always held." *(a9–a12 make this true.)*

### "What FWD Deliberately IS NOT"
- **Add:** "**Not a broadcaster.** fwd signs and allocates nonces; clients broadcast
  the signed tx and report the outcome back."
- **Change:** "No public network exposure in v1" → "**No network egress at all.**
  fwd makes no outbound connection (code-level: no RPC/httpx in `app|api|infra`;
  network-level: the `internal: true` compose network gives the container no
  internet route — v1.1.0a11). Inbound only, from local callers."

### Core #3 — "Sign intent, never opaque bytes"
No reword needed; it is *strengthened* (fwd now only ever signs the intent it
decoded/reconstructed and never broadcasts). Add a one-line clarifier that the
sign-only model removes the broadcast surface entirely.

### `docs/threat-model.md`
- **A4 (compromised fwd exfiltrates keys over the network): eliminated.** fwd has
  no egress (code + network level), so the network-exfil channel is closed; record
  this as a resolved mitigation, not an open residual.
- **Add the new operational risk:** orphaned nonce reservation (client signs then
  dies pre-broadcast) → wedge; mitigation = the reclaim mechanic decided above
  (same-intent replacement / rescue / operator alarm; never cross-intent reissue).

### The D20 record (append to `docs/decisions.md`)
A D-record capturing: the operator decision (whole-stack zero egress; clients
broadcast; 2026-05-27), the rejected alternatives (keyless egress relay; LAN-only
network lock — both moot once "only public internet" + "whole-stack zero egress"
were chosen), the multiple-clients rationale for keeping nonce allocation in fwd,
and the reclaim-mechanic decision above. Note honestly that D20 is the
zero-egress initiative's reconciliation ship and is self-referential per the D17
constitutional-amendment definition (operator-authorized, not a Reviewer
self-grant).

## Bounded surface (when authorized)
The amended CLAUDE.md sections (Core #3/#4/#11/#14 + IS-NOT) + the `decisions.md`
D20 record + `threat-model.md` A4/new-risk + the three feature-ship artifacts
(history file, README line, § Scope current-state line) + the two version files.
This is the D17 "constitutional-amendment ship" bounded surface — it exceeds the
3-artifact feature cap by definition, and is the right vehicle.

## Sequencing note
Best applied **after** the a13 ship (replacement / reclaim / admin nonce-sync)
lands, so the Core #4/#11 reword describes code that fully exists rather than
carrying "(deferred to a13)" clauses. If you prefer, authorize D20 now with the
a13 clauses marked-deferred (still #18-compliant), or hold D20 until a13 is in.
