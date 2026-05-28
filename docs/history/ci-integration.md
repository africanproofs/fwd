# CI integration runbook — running `tests/integration/` locally and in CI

> ℹ️ **Partially historical.** Predates Vault retirement (v1.0.0a1) and the
> zero-egress turn (v1.1.0a9): references to "real Vault" and `/v1/sign-and-send` are
> stale — the integration suite now runs against the sealed master with no Vault
> stage. Kept per Core invariant #18; a refresh is a tracked follow-up.

> The 3 integration tests under `tests/integration/` exercise real Vault
> encrypt/decrypt + real argon2id + the full sign-and-send path with the
> RPC layer mocked. They skip when Vault is unreachable. This runbook
> documents how to run them deliberately — locally for dev, and what the
> CI `integration:` job does.

## In CI (GitLab)

The `integration:` job in `.gitlab-ci.yml`:

1. Starts a HashiCorp Vault 1.18.2 service container in dev mode
   (auto-unsealed, root token `ci-root-token`).
2. Runs `scripts/ci_vault_init.py` against that Vault — enables Transit,
   creates the `fwd-master` key, writes the `fwd-app` policy, enables
   AppRole, creates the `fwd` role, and prints the `role_id` +
   `secret_id` to `vault.env`.
3. Sources `vault.env` to export `FWD_VAULT_ROLE_ID` + `FWD_VAULT_SECRET_ID`
   into the shell.
4. Runs `pytest -v tests/integration/`.

Pass criterion: all 3 integration tests PASS (not skip). A skip in this
job is a failure — it means VAULT_ADDR isn't reachable or the env vars
weren't exported.

## Running the same locally

If you want to reproduce the CI environment on your laptop:

```sh
# 1. Start a throwaway dev Vault.
docker run -d --rm \
    --name fwd-dev-vault \
    -p 8200:8200 \
    -e VAULT_DEV_ROOT_TOKEN_ID=ci-root-token \
    hashicorp/vault:1.18.2 \
    server -dev -dev-listen-address=0.0.0.0:8200

# 2. Init Transit + AppRole.
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=ci-root-token
poetry run python scripts/ci_vault_init.py > vault.env

# 3. Source and run.
set -a; . ./vault.env; set +a
poetry run pytest -v tests/integration/

# 4. Cleanup.
docker stop fwd-dev-vault
```

The full docker-compose Vault (Shamir + raft + Litestream + vault-snapshot)
is overkill for this — the integration tests don't depend on Shamir or
on the sidecars.

## When this is wrong

- `tests/integration/` add a test that depends on Litestream, vault-snapshot,
  or live RPC → re-scope F6.2 or split the test into a Phase 6 GA drill
  step.
- HashiCorp publishes a Vault major-version bump that breaks the dev-mode
  CLI signature → update the `command:` array in `.gitlab-ci.yml` AND the
  `docker run` example above.
- `scripts/ci_vault_init.py` drifts from `scripts/vault-init.sh` (the
  production init flow) → reconcile. Both should produce the same
  end-state: Transit enabled, fwd-master key created, fwd-app policy
  written, fwd AppRole bound. The production script also creates the
  fwd-snapshot AppRole (v0.4.2+) — the CI script does NOT, because the
  vault-snapshot sidecar is not in scope for CI.
