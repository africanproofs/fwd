"""Pure business logic.

Per architecture.md § Layer boundaries: must NOT import from infra/, app/,
api/, or cli/; must NOT touch SQLite, Vault, RPC, FastAPI, environment
variables, or the filesystem; must NOT take any I/O dependency.

Phase 2 ships this layer empty. Phase 3+ adds policy evaluation, intent
decoding, EIP-1559 RLP encoding, etc.
"""
