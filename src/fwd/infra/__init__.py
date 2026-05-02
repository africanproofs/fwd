"""External-system adapters.

Per architecture.md § Layer boundaries: implements adapters for Vault, SQLite,
RPC, structlog setup, etc. Must NOT make policy decisions or import from
app/, api/, cli/.

Phase 2 ships this layer empty. Phase 3 adds VaultEnvelopeClient; Phase 5
adds SQLite repositories; Phase 5 adds the JSON-RPC client.
"""
