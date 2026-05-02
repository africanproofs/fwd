"""HTTP API layer (FastAPI routers).

Per architecture.md § Layer boundaries: must NOT decode calldata, manage
nonces, call Vault directly, or write to SQLite directly. Goes through app/.
"""
