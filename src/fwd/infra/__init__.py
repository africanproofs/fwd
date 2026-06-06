"""External-system adapters.

Per architecture.md § Layer boundaries: implements adapters for SealedMaster,
SQLite, structlog setup, etc. Must NOT make policy decisions or import from
app/, api/, cli/.
"""
