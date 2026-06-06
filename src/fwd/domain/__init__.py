"""Pure business logic.

Per architecture.md § Layer boundaries: must NOT import from infra/, app/,
api/, or cli/; must NOT touch SQLite, SealedMaster, FastAPI, environment
variables, or the filesystem; must NOT take any I/O dependency.
"""
