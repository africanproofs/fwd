"""Use-case orchestrators (the application layer).

Per architecture.md § Layer boundaries: coordinates domain/ + infra/. Must
NOT implement signing math, format HTTP responses, or import from api/.

Note: the FastAPI ASGI app instance lives at fwd.main, not here. fwd.app
is the application LAYER — a package of use-case orchestrators that the
api/ and cli/ layers call into. Avoid the temptation to put runtime entry
points here.
"""
