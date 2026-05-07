"""FastAPI ASGI entry point.

The uvicorn entry is `fwd.main:app`. Lives at the top level of the package
(not inside a layer directory) so the layer-boundary import-graph test
correctly skips it — the FastAPI app instance composes routers from the
api/ layer but is itself an ASGI runtime artifact, not a layer member.

Phase 2 wires only the /healthz endpoint. Phase 3b adds /v1/admin/wallets.
Phase 3c adds /v1/sign-and-send.
"""

from __future__ import annotations

import logging
import os

import structlog
from fastapi import FastAPI

from fwd.api.health import router as health_router
from fwd.api.wallets import router as wallets_router
from fwd.version import __version__


def _configure_logging() -> None:
    """Configure structlog for JSON output to stdout.

    Phase 3 will add the privkey-scrubber processor (per architecture.md
    § Implementation hazards #3). Phase 2 has no privkey path, so the scrubber
    is not yet in place.
    """
    log_level = os.environ.get("FWD_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level, logging.INFO)
        ),
        cache_logger_on_first_use=True,
    )


_configure_logging()

app = FastAPI(
    title="fwd",
    version=__version__,
    description="Flare Wallet Daemon — policy-gated signing service",
    docs_url=None,
    redoc_url=None,
)

app.include_router(health_router)
app.include_router(wallets_router)
