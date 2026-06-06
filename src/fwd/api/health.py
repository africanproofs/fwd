"""GET /healthz — liveness + sealed-master readiness.

Reports:
  master:        "ok" | "unavailable"  (stat probe — no key material loaded)
  sealed_master: "ok" | "unavailable"  (liveness: SealedMaster() instantiation)
  fwd:           "ok"                  (the service is responding)

Liveness probe (sealed_master): instantiates SealedMaster() on every /healthz
request to verify the sealed master is loadable (correct path, mode, size,
ownership, readability). Returns 503 with status=degraded if it fails.
This is a liveness probe — not cached, called on every request.

v1.0.0a1: the prior `vault` field (Vault /sys/health probe) is retired
with the Vault backend — replaced by `master`.
v1.1.0a9: the `rpc` field is retired (zero-egress; no RPC calls from daemon).
"""

from __future__ import annotations

import os
import stat
from typing import Literal

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from fwd.app.health import sealed_master_liveness
from fwd.settings import get_settings

router = APIRouter()


class HealthResponse(BaseModel):
    master: Literal["ok", "unavailable"]
    sealed_master: Literal["ok", "unavailable"]
    fwd: Literal["ok"]


def _master_status() -> Literal["ok", "unavailable"]:
    """Stat-only readiness of the sealed master key file.

    Mirrors SealedMaster.__init__'s validation WITHOUT reading the key
    material — the health endpoint must never pull the master into memory.
    """
    path = get_settings().fwd_master_key_file
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            return "unavailable"
        if stat.S_IMODE(st.st_mode) != 0o600:
            return "unavailable"
        if st.st_uid != os.geteuid():
            return "unavailable"
        if st.st_size != 32:
            return "unavailable"
    except OSError:
        return "unavailable"
    return "ok"


@router.get("/healthz")
async def healthz() -> JSONResponse:
    sealed_master_status = sealed_master_liveness()
    master_status = _master_status()

    body = {
        "master": master_status,
        "sealed_master": sealed_master_status,
        "fwd": "ok",
    }

    if sealed_master_status == "unavailable":
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "detail": "sealed master unavailable"},
        )

    return JSONResponse(status_code=200, content=body)
