"""GET /healthz — liveness + sealed-master readiness + RPC reachability.

Reports:
  master: "ok" | "unavailable"   (the sealed master key file passes the
          same gate SealedMaster.__init__ enforces: regular file, mode
          0600, owned by this uid, exactly 32 bytes — a pure stat probe;
          no key material is loaded into the health path)
  rpc:    "unknown"              (Phase 3 wires real RPC checks)
  fwd:    "ok"                   (the service is responding)

v1.0.0a1: the prior `vault` field (Vault /sys/health probe) is retired
with the Vault backend — replaced by `master`. The Reviewer added this
at commit (the v1.0.0a1 canonical prompt scoped docker-compose but not
this app healthcheck; v0.4.0a5 Reviewer-correction precedent).
"""

from __future__ import annotations

import os
import stat
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel

from fwd.settings import get_settings

router = APIRouter()


class HealthResponse(BaseModel):
    master: Literal["ok", "unavailable"]
    rpc: Literal["ok", "unknown", "unreachable"]
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


@router.get("/healthz", response_model=HealthResponse)
async def healthz() -> HealthResponse:
    return HealthResponse(
        master=_master_status(),
        rpc="unknown",
        fwd="ok",
    )
