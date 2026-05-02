"""GET /healthz — liveness + Vault sealed status + RPC reachability.

Phase 2 reports:
  vault: "ok" | "sealed" | "unreachable"
  rpc:   "unknown"  (Phase 3 wires real RPC checks)
  fwd:   "ok"       (the service is responding)
"""

from __future__ import annotations

import os
from typing import Literal

import httpx
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class HealthResponse(BaseModel):
    vault: Literal["ok", "sealed", "unreachable"]
    rpc: Literal["ok", "unknown", "unreachable"]
    fwd: Literal["ok"]


async def _vault_status() -> Literal["ok", "sealed", "unreachable"]:
    addr = os.environ.get("VAULT_ADDR", "http://vault:8200")
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            r = await client.get(f"{addr}/v1/sys/health")
    except (httpx.HTTPError, OSError):
        return "unreachable"
    # Vault /sys/health response codes:
    #   200 — initialized, unsealed, active
    #   429 — initialized, unsealed, standby
    #   472 — disaster recovery secondary
    #   473 — performance standby
    #   501 — uninitialized
    #   503 — sealed
    if r.status_code in (200, 429, 472, 473):
        return "ok"
    if r.status_code in (501, 503):
        return "sealed"
    return "unreachable"


@router.get("/healthz", response_model=HealthResponse)
async def healthz() -> HealthResponse:
    return HealthResponse(
        vault=await _vault_status(),
        rpc="unknown",
        fwd="ok",
    )
