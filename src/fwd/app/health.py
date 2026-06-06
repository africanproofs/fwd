"""App-layer sealed-master liveness probe.

Isolates the infra import (SealedMaster) in the app layer so api/health.py
can call this without importing infra/ directly (layer-boundary rule: api →
app, domain only).
"""

from __future__ import annotations

from typing import Literal


def sealed_master_liveness() -> Literal["ok", "unavailable"]:
    """Liveness probe: attempt to instantiate SealedMaster.

    Verifies the master key file is openable, has the correct mode/size/
    ownership, and is readable. Does NOT cache the result — called on
    every /healthz request (this is a liveness check, not a readiness
    check for hot paths). No key material is retained after the probe.
    """
    try:
        from fwd.infra.sealed_master import SealedMaster  # noqa: PLC0415

        master = SealedMaster()
        # Zeroize the in-memory key immediately — we only need the
        # constructor to succeed (it validates all custody properties).
        for i in range(len(master._master)):  # noqa: SLF001
            master._master[i] = 0  # noqa: SLF001
    except Exception:  # noqa: BLE001
        return "unavailable"
    return "ok"
