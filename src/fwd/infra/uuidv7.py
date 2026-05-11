"""UUIDv7 generator (RFC 9562).

Format: 48 bits ms-since-epoch | 4 bits version (7) | 12 bits rand_a |
2 bits variant (10) | 62 bits rand_b. Canonical 36-char string output.

Time-ordered so transactions table indexes well by tx_id.
"""

from __future__ import annotations

import os
import time
import uuid


def uuid7() -> uuid.UUID:
    ms = int(time.time() * 1000)
    rand_a = int.from_bytes(os.urandom(2), "big") & 0x0FFF  # 12 bits
    rand_b = int.from_bytes(os.urandom(8), "big") & 0x3FFFFFFFFFFFFFFF  # 62 bits

    uuid_int = (
        (ms & 0xFFFFFFFFFFFF) << 80  # 48 bits ms
        | 0x7 << 76  # 4 bits version
        | (rand_a & 0xFFF) << 64  # 12 bits rand_a
        | 0x2 << 62  # 2 bits variant
        | rand_b  # 62 bits rand_b
    )
    return uuid.UUID(int=uuid_int)


def uuid7_str() -> str:
    return str(uuid7())
