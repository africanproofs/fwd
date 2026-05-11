"""UUIDv7 generator tests (RFC 9562)."""

from __future__ import annotations

import time
import uuid

from fwd.infra.uuidv7 import uuid7_str


def test_uuid7_str_is_36_chars_canonical_form() -> None:
    s = uuid7_str()
    assert len(s) == 36
    # Canonical form: 8-4-4-4-12 hex groups separated by hyphens.
    parts = s.split("-")
    assert len(parts) == 5
    assert [len(p) for p in parts] == [8, 4, 4, 4, 12]


def test_uuid7_str_version_field_is_7() -> None:
    s = uuid7_str()
    parsed = uuid.UUID(s)
    assert parsed.version == 7


def test_uuid7_str_is_monotonic_in_practice() -> None:
    """UUIDv7 strings are time-ordered when generated across distinct ms timestamps.

    Monotonicity is guaranteed when consecutive UUIDs have different ms
    timestamps (the 48-bit field occupies the highest bits of the string).
    Within the same ms, rand_a provides random ordering; same-ms pairs
    are NOT guaranteed monotonic by this implementation.
    """
    generated = []
    for _ in range(20):
        generated.append(uuid7_str())
        time.sleep(0.002)  # 2ms gap ensures distinct ms timestamps
    assert sorted(generated) == generated
