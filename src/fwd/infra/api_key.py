"""Caller API key generation, hashing, and verification.

Per docs/architecture.md § Caller authentication and decisions.md D8:
caller bearer tokens are argon2id-hashed and prefix-indexed.

Token format: `fwd_live_<43-char-base64url>` (256 bits of entropy from
32 random bytes via secrets.token_urlsafe(32); base64url has no padding
so 32 bytes → exactly 43 chars).
- Constant prefix `fwd_live_` (9 chars) — environment indicator.
- 43-char random portion (base64url of 32 random bytes).
- Total length: 52 chars.

Storage:
- api_key_hash: argon2id(token, ...) — verified at request time.
- api_key_prefix: first 8 chars of the random portion (NOT the
  `fwd_live_` part) — used as a SQL filter to narrow the verify
  scope to a single row in the common case.

Phase 4 uses argon2-cffi PasswordHasher() defaults (as of argon2-cffi
23.1.0: time_cost=3, memory_cost=65536 KiB, parallelism=4, hash_len=32,
salt_len=16). These exceed OWASP 2024 minimum recommendations for
argon2id (m=46 MiB t=1 p=1 OR m=19 MiB t=2 p=1). They are CPU-bound;
expect ~50-100ms per verify on commodity hardware. Phase 7 may add a
per-process verification cache. Closes v0.4.0a1 audit F5.2 (the prior
comment said "252 bits" and "parallelism=2" — both wrong).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Per architecture.md: stable prefix for the live environment.
# Phase 10+ may add `fwd_test_` for a non-prod environment indicator.
_PREFIX = "fwd_live_"
_RANDOM_BYTES = 32  # → 43 base64url chars (no padding).
_PREFIX_INDEX_LEN = 8  # First 8 chars of the random portion.

_HASHER = PasswordHasher()  # argon2-cffi defaults; tune in Phase 7.


@dataclass(frozen=True)
class GeneratedKey:
    """A freshly minted caller key. The `key` field is the only place
    the operator ever sees the plaintext — `clifwd callers create`
    prints it once and immediately forgets.
    """

    key: str  # Full token: fwd_live_<43-chars>
    key_hash: str  # argon2id hash for storage
    key_prefix: str  # 8-char SQL-filter prefix


def generate_api_key() -> GeneratedKey:
    """Mint a fresh caller key.

    Returns the plaintext key (display once, never again), the hash
    (persist), and the prefix (persist for SQL filtering).
    """
    random_part = secrets.token_urlsafe(_RANDOM_BYTES)
    # secrets.token_urlsafe drops padding; 32 bytes → 43 chars exactly.
    if len(random_part) != 43:
        raise RuntimeError(
            f"unexpected token_urlsafe length: {len(random_part)}; "
            f"expected 43 chars from 32 bytes"
        )
    key = _PREFIX + random_part
    key_hash = _HASHER.hash(key)
    key_prefix = random_part[:_PREFIX_INDEX_LEN]
    return GeneratedKey(key=key, key_hash=key_hash, key_prefix=key_prefix)


def extract_prefix(presented_key: str) -> str | None:
    """Extract the 8-char prefix from a presented bearer token.

    Returns None if the token doesn't have the expected shape (which
    immediately fails authentication — no need to hash or DB-lookup).
    """
    if not presented_key.startswith(_PREFIX):
        return None
    random_part = presented_key[len(_PREFIX) :]
    if len(random_part) != 43:
        return None
    return random_part[:_PREFIX_INDEX_LEN]


def verify_api_key(presented_key: str, stored_hash: str) -> bool:
    """Argon2id-verify the presented key against the stored hash.

    Returns True on match, False on mismatch. Re-raises on any other
    argon2 error (treat as auth failure at the call site).
    """
    try:
        _HASHER.verify(stored_hash, presented_key)
        return True
    except VerifyMismatchError:
        return False
