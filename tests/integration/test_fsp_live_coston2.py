"""FSP signing GATE-1 integration test (Phase 9a-ii).

GATE-1 has two parts:
  (a) Offline determinism: import the KAT key (0x11*32) into a real
      SealedMaster+WalletRepo+EnvelopeSigner, call sign_fsp_eip191 on a
      build_fsp_message(UPTIME, 0) hash, and assert the recovered signer
      address matches the expected KAT address.

  (b) Live (only when FWD_LIVE_COSTON2=1): eth_call Coston2
      FlareSystemsManager.signUptimeVote with the fwd-produced signature
      and assert no revert with a signature/signer error.

The offline part (a) always runs. Part (b) skips when FWD_LIVE_COSTON2 is
not set. The test module must be importable without error even when the
live gate is unset.
"""

from __future__ import annotations

import os

import pytest

# KAT key: 0x11*32 (the "known-answer test" key per the spec).
_KAT_PRIVKEY_HEX = "11" * 32
# Address derived from 0x11*32 (eth_account.Account.from_key).
_KAT_ADDRESS = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A"

# Coston2 FlareSystemsManager address (per Flare protocol docs).
_FSM_COSTON2 = "0xbC1F76CEB521Eb5484b8943B5462D08ea96617A1"
_COSTON2_RPC = "https://coston2-api.flare.network/ext/C/rpc"


# ---------------------------------------------------------------------------
# Part (a) — Offline determinism (always runs)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fsp_sign_offline_determinism(
    tmp_path, monkeypatch  # type: ignore[no-untyped-def]
) -> None:
    """KAT key 0x11*32 + UPTIME epoch 0 -> recovered address = _KAT_ADDRESS."""
    from eth_account import Account
    from eth_account.messages import encode_defunct

    from fwd import settings as settings_mod
    from fwd.domain.fsp_message import UPTIME, build_fsp_message
    from fwd.infra import db as db_mod
    from fwd.infra.envelope_signer import EnvelopeSigner
    from fwd.infra.sealed_master import SealedMaster
    from fwd.infra.wallet_repo import WalletRepo
    from fwd.infra.wallet_repo import metadata as wallet_metadata

    # Set up a tmp DB + master key file.
    db_path = tmp_path / "kat.db"
    master_path = tmp_path / "master.key"
    master_key = bytes(range(32))  # deterministic 32-byte master
    master_path.write_bytes(master_key)
    master_path.chmod(0o600)

    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("FWD_MASTER_KEY_FILE", str(master_path))
    # Clear LRU caches so the new env values are picked up.
    settings_mod.get_settings.cache_clear()
    db_mod.get_engine.cache_clear()
    db_mod._session_factory.cache_clear()

    engine = db_mod.get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(wallet_metadata.create_all)

    async with db_mod.session_scope() as session:
        async with SealedMaster() as vault:
            signer = EnvelopeSigner(vault, WalletRepo(session))
            privkey_buf = bytearray(bytes.fromhex(_KAT_PRIVKEY_HEX))
            await signer.import_wallet(
                name="kat-wallet",
                privkey_buf=privkey_buf,
                policy_path="fsp/kat",
                expected_address=_KAT_ADDRESS,
            )

        # Reconstruct the FSP messageHash for UPTIME epoch 0.
        built = build_fsp_message(UPTIME, 0)
        assert built is not None, "build_fsp_message(UPTIME, 0) should not return None"

        async with SealedMaster() as vault2:
            signer2 = EnvelopeSigner(vault2, WalletRepo(session))
            signed = await signer2.sign_fsp_eip191("kat-wallet", built.message_hash)

    await engine.dispose()

    # Recover the signer address from the signature.
    msg = encode_defunct(primitive=built.message_hash)
    recovered = Account.recover_message(msg, signature=signed.signature)
    assert recovered.lower() == _KAT_ADDRESS.lower(), (
        f"KAT address mismatch: expected {_KAT_ADDRESS!r}, got {recovered!r}"
    )


# ---------------------------------------------------------------------------
# Part (b) — Live Coston2 (only when FWD_LIVE_COSTON2=1)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.skipif(
    os.environ.get("FWD_LIVE_COSTON2") != "1",
    reason="FWD_LIVE_COSTON2=1 not set; skipping live Coston2 check",
)
async def test_fsp_sign_live_coston2_no_revert(
    tmp_path, monkeypatch  # type: ignore[no-untyped-def]
) -> None:
    """Live: eth_call FlareSystemsManager.signUptimeVote on Coston2 with
    fwd-produced {v,r,s} asserts no signature/signer revert."""
    import httpx

    from fwd import settings as settings_mod
    from fwd.domain.fsp_message import UPTIME, build_fsp_message
    from fwd.infra import db as db_mod
    from fwd.infra.envelope_signer import EnvelopeSigner
    from fwd.infra.sealed_master import SealedMaster
    from fwd.infra.wallet_repo import WalletRepo
    from fwd.infra.wallet_repo import metadata as wallet_metadata

    db_path = tmp_path / "live.db"
    master_path = tmp_path / "master.key"
    master_key = bytes(range(32))
    master_path.write_bytes(master_key)
    master_path.chmod(0o600)

    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("FWD_MASTER_KEY_PATH", str(master_path))
    settings_mod.get_settings.cache_clear()
    db_mod.get_engine.cache_clear()
    db_mod._session_factory.cache_clear()

    engine = db_mod.get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(wallet_metadata.create_all)

    built = build_fsp_message(UPTIME, 0)
    assert built is not None

    async with db_mod.session_scope() as session, SealedMaster() as vault:
        signer = EnvelopeSigner(vault, WalletRepo(session))
        privkey_buf = bytearray(bytes.fromhex(_KAT_PRIVKEY_HEX))
        await signer.import_wallet(
            name="kat-live",
            privkey_buf=privkey_buf,
            policy_path="fsp/kat",
            expected_address=_KAT_ADDRESS,
        )
        signed = await signer.sign_fsp_eip191("kat-live", built.message_hash)

    await engine.dispose()

    # Encode signUptimeVote(uint24 rewardEpochId, bytes20 uptimeVoteHash, (uint8,bytes32,bytes32))
    import eth_abi  # type: ignore[import]

    selector_hex = "0xf9ec3c86"  # pre-computed selector for signUptimeVote
    uptime_vote_hash = b"\x00" * 20  # dummy 20-byte hash for eth_call check

    v = signed.v
    r = signed.r.to_bytes(32, "big")
    s = signed.s.to_bytes(32, "big")

    encoded = eth_abi.encode(  # type: ignore[attr-defined]
        ["uint24", "bytes20", "(uint8,bytes32,bytes32)"],
        [0, uptime_vote_hash, (v, r, s)],
    )
    call_data = selector_hex + encoded.hex()

    async with httpx.AsyncClient() as client:
        response = await client.post(
            _COSTON2_RPC,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_call",
                "params": [
                    {"to": _FSM_COSTON2, "data": call_data},
                    "latest",
                ],
            },
            timeout=30.0,
        )

    body = response.json()
    # We only assert that the call doesn't revert with a signer/signature error.
    # A revert with "other" reason (e.g. epoch not open) is acceptable.
    if "error" in body:
        error_msg = str(body["error"]).lower()
        assert "invalid signature" not in error_msg, (
            f"Signature validation failed on Coston2: {body['error']}"
        )
        assert "wrong signer" not in error_msg, (
            f"Wrong signer on Coston2: {body['error']}"
        )
