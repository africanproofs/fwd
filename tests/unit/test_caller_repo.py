"""CallerRepo unit tests against an in-memory SQLite."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from fwd.infra.caller_repo import (
    CallerAlreadyRevokedError,
    CallerExistsError,
    CallerNotFoundError,
    CallerRepo,
    metadata,
)


@pytest.fixture()
async def session(tmp_path) -> AsyncSession:  # type: ignore[no-untyped-def]
    db = tmp_path / "test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
    async with AsyncSession(engine) as session:
        yield session
    await engine.dispose()


@pytest.mark.asyncio
async def test_create_then_get(session: AsyncSession) -> None:
    repo = CallerRepo(session)
    c = await repo.create(
        name="alice",
        api_key_hash="hash1",
        api_key_prefix="abcd1234",
        policy_path="policies/alice.yaml",
    )
    await session.commit()
    assert c.name == "alice"
    assert c.revoked_at is None
    got = await repo.get_by_name("alice")
    assert got is not None
    assert got.api_key_prefix == "abcd1234"


@pytest.mark.asyncio
async def test_create_duplicate_raises(session: AsyncSession) -> None:
    repo = CallerRepo(session)
    await repo.create(
        name="bob",
        api_key_hash="hashB",
        api_key_prefix="bbbb1234",
        policy_path="policies/bob.yaml",
    )
    await session.commit()
    with pytest.raises(CallerExistsError):
        await repo.create(
            name="bob",
            api_key_hash="hashB2",
            api_key_prefix="cccc5678",
            policy_path="policies/bob.yaml",
        )


@pytest.mark.asyncio
async def test_get_missing_raises(session: AsyncSession) -> None:
    repo = CallerRepo(session)
    with pytest.raises(CallerNotFoundError):
        await repo.get_by_name("nobody")


@pytest.mark.asyncio
async def test_get_missing_ok(session: AsyncSession) -> None:
    repo = CallerRepo(session)
    got = await repo.get_by_name("nobody", missing_ok=True)
    assert got is None


@pytest.mark.asyncio
async def test_revoke_happy(session: AsyncSession) -> None:
    repo = CallerRepo(session)
    await repo.create(
        name="carol",
        api_key_hash="hashC",
        api_key_prefix="cccc1234",
        policy_path="policies/carol.yaml",
    )
    await session.commit()
    revoked = await repo.revoke("carol")
    await session.commit()
    assert revoked.revoked_at is not None
    got = await repo.get_by_name("carol")
    assert got is not None
    assert got.revoked_at is not None


@pytest.mark.asyncio
async def test_revoke_not_found_raises(session: AsyncSession) -> None:
    repo = CallerRepo(session)
    with pytest.raises(CallerNotFoundError):
        await repo.revoke("nobody")


@pytest.mark.asyncio
async def test_revoke_already_revoked_raises(session: AsyncSession) -> None:
    repo = CallerRepo(session)
    await repo.create(
        name="dave",
        api_key_hash="hashD",
        api_key_prefix="dddd1234",
        policy_path="policies/dave.yaml",
    )
    await session.commit()
    await repo.revoke("dave")
    await session.commit()
    with pytest.raises(CallerAlreadyRevokedError):
        await repo.revoke("dave")


@pytest.mark.asyncio
async def test_list_by_prefix_active_excludes_revoked(session: AsyncSession) -> None:
    repo = CallerRepo(session)
    await repo.create(
        name="eve",
        api_key_hash="hashE",
        api_key_prefix="eeee1234",
        policy_path="policies/eve.yaml",
    )
    await session.commit()
    await repo.revoke("eve")
    await session.commit()
    results = await repo.list_by_prefix_active("eeee1234")
    assert results == []


@pytest.mark.asyncio
async def test_list_all_includes_revoked(session: AsyncSession) -> None:
    repo = CallerRepo(session)
    await repo.create(
        name="frank",
        api_key_hash="hashF",
        api_key_prefix="ffff1234",
        policy_path="policies/frank.yaml",
    )
    await session.commit()
    await repo.revoke("frank")
    await session.commit()
    results = await repo.list_all(include_revoked=True)
    assert any(c.name == "frank" for c in results)


# ---------------------------------------------------------------------------
# replace=True tests (capability 3)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_replace_true_on_revoked_remints(session: AsyncSession) -> None:
    """create(..., replace=True) on a REVOKED caller re-mints with new key, revoked_at=None."""
    import time

    repo = CallerRepo(session)
    original = await repo.create(
        name="grace",
        api_key_hash="hashG1",
        api_key_prefix="gggg1111",
        policy_path="policies/grace.yaml",
    )
    await session.commit()
    await repo.revoke("grace")
    await session.commit()

    # Small sleep so created_at timestamp is later.
    time.sleep(0.01)

    reminted = await repo.create(
        name="grace",
        api_key_hash="hashG2",
        api_key_prefix="gggg2222",
        policy_path="policies/grace.yaml",
        replace=True,
    )
    await session.commit()

    assert reminted.revoked_at is None
    assert reminted.api_key_hash == "hashG2"
    assert reminted.api_key_prefix == "gggg2222"
    assert reminted.created_at >= original.created_at

    # Row count for that name stays 1.
    got = await repo.get_by_name("grace")
    assert got is not None
    assert got.revoked_at is None
    assert got.api_key_prefix == "gggg2222"


@pytest.mark.asyncio
async def test_create_replace_true_on_active_raises(session: AsyncSession) -> None:
    """create(..., replace=True) on an ACTIVE caller still raises CallerExistsError."""
    repo = CallerRepo(session)
    await repo.create(
        name="henry",
        api_key_hash="hashH",
        api_key_prefix="hhhh1234",
        policy_path="policies/henry.yaml",
    )
    await session.commit()

    with pytest.raises(CallerExistsError):
        await repo.create(
            name="henry",
            api_key_hash="hashH2",
            api_key_prefix="hhhh5678",
            policy_path="policies/henry.yaml",
            replace=True,
        )


@pytest.mark.asyncio
async def test_create_replace_false_on_revoked_raises(session: AsyncSession) -> None:
    """create(..., replace=False) on a REVOKED caller still raises CallerExistsError."""
    repo = CallerRepo(session)
    await repo.create(
        name="iris",
        api_key_hash="hashI",
        api_key_prefix="iiii1234",
        policy_path="policies/iris.yaml",
    )
    await session.commit()
    await repo.revoke("iris")
    await session.commit()

    with pytest.raises(CallerExistsError):
        await repo.create(
            name="iris",
            api_key_hash="hashI2",
            api_key_prefix="iiii5678",
            policy_path="policies/iris.yaml",
            replace=False,
        )


@pytest.mark.asyncio
async def test_create_no_replace_fresh_unchanged(session: AsyncSession) -> None:
    """A fresh create (no existing row) is unchanged — works as before."""
    repo = CallerRepo(session)
    c = await repo.create(
        name="jake",
        api_key_hash="hashJ",
        api_key_prefix="jjjj1234",
        policy_path="policies/jake.yaml",
    )
    await session.commit()
    assert c.name == "jake"
    assert c.revoked_at is None
