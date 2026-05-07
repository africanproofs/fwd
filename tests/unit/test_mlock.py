"""Tests for the mlockall lifespan hook.

The actual mlockall() syscall requires CAP_IPC_LOCK in the container,
which the test runner does not have. These tests verify the gate logic
(env var honored, lifespan calls _mlockall when not disabled) by
patching _mlockall directly. Real mlockall behaviour is verified at
container startup (the fwd container fails-loud if mlockall errors).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_lifespan_calls_mlockall_when_not_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default behaviour: lifespan startup invokes _mlockall."""
    monkeypatch.delenv("FWD_DISABLE_MLOCK", raising=False)
    with patch("fwd.main._mlockall") as mock_mlock:
        from fwd.main import lifespan

        async with lifespan(MagicMock()):
            pass
    mock_mlock.assert_called_once()


@pytest.mark.asyncio
async def test_lifespan_skips_mlockall_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FWD_DISABLE_MLOCK=1 skips the syscall (dev/test escape hatch)."""
    monkeypatch.setenv("FWD_DISABLE_MLOCK", "1")
    with patch("fwd.main._mlockall") as mock_mlock:
        from fwd.main import lifespan

        async with lifespan(MagicMock()):
            pass
    mock_mlock.assert_not_called()


@pytest.mark.asyncio
async def test_lifespan_skip_only_on_exact_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Other truthy values (true, yes, 0, empty) do NOT skip — only literal '1'."""
    for skip_val in ("0", "true", "yes", "TRUE", ""):
        monkeypatch.setenv("FWD_DISABLE_MLOCK", skip_val)
        with patch("fwd.main._mlockall") as mock_mlock:
            from fwd.main import lifespan

            async with lifespan(MagicMock()):
                pass
        if skip_val == "":
            # Empty string also != "1" — mlock fires.
            mock_mlock.assert_called_once()
        else:
            mock_mlock.assert_called_once(), f"unexpected skip on FWD_DISABLE_MLOCK={skip_val!r}"


def test_mlockall_function_exists_and_is_callable() -> None:
    """Sanity: _mlockall is a callable defined in fwd.main."""
    from fwd.main import _mlockall

    assert callable(_mlockall)


def test_mlockall_constants_are_posix() -> None:
    """MCL_CURRENT=1 and MCL_FUTURE=2 are POSIX-defined constants."""
    from fwd.main import _MCL_CURRENT, _MCL_FUTURE

    assert _MCL_CURRENT == 1
    assert _MCL_FUTURE == 2
