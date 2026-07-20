import logging
from concurrent.futures import CancelledError as FutureCancelledError
from unittest.mock import MagicMock, patch

from src.core.engine.master_conductor import MasterConductor


def test_shutdown_suppresses_expected_cancelled_error_after_normal_completion(caplog) -> None:
    mc = MasterConductor.__new__(MasterConductor)
    mc._finished_normally = True
    mc._loop_thread = None

    loop = MagicMock()
    loop.is_running.return_value = True
    mc._get_loop = MagicMock(return_value=loop)

    future = MagicMock()
    future.result.side_effect = FutureCancelledError()

    def _fake_run_coroutine_threadsafe(coro, _loop):
        coro.close()
        return future

    with patch(
        "src.core.engine.master_conductor.asyncio.run_coroutine_threadsafe",
        side_effect=_fake_run_coroutine_threadsafe,
    ):
        with caplog.at_level(logging.DEBUG):
            mc.shutdown()

    assert "Shutdown error" not in caplog.text
    assert "expected cancellation cleanup" in caplog.text
