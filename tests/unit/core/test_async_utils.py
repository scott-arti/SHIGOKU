from src.core.utils.async_utils import SharedLoopManager, safe_run_async_forget


def test_safe_run_async_forget_returns_future_and_completes():
    async def _sample() -> str:
        return "ok"

    future = safe_run_async_forget(_sample())
    assert future is not None
    assert future.result(timeout=5) == "ok"

    # Keep the shared loop clean for subsequent tests.
    SharedLoopManager.get_instance().stop()
