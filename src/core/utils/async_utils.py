import asyncio
import threading
import logging
import inspect
from concurrent.futures import TimeoutError as FutureTimeoutError
from concurrent.futures import Future
from typing import Any, Coroutine, Optional, Callable, TypeVar

T = TypeVar("T")
logger = logging.getLogger(__name__)

class SharedLoopManager:
    """
    複数スレッドから安全に AsyncIO イベントループを共有・操作するためのクラス。
    MasterConductor だけでなく、各種エージェントからも呼び出されることを想定。
    """
    _instance: Optional["SharedLoopManager"] = None
    _lock = threading.Lock()

    def __init__(self):
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._loop_thread: Optional[threading.Thread] = None
        self._is_running = False

    @classmethod
    def get_instance(cls) -> "SharedLoopManager":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def get_loop(self) -> asyncio.AbstractEventLoop:
        """
        共有イベントループを取得する。存在しない場合は開始する。
        """
        with self._lock:
            if self._loop and not self._loop.is_closed() and self._is_running:
                return self._loop

            # 既存のループがない or 閉じられている場合、新しく作成
            self._loop = asyncio.new_event_loop()
            self._is_running = True
            self._loop_thread = threading.Thread(
                target=self._run_loop,
                args=(self._loop,),
                name="ShigokuSharedLoop",
                daemon=True
            )
            self._loop_thread.start()
            logger.debug("Shared background event loop started.")
            return self._loop

    def _run_loop(self, loop: asyncio.AbstractEventLoop):
        asyncio.set_event_loop(loop)
        try:
            loop.run_forever()
        finally:
            self._is_running = False
            try:
                pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception as e:
                logger.debug("Shared loop pending task cleanup failed: %s", e)
            loop.close()
            logger.debug("Shared background event loop stopped.")

    def run_coro(self, coro: Coroutine[Any, Any, T], timeout: Optional[float] = 300) -> T:
        """
        コルーチンをスレッドセーフに実行し、結果を待機する。
        """
        loop = self.get_loop()
        coro_name = getattr(coro, "__qualname__", coro.__class__.__name__)
        try:
            future = asyncio.run_coroutine_threadsafe(coro, loop)
        except Exception:
            if inspect.iscoroutine(coro):
                try:
                    coro.close()
                except Exception:
                    pass
            raise

        try:
            return future.result(timeout=timeout)
        except FutureTimeoutError as e:
            logger.error("Async execution timeout after %ss (coro=%s)", timeout, coro_name)
            future.cancel()
            try:
                future.result(timeout=5)
            except Exception:
                pass
            raise e
        except Exception as e:
            logger.error("Async execution failed (coro=%s): %r", coro_name, e)
            raise

    def run_coro_forget(self, coro: Coroutine[Any, Any, Any]) -> Optional[Future]:
        """
        コルーチンをスレッドセーフに実行し、完了を待機しない(Fire-and-forget)。
        """
        loop = self.get_loop()
        try:
            return asyncio.run_coroutine_threadsafe(coro, loop)
        except Exception as e:
            logger.error("Failed to enqueue async task (forget): %s", str(e))
            if inspect.iscoroutine(coro):
                try:
                    coro.close()
                except Exception:
                    pass
            return None

    def run_safe(self, func: Callable[..., Any], *args, timeout: Optional[float] = 300, **kwargs) -> Any:
        """
        同期/非同期関数を問わず、安全にループで実行して結果を待つ。
        """
        async def _wrapper():
            res = func(*args, **kwargs)
            if inspect.isawaitable(res):
                return await res
            return res
        
        return self.run_coro(_wrapper(), timeout=timeout)

    def stop(self):
        """
        ループを停止する。実行中のタスクを全てキャンセルする。
        """
        import threading
        
        with self._lock:
            if not self._is_running:
                return

            self._is_running = False

            if self._loop:
                # 1. 全てのタスクをキャンセル
                try:
                    pending = asyncio.all_tasks(self._loop)
                    for task in pending:
                        task.cancel()
                except Exception:
                    pass

                # 2. ループを停止
                try:
                    self._loop.call_soon_threadsafe(self._loop.stop)
                except RuntimeError:
                    pass  # 既に停止している

                # 3. スレッドの終了を待機（現在のスレッドではない場合のみ）
                current_thread = threading.current_thread()
                if self._loop_thread and self._loop_thread.is_alive() and self._loop_thread != current_thread:
                    self._loop_thread.join(timeout=5.0)

                # 4. ループを閉じる
                try:
                    self._loop.close()
                except Exception:
                    pass

                self._loop = None
                self._loop_thread = None

            logger.debug("Shared background event loop stopped.")

# グローバルショートカット
def safe_run_async(coro: Coroutine[Any, Any, T], timeout: Optional[float] = 300) -> T:
    return SharedLoopManager.get_instance().run_coro(coro, timeout=timeout)

def safe_run_async_forget(coro: Coroutine[Any, Any, Any]) -> Optional[Future]:
    return SharedLoopManager.get_instance().run_coro_forget(coro)

def safe_run(func: Callable[..., Any], *args, timeout: Optional[float] = 300, **kwargs) -> Any:
    return SharedLoopManager.get_instance().run_safe(func, *args, timeout=timeout, **kwargs)
