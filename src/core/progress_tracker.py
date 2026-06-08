"""
Progress Tracker - 進捗トラッカー

キャンセル可能な進捗バー
"""

import logging
import threading
import time
from typing import Optional, Callable, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ProgressState:
    """進捗状態"""
    current: int = 0
    total: int = 0
    message: str = ""
    status: str = "running"  # running/completed/cancelled/error
    start_time: float = 0.0
    elapsed: float = 0.0
    eta: float = 0.0  # 推定残り時間


class ProgressTracker:
    """
    進捗トラッカー
    
    機能:
    - リアルタイム進捗
    - キャンセルサポート
    - ETA計算
    - コールバック
    """
    
    def __init__(
        self,
        total: int = 0,
        message: str = "",
        callback: Callable[[ProgressState], None] = None
    ):
        self.state = ProgressState(
            total=total,
            message=message,
            start_time=time.time()
        )
        self.callback = callback
        self._cancelled = threading.Event()
        self._lock = threading.Lock()
    
    def update(self, current: int = None, message: str = None):
        """進捗更新"""
        with self._lock:
            if current is not None:
                self.state.current = current
            if message is not None:
                self.state.message = message
            
            # 経過時間・ETA計算
            self.state.elapsed = time.time() - self.state.start_time
            if self.state.current > 0 and self.state.total > 0:
                rate = self.state.current / self.state.elapsed
                remaining = self.state.total - self.state.current
                self.state.eta = remaining / rate if rate > 0 else 0
            
            # コールバック
            if self.callback:
                self.callback(self.state)
    
    def increment(self, amount: int = 1):
        """進捗インクリメント"""
        self.update(current=self.state.current + amount)
    
    def set_total(self, total: int):
        """総数設定"""
        with self._lock:
            self.state.total = total
    
    def cancel(self):
        """キャンセル"""
        self._cancelled.set()
        with self._lock:
            self.state.status = "cancelled"
        logger.info("Progress cancelled")
    
    def is_cancelled(self) -> bool:
        """キャンセル確認"""
        return self._cancelled.is_set()
    
    def complete(self):
        """完了"""
        with self._lock:
            self.state.status = "completed"
            self.state.current = self.state.total
            self.state.elapsed = time.time() - self.state.start_time
        
        if self.callback:
            self.callback(self.state)
    
    def error(self, message: str = ""):
        """エラー終了"""
        with self._lock:
            self.state.status = "error"
            if message:
                self.state.message = message
    
    def get_progress_bar(self, width: int = 40) -> str:
        """プログレスバー文字列生成"""
        if self.state.total == 0:
            return f"[{'?' * width}] {self.state.message}"
        
        percent = self.state.current / self.state.total
        filled = int(width * percent)
        bar = "█" * filled + "░" * (width - filled)
        
        return f"[{bar}] {self.state.current}/{self.state.total} ({percent:.1%})"
    
    def get_status_line(self) -> str:
        """ステータス行生成"""
        eta_str = self._format_time(self.state.eta) if self.state.eta > 0 else "--:--"
        elapsed_str = self._format_time(self.state.elapsed)
        
        return f"{self.get_progress_bar()} ETA: {eta_str} | Elapsed: {elapsed_str}"
    
    def _format_time(self, seconds: float) -> str:
        """時間フォーマット"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds // 60)}m {int(seconds % 60)}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h {minutes}m"
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.error(str(exc_val))
        else:
            self.complete()


class CancellableTask:
    """
    キャンセル可能タスク
    
    長時間タスクのラッパー
    """
    
    def __init__(self, name: str = "task"):
        self.name = name
        self.tracker: Optional[ProgressTracker] = None
        self._cancelled = threading.Event()
    
    def create_tracker(
        self,
        total: int,
        message: str = "",
        callback: Callable = None
    ) -> ProgressTracker:
        """トラッカー作成"""
        self.tracker = ProgressTracker(total, message, callback)
        return self.tracker
    
    def cancel(self):
        """キャンセル"""
        self._cancelled.set()
        if self.tracker:
            self.tracker.cancel()
    
    def is_cancelled(self) -> bool:
        """キャンセル確認"""
        return self._cancelled.is_set()
    
    def check_cancelled(self):
        """キャンセル確認（例外発生版）"""
        if self._cancelled.is_set():
            raise TaskCancelledException(f"Task '{self.name}' was cancelled")


class TaskCancelledException(Exception):
    """タスクキャンセル例外"""
    pass


def create_progress_tracker(
    total: int = 0,
    message: str = "",
    callback: Callable = None
) -> ProgressTracker:
    """ProgressTracker作成ヘルパー"""
    return ProgressTracker(total, message, callback)
