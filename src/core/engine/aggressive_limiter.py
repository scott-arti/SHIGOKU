"""
Aggressive Limiter: is_aggressive タスクの同時実行制御

Implementation Plan Section 6.4 準拠:
- is_aggressive タスクは同時 1 つまで
- POST/PUT/DELETE メソッドは is_aggressive=True
- 10 RPS 以上のリクエストは is_aggressive=True

Phase 5: Operational Features
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any, Callable, Awaitable
from collections import deque

logger = logging.getLogger(__name__)


@dataclass
class AggressiveConfig:
    """Aggressive Limiter 設定"""
    # 同時実行可能な aggressive タスク数
    max_concurrent_aggressive: int = 1
    
    # RPS 閾値（これを超えると aggressive 扱い）
    aggressive_rps_threshold: int = 10
    
    # aggressive と判定する HTTP メソッド
    aggressive_methods: tuple = ("POST", "PUT", "DELETE", "PATCH")
    
    # HITL モード
    # - "hitl_aggressive": is_aggressive=True のみ確認
    # - "hitl_all": 全タスク確認
    # - "hitl_off": 確認なし
    hitl_mode: str = "hitl_aggressive"


class AggressiveLimiter:
    """
    Global Aggressive Limiter
    
    is_aggressive=True のタスクを同時 1 つまでに制限し、
    必要に応じて HITL (Human-in-the-Loop) 確認を行う。
    """
    
    def __init__(
        self,
        config: Optional[AggressiveConfig] = None,
        hitl_callback: Optional[Callable[[Dict[str, Any]], Awaitable[bool]]] = None,
    ):
        self.config = config or AggressiveConfig()
        self.hitl_callback = hitl_callback
        
        # 現在実行中の aggressive タスク数
        self._active_aggressive_count = 0
        
        # ペンディングキュー (asyncio.Queue で非同期待機)
        self._pending_queue: asyncio.Queue = asyncio.Queue()
        
        # セマフォで同時実行制御
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent_aggressive)
        
        # RPS 計算用のリクエストタイムスタンプ
        self._request_timestamps: deque = deque(maxlen=100)
        
        # ロック
        self._lock = asyncio.Lock()
        
        logger.info(
            "AggressiveLimiter initialized: max_concurrent=%d, rps_threshold=%d, hitl_mode=%s",
            self.config.max_concurrent_aggressive,
            self.config.aggressive_rps_threshold,
            self.config.hitl_mode,
        )
    
    def calculate_current_rps(self) -> float:
        """直近 1 秒間のリクエスト数を計算"""
        now = datetime.now()
        one_second_ago = now.timestamp() - 1.0
        
        # 1秒以内のリクエストをカウント
        recent_count = sum(
            1 for ts in self._request_timestamps
            if ts > one_second_ago
        )
        return float(recent_count)
    
    def record_request(self) -> None:
        """リクエストを記録（RPS 計算用）"""
        self._request_timestamps.append(datetime.now().timestamp())

    def should_be_aggressive(self, task_params: Dict[str, Any]) -> bool:
        """
        タスクが aggressive として扱われるべきかを判定
        
        条件:
        1. タスク自体に is_aggressive=True が設定されている
        2. 現在の RPS が閾値を超えている
        """
        # 明示的に設定されている場合
        if task_params.get("is_aggressive", False):
            return True
        
        # RPS チェック
        current_rps = self.calculate_current_rps()
        if current_rps >= self.config.aggressive_rps_threshold:
            logger.warning(
                "RPS threshold exceeded: %.1f >= %d, marking as aggressive",
                current_rps, self.config.aggressive_rps_threshold
            )
            return True
        
        return False
    
    async def request_approval(self, task_info: Dict[str, Any]) -> bool:
        """
        HITL: ユーザーに承認を求める
        
        Returns:
            True: 承認された
            False: 拒否された
        """
        if self.config.hitl_mode == "hitl_off":
            return True
        
        if self.config.hitl_mode == "hitl_aggressive":
            # is_aggressive=True の場合のみ確認
            if not task_info.get("is_aggressive", False):
                return True
        
        # hitl_all または hitl_aggressive で該当する場合
        if self.hitl_callback:
            try:
                return await self.hitl_callback(task_info)
            except Exception as e:
                logger.error("HITL callback error: %s", e)
                return False  # エラー時は安全側に倒す
        else:
            # コールバックがない場合はコンソールで確認
            return await self._console_approval(task_info)
    
    async def _console_approval(self, task_info: Dict[str, Any]) -> bool:
        """コンソールでの承認プロンプト"""
        print("\n" + "=" * 60)
        print("🔴 AGGRESSIVE TASK - Approval Required")
        print("=" * 60)
        print(f"  Target: {task_info.get('target', 'unknown')}")
        print(f"  Method: {task_info.get('method', 'unknown')}")
        print(f"  Action: {task_info.get('action', 'unknown')}")
        if task_info.get("tag"):
            print(f"  Tag: {task_info.get('tag')}")
        print("=" * 60)
        
        # 非同期入力（テスト時は即座に True を返す）
        try:
            import sys
            if sys.stdin.isatty():
                response = input("Execute this task? [y/N]: ").strip().lower()
                return response in ("y", "yes")
            else:
                # 非対話モードではスキップ
                logger.warning("Non-interactive mode, skipping approval prompt")
                return False
        except EOFError:
            return False
    
    async def acquire(self, task_info: Dict[str, Any]) -> bool:
        """
        aggressive タスクの実行権を取得
        
        - is_aggressive=True のタスクはセマフォで制限
        - HITL モードに応じて承認を求める
        
        Returns:
            True: 実行可能
            False: 拒否またはスキップ
        """
        is_aggressive = task_info.get("is_aggressive", False)
        
        # HITL 確認
        if is_aggressive or self.config.hitl_mode == "hitl_all":
            approved = await self.request_approval(task_info)
            if not approved:
                logger.info("Task rejected by user: %s", task_info.get("target", "unknown"))
                return False
        
        # aggressive タスクはセマフォで待機
        if is_aggressive:
            logger.info("Acquiring aggressive semaphore...")
            await self._semaphore.acquire()
            async with self._lock:
                self._active_aggressive_count += 1
            logger.info(
                "Aggressive task started (active=%d/%d)",
                self._active_aggressive_count,
                self.config.max_concurrent_aggressive
            )
        
        # リクエスト記録
        self.record_request()
        
        return True
    
    async def release(self, is_aggressive: bool) -> None:
        """aggressive タスクの実行権を解放"""
        if is_aggressive:
            self._semaphore.release()
            async with self._lock:
                self._active_aggressive_count -= 1
            logger.info(
                "Aggressive task completed (active=%d/%d)",
                self._active_aggressive_count,
                self.config.max_concurrent_aggressive
            )
    
    def get_status(self) -> Dict[str, Any]:
        """現在の状態を取得"""
        return {
            "active_aggressive_count": self._active_aggressive_count,
            "max_concurrent_aggressive": self.config.max_concurrent_aggressive,
            "current_rps": self.calculate_current_rps(),
            "rps_threshold": self.config.aggressive_rps_threshold,
            "hitl_mode": self.config.hitl_mode,
            "pending_queue_size": self._pending_queue.qsize(),
        }


# シングルトンインスタンス
_limiter_instance: Optional[AggressiveLimiter] = None


def get_aggressive_limiter(
    config: Optional[AggressiveConfig] = None,
    hitl_callback: Optional[Callable[[Dict[str, Any]], Awaitable[bool]]] = None,
) -> AggressiveLimiter:
    """AggressiveLimiter のシングルトンを取得"""
    global _limiter_instance
    if _limiter_instance is None:
        _limiter_instance = AggressiveLimiter(config=config, hitl_callback=hitl_callback)
    return _limiter_instance


def reset_aggressive_limiter() -> None:
    """テスト用: シングルトンをリセット"""
    global _limiter_instance
    _limiter_instance = None
