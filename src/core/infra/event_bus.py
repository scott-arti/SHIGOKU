"""
EventBus: イベント駆動アーキテクチャの中核

MasterConductor → Agent間の非同期イベント通知を実現する。
asyncio.Queueベースのインプロセス実装。
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    """イベントタイプ定義"""
    # タスク関連
    TASK_ASSIGNED = "task_assigned"
    TASK_STARTED = "task_started"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    FLAKY_QUARANTINE_RELEASED = "flaky_quarantine_released"
    
    # 発見関連
    ASSET_FOUND = "asset_found"
    VULN_FOUND = "vuln_found"
    TECH_STACK_DETECTED = "tech_stack_detected"
    
    # 優先度関連
    PRIORITY_BOOST = "priority_boost"
    
    # システム関連
    RATE_LIMIT_DETECTED = "rate_limit_detected"
    ERROR_OCCURRED = "error_occurred"
    LOG_MESSAGE = "log_message"  # Tier 7: ダッシュボード配信用ログ
    
    # === Phase 5: リアルタイムダッシュボード用 ===
    
    # LLM関連
    LLM_CALL_START = "llm_call_start"
    LLM_CALL_END = "llm_call_end"
    LLM_ERROR = "llm_error"
    
    # 意思決定
    DECISION_MADE = "decision_made"
    
    # Reconステップ
    RECON_STEP_START = "recon_step_start"
    RECON_STEP_END = "recon_step_end"
    
    # Specialist実行
    SPECIALIST_EXECUTE = "specialist_execute"

    # バックグラウンド Recon 完了
    RECON_COMPLETED = "recon.completed"
    RECON_FAILED = "recon.failed"
    
    # === Phase 6.2: Granular Notification System ===
    
    # スキャン状態
    SCAN_STARTED = "scan_started"           # ターゲットに対するスキャン開始
    VULN_HUNTING = "vuln_hunting"           # 特定脆弱性タイプの探索開始
    VULN_NOT_FOUND = "vuln_not_found"       # 脆弱性なし（探索完了）
    
    # エージェント状態
    AGENT_DISPATCHED = "agent_dispatched"   # サブエージェント起動
    
    # === Tier 2 Phase 4-5: Session & Auth ===
    SESSION_EXPIRED = "session_expired"     # 401 Unauthorized 等によるセッション切れ
    REAUTH_SUCCESS = "reauth_success"       # 自動再認証成功
    REAUTH_FAILED = "reauth_failed"         # 自動再認証失敗


@dataclass
class Event:
    """イベントデータ構造"""
    type: EventType
    payload: dict = field(default_factory=dict)
    source: str = "unknown"
    timestamp: float = field(default_factory=time.time)
    event_id: str = field(default_factory=lambda: f"evt_{int(time.time() * 1000)}_{uuid.uuid4().hex[:6]}")
    
    def to_dict(self) -> dict:
        """辞書形式に変換"""
        return {
            "event_id": self.event_id,
            "type": self.type.value if isinstance(self.type, EventType) else self.type,
            "payload": self.payload,
            "source": self.source,
            "timestamp": self.timestamp,
        }


# イベントハンドラの型定義
EventHandler = Callable[[Event], Coroutine[Any, Any, None]]


class EventBus:
    """
    非同期イベントバス
    
    MasterConductorとAgent間のイベント通知を管理する。
    
    使用例:
        bus = EventBus()
        
        async def on_asset_found(event: Event):
            print(f"Asset found: {event.payload}")
        
        bus.subscribe(EventType.ASSET_FOUND, on_asset_found)
        await bus.emit(Event(type=EventType.ASSET_FOUND, payload={"url": "http://..."}))
    """
    
    def __init__(self, max_queue_size: int = 1000):
        self._subscribers: dict[EventType, list[EventHandler]] = defaultdict(list)
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=max_queue_size)
        self._running: bool = False
        self._worker_task: Optional[asyncio.Task] = None
        self._processed_ids: set[str] = set()  # 重複排除用
        self._max_processed_ids: int = 10000  # メモリ制限
    
    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """
        イベントハンドラを登録
        
        Args:
            event_type: 購読するイベントタイプ
            handler: 非同期ハンドラ関数
        """
        if handler not in self._subscribers[event_type]:
            self._subscribers[event_type].append(handler)
            logger.debug(f"Subscribed handler to {event_type.value}")
    
    def unsubscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """
        イベントハンドラを解除
        
        Args:
            event_type: 解除するイベントタイプ
            handler: 解除するハンドラ関数
        """
        if handler in self._subscribers[event_type]:
            self._subscribers[event_type].remove(handler)
            logger.debug(f"Unsubscribed handler from {event_type.value}")
    
    async def emit(self, event: Event) -> None:
        """
        イベントを発行
        
        Args:
            event: 発行するイベント
        """
        # 重複チェック
        if event.event_id in self._processed_ids:
            logger.warning(f"Duplicate event ignored: {event.event_id}")
            return
        
        try:
            await asyncio.wait_for(
                self._queue.put(event),
                timeout=5.0
            )
            logger.debug(f"Event emitted: {event.type.value} from {event.source}")
        except asyncio.TimeoutError:
            logger.error(f"Event queue full, dropping event: {event.event_id}")
    
    def emit_sync(self, event: Event) -> None:
        """
        同期的にイベントを発行（非asyncコンテキスト用）
        
        Args:
            event: 発行するイベント
        """
        try:
            self._queue.put_nowait(event)
            logger.debug(f"Event emitted (sync): {event.type.value}")
            
            # Phase 5: 同期オブザーバーに直接通知（LiveDashboard用）
            if hasattr(self, '_sync_observers'):
                for observer in self._sync_observers:
                    try:
                        observer(event)
                    except Exception as e:
                        logger.debug(f"Sync observer error: {e}")
        except asyncio.QueueFull:
            logger.error(f"Event queue full, dropping event: {event.event_id}")
    
    async def start(self) -> None:
        """イベント処理ワーカーを開始"""
        if self._running:
            return
        
        self._running = True
        self._worker_task = asyncio.create_task(self._process_events())
        logger.info("EventBus started")
    
    async def stop(self) -> None:
        """イベント処理ワーカーを停止"""
        self._running = False

        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error(f"Error waiting for worker task: {e}")

        # キューに残っているイベントをクリア
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
                self._queue.task_done()
            except asyncio.QueueEmpty:
                break

        logger.info("EventBus stopped")
    
    async def _process_events(self) -> None:
        """イベントキューを処理するワーカー"""
        while self._running:
            try:
                event = await asyncio.wait_for(
                    self._queue.get(),
                    timeout=1.0
                )
                
                # 重複排除
                if event.event_id in self._processed_ids:
                    continue
                
                self._processed_ids.add(event.event_id)
                
                # メモリ制限
                if len(self._processed_ids) > self._max_processed_ids:
                    # 古いIDを削除（簡易実装）
                    self._processed_ids = set(list(self._processed_ids)[-5000:])
                
                # ハンドラ実行
                handlers = self._subscribers.get(event.type, [])
                for handler in handlers:
                    try:
                        await handler(event)
                    except Exception as e:
                        logger.error(f"Error in event handler: {e}", exc_info=True)
                
                self._queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing event: {e}", exc_info=True)
    
    @property
    def pending_count(self) -> int:
        """未処理イベント数"""
        return self._queue.qsize()
    
    def clear_subscribers(self) -> None:
        """全ての購読を解除"""
        self._subscribers.clear()


# シングルトンインスタンス（オプション）
_default_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    """デフォルトのEventBusインスタンスを取得"""
    global _default_bus
    if _default_bus is None:
        _default_bus = EventBus()
    return _default_bus
