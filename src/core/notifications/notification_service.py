"""
NotificationService: Finding通知の統合管理

EventBusと連携し、Findingsを重要度に応じて
即時通知またはバッチ通知する。
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from src.core.infra.event_bus import Event, EventType, get_event_bus
from src.core.models.finding import Finding, Severity
from src.core.notifications.notifier import get_notifier
from src.core.config.feature_config import get_feature_config

logger = logging.getLogger(__name__)


@dataclass
class NotificationEntry:
    """通知エントリ"""
    finding: Finding
    timestamp: float = field(default_factory=time.time)
    notified: bool = False


class NotificationService:
    """
    Finding通知サービス
    
    重要度に応じた通知戦略:
    - Critical/High: 即時通知
    - Medium/Low: バッチ通知（5分間隔）
    
    機能:
    - 重複排除（同一Finding IDは一定時間内に再通知しない）
    - EventBusサブスクライバとして自動登録
    - 統計情報の追跡
    
    使用例:
        service = NotificationService()
        await service.start()
        
        # または手動で通知
        service.notify(finding)
    """

    def __init__(self):
        self.config = get_feature_config().notifications
        self.notifier = get_notifier()
        self._batch_queue: deque[NotificationEntry] = deque()
        self._sent_ids: dict[str, float] = {}  # finding_id -> timestamp
        self._running = False
        self._batch_task: Optional[asyncio.Task] = None
        
        # 統計
        self._stats = {
            "immediate_sent": 0,
            "batch_sent": 0,
            "duplicates_skipped": 0,
            "errors": 0,
        }

    async def start(self) -> None:
        """サービスを開始し、EventBusにサブスクライブ"""
        if not self.config.enabled:
            logger.info("Notification service disabled")
            return

        if self._running:
            return

        self._running = True
        
        # EventBusにサブスクライブ
        bus = get_event_bus()
        bus.subscribe(EventType.VULN_FOUND, self._on_finding_event)
        
        # バッチ処理タスクを開始
        self._batch_task = asyncio.create_task(self._batch_processor())
        
        logger.info("NotificationService started")

    async def stop(self) -> None:
        """サービスを停止"""
        self._running = False

        if self._batch_task:
            self._batch_task.cancel()
            try:
                await self._batch_task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error(f"Error waiting for batch task: {e}")

        # 残りのバッチを送信
        await self._flush_batch()

        logger.info("NotificationService stopped")

    async def _on_finding_event(self, event: Event) -> None:
        """VULN_FOUNDイベントハンドラ"""
        finding_data = event.payload.get("finding")
        if not finding_data:
            return
        
        # Findingオブジェクトに変換（既にFindingの場合はそのまま）
        if isinstance(finding_data, Finding):
            finding = finding_data
        elif isinstance(finding_data, dict):
            # 簡易変換（必要に応じて拡張）
            try:
                finding = Finding(
                    vuln_type=finding_data.get("vuln_type"),
                    severity=Severity(finding_data.get("severity", "info")),
                    title=finding_data.get("title", "Unknown"),
                    description=finding_data.get("description", ""),
                    target_url=finding_data.get("target_url", ""),
                )
            except Exception as e:
                logger.error(f"Failed to parse finding from event: {e}")
                return
        else:
            return
        
        await self.notify_async(finding)

    def notify(self, finding: Finding) -> bool:
        """
        Findingを通知（同期版）
        
        Args:
            finding: 通知するFinding
            
        Returns:
            通知成功ならTrue
        """
        if not self.config.enabled:
            return False

        # 重複チェック
        if self._is_duplicate(finding):
            self._stats["duplicates_skipped"] += 1
            logger.debug(f"Duplicate finding skipped: {finding.id}")
            return False

        severity = finding.severity.value
        
        # 即時通知の判定
        if severity in self.config.immediate_severities:
            return self._send_immediate(finding)
        else:
            # バッチキューに追加
            self._batch_queue.append(NotificationEntry(finding=finding))
            return True

    async def notify_async(self, finding: Finding) -> bool:
        """Findingを通知（非同期版）"""
        return self.notify(finding)

    def _is_duplicate(self, finding: Finding) -> bool:
        """重複チェック"""
        dedup_window = self.config.dedup_window_seconds
        now = time.time()
        
        # 古いエントリをクリーンアップ
        expired = [k for k, v in self._sent_ids.items() if now - v > dedup_window]
        for k in expired:
            del self._sent_ids[k]
        
        # 同一IDがあればスキップ
        if finding.id in self._sent_ids:
            return True
        
        # コンテンツベースの重複チェック
        content_hash = self._get_content_hash(finding)
        if content_hash in self._sent_ids:
            return True
        
        return False

    def _get_content_hash(self, finding: Finding) -> str:
        """Finding内容のハッシュを生成"""
        content = f"{finding.vuln_type.value}:{finding.target_url}:{finding.title}"
        return hashlib.md5(content.encode()).hexdigest()[:16]

    def _send_immediate(self, finding: Finding) -> bool:
        """即時通知を送信"""
        try:
            success = self.notifier.notify_finding(finding)
            if success:
                self._sent_ids[finding.id] = time.time()
                self._sent_ids[self._get_content_hash(finding)] = time.time()
                self._stats["immediate_sent"] += 1
                logger.info(f"Immediate notification sent: {finding.title}")
            return success
        except Exception as e:
            logger.error(f"Failed to send immediate notification: {e}")
            self._stats["errors"] += 1
            return False

    async def _batch_processor(self) -> None:
        """バッチ処理ワーカー"""
        while self._running:
            try:
                await asyncio.sleep(self.config.batch_interval_seconds)
                await self._flush_batch()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in batch processor: {e}")

    async def _flush_batch(self) -> None:
        """バッチキューをフラッシュして送信"""
        if not self._batch_queue:
            return

        # キューをコピーしてクリア
        entries = list(self._batch_queue)
        self._batch_queue.clear()
        
        # 重複を除去
        unique_findings = []
        for entry in entries:
            if not entry.notified and not self._is_duplicate(entry.finding):
                unique_findings.append(entry.finding)
        
        if not unique_findings:
            return
        
        # バッチメッセージを構築
        message = self._format_batch_message(unique_findings)
        
        try:
            success = self.notifier.notify(message, bulk=True)
            if success:
                for f in unique_findings:
                    self._sent_ids[f.id] = time.time()
                    self._sent_ids[self._get_content_hash(f)] = time.time()
                self._stats["batch_sent"] += len(unique_findings)
                logger.info(f"Batch notification sent: {len(unique_findings)} findings")
        except Exception as e:
            logger.error(f"Failed to send batch notification: {e}")
            self._stats["errors"] += 1

    def _format_batch_message(self, findings: list[Finding]) -> str:
        """バッチ通知メッセージをフォーマット"""
        lines = [
            f"📋 **SHIGOKU Findings Summary** ({len(findings)} new)",
            "---",
        ]
        
        for f in findings[:10]:  # 最大10件
            icon = f.get_severity_icon()
            lines.append(f"{icon} [{f.severity.value.upper()}] {f.title}")
            lines.append(f"   └─ {f.target_url}")
        
        if len(findings) > 10:
            lines.append(f"   ... and {len(findings) - 10} more")
        
        return "\n".join(lines)

    def get_stats(self) -> dict:
        """統計情報を取得"""
        return {
            **self._stats,
            "queue_size": len(self._batch_queue),
            "tracked_ids": len(self._sent_ids),
        }


# シングルトンインスタンス
_service_instance: Optional[NotificationService] = None


def get_notification_service() -> NotificationService:
    """NotificationServiceのシングルトンインスタンスを取得"""
    global _service_instance
    if _service_instance is None:
        _service_instance = NotificationService()
    return _service_instance
