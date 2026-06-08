"""
Audit Logger - 監査ログ

全アクションの記録と追跡
"""

import json
import logging
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


class AuditEventType(Enum):
    """監査イベントタイプ"""
    SCAN_START = "scan_start"
    SCAN_END = "scan_end"
    REQUEST_SENT = "request_sent"
    REQUEST_BLOCKED = "request_blocked"
    FINDING_DETECTED = "finding_detected"
    TOOL_EXECUTED = "tool_executed"
    CONFIG_CHANGED = "config_changed"
    SCOPE_VIOLATION = "scope_violation"
    AUTH_USED = "auth_used"
    ERROR = "error"


@dataclass
class AuditEvent:
    """監査イベント"""
    event_type: AuditEventType
    timestamp: str = ""
    session_id: str = ""
    target: str = ""
    action: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    result: str = ""  # success/failed/blocked
    user: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + "Z"


class AuditLogger:
    """
    監査ログ
    
    機能:
    - 全アクション記録
    - JSON Lines形式
    - セッション追跡
    - 検索・フィルタ
    """
    
    def __init__(
        self,
        log_dir: str = None,
        session_id: str = None
    ):
        self.log_dir = Path(log_dir or os.path.expanduser("~/.shigoku/audit"))
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.session_id = session_id or self._generate_session_id()
        self.events: List[AuditEvent] = []
        
        # 現在のログファイル
        today = datetime.utcnow().strftime("%Y-%m-%d")
        self.log_file = self.log_dir / f"audit-{today}.jsonl"
    
    def _generate_session_id(self) -> str:
        """セッションID生成"""
        from uuid import uuid4
        return str(uuid4())[:8]
    
    def log(self, event: AuditEvent):
        """イベントログ記録"""
        event.session_id = self.session_id
        self.events.append(event)
        
        # ファイルに追記
        self._write_event(event)
        
        logger.debug("Audit: %s - %s", event.event_type.value, event.action)
    
    def log_scan_start(self, target: str, scan_type: str = ""):
        """スキャン開始記録"""
        self.log(AuditEvent(
            event_type=AuditEventType.SCAN_START,
            target=target,
            action=f"scan_start:{scan_type}",
            result="started",
        ))
    
    def log_scan_end(self, target: str, findings_count: int = 0):
        """スキャン終了記録"""
        self.log(AuditEvent(
            event_type=AuditEventType.SCAN_END,
            target=target,
            action="scan_end",
            result="completed",
            details={"findings_count": findings_count},
        ))
    
    def log_request(
        self,
        url: str,
        method: str = "GET",
        status_code: int = 0,
        blocked: bool = False,
        block_reason: str = ""
    ):
        """リクエスト記録"""
        event_type = AuditEventType.REQUEST_BLOCKED if blocked else AuditEventType.REQUEST_SENT
        
        self.log(AuditEvent(
            event_type=event_type,
            target=url,
            action=f"{method} {url}",
            result="blocked" if blocked else "sent",
            details={
                "method": method,
                "status_code": status_code,
                "block_reason": block_reason,
            },
        ))
    
    def log_finding(self, finding: Dict):
        """Finding検出記録"""
        self.log(AuditEvent(
            event_type=AuditEventType.FINDING_DETECTED,
            target=finding.get("url", ""),
            action=f"finding:{finding.get('type', 'unknown')}",
            result="detected",
            details={
                "severity": finding.get("severity", ""),
                "title": finding.get("title", ""),
            },
        ))
    
    def log_tool(self, tool_name: str, command: str, result: str = "success"):
        """ツール実行記録"""
        self.log(AuditEvent(
            event_type=AuditEventType.TOOL_EXECUTED,
            action=f"tool:{tool_name}",
            result=result,
            details={"command": command[:200]},  # コマンド切り詰め
        ))
    
    def log_scope_violation(self, url: str, reason: str):
        """スコープ違反記録"""
        self.log(AuditEvent(
            event_type=AuditEventType.SCOPE_VIOLATION,
            target=url,
            action="scope_violation",
            result="blocked",
            details={"reason": reason},
        ))
    
    def log_error(self, error: str, context: Dict = None):
        """エラー記録"""
        self.log(AuditEvent(
            event_type=AuditEventType.ERROR,
            action="error",
            result="error",
            details={"error": error, "context": context or {}},
        ))
    
    def _write_event(self, event: AuditEvent):
        """イベントをファイルに書き込み"""
        data = asdict(event)
        data["event_type"] = event.event_type.value
        
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(data, ensure_ascii=False) + "\n")
    
    def search(
        self,
        event_type: AuditEventType = None,
        target: str = None,
        from_date: str = None,
        to_date: str = None
    ) -> List[AuditEvent]:
        """
        ログ検索
        
        Returns:
            フィルタされたイベント
        """
        results = []
        
        # ログファイル読み込み
        for log_file in sorted(self.log_dir.glob("audit-*.jsonl")):
            with open(log_file, encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    
                    try:
                        data = json.loads(line)
                        
                        # フィルタ
                        if event_type and data.get("event_type") != event_type.value:
                            continue
                        if target and target not in data.get("target", ""):
                            continue
                        
                        event = AuditEvent(
                            event_type=AuditEventType(data["event_type"]),
                            timestamp=data.get("timestamp", ""),
                            session_id=data.get("session_id", ""),
                            target=data.get("target", ""),
                            action=data.get("action", ""),
                            details=data.get("details", {}),
                            result=data.get("result", ""),
                        )
                        results.append(event)
                        
                    except (json.JSONDecodeError, ValueError):
                        continue
        
        return results
    
    def get_session_summary(self) -> Dict:
        """現在セッションのサマリー"""
        by_type = {}
        for e in self.events:
            by_type.setdefault(e.event_type.value, 0)
            by_type[e.event_type.value] += 1
        
        return {
            "session_id": self.session_id,
            "total_events": len(self.events),
            "by_type": by_type,
        }


# シングルトン
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """AuditLoggerシングルトン取得"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger
