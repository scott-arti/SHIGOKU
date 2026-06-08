"""
Collaborative Mode - 人間との協調ワークフロー

AIが「次にこの操作をしてもよいか？」と提案し、
人間がCLI経由で承認・修正・拒否できるワークフロー。

用途:
- 高リスク操作の事前確認
- IDOR/Race Condition等のマルチアカウントテスト許可
- 攻撃ペイロード送信前の確認
"""

import logging
import json
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Callable, Any
from enum import Enum
from datetime import datetime
from pathlib import Path

from src.core.notifications.notifier import get_notifier

logger = logging.getLogger(__name__)


class ApprovalStatus(Enum):
    """承認ステータス"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    MODIFIED = "modified"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


class ActionCategory(Enum):
    """アクションカテゴリ"""
    SCAN = "scan"                     # スキャン開始
    ATTACK = "attack"                 # 攻撃ペイロード送信
    IDOR_CROSS_TEST = "idor_cross_test"  # IDORクロステスト
    RACE_CONDITION = "race_condition"    # Race Conditionテスト
    DESTRUCTIVE = "destructive"          # 破壊的操作
    EXTERNAL = "external"                # 外部通信
    CREDENTIAL = "credential"            # クレデンシャル使用
    HIGH_RISK = "high_risk"              # 高リスク操作


@dataclass
class ApprovalRequest:
    """承認リクエスト"""
    request_id: str
    category: ActionCategory
    action: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    risk_level: str = "medium"  # low, medium, high, critical
    auto_approve: bool = False
    timeout_seconds: int = 300  # 5分
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            "request_id": self.request_id,
            "category": self.category.value,
            "action": self.action,
            "description": self.description,
            "details": self.details,
            "risk_level": self.risk_level,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class ApprovalResponse:
    """承認レスポンス"""
    request_id: str
    status: ApprovalStatus
    modified_params: Optional[Dict[str, Any]] = None
    reason: str = ""
    approved_by: str = ""
    approved_at: datetime = field(default_factory=datetime.now)


class CollaborativeMode:
    """
    Collaborative Mode マネージャー
    
    高リスク操作の事前確認ワークフローを管理。
    """
    
    # リスクレベル別の自動承認設定
    AUTO_APPROVE_LEVELS = {
        "low": True,      # 低リスクは自動承認
        "medium": False,  # 中リスクは確認必要
        "high": False,    # 高リスクは確認必須
        "critical": False,  # 重大リスクは確認必須
    }
    
    # カテゴリ別のデフォルトリスクレベル
    CATEGORY_RISK_LEVELS = {
        ActionCategory.SCAN: "low",
        ActionCategory.ATTACK: "medium",
        ActionCategory.IDOR_CROSS_TEST: "high",
        ActionCategory.RACE_CONDITION: "high",
        ActionCategory.DESTRUCTIVE: "critical",
        ActionCategory.EXTERNAL: "medium",
        ActionCategory.CREDENTIAL: "high",
        ActionCategory.HIGH_RISK: "critical",
    }
    
    def __init__(
        self,
        enabled: bool = True,
        approval_file: Optional[Path] = None,
        notify_on_request: bool = True,
    ):
        """
        Args:
            enabled: Collaborative Modeを有効化
            approval_file: 承認状態保存ファイル
            notify_on_request: リクエスト時に通知を送信
        """
        self.enabled = enabled
        self.approval_file = approval_file or Path.home() / ".shigoku" / "approvals.json"
        self.notify_on_request = notify_on_request
        
        self.pending_requests: Dict[str, ApprovalRequest] = {}
        self.history: List[ApprovalResponse] = []
        self.notifier = get_notifier()
        self._approval_callbacks: List[Callable[[ApprovalRequest], ApprovalResponse]] = []
        
        # 承認ファイルの親ディレクトリを作成
        self.approval_file.parent.mkdir(parents=True, exist_ok=True)
    
    def request_approval(
        self,
        category: ActionCategory,
        action: str,
        description: str,
        details: Optional[Dict[str, Any]] = None,
        risk_level: Optional[str] = None,
    ) -> ApprovalResponse:
        """
        承認をリクエスト
        
        Args:
            category: アクションカテゴリ
            action: アクション名
            description: 説明
            details: 詳細情報
            risk_level: リスクレベル（省略時はカテゴリから推測）
        
        Returns:
            ApprovalResponse
        """
        if not self.enabled:
            return ApprovalResponse(
                request_id="disabled",
                status=ApprovalStatus.SKIPPED,
                reason="Collaborative mode is disabled",
            )
        
        # リスクレベル決定
        if risk_level is None:
            risk_level = self.CATEGORY_RISK_LEVELS.get(category, "medium")
        
        # 自動承認チェック
        if self.AUTO_APPROVE_LEVELS.get(risk_level, False):
            return ApprovalResponse(
                request_id="auto",
                status=ApprovalStatus.APPROVED,
                reason=f"Auto-approved: {risk_level} risk level",
            )
        
        # リクエスト作成
        import secrets
        request_id = secrets.token_hex(8)
        request = ApprovalRequest(
            request_id=request_id,
            category=category,
            action=action,
            description=description,
            details=details or {},
            risk_level=risk_level,
        )
        
        self.pending_requests[request_id] = request
        
        # 通知送信
        if self.notify_on_request:
            self._send_approval_notification(request)
        
        # コールバックがあれば実行
        for callback in self._approval_callbacks:
            try:
                response = callback(request)
                if response:
                    return self._process_response(request_id, response)
            except Exception as e:
                logger.error("Approval callback error: %s", e)
        
        # 承認ファイルに書き込み
        self._save_pending_request(request)
        
        # CLI入力待ち（同期）
        return self._wait_for_cli_approval(request)
    
    def _send_approval_notification(self, request: ApprovalRequest) -> None:
        """承認リクエスト通知を送信"""
        risk_icon = {
            "low": "🟢",
            "medium": "🟡", 
            "high": "🟠",
            "critical": "🔴",
        }.get(request.risk_level, "⚪")
        
        message = (
            f"{risk_icon} **承認リクエスト: {request.action}**\n"
            f"\n"
            f"カテゴリ: {request.category.value}\n"
            f"リスク: {request.risk_level.upper()}\n"
            f"\n"
            f"{request.description}\n"
        )
        
        if request.details:
            message += "\n**詳細:**\n"
            for key, value in list(request.details.items())[:5]:
                message += f"- {key}: {value}\n"
        
        message += (
            f"\n"
            f"---\n"
            f"承認: `shigoku approve {request.request_id}`\n"
            f"拒否: `shigoku reject {request.request_id}`"
        )
        
        self.notifier.notify(message, bulk=True)
    
    def _save_pending_request(self, request: ApprovalRequest) -> None:
        """承認待ちリクエストをファイルに保存"""
        try:
            existing = []
            if self.approval_file.exists():
                with open(self.approval_file, 'r') as f:
                    existing = json.load(f)
            
            existing.append(request.to_dict())
            
            with open(self.approval_file, 'w') as f:
                json.dump(existing, f, indent=2)
        except Exception as e:
            logger.error("Failed to save approval request: %s", e)
    
    def _wait_for_cli_approval(
        self,
        request: ApprovalRequest,
    ) -> ApprovalResponse:
        """
        CLI入力を待機
        
        NOTE: 実際の実装ではファイル監視またはソケット通信を使用。
        ここではファイルベースのポーリングを実装。
        """
        import time
        
        response_file = self.approval_file.parent / f"response_{request.request_id}.json"
        start_time = time.time()
        
        logger.info(
            "Waiting for approval: %s (timeout: %ds)",
            request.request_id,
            request.timeout_seconds,
        )
        
        print(f"\n{'='*60}")
        print(f"🔔 承認待ち: {request.action}")
        print(f"   リスク: {request.risk_level.upper()}")
        print(f"   {request.description}")
        print(f"\n   承認: shigoku approve {request.request_id}")
        print(f"   拒否: shigoku reject {request.request_id}")
        print(f"{'='*60}\n")
        
        while time.time() - start_time < request.timeout_seconds:
            if response_file.exists():
                try:
                    with open(response_file, 'r') as f:
                        data = json.load(f)
                    response_file.unlink()  # 削除
                    return self._process_response(
                        request.request_id,
                        ApprovalResponse(
                            request_id=request.request_id,
                            status=ApprovalStatus(data.get("status", "rejected")),
                            modified_params=data.get("modified_params"),
                            reason=data.get("reason", ""),
                            approved_by=data.get("approved_by", "cli"),
                        )
                    )
                except Exception as e:
                    logger.error("Failed to read response: %s", e)
            
            time.sleep(1)
        
        # タイムアウト
        return self._process_response(
            request.request_id,
            ApprovalResponse(
                request_id=request.request_id,
                status=ApprovalStatus.TIMEOUT,
                reason="Approval request timed out",
            )
        )
    
    def _process_response(
        self,
        request_id: str,
        response: ApprovalResponse,
    ) -> ApprovalResponse:
        """レスポンスを処理"""
        if request_id in self.pending_requests:
            del self.pending_requests[request_id]
        
        self.history.append(response)
        
        logger.info(
            "Approval %s: %s - %s",
            request_id,
            response.status.value,
            response.reason,
        )
        
        return response
    
    def approve(
        self,
        request_id: str,
        modified_params: Optional[Dict[str, Any]] = None,
        reason: str = "",
    ) -> bool:
        """
        リクエストを承認（CLI用）
        
        Returns:
            承認に成功したか
        """
        response_file = self.approval_file.parent / f"response_{request_id}.json"
        
        status = ApprovalStatus.MODIFIED if modified_params else ApprovalStatus.APPROVED
        
        try:
            with open(response_file, 'w') as f:
                json.dump({
                    "status": status.value,
                    "modified_params": modified_params,
                    "reason": reason,
                    "approved_by": "cli",
                }, f)
            return True
        except Exception as e:
            logger.error("Failed to write approval: %s", e)
            return False
    
    def reject(
        self,
        request_id: str,
        reason: str = "",
    ) -> bool:
        """
        リクエストを拒否（CLI用）
        """
        response_file = self.approval_file.parent / f"response_{request_id}.json"
        
        try:
            with open(response_file, 'w') as f:
                json.dump({
                    "status": ApprovalStatus.REJECTED.value,
                    "reason": reason,
                    "approved_by": "cli",
                }, f)
            return True
        except Exception as e:
            logger.error("Failed to write rejection: %s", e)
            return False
    
    def register_callback(
        self,
        callback: Callable[[ApprovalRequest], ApprovalResponse],
    ) -> None:
        """承認コールバックを登録"""
        self._approval_callbacks.append(callback)
    
    def is_approved(self, response: ApprovalResponse) -> bool:
        """承認されたか判定"""
        return response.status in (ApprovalStatus.APPROVED, ApprovalStatus.MODIFIED)
    
    def get_pending_requests(self) -> List[ApprovalRequest]:
        """承認待ちリクエストを取得"""
        return list(self.pending_requests.values())
    
    def get_summary(self) -> Dict:
        """サマリー取得"""
        by_status = {}
        for r in self.history:
            s = r.status.value
            by_status[s] = by_status.get(s, 0) + 1
        
        return {
            "enabled": self.enabled,
            "pending": len(self.pending_requests),
            "total_processed": len(self.history),
            "by_status": by_status,
        }


# シングルトン
_collaborative_instance: Optional[CollaborativeMode] = None


def get_collaborative_mode() -> CollaborativeMode:
    """CollaborativeMode取得"""
    global _collaborative_instance
    if _collaborative_instance is None:
        _collaborative_instance = CollaborativeMode()
    return _collaborative_instance


def request_approval(
    category: ActionCategory,
    action: str,
    description: str,
    details: Optional[Dict[str, Any]] = None,
) -> ApprovalResponse:
    """承認リクエストショートカット"""
    return get_collaborative_mode().request_approval(
        category=category,
        action=action,
        description=description,
        details=details,
    )
