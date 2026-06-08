"""
TaskExecutionRecord: サブエージェントタスク実行の詳細記録

Phase 6.3 Dashboard Traceability 用データモデル
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum


class TaskResult(str, Enum):
    """タスク実行結果"""
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


@dataclass
class TaskExecutionRecord:
    """
    サブエージェントタスク実行の詳細記録
    
    Dashboard でのトレーサビリティ向上のため、
    各タスクの実行コンテキストと結果を詳細に記録。
    """
    # 基本情報
    task_id: str
    task_name: str
    agent_type: str
    action: str
    
    # ターゲット情報
    target_url: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    
    # 実行時刻
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    
    # 結果
    result: TaskResult = TaskResult.SKIPPED
    result_summary: str = ""
    
    # 発見した脆弱性
    vulnerabilities_found: List[Dict[str, Any]] = field(default_factory=list)
    
    # エラー情報
    error_message: Optional[str] = None
    
    # ソース情報
    source: str = ""  # recipe, dynamic, replan など
    
    # 追加メタデータ
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def mark_completed(
        self, 
        success: bool, 
        summary: str = "",
        error: Optional[str] = None,
        **kwargs
    ) -> None:
        """タスク完了をマーク"""
        self.completed_at = datetime.now()
        self.result = TaskResult.SUCCESS if success else TaskResult.FAILURE
        self.result_summary = summary
        if error:
            self.error_message = error
        
        # 未知の引数（例: output）があれば metadata に格納
        if kwargs:
            self.metadata.update(kwargs)

    
    def mark_timeout(self) -> None:
        """タイムアウトをマーク"""
        self.completed_at = datetime.now()
        self.result = TaskResult.TIMEOUT
        self.error_message = "Execution timed out"
    
    def add_vulnerability(self, vuln: Any) -> None:
        """
        脆弱性を追加
        
        Finding オブジェクトまたは辞書を受け取り、辞書形式で保存する。
        """
        if hasattr(vuln, 'to_dict') and callable(vuln.to_dict):
            self.vulnerabilities_found.append(vuln.to_dict())
        else:
            self.vulnerabilities_found.append(vuln)
    
    def duration_seconds(self) -> Optional[float]:
        """実行時間（秒）"""
        if self.completed_at and self.started_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """辞書形式に変換"""
        return {
            "task_id": self.task_id,
            "task_name": self.task_name,
            "agent_type": self.agent_type,
            "action": self.action,
            "target_url": self.target_url,
            "parameters": self.parameters,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "result": self.result.value,
            "result_summary": self.result_summary,
            "vulnerabilities_found": self.vulnerabilities_found,
            "error_message": self.error_message,
            "source": self.source,
            "duration_seconds": self.duration_seconds(),
            "metadata": self.metadata,
        }


class TaskExecutionLog:
    """
    タスク実行ログのコレクション
    
    全タスクの実行記録を保持し、Dashboard への提供やレポート生成に使用。
    """
    
    def __init__(self, max_records: int = 1000):
        self._records: List[TaskExecutionRecord] = []
        self.max_records = max_records
    
    def add_record(self, record: TaskExecutionRecord) -> None:
        """記録を追加（上限を超えた場合は古いものを削除）"""
        self._records.append(record)
        if len(self._records) > self.max_records:
            # 古いものを削除（メモリ管理）
            self._records.pop(0)
    
    def get_all(self) -> List[TaskExecutionRecord]:
        """全記録を取得"""
        return self._records.copy()
    
    def get_by_agent(self, agent_type: str) -> List[TaskExecutionRecord]:
        """エージェントタイプで絞り込み"""
        return [r for r in self._records if r.agent_type == agent_type]
    
    def get_by_target(self, target_url: str) -> List[TaskExecutionRecord]:
        """ターゲットURLで絞り込み"""
        return [r for r in self._records if r.target_url == target_url]
    
    def get_failures(self) -> List[TaskExecutionRecord]:
        """失敗したタスクのみ"""
        return [r for r in self._records if r.result == TaskResult.FAILURE]
    
    def get_with_vulnerabilities(self) -> List[TaskExecutionRecord]:
        """脆弱性を発見したタスクのみ"""
        return [r for r in self._records if len(r.vulnerabilities_found) > 0]
    
    def summary(self) -> Dict[str, Any]:
        """サマリー統計"""
        total = len(self._records)
        success = sum(1 for r in self._records if r.result == TaskResult.SUCCESS)
        failure = sum(1 for r in self._records if r.result == TaskResult.FAILURE)
        timeout = sum(1 for r in self._records if r.result == TaskResult.TIMEOUT)
        vulns = sum(len(r.vulnerabilities_found) for r in self._records)
        
        return {
            "total_tasks": total,
            "success": success,
            "failure": failure,
            "timeout": timeout,
            "vulnerabilities_found": vulns,
            "success_rate": success / total if total > 0 else 0.0,
        }
    
    def to_list(self) -> List[Dict[str, Any]]:
        """全記録を辞書リストに変換"""
        return [r.to_dict() for r in self._records]


# シングルトンインスタンス
_execution_log_instance: Optional[TaskExecutionLog] = None


def get_execution_log() -> TaskExecutionLog:
    """シングルトン TaskExecutionLog を取得"""
    global _execution_log_instance
    if _execution_log_instance is None:
        _execution_log_instance = TaskExecutionLog()
    return _execution_log_instance
