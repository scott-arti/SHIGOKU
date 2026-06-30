"""
DecisionTrace: MasterConductor の意思決定ログ

Phase 6.4 MasterConductor Decision Log 用データモデル
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum


class DecisionType(str, Enum):
    """意思決定タイプ"""
    RECON_DISPATCH = "recon_dispatch"           # Recon エージェント選択
    VULN_HUNTER_DISPATCH = "vuln_hunter_dispatch"  # 脆弱性ハンター選択
    RECIPE_INJECTION = "recipe_injection"       # Recipe 動的注入
    REPLAN = "replan"                           # リプラン判断
    PRIORITY_BOOST = "priority_boost"           # 優先度ブースト
    TARGET_ESCALATE = "target_escalate"         # ターゲットエスカレーション
    SKIP_TASK = "skip_task"                     # タスクスキップ
    FALLBACK = "fallback"                       # フォールバック戦略
    # Phase 6 (SGK-2026-0315): Task pruning lifecycle
    TASK_RETIRED = "task_retired"               # 価値がなくなったタスク
    TASK_SUPERSEDED = "task_superseded"         # 別タスクが代替したタスク
    TASK_INVALIDATED = "task_invalidated"       # 前提snapshotが古くなったタスク


@dataclass
class DecisionTrace:
    """
    MasterConductor の意思決定ログ
    
    判断ポイント、入力情報、選択肢、選択理由を記録。
    """
    # 意思決定識別
    decision_id: str
    decision_type: DecisionType
    timestamp: datetime = field(default_factory=datetime.now)
    
    # 入力情報
    input_context: Dict[str, Any] = field(default_factory=dict)
    
    # 選択肢と選択
    available_options: List[str] = field(default_factory=list)
    selected_option: str = ""
    
    # 選択理由
    reasoning: str = ""
    
    # 関連タスク
    related_task_id: Optional[str] = None
    related_target: Optional[str] = None
    
    # 結果（後から更新）
    outcome: Optional[str] = None
    was_successful: Optional[bool] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """辞書形式に変換"""
        return {
            "decision_id": self.decision_id,
            "decision_type": self.decision_type.value,
            "timestamp": self.timestamp.isoformat(),
            "input_context": self.input_context,
            "available_options": self.available_options,
            "selected_option": self.selected_option,
            "reasoning": self.reasoning,
            "related_task_id": self.related_task_id,
            "related_target": self.related_target,
            "outcome": self.outcome,
            "was_successful": self.was_successful,
        }


class DecisionTracer:
    """
    意思決定トレーサー
    
    MasterConductor の判断プロセスを記録し、
    デバッグやレポート生成に使用。
    """
    
    def __init__(self, max_traces: int = 1000):
        self._traces: List[DecisionTrace] = []
        self._decision_counter = 0
        self.max_traces = max_traces
    
    def trace(
        self,
        decision_type: DecisionType,
        input_context: Dict[str, Any],
        available_options: List[str],
        selected_option: str,
        reasoning: str,
        related_task_id: Optional[str] = None,
        related_target: Optional[str] = None,
    ) -> DecisionTrace:
        """
        新しい意思決定を記録（上限を超えた場合は古いものを削除）
        
        Args:
            decision_type: 意思決定タイプ
            input_context: 入力コンテキスト（判断材料）
            available_options: 利用可能な選択肢
            selected_option: 選択したオプション
            reasoning: 選択理由
            related_task_id: 関連タスクID
            related_target: 関連ターゲット
            
        Returns:
            DecisionTrace: 作成されたトレース
        """
        self._decision_counter += 1
        trace = DecisionTrace(
            decision_id=f"dec_{self._decision_counter:04d}",
            decision_type=decision_type,
            input_context=input_context,
            available_options=available_options,
            selected_option=selected_option,
            reasoning=reasoning,
            related_task_id=related_task_id,
            related_target=related_target,
        )
        self._traces.append(trace)
        
        # メモリ制限: 古いトレースを削除
        if len(self._traces) > self.max_traces:
            self._traces.pop(0)
            
        return trace
    
    def update_outcome(
        self,
        decision_id: str,
        outcome: str,
        was_successful: bool
    ) -> None:
        """意思決定の結果を更新"""
        for trace in self._traces:
            if trace.decision_id == decision_id:
                trace.outcome = outcome
                trace.was_successful = was_successful
                break
    
    def get_all(self) -> List[DecisionTrace]:
        """全トレースを取得"""
        return self._traces.copy()
    
    def get_by_type(self, decision_type: DecisionType) -> List[DecisionTrace]:
        """タイプで絞り込み"""
        return [t for t in self._traces if t.decision_type == decision_type]
    
    def get_failures(self) -> List[DecisionTrace]:
        """失敗した意思決定のみ"""
        return [t for t in self._traces if t.was_successful is False]
    
    def summary(self) -> Dict[str, Any]:
        """サマリー統計"""
        total = len(self._traces)
        by_type = {}
        for t in self._traces:
            type_name = t.decision_type.value
            by_type[type_name] = by_type.get(type_name, 0) + 1
        
        success_count = sum(1 for t in self._traces if t.was_successful is True)
        failure_count = sum(1 for t in self._traces if t.was_successful is False)
        
        return {
            "total_decisions": total,
            "by_type": by_type,
            "success_count": success_count,
            "failure_count": failure_count,
            "pending_count": total - success_count - failure_count,
        }
    
    def to_list(self) -> List[Dict[str, Any]]:
        """全トレースを辞書リストに変換"""
        return [t.to_dict() for t in self._traces]


# シングルトンインスタンス
_decision_tracer_instance: Optional[DecisionTracer] = None


def get_decision_tracer() -> DecisionTracer:
    """シングルトン DecisionTracer を取得"""
    global _decision_tracer_instance
    if _decision_tracer_instance is None:
        _decision_tracer_instance = DecisionTracer()
    return _decision_tracer_instance
