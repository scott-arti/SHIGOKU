from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Protocol, runtime_checkable
import json

@dataclass
class HandoffContext:
    """
    全サブエージェント共通のHandoffコンテキスト
    SYSTEM A / SYSTEM B の両方で使用可能な統一規格
    """
    agent_name: str
    task_id: str
    success: bool
    result: Dict[str, Any]
    
    # 標準化されたアウトプット
    discovered_assets: List[str] = field(default_factory=list)  # 発見されたURL/エンドポイント
    bypass_methods: List[str] = field(default_factory=list)     # 成功した攻撃手法
    next_suggestions: List[str] = field(default_factory=list)   # 次に行うべきアクションの提案
    
    # 共有ワークスペース参照
    workspace_refs: List[str] = field(default_factory=list)     # 保存されたファイルのPOS
    
    def to_dict(self) -> dict:
        """辞書形式に変換"""
        return {
            "agent_name": self.agent_name,
            "task_id": self.task_id,
            "success": self.success,
            "result": self.result,
            "discovered_assets": self.discovered_assets,
            "bypass_methods": self.bypass_methods,
            "next_suggestions": self.next_suggestions,
            "workspace_refs": self.workspace_refs,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "HandoffContext":
        """辞書から復元"""
        return cls(
            agent_name=data.get("agent_name", "Unknown"),
            task_id=data.get("task_id", ""),
            success=data.get("success", False),
            result=data.get("result", {}),
            discovered_assets=data.get("discovered_assets", []),
            bypass_methods=data.get("bypass_methods", []),
            next_suggestions=data.get("next_suggestions", []),
            workspace_refs=data.get("workspace_refs", []),
        )


@runtime_checkable
class AgentProtocol(Protocol):
    """全エージェントが実装すべき共通インターフェース (Phase 1: ADR-002)
    
    MasterConductor._dispatch() の hasattr() チェックを削除するために導入。
    
    Usage:
        class MyAgent(BaseAgent):
            async def run(self, task: dict[str, Any]) -> dict[str, Any]:
                target = task.get("target")
                params = task.get("params", {})
                # ... 処理 ...
                return create_run_result(success=True, data=result, agent=self.name)
    """
    
    @property
    def name(self) -> str:
        """エージェント名を返す"""
        ...
    
    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """統一された実行メソッド
        
        Args:
            task: タスクパラメータ辞書
                - target: ターゲットURL/ドメイン
                - action: 実行アクション (optional)
                - params: 追加パラメータ (optional)
        
        Returns:
            実行結果辞書 (create_run_result() で作成推奨)
        """
        ...


def create_run_result(
    success: bool,
    data: Any = None,
    error: str | None = None,
    agent: str = ""
) -> Dict[str, Any]:
    """統一された結果フォーマットを作成するヘルパー
    
    Args:
        success: 処理が成功したか
        data: 結果データ
        error: エラーメッセージ (失敗時)
        agent: エージェント名
    
    Returns:
        統一フォーマットの結果辞書
    """
    result: Dict[str, Any] = {
        "success": success,
        "agent": agent,
    }
    if data is not None:
        result["data"] = data
    if error is not None:
        result["error"] = error
    return result
