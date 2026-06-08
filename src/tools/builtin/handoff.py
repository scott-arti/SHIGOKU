"""Handoffプロトコル - Context-Aware Handoff 2.0

標準化されたHandoff Protocol:
- HandoffContext: Master Conductor→サブエージェント用の入力コンテキスト
- HandoffResult: サブエージェント→Master Conductor用の結果返却形式
- HandoffTool: エージェント間切り替え用ツール
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional
from src.tools.base import BaseTool
from src.tools import ToolRegistry


class HandoffStatus(Enum):
    """Handoff結果ステータス"""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass
class HandoffContext:
    """
    MC → サブエージェント への入力コンテキスト
    
    「何を」「どうやって」調べるかの指示書。
    Context-Aware Handoff 2.0 仕様準拠。
    """
    # ターゲット情報
    target_url: str
    original_request: Dict[str, Any] = field(default_factory=dict)
    
    # 認証情報（トークン、Cookie等）
    authentication: Dict[str, Any] = field(default_factory=dict)
    
    # RAGからのヒント
    rag_hints: List[str] = field(default_factory=list)
    
    # 具体的指示（プロンプト）
    instructions: str = ""
    
    # メタデータ（親タスク情報、優先度等）
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """辞書形式に変換"""
        return {
            "target_url": self.target_url,
            "original_request": self.original_request,
            "authentication": self.authentication,
            "rag_hints": self.rag_hints,
            "instructions": self.instructions,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HandoffContext":
        """辞書から生成"""
        return cls(
            target_url=data.get("target_url", ""),
            original_request=data.get("original_request", {}),
            authentication=data.get("authentication", {}),
            rag_hints=data.get("rag_hints", []),
            instructions=data.get("instructions", ""),
            metadata=data.get("metadata", {}),
        )
    
    @classmethod
    def from_params(cls, params: Dict[str, Any]) -> "HandoffContext":
        """従来のparams辞書から移行用ファクトリ"""
        return cls(
            target_url=params.get("target", ""),
            original_request=params.get("request", {}),
            authentication=params.get("auth", {}),
            rag_hints=params.get("hints", []),
            instructions=params.get("instructions", ""),
            metadata=params,
        )


@dataclass
class HandoffResult:
    """
    サブエージェント → MC への出力結果
    
    「誰が」「何を発見し」「次に何をすべきか」の報告書。
    Context-Aware Handoff 2.0 仕様準拠。
    """
    agent_name: str
    status: HandoffStatus
    
    # ターゲット情報
    target_url: str = ""
    bypass_method: Optional[str] = None
    
    # 発見情報
    findings: List[Dict[str, Any]] = field(default_factory=list)
    
    # リクエスト/レスポンス詳細
    original_request: Dict[str, Any] = field(default_factory=dict)
    response_data: Dict[str, Any] = field(default_factory=dict)
    
    # 取得した認証情報
    credentials: Dict[str, Any] = field(default_factory=dict)
    
    # 次への推奨
    recommendations: List[str] = field(default_factory=list)
    next_suggested_agent: Optional[str] = None
    
    # 脆弱性仮説・成功確率
    vulnerability_hypothesis: Optional[str] = None
    success_probability: float = 0.0
    
    # コンテキスト・エラー
    context: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """辞書形式に変換"""
        return {
            "agent_name": self.agent_name,
            "status": self.status.value,
            "target_url": self.target_url,
            "bypass_method": self.bypass_method,
            "findings": self.findings,
            "original_request": self.original_request,
            "response_data": self.response_data,
            "credentials": self.credentials,
            "recommendations": self.recommendations,
            "next_suggested_agent": self.next_suggested_agent,
            "vulnerability_hypothesis": self.vulnerability_hypothesis,
            "success_probability": self.success_probability,
            "context": self.context,
            "error": self.error,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HandoffResult":
        """辞書から生成"""
        status_str = data.get("status", "failed")
        try:
            status = HandoffStatus(status_str)
        except ValueError:
            status = HandoffStatus.FAILED
        
        return cls(
            agent_name=data.get("agent_name", "unknown"),
            status=status,
            target_url=data.get("target_url", ""),
            bypass_method=data.get("bypass_method"),
            findings=data.get("findings", []),
            original_request=data.get("original_request", {}),
            response_data=data.get("response_data", {}),
            credentials=data.get("credentials", {}),
            recommendations=data.get("recommendations", []),
            next_suggested_agent=data.get("next_suggested_agent"),
            vulnerability_hypothesis=data.get("vulnerability_hypothesis"),
            success_probability=data.get("success_probability", 0.0),
            context=data.get("context", {}),
            error=data.get("error"),
        )
    
    def is_success(self) -> bool:
        """成功ステータスか"""
        return self.status in [HandoffStatus.SUCCESS, HandoffStatus.PARTIAL]
    
    def add_finding(self, finding: Dict[str, Any]) -> None:
        """発見を追加"""
        self.findings.append(finding)
    
    def add_recommendation(self, recommendation: str) -> None:
        """推奨事項を追加"""
        if recommendation not in self.recommendations:
            self.recommendations.append(recommendation)


@ToolRegistry.register
class HandoffTool(BaseTool):
    """エージェント間でタスクを委譲するツール"""
    name = "handoff"
    description = "Transfer control to another specialized agent"
    
    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "agent_name": {
                            "type": "string",
                            "description": "Name of the agent to hand off to"
                        },
                        "context": {
                            "type": "string",
                            "description": "Context or summary to pass to the next agent"
                        }
                    },
                    "required": ["agent_name", "context"]
                }
            }
        }
    
    def run(self, agent_name: str, context: str) -> str:
        """
        エージェントにハンドオフ
        
        Args:
            agent_name: ハンドオフ先のエージェント名
            context: 引き継ぎコンテキスト
            
        Returns:
            ハンドオフ結果メッセージ
        """
        from src.core.agent_registry import AgentRegistry
        
        # エージェントの存在確認
        target_agent = AgentRegistry.get(agent_name)
        if not target_agent:
            available = ", ".join(AgentRegistry.list_all().keys())
            return f"Error: Agent '{agent_name}' not found. Available: {available}"
        
        # ハンドオフ実行
        success = AgentRegistry.set_current(agent_name)
        if success:
            return f"✓ Handed off to {agent_name}. Context: {context}"
        else:
            return f"Error: Failed to hand off to {agent_name}"


def create_handoff_result(
    agent_name: str,
    status: str = "success",
    target_url: str = "",
    bypass_method: Optional[str] = None,
    findings: Optional[List[Dict]] = None,
    original_request: Optional[Dict] = None,
    response_data: Optional[Dict] = None,
    credentials: Optional[Dict] = None,
    recommendations: Optional[List[str]] = None,
    next_agent: Optional[str] = None,
    vulnerability_hypothesis: Optional[str] = None,
    success_probability: float = 0.0,
    context: Optional[Dict] = None,
    error: Optional[str] = None,
) -> HandoffResult:
    """
    HandoffResultを簡単に作成するファクトリ関数
    
    Args:
        agent_name: エージェント名
        status: ステータス文字列 ("success", "partial", "failed", "blocked")
        target_url: ターゲットURL
        bypass_method: 成功時のバイパス手法
        findings: 発見リスト
        original_request: 元リクエスト情報
        response_data: レスポンス情報
        credentials: 取得した認証情報
        recommendations: 推奨事項リスト
        next_agent: 次に推奨するエージェント
        vulnerability_hypothesis: 脆弱性仮説
        success_probability: 成功確率
        context: コンテキスト辞書
        error: エラーメッセージ
    
    Returns:
        HandoffResult インスタンス
    """
    try:
        status_enum = HandoffStatus(status)
    except ValueError:
        status_enum = HandoffStatus.FAILED
    
    return HandoffResult(
        agent_name=agent_name,
        status=status_enum,
        target_url=target_url,
        bypass_method=bypass_method,
        findings=findings or [],
        original_request=original_request or {},
        response_data=response_data or {},
        credentials=credentials or {},
        recommendations=recommendations or [],
        next_suggested_agent=next_agent,
        vulnerability_hypothesis=vulnerability_hypothesis,
        success_probability=success_probability,
        context=context or {},
        error=error,
    )


def create_handoff_context(
    target_url: str,
    original_request: Optional[Dict] = None,
    authentication: Optional[Dict] = None,
    rag_hints: Optional[List[str]] = None,
    instructions: str = "",
    metadata: Optional[Dict] = None,
) -> HandoffContext:
    """
    HandoffContextを簡単に作成するファクトリ関数
    
    Args:
        target_url: ターゲットURL
        original_request: 元リクエスト情報
        authentication: 認証情報
        rag_hints: RAGからのヒント
        instructions: 具体的指示
        metadata: メタデータ
    
    Returns:
        HandoffContext インスタンス
    """
    return HandoffContext(
        target_url=target_url,
        original_request=original_request or {},
        authentication=authentication or {},
        rag_hints=rag_hints or [],
        instructions=instructions,
        metadata=metadata or {},
    )
