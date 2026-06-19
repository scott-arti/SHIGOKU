"""
AuthNinja Base: 認証特化型エージェントの基盤クラス

BaseAuthAgent, AuthBypassResult, logger などの共通基盤を提供する。
"""

from abc import ABC, abstractmethod
from typing import Optional, Any
import logging

from src.tools.builtin.handoff import (
    HandoffContext,
    HandoffResult,
    HandoffStatus,
    create_handoff_result,
)
from src.core.agents.base import BaseAgent, AgentConfig

# 後方互換性のため AuthBypassResult を HandoffStatus にマッピング
AuthBypassResult = HandoffStatus
logger = logging.getLogger(__name__)


class BaseAuthAgent(BaseAgent):  # Inherit BaseAgent
    """認証バイパスエージェントの基底クラス"""

    def __init__(self, config: AgentConfig = None, workspace_root: Optional[str] = None):
        # Default config if missing
        if config is None:
            config = AgentConfig(
                name="AuthAgent",
                description="Base authentication bypass agent",
                model="default",
                instructions="Execute authentication bypass"
            )

        super().__init__(config, workspace_root=workspace_root)
        # Note: self.name is inherited from BaseAgent (property accessing config.name)
        self.attack_history: list[dict] = []

        # Phase 1.3: AsyncNetworkClient統合
        from src.core.infra.network_client import create_network_client

        # プロキシマネージャーはグローバルから取得（またはDI）
        from src.core.infra.proxy_manager import get_proxy_manager
        self.network_client = create_network_client(proxy_manager=get_proxy_manager())

    async def process(self, input_message: str) -> str:
        """Required by BaseAgent."""
        return "BaseAuthAgent processes structured tasks via execute()."

    @abstractmethod
    async def execute(self, context: Optional[HandoffContext] = None, **kwargs) -> HandoffResult:
        """
        認証バイパスを実行

        Args:
            context: HandoffContext入力コンテキスト (Optional)
            **kwargs: 後方互換性のための引数 (target, params)

        Returns:
            HandoffResult: 次エージェントへ渡す結果
        """
        pass

    async def execute_legacy(self, target: str, params: dict) -> HandoffResult:
        """
        後方互換性のためのレガシーインターフェース
        """
        context = HandoffContext.from_params({"target": target, **params})
        return await self.execute(context)

    async def close(self):
        """Auth系エージェントのネットワークリソースを解放"""
        try:
            client = getattr(self, "network_client", None)
            if client and hasattr(client, "close") and callable(client.close):
                await client.close()
        finally:
            self.network_client = None

    def log_attempt(self, target: str, method: str, success: bool) -> None:
        """試行を記録"""
        self.attack_history.append({
            "target": target,
            "method": method,
            "success": success,
        })

    async def run(self, task: dict) -> dict:
        """AgentProtocol準拠の統一実行メソッド (Phase 1: ADR-002)

        内部で既存の execute() を呼び出し、HandoffResult を dict に変換。

        Args:
            task: タスクパラメータ辞書
                - target: ターゲットURL
                - params: 追加パラメータ (token, test_endpoint等)

        Returns:
            実行結果辞書 (create_run_result() 形式)
        """
        from src.core.agents.protocol import create_run_result
        from src.tools.builtin.handoff import HandoffContext, HandoffStatus

        try:
            target = task.get("target", "")
            params = task.get("params", {})

            # HandoffContext を構築
            context = HandoffContext.from_params({
                "target": target,
                **params
            })

            # execute() を呼び出し (async)
            result = await self.execute(context)

            # HandoffResult を dict に変換
            if hasattr(result, "to_dict"):
                data = result.to_dict()
            else:
                data = {"result": str(result)}

            success = result.status == HandoffStatus.SUCCESS if hasattr(result, "status") else bool(result)

            return create_run_result(
                success=success,
                data=data,
                agent=self.name
            )
        except Exception as e:
            return create_run_result(
                success=False,
                error=str(e),
                agent=self.name
            )
