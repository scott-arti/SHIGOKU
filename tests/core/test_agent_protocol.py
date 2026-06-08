"""AgentProtocol 実装の検証テスト

Phase 1: ADR-002に基づくエージェントインターフェース統一の検証
"""
import pytest
from typing import Any


class TestAgentProtocol:
    """AgentProtocolの基本テスト"""
    
    def test_protocol_is_importable(self):
        """AgentProtocol がインポート可能"""
        from src.core.agents.protocol import AgentProtocol
        assert AgentProtocol is not None
    
    def test_create_run_result_helper(self):
        """create_run_result ヘルパーが正しい形式を返す"""
        from src.core.agents.protocol import create_run_result
        
        result = create_run_result(
            success=True,
            data={"output": "test"},
            agent="TestAgent"
        )
        
        assert result["success"] is True
        assert result["data"] == {"output": "test"}
        assert result["agent"] == "TestAgent"
        assert "error" not in result
    
    def test_create_run_result_with_error(self):
        """create_run_result がエラー情報を含められる"""
        from src.core.agents.protocol import create_run_result
        
        result = create_run_result(
            success=False,
            error="Something went wrong",
            agent="TestAgent"
        )
        
        assert result["success"] is False
        assert result["error"] == "Something went wrong"
        assert "data" not in result


class TestBaseAgentRun:
    """BaseAgent.run() のテスト"""
    
    def test_base_agent_has_run_method(self):
        """BaseAgent クラスに run() メソッドがある"""
        from src.core.agents.base import BaseAgent
        assert hasattr(BaseAgent, "run")
        
        import asyncio
        assert asyncio.iscoroutinefunction(BaseAgent.run)


class TestSwarmAgentRun:
    """Swarm系エージェントの run() テスト"""
    
    def test_base_auth_agent_has_run_method(self):
        """BaseAuthAgent クラスに run() メソッドがある"""
        from src.core.agents.swarm.auth_ninja import BaseAuthAgent
        assert hasattr(BaseAuthAgent, "run")
        
        import asyncio
        assert asyncio.iscoroutinefunction(BaseAuthAgent.run)
    
    def test_biz_logic_hunter_has_run_method(self):
        """BizLogicHunter クラスに run() メソッドがある"""
        from src.core.agents.swarm.biz_logic_hunter import BizLogicHunter
        assert hasattr(BizLogicHunter, "run")
        
        import asyncio
        assert asyncio.iscoroutinefunction(BizLogicHunter.run)
    
    def test_jwt_inspector_inherits_run(self):
        """JWTInspector が BaseAuthAgent から run() を継承している"""
        from src.core.agents.swarm.auth_ninja import JWTInspector
        assert hasattr(JWTInspector, "run")


class TestProtocolConformance:
    """AgentProtocol への準拠テスト"""
    
    def test_base_auth_agent_conforms_to_protocol(self):
        """BaseAuthAgent が AgentProtocol に準拠している"""
        from src.core.agents.protocol import AgentProtocol
        from src.core.agents.swarm.auth_ninja import JWTInspector
        
        agent = JWTInspector()
        
        # runtime_checkable なので isinstance で確認可能
        assert isinstance(agent, AgentProtocol)
    
    def test_biz_logic_hunter_conforms_to_protocol(self):
        """BizLogicHunter が AgentProtocol に準拠している"""
        from src.core.agents.protocol import AgentProtocol
        from src.core.agents.swarm.biz_logic_hunter import BizLogicHunter
        
        agent = BizLogicHunter()
        
        assert isinstance(agent, AgentProtocol)
