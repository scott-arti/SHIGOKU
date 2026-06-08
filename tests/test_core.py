"""
Core module tests - Agent and Runner基本テスト
"""
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from src.core.agent import Agent


class MockTool:
    """テスト用モックツール"""
    name = "mock_tool"
    
    def to_schema(self):
        return {
            "type": "function",
            "function": {
                "name": "mock_tool",
                "description": "A mock tool",
                "parameters": {"type": "object", "properties": {}}
            }
        }
    
    def run(self):
        return "Tool executed"


class TestAgentInitialization:
    """Agentクラスの初期化テスト"""
    
    def test_agent_basic_initialization(self):
        """基本的なAgent初期化"""
        agent = Agent(name="TestAgent", instructions="Test instructions")
        assert agent.name == "TestAgent"
        assert agent.instructions == "Test instructions"
    
    def test_agent_with_tools(self):
        """ツール付きAgent初期化"""
        tool = MockTool()
        agent = Agent(name="TestAgent", instructions="Test", tools=[tool])
        assert len(agent.tools) == 1
        assert agent.tools[0].name == "mock_tool"
    
    def test_agent_messages_initialized(self):
        """メッセージリストが初期化されている"""
        agent = Agent(name="TestAgent", instructions="Test instructions")
        assert len(agent.messages) >= 1
        assert agent.messages[0]["role"] == "system"
    
    def test_agent_add_message(self):
        """メッセージ追加機能"""
        agent = Agent(name="TestAgent", instructions="Test")
        initial_count = len(agent.messages)
        agent.add_message("user", "Hello")
        assert len(agent.messages) == initial_count + 1
        assert agent.messages[-1]["role"] == "user"
        assert agent.messages[-1]["content"] == "Hello"


class TestRunnerBasics:
    """Runnerクラスの基本テスト"""
    
    def test_runner_initialization(self):
        """Runner初期化テスト"""
        from src.core.engine.runner import Runner
        
        agent = Agent(name="TestAgent", instructions="Test")
        runner = Runner(agent)
        
        assert runner.agent == agent
        assert runner.llm is not None
        assert runner.interrupted == False
    
    def test_runner_has_run_method(self):
        """runメソッドが存在する"""
        from src.core.engine.runner import Runner
        
        agent = Agent(name="TestAgent", instructions="Test")
        runner = Runner(agent)
        
        assert hasattr(runner, 'run')
        assert callable(runner.run)
    
    def test_runner_has_run_sync_method(self):
        """run_syncメソッドが存在する"""
        from src.core.engine.runner import Runner
        
        agent = Agent(name="TestAgent", instructions="Test")
        runner = Runner(agent)
        
        assert hasattr(runner, 'run_sync')
        assert callable(runner.run_sync)
