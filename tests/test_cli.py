"""CLI tests - CLIコマンドと機能のテスト"""
import pytest
from unittest.mock import MagicMock, patch
from src.cli.commands import CommandRegistry
from src.cli.cli import CLI
from src.core.agent import Agent
from src.core.engine.runner import Runner


class TestCommandRegistry:
    """コマンドレジストリのテスト"""
    
    def test_command_registration(self):
        """コマンドが登録されているか確認"""
        commands = CommandRegistry.list_all()
        
        # 必須コマンドの存在確認
        required_commands = ["help", "tools", "history", "model", "agent", "compact", "load", "clear"]
        for cmd in required_commands:
            assert cmd in commands, f"Command {cmd} not registered"
    
    def test_command_retrieval(self):
        """コマンド取得機能の確認"""
        help_cmd = CommandRegistry.get("help")
        assert help_cmd is not None
        assert callable(help_cmd)
    
    def test_unknown_command(self):
        """存在しないコマンドの取得"""
        unknown = CommandRegistry.get("nonexistent_command_xyz")
        assert unknown is None


class TestRunner:
    """Runnerクラスのテスト"""
    
    def test_runner_initialization(self):
        """Runner初期化テスト"""
        agent = Agent(name="TestAgent", instructions="Test")
        runner = Runner(agent)
        
        assert runner.agent == agent
        assert runner.llm is not None
        assert runner.interrupted == False
    
    def test_runner_has_run_method(self):
        """runメソッドが存在する"""
        agent = Agent(name="TestAgent", instructions="Test")
        runner = Runner(agent)
        
        assert hasattr(runner, 'run')
        assert callable(runner.run)
    
    def test_runner_has_run_sync_method(self):
        """run_syncメソッドが存在する"""
        agent = Agent(name="TestAgent", instructions="Test")
        runner = Runner(agent)
        
        assert hasattr(runner, 'run_sync')
        assert callable(runner.run_sync)


class TestCLI:
    """CLIクラスのテスト"""
    
    def test_cli_initialization(self):
        """CLI初期化のテスト"""
        agent = Agent(name="TestAgent", instructions="Test")
        runner = Runner(agent)
        cli = CLI(runner)
        
        assert cli.runner == runner
        assert cli.console is not None
        assert cli.running == True
    
    def test_command_parsing(self):
        """コマンドパースのテスト"""
        agent = Agent(name="TestAgent", instructions="Test")
        runner = Runner(agent)
        cli = CLI(runner)
        
        # 正常なコマンド
        cmd, args = cli.parse_command("/help")
        assert cmd == "help"
        assert args == []
        
        # 引数付きコマンド
        cmd, args = cli.parse_command("/model gpt-4")
        assert cmd == "model"
        assert args == ["gpt-4"]
        
        # 通常入力（コマンドでない）
        cmd, args = cli.parse_command("Hello world")
        assert cmd is None
        assert args is None


class TestCommandFunctions:
    """コマンド関数のテスト"""
    
    def test_compact_command(self):
        """/compactコマンドのテスト"""
        agent = Agent(name="TestAgent", instructions="Test")
        runner = Runner(agent)
        cli = CLI(runner)
        
        # メッセージを追加
        for i in range(20):
            agent.add_message("user", f"Message {i}")
        
        initial_count = len(agent.messages)
        assert initial_count > 11  # システム + 20メッセージ
        
        # compactコマンド実行
        from src.cli.commands import cmd_compact
        cmd_compact(cli)
        
        # メッセージ数が減っていることを確認
        assert len(agent.messages) < initial_count
        assert len(agent.messages) <= 11  # システム + 最新10件
    
    def test_clear_command(self):
        """/clearコマンドのテスト"""
        agent = Agent(name="TestAgent", instructions="Test")
        runner = Runner(agent)
        cli = CLI(runner)
        
        # メッセージを追加
        for i in range(10):
            agent.add_message("user", f"Message {i}")
        
        assert len(agent.messages) > 1
        
        # clearコマンド実行
        from src.cli.commands import cmd_clear
        cmd_clear(cli)
        
        # システムメッセージのみ残っているはず
        assert len(agent.messages) == 1
        assert agent.messages[0]["role"] == "system"
