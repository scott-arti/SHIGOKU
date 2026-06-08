import pytest
from src.tools import ToolRegistry
from src.tools.base import BaseTool
from src.tools.builtin.linux_cmd import LinuxCmd
from src.tools.builtin.code import Code

class TestToolRegistry:
    def test_registry_registration(self):
        """ツールがレジストリに登録されているか確認"""
        tools = ToolRegistry.get_all()
        assert len(tools) >= 2  # LinuxCmd and Code
        
        tool_names = [t.name for t in tools]
        assert "linux_cmd" in tool_names
        assert "python_code" in tool_names
    
    def test_get_tool_by_name(self):
        """名前でツールを取得できるか確認"""
        linux_cmd = ToolRegistry.get("linux_cmd")
        assert linux_cmd is not None
        assert linux_cmd.name == "linux_cmd"
    
    def test_list_tools(self):
        """ツール一覧を取得できるか確認"""
        tool_list = ToolRegistry.list_tools()
        assert len(tool_list) >= 2
        assert all(isinstance(item, tuple) and len(item) == 2 for item in tool_list)

class TestLinuxCmd:
    def test_schema_generation(self):
        """スキーマが正しく生成されるか確認"""
        tool = LinuxCmd()
        schema = tool.to_schema()
        
        assert schema["type"] == "function"
        assert schema["function"]["name"] == "linux_cmd"
        assert "parameters" in schema["function"]
        assert "command" in schema["function"]["parameters"]["properties"]
    
    def test_simple_command(self):
        """シンプルなコマンドが実行できるか確認"""
        tool = LinuxCmd()
        result = tool.run("echo 'Hello World'")
        assert "Hello World" in result
    
    def test_command_with_error(self):
        """存在しないコマンドのエラーハンドリング"""
        tool = LinuxCmd()
        result = tool.run("nonexistent_command_12345")
        assert "Error" in result or "not found" in result.lower() or "BLOCKED" in result
    
    def test_timeout(self):
        """タイムアウトが機能するか確認"""
        tool = LinuxCmd()
        # sleep is not in Allowlist, use ping instead
        result = tool.run("ping -c 10 127.0.0.1", timeout=1)
        assert "timed out" in result.lower()

class TestCode:
    def test_schema_generation(self):
        """スキーマが正しく生成されるか確認"""
        tool = Code()
        schema = tool.to_schema()
        
        assert schema["type"] == "function"
        assert schema["function"]["name"] == "python_code"
        assert "code" in schema["function"]["parameters"]["properties"]
    
    def test_simple_execution(self):
        """シンプルなコード実行"""
        tool = Code()
        result = tool.run("print('Hello from Python')")
        assert "Hello from Python" in result
    
    def test_math_operations(self):
        """数学演算が実行できるか確認"""
        tool = Code()
        result = tool.run("print(sum([1, 2, 3, 4, 5]))")
        assert "15" in result
    
    def test_restricted_builtins(self):
        """危険な組み込み関数が制限されているか確認"""
        tool = Code()
        # open() は制限されているべき
        result = tool.run("open('/etc/passwd', 'r')")
        assert "Error" in result or "NameError" in result
    
    def test_import_restriction(self):
        """importが制限されているか確認"""
        tool = Code()
        result = tool.run("import os; os.system('ls')")
        assert "Error" in result or "NameError" in result
    
    def test_error_handling(self):
        """エラーハンドリングが機能するか確認"""
        tool = Code()
        result = tool.run("1 / 0")
        assert "ZeroDivisionError" in result

@pytest.mark.skip(reason="Agent prompt structure changed, needs rewrite")
class TestAgentIntegration:
    def test_agent_auto_discovery(self):
        """Agentがツールを自動検出するか確認"""
        from src.core.agent import Agent
        
        agent = Agent(
            name="TestAgent",
            instructions="You are a test agent"
        )
        
        # ツールが自動的にロードされているか確認
        assert len(agent.tools) >= 2
        tool_names = [getattr(t, 'name', None) for t in agent.tools]
        assert "linux_cmd" in tool_names
        assert "python_code" in tool_names
    
    def test_agent_tool_descriptions_in_prompt(self):
        """システムプロンプトにツール説明が含まれるか確認"""
        from src.core.agent import Agent
        
        agent = Agent(
            name="TestAgent",
            instructions="You are a test agent"
        )
        
        # システムメッセージを確認
        system_message = agent.messages[0]["content"]
        assert "利用可能なツール" in system_message
        assert "linux_cmd" in system_message
        assert "python_code" in system_message
