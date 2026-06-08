"""Phase 4: レガシー削除の回帰テスト

技術的負債解消の検証テスト。インターフェース・ロジック・副作用の3点チェック。
"""
import pytest
import sys
import os
from pathlib import Path

# テスト用にDEV_MODEを有効化（Neo4jパスワード検証をスキップ）
os.environ["SHIGOKU_DEV_MODE"] = "true"


class TestPhase4EntryPoints:
    """エントリポイント統一の検証"""
    
    def test_main_module_importable(self):
        """src.mainがインポート可能か"""
        from src import main
        assert hasattr(main, 'main')
    
    def test_dunder_main_redirects_to_main(self):
        """__main__.pyがmain.pyにリダイレクトしているか"""
        # __main__.pyの内容を確認
        main_py = Path(__file__).parent.parent.parent / "src" / "__main__.py"
        content = main_py.read_text()
        
        assert "from src.main import main" in content
        assert "if __name__" in content
        # legacyモードのコードが削除されているか
        assert "--legacy" not in content
        assert "Runner" not in content
    
    def test_sys_path_hack_removed_from_main(self):
        """main.pyからsys.pathハックが削除されているか"""
        main_py = Path(__file__).parent.parent.parent / "src" / "main.py"
        content = main_py.read_text()
        
        # sys.path.insertが使用されていないことを確認
        assert "sys.path.insert" not in content
        # ただしコメントアウトされた説明は許容
        assert "Phase 4" in content  # 削除コメントが残っているはず


class TestPhase4Deprecations:
    """非推奨化されたコードの検証"""
    
    def test_runner_is_deprecated(self):
        """Runner クラスに非推奨警告があるか"""
        runner_py = Path(__file__).parent.parent.parent / "src" / "core" / "engine" / "runner.py"
        content = runner_py.read_text()
        
        assert "DEPRECATED" in content
        assert "MasterConductor" in content or "InteractiveBridge" in content
    
    def test_cli_is_deprecated(self):
        """CLI クラスに非推奨警告があるか"""
        cli_py = Path(__file__).parent.parent.parent / "src" / "cli" / "cli.py"
        content = cli_py.read_text()
        
        assert "DEPRECATED" in content
        assert "InteractiveBridge" in content


class TestPhase3ConfigYAML:
    """設定一元化の検証"""
    
    def test_vulnerabilities_yaml_exists(self):
        """vulnerabilities.yamlが存在するか"""
        yaml_path = Path(__file__).parent.parent.parent / "config" / "vulnerabilities.yaml"
        assert yaml_path.exists()
    
    def test_tools_yaml_exists(self):
        """tools.yamlが存在するか"""
        yaml_path = Path(__file__).parent.parent.parent / "config" / "tools.yaml"
        assert yaml_path.exists()
    
    def test_config_has_yaml_loader(self):
        """config.pyにYAMLローダーがあるか"""
        from src.config import settings
        
        assert hasattr(settings, 'get_vuln_info')
        assert hasattr(settings, 'get_tool_profile')


class TestPhase2AgentRegistry:
    """Factoryリファクタリングの検証"""
    
    def test_agent_registry_exists(self):
        """agent_registry.pyが存在しインポート可能か"""
        from src.core.engine.agent_registry import get_agent_class
        
        # get_agent_classが存在することを確認
        assert callable(get_agent_class)
    
    def test_factory_uses_registry(self):
        """AgentFactoryがレジストリを使用しているか"""
        factory_py = Path(__file__).parent.parent.parent / "src" / "core" / "factory.py"
        content = factory_py.read_text()
        
        assert "get_agent_class" in content
        assert "agent_registry" in content


class TestPhase1AgentProtocol:
    """インターフェース統一の検証"""
    
    def test_agent_protocol_exists(self):
        """AgentProtocolが定義されているか"""
        from src.core.agents.protocol import AgentProtocol, create_run_result
        
        assert AgentProtocol is not None
        assert callable(create_run_result)
    
    def test_base_agent_has_run_method(self):
        """BaseAgentにrun()メソッドがあるか"""
        from src.core.agents.base import BaseAgent
        
        assert hasattr(BaseAgent, 'run')


class TestInterfacePreservation:
    """インターフェース保持の検証（3点チェック）"""
    
    def test_settings_interface_unchanged(self):
        """Settings クラスのインターフェースが保持されているか"""
        from src.config import settings
        
        # 既存の属性が存在するか
        assert hasattr(settings, 'model')
        assert hasattr(settings, 'log_level')
        assert hasattr(settings, 'guardrails_enabled')
        
        # 新規追加の属性も存在するか
        assert hasattr(settings, 'get_vuln_info')
        assert hasattr(settings, 'get_tool_profile')
    
    def test_pyproject_shigoku_command(self):
        """pyproject.tomlにshigokuコマンドが定義されているか"""
        pyproject = Path(__file__).parent.parent.parent / "pyproject.toml"
        content = pyproject.read_text()
        
        assert "[project.scripts]" in content
        assert "shigoku" in content
