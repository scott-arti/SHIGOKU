"""
AI統合検証テスト: AIToolBridge + ScannerSwarm統合確認

CTOレビュー指摘対応: AIが新外部ツールを使用できることの検証
"""

import pytest
import asyncio


class TestAIToolBridgeIntegration:
    """AIToolBridge統合テスト"""
    
    @pytest.mark.asyncio
    async def test_nuclei_bridge_creation(self):
        """Nuclei Bridgeインスタンス化確認"""
        from src.core.adapters.external.ai_tool_bridge import create_nuclei_bridge
        
        bridge = create_nuclei_bridge()
        
        assert bridge.name == "nuclei_scan"
        assert "Nuclei" in bridge.description
        assert bridge._adapter is not None
    
    @pytest.mark.asyncio
    async def test_dalfox_bridge_creation(self):
        """DalFox Bridgeインスタンス化確認"""
        from src.core.adapters.external.ai_tool_bridge import create_dalfox_bridge
        
        bridge = create_dalfox_bridge()
        
        assert bridge.name == "dalfox_scan"
        assert "DalFox" in bridge.description
        assert bridge._adapter is not None

    @pytest.mark.asyncio
    async def test_additional_bridge_creation(self):
        """Ffuf/Nmap/Arjun/Gau Bridgeインスタンス化確認"""
        from src.core.adapters.external.ai_tool_bridge import (
            create_ffuf_bridge,
            create_nmap_bridge,
            create_arjun_bridge,
            create_gau_bridge,
        )

        assert create_ffuf_bridge().name == "ffuf_scan"
        assert create_nmap_bridge().name == "nmap_scan"
        assert create_arjun_bridge().name == "arjun_scan"
        assert create_gau_bridge().name == "gau_scan"
    
    @pytest.mark.asyncio
    async def test_bridge_schema_format(self):
        """BridgeスキーマがOpenAI function calling形式であること"""
        from src.core.adapters.external.ai_tool_bridge import create_nuclei_bridge
        
        bridge = create_nuclei_bridge()
        schema = bridge.to_schema()
        
        # OpenAI function calling形式
        assert schema["type"] == "function"
        assert "function" in schema
        assert schema["function"]["name"] == "nuclei_scan"
        assert "parameters" in schema["function"]
        assert "properties" in schema["function"]["parameters"]
    
    @pytest.mark.asyncio
    async def test_bridge_run_requires_target(self):
        """Bridge.run()はtarget必須"""
        from src.core.adapters.external.ai_tool_bridge import create_nuclei_bridge
        
        bridge = create_nuclei_bridge()
        result = await bridge.run()  # targetなし
        
        assert result["success"] is False
        assert "Target URL is required" in result["error"]
    
    @pytest.mark.asyncio
    async def test_bridge_run_returns_expected_format(self):
        """Bridge.run()が期待形式を返却"""
        from src.core.adapters.external.ai_tool_bridge import create_nuclei_bridge
        
        bridge = create_nuclei_bridge()
        result = await bridge.run(target="https://example.com")
        
        # AI向け形式
        assert "success" in result
        assert "execution_time_ms" in result
        assert "findings" in result
        assert isinstance(result["findings"], list)


class TestScannerSwarmIntegration:
    """ScannerSwarm統合テスト"""
    
    def test_swarm_external_tools_registration(self):
        """ScannerSwarmが外部ツールを登録すること"""
        from src.core.agents.swarm.scanner.manager import ScannerSwarm
        
        swarm = ScannerSwarm()
        tools = swarm.get_external_tools()
        
        # nuclei_scanが登録されている
        assert "nuclei_scan" in tools
        assert "func" in tools["nuclei_scan"]
        assert "description" in tools["nuclei_scan"]
        assert "schema" in tools["nuclei_scan"]
    
    def test_swarm_dalfox_registration(self):
        """ScannerSwarmがdalfox_scanを登録すること"""
        from src.core.agents.swarm.scanner.manager import ScannerSwarm
        
        swarm = ScannerSwarm()
        tools = swarm.get_external_tools()
        
        assert "dalfox_scan" in tools
        assert "func" in tools["dalfox_scan"]

    def test_swarm_registers_all_external_tools(self):
        """ScannerSwarmが6種類の外部ツールを登録すること"""
        from src.core.agents.swarm.scanner.manager import ScannerSwarm

        swarm = ScannerSwarm()
        tools = swarm.get_external_tools()
        expected = {"nuclei_scan", "dalfox_scan", "ffuf_scan", "nmap_scan", "arjun_scan", "gau_scan"}
        assert expected.issubset(set(tools.keys()))
    
    def test_swarm_tool_func_is_callable(self):
        """登録されたツール関数が呼び出し可能であること"""
        from src.core.agents.swarm.scanner.manager import ScannerSwarm
        import inspect
        
        swarm = ScannerSwarm()
        tools = swarm.get_external_tools()
        
        for name, tool_info in tools.items():
            func = tool_info["func"]
            # 非同期関数であること
            assert inspect.iscoroutinefunction(func), f"{name} must be async"
    
    @pytest.mark.asyncio
    async def test_swarm_tool_execution_mock(self):
        """登録ツールの実行（モック）"""
        from src.core.agents.swarm.scanner.manager import ScannerSwarm
        
        swarm = ScannerSwarm()
        tools = swarm.get_external_tools()
        
        # nuclei_scan関数を取得
        nuclei_func = tools["nuclei_scan"]["func"]
        
        # 実行（実際の実行はスキップ、モックターゲットで）
        result = await nuclei_func(target="http://localhost:9999")
        
        # 結果形式確認
        assert "success" in result
        assert "findings" in result


class TestExternalToolExecutorIntegration:
    """ExternalToolExecutor統合テスト"""
    
    def test_global_executor_singleton(self):
        """グローバルエグゼキューターがシングルトンであること"""
        from src.core.adapters.external.external_tool_executor import get_global_executor
        
        executor1 = get_global_executor()
        executor2 = get_global_executor()
        
        assert executor1 is executor2
    
    def test_executor_config_from_env(self):
        """環境変数からExecutorConfigが設定されること"""
        import os
        from src.core.adapters.external.external_tool_executor import ExecutorConfig
        
        # 環境変数設定
        os.environ["SHIGOKU_EXTERNAL_TOOL_CONCURRENCY"] = "10"
        
        config = ExecutorConfig()
        
        assert config.max_concurrent == 10
        
        # クリーンアップ
        del os.environ["SHIGOKU_EXTERNAL_TOOL_CONCURRENCY"]
    
    def test_executor_config_invalid_env(self):
        """無効な環境変数値はデフォルト値を使用"""
        import os
        from src.core.adapters.external.external_tool_executor import ExecutorConfig
        
        # 無効な値
        os.environ["SHIGOKU_EXTERNAL_TOOL_CONCURRENCY"] = "invalid"
        
        config = ExecutorConfig()
        
        # デフォルト値（5）にフォールバック
        assert config.max_concurrent == 5
        
        # クリーンアップ
        del os.environ["SHIGOKU_EXTERNAL_TOOL_CONCURRENCY"]

    def test_executor_config_out_of_range_env(self):
        """範囲外の環境変数値はデフォルト値を使用"""
        import os
        from src.core.adapters.external.external_tool_executor import ExecutorConfig

        os.environ["SHIGOKU_EXTERNAL_TOOL_CONCURRENCY"] = "100"
        config = ExecutorConfig()
        assert config.max_concurrent == 5
        del os.environ["SHIGOKU_EXTERNAL_TOOL_CONCURRENCY"]
    
    def test_executor_semaphore_stats(self):
        """セマフォ統計情報が取得できること"""
        from src.core.adapters.external.external_tool_executor import get_global_executor
        
        executor = get_global_executor()
        stats = executor.get_semaphore_stats()
        
        assert "enabled" in stats
        assert "max_concurrent" in stats
        assert "current_active" in stats
        assert "total_executed" in stats


class TestFeatureFlags:
    """フィーチャーフラグ統合テスト"""
    
    def test_features_yaml_exists(self):
        """features.yamlにexternal_tools設定が存在すること"""
        import yaml
        from pathlib import Path
        
        config_path = Path("config/features.yaml")
        assert config_path.exists()
        
        with open(config_path) as f:
            config = yaml.safe_load(f)
        
        assert "external_tools" in config
        assert "use_new_adapter_framework" in config["external_tools"]
    
    def test_feature_flag_default_disabled(self):
        """新基盤フラグはデフォルト無効であること"""
        import yaml
        
        with open("config/features.yaml") as f:
            config = yaml.safe_load(f)
        
        framework_config = config["external_tools"]["use_new_adapter_framework"]
        assert framework_config["enabled"] is False
        assert framework_config["rollout_percentage"] == 0


# 手動検証用スクリプト
if __name__ == "__main__":
    print("=" * 60)
    print("Phase E-2 AI Integration Verification")
    print("=" * 60)
    
    # 1. Bridge作成確認
    print("\n1. Testing AIToolBridge creation...")
    from src.core.adapters.external.ai_tool_bridge import create_nuclei_bridge, create_dalfox_bridge
    
    nuclei_bridge = create_nuclei_bridge()
    dalfox_bridge = create_dalfox_bridge()
    
    print(f"   ✅ Nuclei Bridge: {nuclei_bridge.name}")
    print(f"   ✅ DalFox Bridge: {dalfox_bridge.name}")
    
    # 2. ScannerSwarm統合確認
    print("\n2. Testing ScannerSwarm integration...")
    from src.core.agents.swarm.scanner.manager import ScannerSwarm
    
    swarm = ScannerSwarm()
    tools = swarm.get_external_tools()
    
    print(f"   ✅ Registered tools: {list(tools.keys())}")
    
    # 3. スキーマ確認
    print("\n3. Testing schema format...")
    schema = nuclei_bridge.to_schema()
    print(f"   ✅ Schema type: {schema['type']}")
    print(f"   ✅ Function name: {schema['function']['name']}")
    
    # 4. Executor設定確認
    print("\n4. Testing Executor configuration...")
    from src.core.adapters.external.external_tool_executor import get_global_executor
    
    executor = get_global_executor()
    stats = executor.get_semaphore_stats()
    
    print(f"   ✅ Semaphore enabled: {stats['enabled']}")
    print(f"   ✅ Max concurrent: {stats['max_concurrent']}")
    
    print("\n" + "=" * 60)
    print("All verification checks passed!")
    print("=" * 60)
    print("\nNext steps:")
    print("- Run: pytest tests/core/adapters/external/test_ai_integration.py -v")
    print("- Run: python tests/core/adapters/test_migration_validator.py")
