"""
ToolRegistryFacade Integration Tests (E-3.7)

統合テスト: Phase E-3 Week 2
- 全ツール検出
- 重複チェック
- 外部ツール実行
- Singleton mode-mismatch regression (SGK-2026-0335)
"""

import pytest
import asyncio


class TestSingletonModeMismatch:
    """Singleton helper mode-mismatch regression (SGK-2026-0335 Phase 2)"""

    def teardown_method(self):
        from src.core.adapters.external.tool_registry_facade import reset_tool_registry_facade
        reset_tool_registry_facade()

    def test_mode_mismatch_recreates_instance(self):
        """get_tool_registry_facade re-creates singleton on mode mismatch."""
        from src.core.adapters.external.tool_registry_facade import (
            get_tool_registry_facade,
            reset_tool_registry_facade,
        )
        reset_tool_registry_facade()

        f1 = get_tool_registry_facade(mode="bugbounty")
        assert f1._external._mode == "bugbounty"

        f2 = get_tool_registry_facade(mode="ctf")
        assert f2._external._mode == "ctf"
        assert f2 is not f1  # Recreated due to mode mismatch

    def test_same_mode_returns_same_instance(self):
        """get_tool_registry_facade returns same instance when mode matches."""
        from src.core.adapters.external.tool_registry_facade import (
            get_tool_registry_facade,
            reset_tool_registry_facade,
        )
        reset_tool_registry_facade()

        f1 = get_tool_registry_facade(mode="ctf")
        f2 = get_tool_registry_facade(mode="ctf")
        assert f2 is f1

    def test_default_mode_returns_bugbounty(self):
        """Default (no mode arg) creates bugbounty facade."""
        from src.core.adapters.external.tool_registry_facade import (
            get_tool_registry_facade,
            reset_tool_registry_facade,
        )
        reset_tool_registry_facade()

        f = get_tool_registry_facade()
        assert f._external._mode == "bugbounty"


class TestToolRegistryFacadeIntegration:
    """ToolRegistryFacade統合テスト"""
    
    def test_facade_initialization(self):
        """Facade初期化テスト"""
        from src.core.adapters.external.tool_registry_facade import ToolRegistryFacade
        
        facade = ToolRegistryFacade(mode="ctf")
        
        assert facade._external is not None
        assert facade._internal is not None
    
    def test_list_all_tools(self):
        """全ツール一覧テスト"""
        from src.core.adapters.external.tool_registry_facade import ToolRegistryFacade
        
        facade = ToolRegistryFacade(mode="ctf")
        tools = facade.list_all()
        
        # 外部ツール + 内部ツール
        assert len(tools) >= 6  # 最低6ツール（外部）
        
        # 名前の重複がないこと
        names = [t.name for t in tools]
        assert len(names) == len(set(names)), f"Duplicate names found: {names}"
    
    def test_external_tools_registered(self):
        """外部ツール登録確認"""
        from src.core.adapters.external.tool_registry_facade import ToolRegistryFacade
        
        facade = ToolRegistryFacade(mode="ctf")
        external = facade.list_by_provider("external")
        
        external_names = {t.name for t in external}
        
        # 6つの外部ツールが登録されていること
        expected = {"nuclei_scan", "dalfox_scan", "ffuf_scan", "nmap_scan", "arjun_scan", "gau_scan"}
        assert expected <= external_names, f"Missing: {expected - external_names}"
    
    def test_internal_tools_registered(self):
        """内部ツール登録確認"""
        from src.core.adapters.external.tool_registry_facade import ToolRegistryFacade
        from src.core.tool_registry import ToolRegistry
        
        facade = ToolRegistryFacade(mode="ctf")
        internal = facade.list_by_provider("internal")

        # Source-of-truth: must match ToolRegistry().tools count exactly
        registry_count = len(ToolRegistry().tools)
        assert len(internal) == registry_count, \
            f"Facade internal count {len(internal)} != ToolRegistry {registry_count}"
        
        # 主要ツールの確認
        internal_names = {t.name for t in internal}
        key_tools = {"cartographer", "fingerprinter", "js_analyzer"}
        assert key_tools <= internal_names, f"Missing: {key_tools - internal_names}"
    
    def test_provider_detection_nuclei(self):
        """nuclei_scanがexternalとして検出される"""
        from src.core.adapters.external.tool_registry_facade import ToolRegistryFacade
        
        facade = ToolRegistryFacade()
        info = facade.get_provider_info("nuclei_scan")
        
        assert info is not None
        assert info["provider"] == "external"
    
    def test_provider_detection_cartographer(self):
        """cartographerがinternalとして検出される"""
        from src.core.adapters.external.tool_registry_facade import ToolRegistryFacade
        
        facade = ToolRegistryFacade()
        info = facade.get_provider_info("cartographer")
        
        assert info is not None
        assert info["provider"] == "internal"
    
    def test_no_duplicate_names(self):
        """外部・内部間で重複がないこと"""
        from src.core.adapters.external.tool_registry_facade import ToolRegistryFacade
        
        facade = ToolRegistryFacade()
        stats = facade.get_statistics()
        
        assert stats["duplicate_count"] == 0, f"Found {stats['duplicate_count']} duplicates: {stats['duplicates']}"
    
    def test_get_by_name_external(self):
        """外部ツール取得テスト"""
        from src.core.adapters.external.tool_registry_facade import ToolRegistryFacade
        
        facade = ToolRegistryFacade()
        tool = facade.get_by_name("nuclei_scan")
        
        assert tool is not None
        assert tool.provider == "external"
        assert tool.category == "external"
    
    def test_get_by_name_internal(self):
        """内部ツール取得テスト"""
        from src.core.adapters.external.tool_registry_facade import ToolRegistryFacade
        
        facade = ToolRegistryFacade()
        tool = facade.get_by_name("cartographer")
        
        assert tool is not None
        assert tool.provider == "internal"
    
    def test_has_tool(self):
        """ツール存在確認テスト"""
        from src.core.adapters.external.tool_registry_facade import ToolRegistryFacade
        
        facade = ToolRegistryFacade()
        
        assert facade.has("nuclei_scan") is True
        assert facade.has("cartographer") is True
        assert facade.has("nonexistent_tool") is False
    
    @pytest.mark.asyncio
    async def test_execute_external_tool_nuclei(self):
        """nuclei外部ツール実行テスト"""
        from src.core.adapters.external.tool_registry_facade import ToolRegistryFacade
        
        facade = ToolRegistryFacade()
        
        # JuiceShopでテスト
        result = await facade.execute("nuclei_scan", target="http://localhost:3000")
        
        # 結果が返却されること
        assert result is not None
        assert hasattr(result, "status")
    
    @pytest.mark.asyncio
    async def test_execute_nonexistent_tool_raises_error(self):
        """存在しないツールでエラーが発生すること"""
        from src.core.adapters.external.tool_registry_facade import ToolRegistryFacade, ToolNotFoundError
        
        facade = ToolRegistryFacade()
        
        with pytest.raises(ToolNotFoundError):
            await facade.execute("nonexistent_tool", target="http://example.com")
    
    def test_list_by_category(self):
        """カテゴリ別一覧テスト"""
        from src.core.adapters.external.tool_registry_facade import ToolRegistryFacade
        
        facade = ToolRegistryFacade()
        
        # intelカテゴリ
        intel_tools = facade.list_by_category("intel")
        assert len(intel_tools) > 0
        
        # externalカテゴリ
        external_tools = facade.list_by_category("external")
        assert len(external_tools) == 6
    
    def test_statistics(self):
        """統計情報テスト"""
        from src.core.adapters.external.tool_registry_facade import ToolRegistryFacade
        from src.core.tool_registry import ToolRegistry
        
        facade = ToolRegistryFacade()
        stats = facade.get_statistics()
        
        assert "total_tools" in stats
        assert "external_tools" in stats
        assert "internal_tools" in stats
        assert stats["external_tools"] == 6
        assert stats["internal_tools"] == len(ToolRegistry().tools)
        assert stats["total_tools"] == 6 + len(ToolRegistry().tools)


class TestExternalToolExecution:
    """外部ツール実行テスト"""
    
    @pytest.mark.asyncio
    async def test_nuclei_execution(self):
        """nuclei実行テスト"""
        from src.core.adapters.external.tool_registry_facade import ToolRegistryFacade
        
        facade = ToolRegistryFacade(mode="ctf")
        result = await facade.execute("nuclei_scan", target="http://localhost:3000")
        
        assert result.status is not None
        assert result.execution_time_ms > 0
    
    @pytest.mark.asyncio
    async def test_dalfox_execution(self):
        """dalfox実行テスト"""
        from src.core.adapters.external.tool_registry_facade import ToolRegistryFacade
        
        facade = ToolRegistryFacade(mode="ctf")
        
        # テスト対象（XSSなしの単純ページ）
        result = await facade.execute("dalfox_scan", target="http://localhost:3000")
        
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_ffuf_execution(self):
        """ffuf実行テスト"""
        from src.core.adapters.external.tool_registry_facade import ToolRegistryFacade
        
        facade = ToolRegistryFacade(mode="ctf")
        
        # FUZZキーワードを含むURL
        result = await facade.execute("ffuf_scan", target="http://localhost:3000/FUZZ")
        
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_nmap_execution(self):
        """nmap実行テスト"""
        from src.core.adapters.external.tool_registry_facade import ToolRegistryFacade
        
        facade = ToolRegistryFacade(mode="ctf")
        
        result = await facade.execute("nmap_scan", target="localhost")
        
        assert result is not None


# CLI実行用
if __name__ == "__main__":
    import sys
    
    print("=" * 60)
    print("ToolRegistryFacade Integration Test")
    print("=" * 60)
    
    from src.core.adapters.external.tool_registry_facade import ToolRegistryFacade
    
    facade = ToolRegistryFacade()
    
    # 1. 統計情報
    print("\n1. Statistics:")
    stats = facade.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    # 2. 外部ツール
    print("\n2. External Tools:")
    external = facade.list_by_provider("external")
    for tool in external:
        print(f"   - {tool.name}")
    
    # 3. 内部ツール（先頭10個）
    print("\n3. Internal Tools (first 10):")
    internal = facade.list_by_provider("internal")[:10]
    for tool in internal:
        print(f"   - {tool.name}")
    
    # 4. Provider情報
    print("\n4. Provider Info:")
    for tool_name in ["nuclei_scan", "ffuf_scan", "cartographer", "fingerprinter"]:
        info = facade.get_provider_info(tool_name)
        print(f"   {tool_name}: {info}")
    
    # 5. 重複チェック
    print("\n5. Duplicate Check:")
    if stats["duplicate_count"] == 0:
        print("   ✅ No duplicates found")
    else:
        print(f"   ⚠️  Found {stats['duplicate_count']} duplicates: {stats['duplicates']}")
    
    print("\n" + "=" * 60)
    print("Integration test completed!")
    print("=" * 60)
    print("\nRun with pytest:")
    print("  pytest tests/core/adapters/external/test_tool_registry_facade_integration.py -v")
