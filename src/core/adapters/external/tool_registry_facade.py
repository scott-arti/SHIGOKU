"""
Tool Registry Facade (Phase E-3)

統一ツールレジストリファサード
外部ツール・内部ツールを透過的に管理
"""

import logging
from typing import Any, Dict, List, Optional, Union

from .base_external_adapter import ToolResult
from .tool_providers import (
    ExternalToolProvider,
    InternalToolProvider,
    ToolMetadata,
    ToolNotFoundError
)

logger = logging.getLogger(__name__)


class ToolRegistryFacade:
    """統一ツールレジストリファサード
    
    Phase E-3: 技術的負債解消
    外部ツール・内部ツールを透過的に管理
    
    Usage:
        facade = ToolRegistryFacade()
        
        # ツール実行（外部・内部自動判別）
        result = await facade.execute("nuclei_scan", target="https://example.com")
        
        # メタデータ取得
        metadata = facade.get_by_name("nuclei_scan")
        
        # 全ツール一覧
        all_tools = facade.list_all()
    """
    
    def __init__(self):
        self._external = ExternalToolProvider()
        self._internal = InternalToolProvider()
        self._logger = logging.getLogger(__name__)
        
        self._logger.info("[ToolRegistryFacade] Initialized with external and internal providers")
    
    async def execute(self, name: str, **kwargs) -> ToolResult:
        """ツール実行（統一インターフェース）
        
        検索順序:
            1. 外部Provider (AIToolBridge経由)
            2. 内部Provider (CoreToolRegistry経由)
        
        ログ:
            DEBUG: どちらのProviderを使用したか記録
        
        Args:
            name: ツール名
            **kwargs: ツール固有引数
            
        Returns:
            ToolResult: 実行結果
            
        Raises:
            ToolNotFoundError: 両方のProviderにツールが見つからない場合
        """
        # 外部Providerを優先検索
        if self._external.has(name):
            self._logger.debug(f"[ToolRegistryFacade] Using external provider for '{name}'")
            return await self._external.execute(name, **kwargs)
        
        # 内部Providerを検索
        if self._internal.has(name):
            self._logger.debug(f"[ToolRegistryFacade] Using internal provider for '{name}'")
            return await self._internal.execute(name, **kwargs)
        
        # 見つからない場合
        available_external = [t.name for t in self._external.list_all()]
        available_internal = [t.name for t in self._internal.list_all()]
        
        error_msg = (
            f"Tool '{name}' not found in any provider.\n"
            f"Available external tools: {available_external}\n"
            f"Available internal tools: {available_internal}"
        )
        self._logger.error(f"[ToolRegistryFacade] {error_msg}")
        raise ToolNotFoundError(error_msg)
    
    def get_by_name(self, name: str) -> Optional[ToolMetadata]:
        """ツールメタデータを取得（統一検索）
        
        検索順序:
            1. 外部Provider
            2. 内部Provider
        
        Args:
            name: ツール名
            
        Returns:
            Optional[ToolMetadata]: ツールメタデータ（見つからない場合はNone）
        """
        # 外部Providerを検索
        metadata = self._external.get_by_name(name)
        if metadata:
            return metadata
        
        # 内部Providerを検索
        return self._internal.get_by_name(name)
    
    def has(self, name: str) -> bool:
        """ツールが存在するか確認（統一検索）
        
        Args:
            name: ツール名
            
        Returns:
            bool: 存在すればTrue
        """
        return self._external.has(name) or self._internal.has(name)
    
    def list_all(self) -> List[ToolMetadata]:
        """全ツール一覧を取得（統合ビュー）
        
        Returns:
            List[ToolMetadata]: 全ツールのメタデータリスト
            
        Note:
            重複するツール名が存在する場合、外部Providerを優先
        """
        external_tools = self._external.list_all()
        internal_tools = self._internal.list_all()
        
        # 重複チェック（外部を優先）
        external_names = {t.name for t in external_tools}
        filtered_internal = [t for t in internal_tools if t.name not in external_names]
        
        all_tools = external_tools + filtered_internal
        
        self._logger.debug(
            f"[ToolRegistryFacade] Listing {len(all_tools)} tools "
            f"({len(external_tools)} external, {len(filtered_internal)} internal)"
        )
        
        return all_tools
    
    def list_by_provider(self, provider: str) -> List[ToolMetadata]:
        """Provider別ツール一覧を取得
        
        Args:
            provider: "external" または "internal"
            
        Returns:
            List[ToolMetadata]: 該当Providerのツールリスト
        """
        if provider == "external":
            return self._external.list_all()
        elif provider == "internal":
            return self._internal.list_all()
        else:
            raise ValueError(f"Unknown provider: {provider}. Use 'external' or 'internal'")
    
    def list_by_category(self, category: str) -> List[ToolMetadata]:
        """カテゴリ別ツール一覧を取得
        
        Args:
            category: カテゴリ名（"intel", "attack", "external"など）
            
        Returns:
            List[ToolMetadata]: 該当カテゴリのツールリスト
        """
        all_tools = self.list_all()
        return [t for t in all_tools if t.category == category]
    
    def get_provider_info(self, name: str) -> Optional[Dict[str, str]]:
        """ツールのProvider情報を取得（デバッグ用）
        
        Args:
            name: ツール名
            
        Returns:
            Optional[Dict]: {"name": str, "provider": "external"|"internal"} または None
        """
        if self._external.has(name):
            return {"name": name, "provider": "external"}
        if self._internal.has(name):
            return {"name": name, "provider": "internal"}
        return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Registry統計情報を取得
        
        Returns:
            Dict: 統計情報
        """
        external_tools = self._external.list_all()
        internal_tools = self._internal.list_all()
        
        # 重複チェック
        external_names = {t.name for t in external_tools}
        internal_names = {t.name for t in internal_tools}
        duplicates = external_names & internal_names
        
        return {
            "total_tools": len(self.list_all()),
            "external_tools": len(external_tools),
            "internal_tools": len(internal_tools),
            "duplicates": list(duplicates),
            "duplicate_count": len(duplicates)
        }


# シングルトンアクセサ（オプション）
_facade_instance: Optional[ToolRegistryFacade] = None


def get_tool_registry_facade() -> ToolRegistryFacade:
    """ToolRegistryFacadeのシングルトンインスタンスを取得"""
    global _facade_instance
    if _facade_instance is None:
        _facade_instance = ToolRegistryFacade()
    return _facade_instance


# CLI検証用
if __name__ == "__main__":
    import asyncio
    
    async def main():
        print("=" * 60)
        print("ToolRegistryFacade Verification")
        print("=" * 60)
        
        facade = ToolRegistryFacade()
        
        # 統計情報表示
        print("\n1. Statistics:")
        stats = facade.get_statistics()
        for key, value in stats.items():
            print(f"   {key}: {value}")
        
        # 全ツール一覧
        print("\n2. All Tools:")
        tools = facade.list_all()
        for tool in tools:
            print(f"   - {tool.name} ({tool.provider}): {tool.description[:40]}...")
        
        # Provider別
        print("\n3. External Tools:")
        external = facade.list_by_provider("external")
        for tool in external:
            print(f"   - {tool.name}")
        
        print("\n4. Internal Tools (sample 5):")
        internal = facade.list_by_provider("internal")[:5]
        for tool in internal:
            print(f"   - {tool.name}")
        
        # Provider情報確認
        print("\n5. Provider Info:")
        info = facade.get_provider_info("nuclei_scan")
        print(f"   nuclei_scan: {info}")
        
        info = facade.get_provider_info("cartographer")
        print(f"   cartographer: {info}")
        
        print("\n" + "=" * 60)
        print("Verification complete!")
        print("=" * 60)
    
    asyncio.run(main())
