"""
Tool Providers for Unified Registry (Phase E-3)

外部ツール・内部ツールの統一Provider実装
"""

import logging
from typing import Any, Dict, List, Optional, Protocol, Union
from dataclasses import dataclass

from .base_external_adapter import ToolInput, ToolResult

logger = logging.getLogger(__name__)


class ToolProvider(Protocol):
    """ツール提供インターフェース（内部・外部抽象化）"""
    
    def get_by_name(self, name: str) -> Optional[Any]:
        """名前でツールを取得"""
        ...
    
    def has(self, name: str) -> bool:
        """ツールが存在するか確認"""
        ...
    
    def list_all(self) -> List["ToolMetadata"]:
        """全ツール一覧を取得"""
        ...
    
    async def execute(self, name: str, **kwargs) -> ToolResult:
        """ツールを実行"""
        ...


@dataclass
class ToolMetadata:
    """ツールメタデータ（統一表示用）"""
    name: str
    display_name: str
    description: str
    category: str  # "external", "internal", "intel", "attack"
    provider: str  # "external", "internal"
    enabled: bool = True


class ExternalToolProvider:
    """外部ツールProvider (AIToolBridge経由)
    
    Phase E-3: 新外部ツール統合基盤をラップ
    """
    
    def __init__(self):
        self._bridges: Dict[str, Any] = {}
        self._executor: Optional[Any] = None
        self._initialized = False
        logger.info("[ExternalToolProvider] Initialized")
    
    def _ensure_initialized(self):
        """初期化を保証（遅延初期化）"""
        if self._initialized:
            return
        
        try:
            from .ai_tool_bridge import create_nuclei_bridge, create_dalfox_bridge
            from .external_tool_executor import get_global_executor
            
            # Bridgeインスタンス作成（AI統合用）
            self._bridges["nuclei_scan"] = create_nuclei_bridge()
            self._bridges["dalfox_scan"] = create_dalfox_bridge()
            
            # Phase E-3 Week 2: 他のAdapterも直接登録（Bridgeなしで実行可能に）
            self._register_direct_adapters()
            
            # Executor取得
            self._executor = get_global_executor()
            self._initialized = True
            
            logger.info(f"[ExternalToolProvider] Loaded {len(self._bridges)} tools")
            
        except Exception as e:
            logger.error(f"[ExternalToolProvider] Initialization failed: {e}")
            raise
    
    def _register_direct_adapters(self):
        """Bridgeなしで直接Adapterを登録（Phase E-3 Week 2）
        
        nuclei_scan, dalfox_scanはBridge経由で既に登録済み。
        残りのAdapterを直接登録する。
        """
        try:
            from .ffuf_adapter import FfufAdapter
            from .nmap_adapter import NmapAdapter
            from .arjun_adapter import ArjunAdapter
            from .gau_adapter import GauAdapter
            
            # AdapterをラップしてBridgeインターフェースと同じにする
            self._bridges["ffuf_scan"] = _AdapterWrapper(FfufAdapter(), "ffuf_scan")
            self._bridges["nmap_scan"] = _AdapterWrapper(NmapAdapter(), "nmap_scan")
            self._bridges["arjun_scan"] = _AdapterWrapper(ArjunAdapter(), "arjun_scan")
            self._bridges["gau_scan"] = _AdapterWrapper(GauAdapter(), "gau_scan")
            
            logger.info(f"[ExternalToolProvider] Registered direct adapters: ffuf, nmap, arjun, gau")
            
        except Exception as e:
            logger.warning(f"[ExternalToolProvider] Failed to register direct adapters: {e}")
    
    def get_by_name(self, name: str) -> Optional[ToolMetadata]:
        """名前でツールメタデータを取得"""
        self._ensure_initialized()
        
        bridge = self._bridges.get(name)
        if bridge is None:
            return None
        
        # Bridgeからメタデータ抽出
        schema = bridge.to_schema()
        func_schema = schema.get("function", {})
        
        return ToolMetadata(
            name=name,
            display_name=func_schema.get("name", name),
            description=func_schema.get("description", ""),
            category="external",
            provider="external",
            enabled=True
        )
    
    def has(self, name: str) -> bool:
        """ツールが存在するか確認"""
        self._ensure_initialized()
        return name in self._bridges
    
    def list_all(self) -> List[ToolMetadata]:
        """全外部ツール一覧を取得"""
        self._ensure_initialized()
        
        tools = []
        for name in self._bridges.keys():
            metadata = self.get_by_name(name)
            if metadata:
                tools.append(metadata)
        
        return tools
    
    async def execute(self, name: str, **kwargs) -> ToolResult:
        """外部ツールを実行
        
        Args:
            name: ツール名（nuclei_scan, dalfox_scanなど）
            **kwargs: ツール固有引数
            
        Returns:
            ToolResult: 実行結果
            
        Raises:
            ToolNotFoundError: ツールが見つからない場合
        """
        self._ensure_initialized()
        
        if name not in self._bridges:
            raise ToolNotFoundError(f"External tool '{name}' not found. Available: {list(self._bridges.keys())}")
        
        bridge = self._bridges[name]
        
        # Bridge.run()はAI向けDictを返却
        # ToolResultに変換
        result_dict = await bridge.run(**kwargs)
        
        # Dict → ToolResult変換
        from .base_external_adapter import ToolStatus
        
        status = ToolStatus.SUCCESS if result_dict.get("success") else ToolStatus.FAILURE
        
        return ToolResult(
            status=status,
            data=result_dict.get("findings", []),
            execution_time_ms=result_dict.get("execution_time_ms", 0),
            error_message=result_dict.get("error"),
            raw_output=result_dict.get("raw_output")
        )


class InternalToolProvider:
    """内部ツールProvider (CoreToolRegistry経由)
    
    Phase E-3: 既存CoreToolRegistryをラップ
    """
    
    def __init__(self):
        self._registry: Optional[Any] = None
        self._initialized = False
        logger.info("[InternalToolProvider] Initialized")
    
    def _ensure_initialized(self):
        """初期化を保証（遅延初期化）"""
        if self._initialized:
            return
        
        try:
            from src.core.tool_registry import ToolRegistry
            self._registry = ToolRegistry()
            self._initialized = True
            
            logger.info(f"[InternalToolProvider] Loaded {len(self._registry.tools)} tools")
            
        except Exception as e:
            logger.error(f"[InternalToolProvider] Initialization failed: {e}")
            raise
    
    def get_by_name(self, name: str) -> Optional[ToolMetadata]:
        """名前でツールメタデータを取得"""
        self._ensure_initialized()
        
        tool_info = self._registry.tools.get(name)
        if tool_info is None:
            return None
        
        return ToolMetadata(
            name=tool_info.name,
            display_name=tool_info.display_name,
            description=tool_info.description,
            category=tool_info.category,
            provider="internal",
            enabled=tool_info.enabled
        )
    
    def has(self, name: str) -> bool:
        """ツールが存在するか確認"""
        self._ensure_initialized()
        return name in self._registry.tools
    
    def list_all(self) -> List[ToolMetadata]:
        """全内部ツール一覧を取得"""
        self._ensure_initialized()
        
        tools = []
        for tool_info in self._registry.tools.values():
            metadata = ToolMetadata(
                name=tool_info.name,
                display_name=tool_info.display_name,
                description=tool_info.description,
                category=tool_info.category,
                provider="internal",
                enabled=tool_info.enabled
            )
            tools.append(metadata)
        
        return tools
    
    async def execute(self, name: str, **kwargs) -> ToolResult:
        """内部ツールを実行
        
        Note: 内部ツールはToolRegistry経由で実行される。
        実際の実行はToolRegistryの機能に委譲される。
        
        Args:
            name: ツール名
            **kwargs: ツール固有引数
            
        Returns:
            ToolResult: 実行結果
            
        Raises:
            ToolNotFoundError: ツールが見つからない場合
            NotImplementedError: 内部ツール実行は未実装（Phase E-3.2で対応）
        """
        self._ensure_initialized()
        
        if not self.has(name):
            raise ToolNotFoundError(f"Internal tool '{name}' not found")
        
        # Phase E-3.2: 内部ツールの実行実装
        # 現状はNotImplementedErrorを返却
        raise NotImplementedError(
            f"Internal tool execution not yet implemented in Phase E-3.1. "
            f"Tool '{name}' requires Phase E-3.2 implementation."
        )


class ToolNotFoundError(Exception):
    """ツールが見つからない場合の例外"""
    pass


class _AdapterWrapper:
    """AdapterをBridgeインターフェースにラップ（Phase E-3 Week 2）
    
    直接Adapterを使う場合も、Bridgeと同じインターフェース（to_schema, run）を提供。
    """
    
    def __init__(self, adapter, name: str):
        self._adapter = adapter
        self.name = name
        self._schema = None
    
    @property
    def description(self) -> str:
        return f"{self._adapter.tool_name} scan via Adapter"
    
    def to_schema(self) -> Dict:
        """OpenAI function calling形式のスキーマを生成"""
        if self._schema is None:
            self._schema = {
                "type": "function",
                "function": {
                    "name": self.name,
                    "description": self.description,
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "Target URL or host"
                            },
                            "options": {
                                "type": "object",
                                "description": "Tool-specific options",
                                "default": {}
                            },
                            "timeout_seconds": {
                                "type": "number",
                                "description": "Execution timeout",
                                "default": 300
                            }
                        },
                        "required": ["target"]
                    }
                }
            }
        return self._schema
    
    async def run(self, **kwargs) -> Dict:
        """Adapterを実行して結果をAI向け形式に変換"""
        from .base_external_adapter import ToolInput
        from .external_tool_executor import get_global_executor
        
        target = kwargs.get("target")
        options = kwargs.get("options", {})
        timeout = kwargs.get("timeout_seconds", 300)
        
        if not target:
            return {
                "success": False,
                "error": "Target is required",
                "findings": []
            }
        
        try:
            executor = get_global_executor()
            result = await executor.execute(
                self._adapter,
                ToolInput(target=target, options=options, timeout_seconds=timeout)
            )
            
            return {
                "success": result.status.value == "success",
                "findings": result.data or [],
                "execution_time_ms": result.execution_time_ms,
                "error": result.error_message,
                "raw_output": result.raw_output
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "findings": []
            }


# 遅延インポート対応
# 循環参照回避のため、必要なモジュールはメソッド内でインポート
