"""
AI Tool Bridge: 新外部ツール統合基盤 ↔ AIエージェント接続層

BaseExternalAdapterをBaseTool互換に変換し、AIエージェントから
呼び出し可能にする橋渡しモジュール。
"""

import logging
from typing import Dict, Any

from src.tools.base import BaseTool
from src.core.adapters.external.base_external_adapter import ToolInput, ToolStatus
from src.core.adapters.external.external_tool_executor import get_global_executor

logger = logging.getLogger(__name__)


class AIToolBridge(BaseTool):
    """外部ツールアダプターをAIエージェント向けにラップ
    
    新外部ツール統合基盤(BaseExternalAdapter)を
    従来のToolRegistryシステムと互換にする。
    
    Example:
        # 1. Adapterインスタンスを作成
        from src.core.adapters.external.nuclei_adapter import NucleiAdapter
        adapter = NucleiAdapter()
        
        # 2. Bridgeでラップ
        nuclei_tool = AIToolBridge(
            name="nuclei_scan",
            adapter=adapter,
            description="Nuclei vulnerability scanner"
        )
        
        # 3. Managerに登録
        manager.register_tool("nuclei_scan", nuclei_tool.run, "Nuclei scanner")
    """
    
    def __init__(
        self,
        name: str,
        adapter: Any,  # BaseExternalAdapter
        description: str = "",
        default_timeout: float = 60.0
    ):
        self.name = name
        self.description = description
        self._adapter = adapter
        self._executor = get_global_executor()
        self._default_timeout = default_timeout
    
    def to_schema(self) -> Dict[str, Any]:
        """OpenAI function callingフォーマットのスキーマを返す"""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target URL to scan"
                        },
                        "options": {
                            "type": "object",
                            "description": "Tool-specific options (tags, severity, etc.)",
                            "default": {}
                        },
                        "timeout_seconds": {
                            "type": "number",
                            "description": "Execution timeout in seconds",
                            "default": self._default_timeout
                        }
                    },
                    "required": ["target"]
                }
            }
        }
    
    async def run(self, **kwargs) -> Dict[str, Any]:
        """ツールを実行（AIエージェントから呼び出される）
        
        Args:
            target: スキャン対象URL
            options: ツール固有オプション
            timeout_seconds: タイムアウト（秒）
            
        Returns:
            Dict: AIが理解しやすい形式の結果
        """
        target = kwargs.get("target")
        options = kwargs.get("options", {})
        timeout = kwargs.get("timeout_seconds", self._default_timeout)
        
        if not target:
            return {
                "success": False,
                "error": "Target URL is required",
                "findings": []
            }
        
        try:
            # 外部ツール統合基盤経由で実行
            result = await self._executor.execute(
                self._adapter,
                ToolInput(
                    target=target,
                    options=options,
                    timeout_seconds=timeout
                )
            )
            
            # AIが理解しやすい形式に変換
            return self._convert_result(result)
            
        except Exception as e:
            logger.exception(f"Tool bridge execution failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "findings": []
            }
    
    def _convert_result(self, result: Any) -> Dict[str, Any]:
        """ToolResultをAI向け形式に変換"""
        status_map = {
            ToolStatus.SUCCESS: True,
            ToolStatus.FAILURE: False,
            ToolStatus.TIMEOUT: False,
            ToolStatus.ERROR: False,
        }
        
        output = {
            "success": status_map.get(result.status, False),
            "execution_time_ms": result.execution_time_ms,
            "findings": result.data if result.data else [],
            "error": result.error_message,
            "raw_output": result.raw_output
        }
        
        # AIへの追加コンテキスト
        if result.status == ToolStatus.TIMEOUT:
            output["note"] = "Scan timed out. Consider increasing timeout or using narrower scope."
        elif result.status == ToolStatus.SUCCESS and not result.data:
            output["note"] = "No vulnerabilities found."
        
        return output


# ============================================================
# プリセット Bridge インスタンス（簡単な登録用）
# ============================================================

def create_nuclei_bridge(mode: str = "bugbounty") -> AIToolBridge:
    """Nuclei Bridgeインスタンスを作成"""
    from src.core.adapters.external.nuclei_adapter import NucleiAdapter
    
    return AIToolBridge(
        name="nuclei_scan",
        adapter=NucleiAdapter(mode=mode),
        description="Execute Nuclei vulnerability scanner. Use tags='cve' for CVE scanning, tags='misconfig' for misconfiguration detection. Severity levels: critical, high, medium, low, info.",
        default_timeout=120.0
    )


def create_dalfox_bridge(mode: str = "bugbounty") -> AIToolBridge:
    """DalFox Bridgeインスタンスを作成"""
    from src.core.adapters.external.dalfox_adapter import DalFoxAdapter
    
    return AIToolBridge(
        name="dalfox_scan",
        adapter=DalFoxAdapter(mode=mode),
        description="Execute DalFox XSS scanner. Finds reflected and stored XSS vulnerabilities in web applications.",
        default_timeout=60.0
    )


def create_ffuf_bridge(mode: str = "bugbounty") -> AIToolBridge:
    """Ffuf Bridgeインスタンスを作成"""
    from src.core.adapters.external.ffuf_adapter import FfufAdapter

    return AIToolBridge(
        name="ffuf_scan",
        adapter=FfufAdapter(mode=mode),
        description="Execute Ffuf content discovery scanner. Target URL must contain FUZZ keyword.",
        default_timeout=90.0,
    )


def create_nmap_bridge(mode: str = "bugbounty") -> AIToolBridge:
    """Nmap Bridgeインスタンスを作成"""
    from src.core.adapters.external.nmap_adapter import NmapAdapter

    return AIToolBridge(
        name="nmap_scan",
        adapter=NmapAdapter(mode=mode),
        description="Execute Nmap port and service scan against host or URL target.",
        default_timeout=120.0,
    )


def create_arjun_bridge(mode: str = "bugbounty") -> AIToolBridge:
    """Arjun Bridgeインスタンスを作成"""
    from src.core.adapters.external.arjun_adapter import ArjunAdapter

    return AIToolBridge(
        name="arjun_scan",
        adapter=ArjunAdapter(mode=mode),
        description="Execute Arjun parameter discovery scanner for hidden GET/POST parameters.",
        default_timeout=90.0,
    )


def create_gau_bridge(mode: str = "bugbounty") -> AIToolBridge:
    """Gau Bridgeインスタンスを作成"""
    from src.core.adapters.external.gau_adapter import GauAdapter

    return AIToolBridge(
        name="gau_scan",
        adapter=GauAdapter(mode=mode),
        description="Execute Gau URL collection scanner from wayback/otx/commoncrawl/urlscan sources.",
        default_timeout=90.0,
    )


# ============================================================
# Manager登録ヘルパー
# ============================================================

def register_external_tools_with_manager(manager: Any, mode: str = "bugbounty") -> None:
    """新外部ツール統合基盤のツールをManagerに一括登録
    
    Args:
        manager: BaseManagerAgentインスタンス
        mode: 動作モード (bugbounty/ctf/vulntest)
    """
    bridge_factories = (
        create_nuclei_bridge,
        create_dalfox_bridge,
        create_ffuf_bridge,
        create_nmap_bridge,
        create_arjun_bridge,
        create_gau_bridge,
    )

    for factory in bridge_factories:
        bridge = factory(mode=mode)
        manager.register_tool(bridge.name, bridge.run, bridge.description)
        logger.info("Registered external tool: %s", bridge.name)
