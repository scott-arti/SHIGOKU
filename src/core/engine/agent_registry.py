"""
Agent Registry: エージェント・ツールのタグ管理

フェーズベース・フィルタリング（Phased Visibility）の実装。
コンテキストに応じてエージェントとツールを動的に絞り込み、
LLMのコンテキスト汚染を防ぎ、推論精度を向上させる。
"""

import logging
import pkgutil
import importlib
import inspect
from typing import Dict, List, Type, Callable, Any, Optional

logger = logging.getLogger(__name__)

class AgentRegistry:
    """Central registry for agents with dynamic discovery support."""
    
    _registry: Dict[str, Dict[str, Any]] = {}
    _loaded_packages: set = set()

    @classmethod
    def register(cls, names: List[str], tags: List[str] = None, factory: Callable[..., Any] = None):
        """Decorator to register an agent."""
        def decorator(agent_cls):
            for name in names:
                cls._registry[name.lower()] = {
                    "class": agent_cls,
                    "tags": tags or ["all"],
                    "factory": factory,
                }
            return agent_cls
        return decorator

    @classmethod
    def get_agent_class(cls, name: str) -> Optional[Type]:
        entry = cls._registry.get(name.lower())
        return entry["class"] if entry else None

    @classmethod
    def list_agents(cls) -> List[str]:
        return list(cls._registry.keys())
    
    @classmethod
    def get_tags(cls, name: str) -> List[str]:
        entry = cls._registry.get(name.lower())
        if entry:
            return entry["tags"]
        return []

    @classmethod
    def autoload(cls, package_paths: List[str]):
        """Recursively load agents from packages."""
        for package_name in package_paths:
            if package_name in cls._loaded_packages:
                continue
                
            try:
                # Import the package itself first
                package = importlib.import_module(package_name)
                cls._loaded_packages.add(package_name)
                
                if hasattr(package, "__path__"):
                    for _, name, ispkg in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
                        try:
                            importlib.import_module(name)
                        except Exception as e:
                            # Skip modules that fail to load (e.g. missing dependencies)
                            # to prevent crashing the whole registry
                            pass
            except ImportError:
                 # Just ignore if package doesn't exist
                 pass

# --- Backward Compatibility / Functional Interface ---

# LLMハルシネーション対策: エージェント名の正規化マッピング
AGENT_ALIASES: Dict[str, str] = {
    # 存在しないエージェント名 -> 実際のエージェント名
    "vulnerabilityscanner": "reconbot",
    "vulnerability_scanner": "reconbot",
    "scanner": "reconbot",
    "web_scanner": "reconbot",
    "webscanner": "reconbot",
    "recon": "reconbot",
    "reconnaissance": "reconbot",
    "reconnaissance_agent": "reconbot",
    "vuln_scanner": "reconbot",
    "vulnscanner": "reconbot",
    "exploit": "redteambot",
    "exploiter": "redteambot",
    "attacker": "redteambot",
    "bizlogicswarm": "bizlogic",
}

def normalize_agent_name(name: str) -> str:
    """
    エージェント名を正規化（LLMハルシネーション対策）
    
    Args:
        name: 元のエージェント名
        
    Returns:
        正規化されたエージェント名（変換不要の場合は元の名前）
    """
    normalized = name.lower().strip()
    return AGENT_ALIASES.get(normalized, normalized)

def register_agent(names: List[str], tags: List[str] = None, factory: Callable[..., Any] = None):
    return AgentRegistry.register(names, tags, factory)

def get_agent_class(name: str) -> Type | None:
    # 正規化してから検索
    normalized_name = normalize_agent_name(name)
    return AgentRegistry.get_agent_class(normalized_name)

def list_registered_agents() -> List[str]:
    return AgentRegistry.list_agents()


def _lazy_load_agents():
    """Dynamically load agents from standard locations."""
    # This solves the "Registration Silence" risk by auto-discovering
    packages = [
        "src.core.agents", 
        "src.core.agents.general",
        "src.core.agents.specialized",
        "src.core.agents.swarm",
        "src.core.agents.analysis",
    ]
    AgentRegistry.autoload(packages)

# エージェントタグ定義（後方互換性と検索用）
# 注: レジストリに登録されていない場合のフォールバックとして機能する
AGENT_TAGS: Dict[str, List[str]] = {
    # === 汎用エージェント ===
    "reconbot": ["web", "recon", "all"],
    "command": ["web", "recon", "all"],
    "reconnaissance_agent": ["web", "recon", "all"], # Alias for LLM hallucination
    "redteambot": ["web", "exploit", "all"],
    
    # ... (omit) ...
}

# ツールタグ定義
TOOL_TAGS: Dict[str, List[str]] = {
    # === Restricted Tools ===
    # Relaxed restrictions to prevent "Tool not found" errors during transition
    "linux_cmd": ["system", "debug", "web", "recon", "exploit"], 
    "python_code": ["system", "debug", "web", "recon", "exploit"],
    "bash": ["system", "debug"],
    # === Recon Tools ===
    "ffuf": ["web", "recon"],
    "meg": ["web", "recon"],
    "secret_finder": ["web", "recon"],
    "httpx": ["web", "recon"],
    "subfinder": ["web", "recon"],
    "amass": ["web", "recon"],
    "naabu": ["web", "recon"],
    "gospider": ["web", "recon"],
    "katana": ["web", "recon"],
    "gau": ["web", "recon"],
    "bbot": ["web", "recon"],
    "shuffledns": ["web", "recon"],
    "uro": ["web", "recon"],
    "gowitness": ["web", "recon"],
    "kiterunner": ["web", "recon"],
    "crawlee": ["web", "recon"],
    
    # === Exploit Tools ===
    "nuclei": ["web", "exploit"],
    "sqlmap": ["web", "exploit"],
    "tplmap": ["web", "exploit"],
    "commix": ["web", "exploit"],
    "nosql_exploit": ["web", "exploit"],
    "jwt_tool": ["web", "auth", "exploit"],
    "xxeinjector": ["web", "exploit"],
    "hydra": ["web", "auth", "exploit"],
    "race_the_web": ["web", "exploit"],
    "nikto": ["web", "exploit"],
    
    # === Cloud/Infrastructure ===
    "cloud_enum": ["web", "recon", "cloud"],
    "s3scanner": ["web", "recon", "cloud"],
    "scoutsuite": ["web", "recon", "cloud"],
    "nmap": ["web", "recon", "infra"],
    
    # === Bypass/WAF ===
    "forbidden_bypasser": ["web", "exploit"],
    "wafw00f": ["web", "recon"],
    
    # === Takeover ===
    "subjack": ["web", "recon"],
    "subzy": ["web", "recon"],
    
    # === Others ===
    "notify": ["all"],
    "git_dumper": ["web", "recon"],
}


def get_agents_by_tag(tag: str = "all") -> List[str]:
    """
    指定タグを持つエージェント名のリストを取得
    """
    # 1. Check dynamic registry
    agents = set()
    for name in AgentRegistry.list_agents():
        if tag in AgentRegistry.get_tags(name) or "all" in AgentRegistry.get_tags(name):
            agents.add(name)
            
    # 2. Check static fallback
    for agent_name, tags in AGENT_TAGS.items():
        if tag in tags:
            agents.add(agent_name)
            
    return list(agents)


def get_tools_by_tag(tag: str = "all") -> List[str]:
    """
    指定タグを持つツール名のリストを取得
    """
    return [
        tool_name 
        for tool_name, tags in TOOL_TAGS.items() 
        if tag in tags
    ]


def get_agent_tags(agent_name: str) -> List[str]:
    """
    エージェントのタグリストを取得
    """
    # Registry priority
    reg_tags = AgentRegistry.get_tags(agent_name)
    if reg_tags:
        return reg_tags
        
    return AGENT_TAGS.get(agent_name.lower(), ["all"])


def get_tool_tags(tool_name: str) -> List[str]:
    """
    ツールのタグリストを取得
    """
    return TOOL_TAGS.get(tool_name.lower(), ["all"])


def is_agent_available(agent_name: str, context_tag: str) -> bool:
    tags = get_agent_tags(agent_name)
    return context_tag in tags or "all" in tags


def is_tool_available(tool_name: str, context_tag: str) -> bool:
    tags = get_tool_tags(tool_name)
    return context_tag in tags or "all" in tags
