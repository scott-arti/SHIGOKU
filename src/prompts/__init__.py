"""
PromptRenderer: プロンプトテンプレートのレンダリング

Jinja2を使用してMarkdownテンプレートをレンダリングし、
実行時コンテキストをプレースホルダに注入する。
"""

from pathlib import Path
from typing import Dict, Any, Optional

try:
    from jinja2 import Environment, FileSystemLoader, TemplateNotFound
    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False
    # Jinja2未インストール時のダミー定義（except句でのNameError回避）
    class TemplateNotFound(Exception):  # type: ignore
        pass



class PromptRenderer:
    """
    プロンプトテンプレートのレンダリング
    
    Usage:
        renderer = PromptRenderer()
        prompt = renderer.render("agents/red_team.md", {"target": "example.com"})
    """
    
    # エージェントタイプからテンプレートパスへのマッピング
    AGENT_TEMPLATE_MAP = {
        "security": "agents/security_agent.md",
        "general": "agents/general_agent.md",
        "redteam": "agents/red_team.md",
        "webpentest": "agents/web_pentesting.md",
        "bugbounty": "agents/bug_bounty.md",
        "ctf": "agents/ctf.md",
        "scope_parser": "agents/scope_parser.md",
        "scope": "agents/scope_parser.md",
        "fingerprinter": "agents/fingerprinter.md",
        "tech_detect": "agents/fingerprinter.md",
        "thought": "agents/thought_agent.md",
    }
    
    def __init__(self, prompts_dir: Optional[Path] = None):
        """
        初期化
        
        Args:
            prompts_dir: プロンプトテンプレートのディレクトリ（デフォルト: このファイルと同じディレクトリ）
        """
        self.prompts_dir = prompts_dir or Path(__file__).parent
        self._env: Optional[Environment] = None
        
    @property
    def env(self) -> "Environment":
        """Jinja2環境を遅延初期化"""
        if self._env is None:
            if not HAS_JINJA2:
                raise ImportError(
                    "Jinja2 is required for PromptRenderer. "
                    "Install it with: pip install jinja2"
                )
            self._env = Environment(
                loader=FileSystemLoader(str(self.prompts_dir)),
                trim_blocks=True,
                lstrip_blocks=True,
            )
        return self._env
    
    def render(self, template_path: str, context: Optional[Dict[str, Any]] = None) -> str:
        """
        テンプレートをレンダリング
        
        Args:
            template_path: テンプレートファイルパス（例: "agents/red_team.md"）
            context: テンプレートに渡すコンテキスト辞書
        
        Returns:
            レンダリング済みプロンプト文字列
        
        Raises:
            TemplateNotFound: テンプレートが見つからない場合
        """
        context = context or {}
        template = self.env.get_template(template_path)
        return template.render(**context)
    
    def get_agent_prompt(
        self, 
        agent_type: str = "security",
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        エージェントタイプに応じたシステムプロンプトを取得（後方互換API）
        
        Args:
            agent_type: エージェントタイプ（"security", "redteam", "ctf"等）
            context: テンプレートに渡すコンテキスト辞書
        
        Returns:
            システムプロンプト文字列
        """
        template_path = self.AGENT_TEMPLATE_MAP.get(agent_type, "agents/security_agent.md")
        
        try:
            return self.render(template_path, context)
        except (TemplateNotFound, FileNotFoundError, ImportError):
            # テンプレートが見つからない場合、またはJinja2未インストール時はフォールバック
            # NOTE: Phase 2完了後（全テンプレート移行後）に削除予定
            return self._get_legacy_prompt(agent_type)
    
    def _get_legacy_prompt(self, agent_type: str) -> str:
        """
        レガシープロンプトを取得（移行期間中のフォールバック）
        
        NOTE: Phase 2完了後に削除予定
        """
        # 名前衝突を避けるため、importlib.utilで明示的にロード
        import importlib.util
        legacy_path = self.prompts_dir.parent / "prompts.py"
        spec = importlib.util.spec_from_file_location("legacy_prompts", legacy_path)
        if spec and spec.loader:
            legacy_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(legacy_module)
            return legacy_module.get_agent_prompt(agent_type)
        return f"Error: Could not load legacy prompts for {agent_type}"


# シングルトンインスタンス
_renderer: Optional[PromptRenderer] = None


def get_renderer() -> PromptRenderer:
    """シングルトンのPromptRendererを取得"""
    global _renderer
    if _renderer is None:
        _renderer = PromptRenderer()
    return _renderer



# ==========================================
# Legacy Compatibility Layer (Backwards Compatibility)
# ==========================================

# 1. Re-export all constants from legacy_prompts to avoid AttributeError
#    (e.g. SECURITY_AGENT_PROMPT, RED_TEAM_PROMPT)
try:
    from src.legacy_prompts import *
except ImportError:
    pass

# 2. Hybrid Wrapper for get_agent_prompt
def get_agent_prompt(
    agent_type: str = "security",
    context: Optional[Dict[str, Any]] = None
) -> str:
    """
    エージェントプロンプト取得（ハイブリッドアプローチ）
    
    1. 新しいJinja2テンプレートシステム (PromptRenderer) を試行
    2. 失敗した場合、またはテンプレート未移行の場合はLegacyを使用
    
    Args:
        agent_type: エージェントタイプ
        context: テンプレート用コンテキスト
    
    Returns:
        プロンプト文字列
    """
    try:
        # Phase 2: Try new renderer first
        renderer = get_renderer()
        return renderer.get_agent_prompt(agent_type, context)
    except Exception:
        # Fallback to legacy implementation
        # (Import inside function to avoid circular imports if any)
        try:
            from src.legacy_prompts import get_agent_prompt as _legacy_func
            return _legacy_func(agent_type)
        except ImportError:
            return "Error: Could not load prompt."




