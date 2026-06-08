"""
PromptRenderer: Jinja2-based Prompt Template Renderer

Handles loading and rendering of prompt templates from src/prompts directory.
"""

import os
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

class PromptRenderer:
    """
    プロンプトテンプレートレンダラー
    
    src/prompts ディレクトリ内のMarkdown/Textファイルを読み込み、
    Jinja2を使用して変数を展開します。
    """
    
    _instance = None
    _env: Optional[Environment] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PromptRenderer, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize Jinja2 Environment"""
        # src/prompts ディレクトリを特定
        # src/core/utils/prompt_renderer.py -> src/core/utils -> src/core -> src -> src/prompts
        base_dir = Path(__file__).resolve().parent.parent.parent
        prompts_dir = base_dir / "prompts"
        
        if not prompts_dir.exists():
            logger.warning(f"Prompts directory not found at {prompts_dir}")
            # Fallback or create? For now just log.
            
        self._env = Environment(
            loader=FileSystemLoader(str(prompts_dir)),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )
        logger.debug(f"PromptRenderer initialized with templates from {prompts_dir}")

    def render(self, template_name: str, context: Dict[str, Any]) -> str:
        """
        テンプレートをレンダリングする
        
        Args:
            template_name (str): テンプレートファイル名 (例: "agents/injection_manager.md")
            context (dict): テンプレートに渡す変数
            
        Returns:
            str: レンダリングされたプロンプト文字列
        """
        if not self._env:
            self._initialize()
            
        try:
            template = self._env.get_template(template_name)
            return template.render(**context)
        except Exception as e:
            logger.error(f"Failed to render prompt template '{template_name}': {e}")
            # Fallback: fix context details if crucial?
            raise ValueError(f"Prompt rendering failed for {template_name}: {e}")

# Global instance
prompt_renderer = PromptRenderer()
