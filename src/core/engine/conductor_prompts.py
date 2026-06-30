"""
MasterConductorの「人格」を定義するシステムプロンプト

Phase 4: Jinja2 template rendering via PromptRenderer.
"""

from src.prompts import get_renderer


def get_ctf_planning_prompt(flag_format: str) -> str:
    """CTFモードのシステムプロンプトを取得"""
    return get_renderer().render("conductor/planning_ctf.md", {"flag_format": flag_format})


def get_bb_planning_prompt() -> str:
    """Bug Bountyモードのシステムプロンプトを取得"""
    return get_renderer().render("conductor/planning_bb.md")
