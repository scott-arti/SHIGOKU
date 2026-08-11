"""
Lane B (SGK-2026-0441): poc_judge role resolution tests.

- config/shigoku.yaml llm.roles.poc_judge resolves to the reasoning_api profile
  (thinking enabled + reasoning_effort high), mirroring xss_final/final_judgement.
- The role's system prompt template (src/prompts/roles/poc_judge.md) exists and
  renders without errors.
"""
from pathlib import Path

import pytest

from src.core.models.llm import LLMClient
from src.prompts import get_renderer


class TestPocJudgeRoleResolution:
    """poc_judge must resolve via the real config (config/shigoku.yaml)."""

    def test_role_resolves_to_reasoning_api_profile(self):
        client = LLMClient(role="poc_judge")
        assert client._role_name == "poc_judge"
        assert client._resolved_profile == "reasoning_api"
        assert client._resolved_provider == "deepseek"

    def test_thinking_enabled_with_high_effort(self):
        client = LLMClient(role="poc_judge")
        thinking = client.model_extra.get("thinking")
        assert thinking is not None
        assert thinking.get("type") == "enabled"
        assert thinking.get("reasoning_effort") == "high"

    def test_system_prompt_template_is_poc_judge(self):
        client = LLMClient(role="poc_judge")
        assert client._role_result.system_prompt_template == "roles/poc_judge.md"

    def test_existing_roles_unchanged(self):
        """Regression: adding poc_judge must not change existing role resolution."""
        xss_final = LLMClient(role="xss_final")
        assert xss_final._resolved_profile == "reasoning_api"
        planner = LLMClient(role="planner")
        assert planner._resolved_profile == "reasoning_api"
        specialist = LLMClient(role="specialist_light")
        assert specialist._resolved_profile == "cheap_api"


class TestPocJudgeTemplate:
    """poc_judge.md must exist, render, and enforce the fail-closed contract."""

    def test_template_exists(self):
        prompts_dir = Path(__file__).resolve().parent.parent.parent / "src" / "prompts"
        target = prompts_dir / "roles" / "poc_judge.md"
        assert target.exists(), f"Missing template: {target}"

    def test_template_renders(self):
        rendered = get_renderer().render("roles/poc_judge.md")
        assert rendered.strip(), "poc_judge.md rendered empty"

    def test_template_requires_real_evidence_and_structured_output(self):
        content = get_renderer().render("roles/poc_judge.md")
        # fail-closed: must not confirm on LLM assertion alone
        assert "payout_grade" in content
        assert '"payout_grade"' in content
        assert '"reason"' in content
        assert '"markers"' in content
        # real request/response evidence + impact proof required
        assert "レスポンス" in content
        assert "影響" in content
        assert "false" in content  # fail-closed output option
