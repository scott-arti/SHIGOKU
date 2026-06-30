from __future__ import annotations

from pathlib import Path


PLAN_PATH = (
    Path(__file__).resolve().parents[3]
    / "docs"
    / "shigoku"
    / "subtasks"
    / "2026-06-02_sgk-2026-0253_program-overrides_subtask_plan.md"
)


def _read_plan_text() -> str:
    return PLAN_PATH.read_text(encoding="utf-8")


def test_program_overrides_plan_documents_cto_value_and_scope() -> None:
    text = _read_plan_text()

    assert "新しい probe 戦略自体は追加せず" in text
    assert "説明可能性を改善する" in text
    assert "事業価値" in text
    assert "監査価値" in text


def test_program_overrides_plan_documents_source_of_truth_and_contracts() -> None:
    text = _read_plan_text()

    assert "rule / workflow 解決の正本" in text
    assert "runtime guard / safety gate / audit 記録の正本" in text
    assert "`template_id` / `steps` / `source`" in text
    assert "`allow` / `deny` / `per_asset_qps_cap` / `global_probe_budget` / `source`" in text


def test_program_overrides_plan_documents_observability_and_rollback_guards() -> None:
    text = _read_plan_text()

    assert "planned_task_count_before_override" in text
    assert "planned_task_count_after_override" in text
    assert "qps_cap_target" in text
    assert "read-only に戻す切り戻し条件" in text
    assert "release gate 候補" in text
