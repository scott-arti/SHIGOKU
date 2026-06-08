from pathlib import Path

from src.main import _build_deferred_checklist_markdown
from src.main import _default_deferred_checklist_output_path
from src.main import _extract_deferred_scenarios_from_payload
from src.main import _normalize_deferred_status
from src.main import _resolve_deferred_scenarios
from src.main import _report_artifact_order_key
from src.main import _select_latest_deferred_backlog_file
from src.main import _summarize_deferred_statuses


def test_extract_deferred_scenarios_filters_non_dict_entries() -> None:
    payload = {
        "deferred_scenarios": [
            {"scenario_id": "scn_10_semantic_business_logic"},
            "invalid",
            {"scenario_id": "scn_12_advanced_ssrf_internal_topology"},
        ]
    }

    scenarios = _extract_deferred_scenarios_from_payload(payload)

    assert len(scenarios) == 2
    assert scenarios[0]["scenario_id"] == "scn_10_semantic_business_logic"
    assert scenarios[1]["scenario_id"] == "scn_12_advanced_ssrf_internal_topology"


def test_report_artifact_order_key_prefers_filename_sequence_over_mtime() -> None:
    old = Path("haddix_deferred_20260421_090000.json")
    new = Path("haddix_deferred_20260421_100000.json")

    assert _report_artifact_order_key(new, "haddix_deferred")[0] > _report_artifact_order_key(old, "haddix_deferred")[0]


def test_select_latest_deferred_backlog_file_uses_filename_sequence(tmp_path: Path) -> None:
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    older = reports_dir / "haddix_deferred_20260421_090000.json"
    newer = reports_dir / "haddix_deferred_20260421_100000.json"
    older.write_text('{"deferred_scenarios":[]}', encoding="utf-8")
    newer.write_text('{"deferred_scenarios":[]}', encoding="utf-8")

    # mtimeを逆転させても、ファイル名時刻を優先することを検証
    older.touch()

    selected = _select_latest_deferred_backlog_file(reports_dir)

    assert selected == newer


def test_select_latest_deferred_backlog_file_returns_none_when_absent(tmp_path: Path) -> None:
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    selected = _select_latest_deferred_backlog_file(reports_dir)
    assert selected is None


def test_default_deferred_checklist_output_path_uses_artifact_timestamp() -> None:
    deferred_file = Path("/tmp/reports/haddix_deferred_20260422_001122.json")
    output_path = _default_deferred_checklist_output_path(deferred_file)
    assert output_path.name == "haddix_deferred_checklist_20260422_001122.md"


def test_build_deferred_checklist_markdown_includes_scenario_details() -> None:
    deferred_file = Path("/tmp/reports/haddix_deferred_20260422_001122.json")
    payload = {"report_path": "/tmp/reports/haddix_report_20260422_001122.md"}
    scenarios = [
        {
            "scenario_id": "scn_10_semantic_business_logic",
            "title": "Semantic Business Logic",
            "route": "human_preferred",
            "trigger": "Initial release gate passed with SCN10 still missing.",
            "why_deferred": "Needs business-context interpretation.",
            "operator_input": "Choose approval workflow and define abuse condition.",
            "success_criteria": "Reproducible abuse path with impact evidence.",
        }
    ]

    md = _build_deferred_checklist_markdown(
        deferred_file=deferred_file,
        payload=payload,
        scenarios=scenarios,
    )

    assert "# 🗂️ Deferred Scenario Execution Checklist" in md
    assert "scn_10_semantic_business_logic - Semantic Business Logic" in md
    assert "### Execution Checklist" in md
    assert "- [ ] operator_input を具体値で埋めた" in md


def test_normalize_deferred_status_supports_aliases() -> None:
    assert _normalize_deferred_status(None) == "pending"
    assert _normalize_deferred_status("queued") == "pending"
    assert _normalize_deferred_status("running") == "in_progress"
    assert _normalize_deferred_status("resolved") == "done"
    assert _normalize_deferred_status("skipped") == "rejected"


def test_summarize_deferred_statuses_counts_with_pending_default() -> None:
    scenarios = [
        {"scenario_id": "scn_10_semantic_business_logic"},
        {"scenario_id": "scn_12_advanced_ssrf_internal_topology", "status": "running"},
        {"scenario_id": "scn_99", "status": "resolved"},
    ]
    summary = _summarize_deferred_statuses(scenarios)
    assert summary == {
        "pending": 1,
        "in_progress": 1,
        "done": 1,
        "rejected": 0,
        "total": 3,
    }


def test_resolve_deferred_scenarios_marks_done_and_reports_missing() -> None:
    scenarios = [
        {"scenario_id": "scn_10_semantic_business_logic", "status": "pending"},
        {"scenario_id": "scn_12_advanced_ssrf_internal_topology", "status": "pending"},
    ]
    resolved_count, unresolved = _resolve_deferred_scenarios(
        scenarios=scenarios,
        scenario_ids=["scn_12_advanced_ssrf_internal_topology", "scn_missing"],
        note="manual verification complete",
        resolved_by="bbb",
        resolved_at="2026-04-24T00:00:00",
    )

    assert resolved_count == 1
    assert unresolved == ["scn_missing"]
    assert scenarios[1]["status"] == "done"
    assert scenarios[1]["resolved_by"] == "bbb"
    assert scenarios[1]["resolved_at"] == "2026-04-24T00:00:00"
    assert scenarios[1]["resolution_note"] == "manual verification complete"
