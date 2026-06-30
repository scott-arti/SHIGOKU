"""
Tests for RunNarrativeFormatter: S1 Run Ledger データから日本語 Markdown レポート生成の検証
"""
import pytest
from datetime import datetime, timezone, timedelta

from src.reporting.run_narrative_formatter import (
    RunNarrativeFormatter,
    _EVENT_TYPE_JA,
    _DECISION_TYPE_JA,
)


# ---------------------------------------------------------------------------
# Session fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def full_session():
    """Build a comprehensive session with S1 expanded fields."""
    return {
        "start_time": 1719240000.0,
        "timestamp": 1719240360.0,
        "session_id": "test-session-1",
        "context": {
            "target_info": {"url": "http://example.com"},
            "pending_hitl": [],
            "scenario_coverage": {
                "missing_scenarios": ["scn_01", "scn_02"],
                "covered_count": 10,
                "required_count": 12,
            },
        },
        "completed_tasks": [
            {"id": "task_1", "state": "success", "target_url": "http://example.com/login",
             "vulnerabilities_found": [{"title": "XSS on login", "severity": "high", "vuln_type": "xss"}]},
            {"id": "task_2", "state": "failed", "target_url": "http://example.com/api",
             "vulnerabilities_found": []},
        ],
        "task_queue": [
            {"id": "task_3", "name": "pending_scan", "state": "pending"},
        ],
        "run_ledger": [
            {"event_id": "ledger_evt_run1_0001", "event_type": "llm_called", "timestamp": "2026-06-24T10:00:00Z",
             "phase": "init", "actor_type": "MasterConductor", "actor_name": "conductor", "action": "plan", "result": "ok", "inference_level": "high"},
            {"event_id": "ledger_evt_run1_0002", "event_type": "swarm_dispatched", "timestamp": "2026-06-24T10:00:05Z",
             "phase": "init", "actor_type": "SwarmWorker", "actor_name": "swarm_1", "task_id": "task_1", "result": "ok"},
            {"event_id": "ledger_evt_run1_0003", "event_type": "swarm_failed", "timestamp": "2026-06-24T10:01:00Z",
             "phase": "init", "actor_type": "SwarmWorker", "actor_name": "swarm_2", "task_id": "task_2", "error": "timeout", "inference_level": "low"},
            {"event_id": "ledger_evt_run1_0004", "event_type": "llm_retry", "timestamp": "2026-06-24T10:01:05Z",
             "phase": "init", "actor_type": "MasterConductor", "actor_name": "conductor", "task_id": "task_2", "action": "retry"},
            {"event_id": "ledger_evt_run1_0005", "event_type": "finding_created", "timestamp": "2026-06-24T10:02:00Z",
             "phase": "init", "actor_type": "SwarmWorker", "actor_name": "swarm_1", "task_id": "task_1", "result": "found XSS"},
            {"event_id": "ledger_evt_run1_0006", "event_type": "decision_made", "timestamp": "2026-06-24T10:02:30Z",
             "phase": "init", "actor_type": "MasterConductor", "actor_name": "conductor", "decision_id": "dec_0001",
             "action": "skip_task_3", "inference_level": "medium"},
        ],
        "llm_usage_summary": {
            "by_model": {
                "gpt-4o": {"input_tokens": 1000, "output_tokens": 500, "input_cache_tokens": 200, "call_count": 5},
                "deepseek-v3": {"input_tokens": 3000, "output_tokens": 1500, "input_cache_tokens": 0, "call_count": 3},
            },
            "totals": {"input_tokens": 4000, "output_tokens": 2000, "input_cache_tokens": 200, "call_count": 8},
            "cache_hit_ratio": 0.25,
            "unknown_count": 0,
            "estimated_count": 0,
        },
        "decision_traces": [
            {"decision_id": "dec_0001", "decision_type": "skip_task",
             "reasoning": "\u30bf\u30b9\u30af3\u306f\u512a\u5148\u5ea6\u304c\u4f4e\u3044\u305f\u3081\u30b9\u30ad\u30c3\u30d7", "selected_option": "skip", "outcome": "skipped",
             "was_successful": True},
            {"decision_id": "dec_0002", "decision_type": "replan",
             "reasoning": "\u30ea\u30bd\u30fc\u30b9\u4e0d\u8db3\u306e\u305f\u3081\u518d\u8a08\u753b", "selected_option": "reduce_scope", "outcome": "rescheduled",
             "was_successful": False},
        ],
        "task_execution_records": [
            {"task_id": "task_1", "task_name": "scan_login", "agent_type": "swarm", "action": "xss_scan",
             "started_at": "2026-06-24T10:00:05Z", "completed_at": "2026-06-24T10:01:55Z",
             "result": "success", "duration_seconds": 110.0},
        ],
        "findings": [
            {"title": "XSS on login page", "severity": "high", "vuln_type": "xss",
             "target_url": "http://example.com/login?token=secret123"},
        ],
        "scenario_coverage": {
            "missing_scenarios": ["scn_01", "scn_02"],
            "required_count": 12, "covered_count": 10,
        },
    }


@pytest.fixture
def legacy_session():
    """Old session without run_ledger, with minimal legacy fields."""
    return {
        "start_time": 1719240000.0,
        "session_id": "legacy-session-1",
        "context": {
            "target_info": {"url": "http://example.com"},
            "scenario_coverage": {
                "missing_scenarios": ["scn_old_01"],
                "covered_count": 5,
                "required_count": 8,
            },
        },
        "completed_tasks": [
            {"id": "task_a", "state": "success", "target_url": "http://example.com/",
             "result": {"findings": [{"title": "SQLi", "severity": "critical", "vuln_type": "sqli"}]}},
            {"id": "task_b", "state": "failed", "target_url": "http://example.com/api"},
        ],
        "task_queue": [
            {"id": "task_c", "name": "pending_scan", "state": "pending"},
        ],
    }


@pytest.fixture
def empty_session():
    return {}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _format(session):
    return RunNarrativeFormatter().format(session)


# ============================================================================
# Tests: Full Session (TestRunNarrativeFormatterFullSession)
# ============================================================================

class TestRunNarrativeFormatterFullSession:

    def test_format_returns_string(self, full_session):
        """1. format returns str"""
        result = _format(full_session)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_section_1_execution_overview(self, full_session):
        """2. Section 1 実行概要 contains run info"""
        result = _format(full_session)
        assert "# 実行概要" in result
        assert "**完了タスク数**: 2" in result
        assert "**発見事項数**: 1" in result
        assert "**未完了タスク数**: 1" in result
        assert "**フェーズ数**:" in result

    def test_section_2_llm_usage(self, full_session):
        """3. Section 2 LLM使用量 has models and token counts"""
        result = _format(full_session)
        assert "## LLM使用量" in result
        assert "gpt-4o" in result
        assert "deepseek-v3" in result
        assert "1,000" in result   # gpt-4o input
        assert "3,000" in result   # deepseek-v3 input
        assert "**総呼出回数**: 8 回" in result
        assert "**キャッシュヒット率**: 25.0%" in result

    def test_section_3_timeline(self, full_session):
        """4. Section 3 実行時系列 has event translations"""
        result = _format(full_session)
        assert "## 実行時系列" in result
        # Check for expected Japanese event type labels
        assert "意思決定" in result
        assert "Swarm派遣" in result
        assert "Swarm失敗" in result
        assert "LLM呼出" in result
        assert "LLM再試行" in result
        assert "発見登録" in result

    def test_section_4_decisions(self, full_session):
        """5. Section 4 判断根拠 has decision type translations"""
        result = _format(full_session)
        assert "## 判断根拠" in result
        assert "タスクスキップ" in result
        assert "再計画" in result
        assert "### 判断 1:" in result
        assert "### 判断 2:" in result
        assert "成功" in result
        assert "失敗" in result

    def test_section_5_swarm_tools(self, full_session):
        """6. Section 5 Swarm・ツール実行 has task references"""
        result = _format(full_session)
        assert "## Swarm・ツール実行" in result
        assert "task_1" in result
        assert "110.0s" in result

    def test_section_6_failures_retries(self, full_session):
        """7. Section 6 失敗・再試行 has failed event and retry count"""
        result = _format(full_session)
        assert "## 失敗・再試行" in result
        assert "### 失敗イベント" in result
        assert "### 再試行イベント" in result
        assert "**再試行回数**: 1" in result
        assert "timeout" in result

    def test_section_7_findings(self, full_session):
        """8. Section 7 発見事項 has XSS finding"""
        result = _format(full_session)
        assert "## 発見事項" in result
        assert "XSS on login page" in result
        assert "high" in result
        assert "xss" in result
        # URL should be masked (no query string)
        assert "token=secret123" not in result

    def test_section_8_next_actions(self, full_session):
        """9. Section 8 次判断・推奨 exists"""
        result = _format(full_session)
        assert "## 次判断・推奨" in result
        # task_3 should appear in unfinished tasks
        assert "task_3" in result
        # missing scenarios should be listed
        assert "scn_01" in result
        assert "scn_02" in result

    def test_section_9_incomplete(self, full_session):
        """10. Section 9 未完了事項 has task_3 and missing scenarios"""
        result = _format(full_session)
        assert "## 未完了事項" in result
        assert "task_3" in result
        assert "scn_01" in result
        assert "scn_02" in result
        assert "保留中タスクキュー" in result
        assert "未カバーシナリオ" in result


# ============================================================================
# Tests: Legacy Session (TestRunNarrativeFormatterLegacySession)
# ============================================================================

class TestRunNarrativeFormatterLegacySession:

    def test_legacy_session_fallback(self, legacy_session):
        """11. Legacy session without run_ledger shows fallback messages"""
        result = _format(legacy_session)
        # Check fallback note in Section 1
        assert "S1 Run Ledgerデータが存在しません" in result
        # Should not crash
        assert isinstance(result, str)
        assert len(result) > 0
        # LLM usage section shows no data
        assert "LLM使用量データなし" in result
        # Basic info should still appear
        assert "**完了タスク数**: 2" in result
        assert "**未完了タスク数**: 1" in result
        # Timeline fallback
        assert "Run Ledger データが存在しないため" in result
        assert "task_a" in result
        assert "task_b" in result


# ============================================================================
# Tests: Edge Cases (TestRunNarrativeFormatterEdgeCases)
# ============================================================================

class TestRunNarrativeFormatterEdgeCases:

    def test_empty_session_not_crash(self, empty_session):
        """12. Empty dict should return Markdown with fallback messages"""
        result = _format(empty_session)
        assert isinstance(result, str)
        assert len(result) > 0
        # Should still have sections
        assert "# 実行概要" in result
        assert "## LLM使用量" in result
        assert "## 実行時系列" in result
        assert "## 判断根拠" in result
        assert "## 発見事項" in result
        assert "## 未完了事項" in result
        # No crash

    def test_url_masking(self, full_session):
        """13. URL with token is masked in findings output"""
        # The fixture already has token URL, verifying it's masked
        result = _format(full_session)
        assert "token=secret123" not in result
        assert "secret123" not in result

    def test_url_masking_explicit(self):
        """13b. Direct test of _mask_url with various URLs"""
        fmt = RunNarrativeFormatter()
        # Token in query param
        assert "token=abc" not in fmt._mask_url("http://example.com/api?token=abc")
        assert "token=abc" not in fmt._mask_url("https://example.com/api?token=abc&user=1")
        # Plain URL preserved
        assert fmt._mask_url("http://example.com/path") == "http://example.com/path"
        # Empty string
        assert fmt._mask_url("") == ""
        # Non-URL string (no scheme)
        assert fmt._mask_url("just some text") == "just some text"

    def test_inference_level_markers(self, full_session):
        """14. Events with inference_level 'low' or 'medium' are marked with (推定)"""
        result = _format(full_session)
        # Section 3 timeline should have (推定) markers
        assert "（推定）" in result
        # ledger_evt_run1_0003 has inference_level="low" (swarm_failed) -> should be marked
        # ledger_evt_run1_0006 has inference_level="medium" (decision_made) -> should be marked

    def test_inference_level_markers_explicit(self):
        """14b. Explicit test: low and medium get (推定), high does not"""
        session = {
            "run_ledger": [
                {"event_id": "evt_001", "event_type": "swarm_dispatched", "timestamp": "2026-06-24T10:00:00Z",
                 "phase": "test", "actor_type": "SwarmWorker", "actor_name": "worker1", "result": "ok",
                 "inference_level": "low"},
                {"event_id": "evt_002", "event_type": "swarm_completed", "timestamp": "2026-06-24T10:00:05Z",
                 "phase": "test", "actor_type": "SwarmWorker", "actor_name": "worker1", "result": "ok",
                 "inference_level": "medium"},
                {"event_id": "evt_003", "event_type": "swarm_merged", "timestamp": "2026-06-24T10:00:10Z",
                 "phase": "test", "actor_type": "SwarmWorker", "actor_name": "worker1", "result": "ok",
                 "inference_level": "high"},
                {"event_id": "evt_004", "event_type": "swarm_skipped", "timestamp": "2026-06-24T10:00:15Z",
                 "phase": "test", "actor_type": "SwarmWorker", "actor_name": "worker1", "result": "ok",
                 "inference_level": ""},
            ],
        }
        result = _format(session)
        # Count (推定) occurrences in timeline rows
        lines = result.split("\n")
        timeline_rows = [line for line in lines if line.startswith("|") and "evt_" in line]
        # evt_001 (low) and evt_002 (medium) should have (推定)
        # evt_003 (high) and evt_004 (empty) should not have (推定)
        assert any("evt_001" in row and "（推定）" in row for row in timeline_rows)
        assert any("evt_002" in row and "（推定）" in row for row in timeline_rows)
        assert not any("evt_003" in row and "（推定）" in row for row in timeline_rows)
        assert not any("evt_004" in row and "（推定）" in row for row in timeline_rows)


# ============================================================================
# Tests: Event Translations (TestRunNarrativeFormatterEventTranslations)
# ============================================================================

class TestRunNarrativeFormatterEventTranslations:

    @pytest.fixture
    def all_events_session(self):
        """Session with all 16 event types for translation verification."""
        events = []
        for i, (event_type, ja_label) in enumerate(sorted(_EVENT_TYPE_JA.items()), 1):
            events.append({
                "event_id": f"evt_trans_{i:04d}",
                "event_type": event_type,
                "timestamp": f"2026-06-24T10:{i:02d}:00Z",
                "phase": "test",
                "actor_type": "TestActor",
                "actor_name": "tester",
                "action": f"action_{event_type}",
                "result": "ok",
                "inference_level": "high",
            })
        return {"run_ledger": events}

    def test_all_event_types_translated(self, all_events_session):
        """15. Verify all 16 event types appear translated in the output"""
        result = _format(all_events_session)
        for event_type, ja_label in _EVENT_TYPE_JA.items():
            assert ja_label in result, f"Event type '{event_type}' -> '{ja_label}' not found in output"

    def test_decision_types_translated(self):
        """15b. Verify decision type translations appear when present in decision_traces"""
        session = {
            "decision_traces": [
                {"decision_id": f"dec_{dt}", "decision_type": dt,
                 "reasoning": "test", "selected_option": "opt", "outcome": "done",
                 "was_successful": True}
                for dt in sorted(_DECISION_TYPE_JA.keys())
            ],
        }
        result = _format(session)
        for dt, ja_label in _DECISION_TYPE_JA.items():
            assert ja_label in result, f"Decision type '{dt}' -> '{ja_label}' not found in output"


# ============================================================================
# Additional Quality Tests
# ============================================================================

class TestRunNarrativeFormatterQuality:

    def test_section_1_no_run_ledger_note(self, legacy_session):
        """Section 1 shows note when run_ledger is missing"""
        result = _format(legacy_session)
        assert "S1 Run Ledgerデータが存在しません" in result

    def test_section_1_no_run_ledger_note_absent(self, full_session):
        """Section 1 does NOT show note when run_ledger is present"""
        result = _format(full_session)
        assert "S1 Run Ledgerデータが存在しません" not in result

    def test_section_2_no_data(self, empty_session):
        """Section 2 shows no data message when llm_usage_summary missing"""
        result = _format(empty_session)
        assert "LLM使用量データなし" in result

    def test_section_4_no_data(self, empty_session):
        """Section 4 shows no data message when decision_traces missing"""
        result = _format(empty_session)
        assert "判断根拠データなし" in result

    def test_section_6_no_failures(self, empty_session):
        """Section 6 shows no failures message when no failures"""
        result = _format(empty_session)
        assert "失敗・再試行はありません" in result

    def test_section_7_no_findings(self, empty_session):
        """Section 7 shows no findings message when no findings"""
        result = _format(empty_session)
        assert "発見事項なし" in result

    def test_section_8_all_complete(self, empty_session):
        """Section 8 shows all complete message when nothing pending"""
        result = _format(empty_session)
        assert "すべてのタスクが完了しています" in result

    def test_section_9_no_incomplete(self, empty_session):
        """Section 9 shows no incomplete message when nothing pending"""
        result = _format(empty_session)
        assert "未完了事項なし" in result

    def test_report_footer(self, full_session):
        """The report should have a generated-at footer"""
        result = _format(full_session)
        assert "Report generated at" in result
        assert "SHIGOKU RunNarrativeFormatter" in result

    def test_phases_collected_from_run_ledger(self, full_session):
        """Phases are collected from run_ledger events"""
        result = _format(full_session)
        assert "init" in result

    def test_llm_usage_with_by_model_only(self):
        """Section 2 works with by_model but no totals"""
        session = {
            "llm_usage_summary": {
                "by_model": {
                    "gpt-4o": {"input_tokens": 100, "output_tokens": 50, "input_cache_tokens": 0, "call_count": 1},
                },
            },
        }
        result = _format(session)
        assert "gpt-4o" in result
        assert "100" in result

    def test_llm_usage_with_totals_only(self):
        """Section 2 works with totals but no by_model"""
        session = {
            "llm_usage_summary": {
                "totals": {"input_tokens": 500, "output_tokens": 300, "input_cache_tokens": 0, "call_count": 2},
                "cache_hit_ratio": 0.5,
            },
        }
        result = _format(session)
        assert "**総呼出回数**: 2 回" in result

    def test_llm_usage_with_unknown_estimated(self):
        """Section 2 shows unknown_count and estimated_count when present"""
        session = {
            "llm_usage_summary": {
                "totals": {"input_tokens": 1, "output_tokens": 1, "input_cache_tokens": 0, "call_count": 1},
                "unknown_count": 3,
                "estimated_count": 2,
            },
        }
        result = _format(session)
        assert "**使用量不明の呼出**: 3 回" in result
        assert "**推定値の呼出**: 2 回" in result

    def test_timeline_fallback_to_completed_tasks(self, legacy_session):
        """Section 3 falls back to completed_tasks when run_ledger missing"""
        result = _format(legacy_session)
        assert "Run Ledger データが存在しないため" in result
        assert "task_a" in result
        assert "task_b" in result

    def test_section_5_fallback_to_completed_tasks(self, legacy_session):
        """Section 5 falls back to completed_tasks when run_ledger missing"""
        result = _format(legacy_session)
        assert "Run Ledger データが存在しないため" in result
        assert "task_a" in result

    def test_section_6_from_completed_tasks_failed(self, legacy_session):
        """Section 6 picks up failed tasks from completed_tasks when no run_ledger"""
        result = _format(legacy_session)
        assert "task_b" in result

    def test_findings_from_completed_tasks_vulnerabilities(self, legacy_session):
        """Section 7 picks up vulnerabilities from completed_tasks result when findings field missing.
        Now uses result.findings (canonical extraction) instead of vulnerabilities_found."""
        result = _format(legacy_session)
        assert "SQLi" in result
        assert "critical" in result

    def test_format_with_none_session(self):
        """Calling format(None) should not crash"""
        result = _format(None)
        assert isinstance(result, str)
        assert len(result) > 0
        assert "# 実行概要" in result

    def test_format_with_string_session(self):
        """Calling format('invalid') should not crash (treated as empty)"""
        result = _format("not a dict")
        assert isinstance(result, str)
        assert len(result) > 0
        assert "# 実行概要" in result

    def test_scenario_coverage_from_context(self):
        """scenario_coverage from context.scenario_coverage is used"""
        session = {
            "context": {
                "scenario_coverage": {
                    "missing_scenarios": ["s1", "s2"],
                },
            },
        }
        result = _format(session)
        assert "s1" in result
        assert "s2" in result
        assert "未カバー" in result

    def test_pending_hitl_from_context(self):
        """pending_hitl from context.pending_hitl is used"""
        session = {
            "context": {
                "pending_hitl": [
                    {"ticket_id": "HITL-001", "task": {"id": "t1"}},
                ],
            },
        }
        result = _format(session)
        assert "HITL-001" in result
        assert "保留中のHITL要求" in result

    def test_decision_with_available_options(self):
        """Decision trace with available_options renders options list"""
        session = {
            "decision_traces": [
                {"decision_id": "dec_opt", "decision_type": "replan",
                 "reasoning": "test", "selected_option": "opt1", "outcome": "done",
                 "was_successful": True,
                 "available_options": [
                     {"label": "Option A"},
                     {"label": "Option B"},
                     "Option C (plain)",
                 ]},
            ],
        }
        result = _format(session)
        assert "Option A" in result
        assert "Option B" in result
        assert "Option C (plain)" in result
        assert "利用可能な選択肢" in result

    def test_findings_count_from_tasks_when_findings_not_list(self):
        """Section 1 findings count falls back to completed_tasks when findings is not a list
        Uses result.findings (canonical extraction)."""
        session = {
            "findings": None,  # Not a list -> triggers fallback path
            "completed_tasks": [
                {"id": "t1", "state": "success",
                 "result": {
                     "findings": [
                         {"title": "A", "severity": "high", "vuln_type": "xss"},
                         {"title": "B", "severity": "medium", "vuln_type": "sqli"},
                     ],
                 }},
            ],
        }
        result = _format(session)
        assert "**発見事項数**: 2" in result

    def test_findings_count_zero_when_empty_list_default(self):
        """Section 1 findings count is 0 when findings defaults to empty list (no key)
        and no tasks have vulnerabilities"""
        session = {
            "completed_tasks": [
                {"id": "t1", "state": "success", "vulnerabilities_found": []},
            ],
        }
        result = _format(session)
        # Default findings=[] is an empty list, no task vulns -> reports 0
        assert "**発見事項数**: 0" in result

    def test_finding_count_falls_back_when_findings_is_empty_list(self):
        """When findings is an empty list but tasks have result.findings,
        Section 1 should count from tasks, not show 0."""
        session = {
            "start_time": 1719240000.0,
            "timestamp": 1719240360.0,
            "findings": [],  # empty list - should trigger fallback to result.* paths
            "completed_tasks": [
                {
                    "id": "task_1",
                    "state": "success",
                    "result": {
                        "findings": [
                            {"title": "XSS", "severity": "high"},
                            {"title": "SQLi", "severity": "critical"},
                        ],
                    },
                },
            ],
            "task_queue": [],
            "context": {},
            "run_ledger": [],
            "llm_usage_summary": {},
        }
        result = _format(session)

        # Should NOT say "発見事項数: 0"
        assert "発見事項数: 0" not in result
        # Should report 2 findings (from result.findings)
        assert "**発見事項数**: 2" in result

    def test_findings_extracted_from_result_findings_and_data_findings(self):
        """Verify findings are extracted from result.findings and result.data.findings
        following the canonical main.py extraction order.
        Each task picks the first non-empty level (short-circuit)."""
        session = {
            "start_time": 1719240000.0,
            "timestamp": 1719240360.0,
            "findings": [],  # empty - should fall through
            "completed_tasks": [
                {
                    "id": "task_result_findings",
                    "state": "success",
                    "result": {
                        "findings": [
                            {"title": "IDOR found via result.findings", "severity": "high"},
                        ],
                    },
                },
                {
                    "id": "task_data_findings",
                    "state": "success",
                    "result": {
                        "data": {
                            "findings": [
                                {"title": "XSS found via data.findings", "severity": "medium"},
                            ],
                        },
                    },
                },
                {
                    "id": "task_data_finding_single",
                    "state": "success",
                    "result": {
                        "data": {
                            "finding": {"title": "SQLi found via data.finding (single)", "severity": "critical"},
                        },
                    },
                },
                {
                    "id": "task_result_finding_single",
                    "state": "success",
                    "result": {
                        "finding": {"title": "CSRF found via result.finding (single)", "severity": "low"},
                    },
                },
                {
                    "id": "task_vulnerability_key",
                    "state": "success",
                    "result": {
                        "vulnerability": {"title": "LFI found via vulnerability", "severity": "info"},
                    },
                },
                {
                    "id": "task_plain_vulnerabilities",
                    "state": "success",
                    "result": {
                        "findings": [{"title": "Plain vuln", "severity": "info"}],
                    },
                },
            ],
            "partial_findings": [],
            "task_queue": [],
            "context": {},
            "run_ledger": [],
            "llm_usage_summary": {},
        }
        formatter = RunNarrativeFormatter()
        result = formatter.format(session)
        assert "IDOR found via result.findings" in result
        assert "XSS found via data.findings" in result
        assert "SQLi found via data.finding" in result
        assert "CSRF found via result.finding" in result
        assert "LFI found via vulnerability" in result
        assert "Plain vuln" in result
        # Should show 6 findings
        assert "**発見事項数**: 6" in result

    def test_fallback_timeline_result_is_summarized_not_raw_dict(self):
        """Legacy session without run_ledger should summarize result, not dump raw dicts."""
        session = {
            "start_time": 1719240000.0,
            "timestamp": 1719240360.0,
            "completed_tasks": [
                {
                    "id": "task_big", "name": "scan_xss", "agent_type": "swarm", "action": "scan",
                    "state": "success",
                    "result": {
                        "findings": [{"title": "XSS in search"}, {"title": "XSS in profile"}],
                        "data": {"pages_scanned": 100},
                        "status": "completed",
                    },
                },
            ],
            "task_queue": [],
            "context": {},
        }
        formatter = RunNarrativeFormatter()
        result = formatter.format(session)
        # Should summarize: mention findings count and status, not dump the entire dict
        assert "findings=2" in result
        # Should NOT contain the raw dict representation that was the original bug
        assert "'pages_scanned': 100" not in result


def test_fallback_summarizes_result_with_success_and_data_status():
    """Legacy session with result={"success": True, "data": {...}} should
    summarize to status=..., success=True, etc. — never dump raw dict."""
    session = {
        "start_time": 1719240000.0,
        "timestamp": 1719240360.0,
        "completed_tasks": [
            {
                "id": "task_real",
                "state": "success",
                "result": {
                    "success": True,
                    "data": {
                        "status": "completed",
                        "findings": [{"title": "IDOR"}],
                    },
                },
            },
        ],
        "task_queue": [],
        "context": {},
    }
    formatter = RunNarrativeFormatter()
    result = formatter.format(session)
    # Should show summarized fields, not raw dict
    assert "success=True" in result
    assert "data_status=completed" in result
    assert "data_findings=1" in result
    # Should NOT dump the raw dict representation
    assert "{'success': True" not in result


# ---------------------------------------------------------------------------
# Phase 1 (SGK-2026-0310): formatter compatibility with execution contract metadata
# ---------------------------------------------------------------------------

class TestRunNarrativeFormatterPhase1Metadata:
    """RunNarrativeFormatter must not crash when session dicts contain Phase 1 metadata."""

    def test_metadata_in_completed_tasks_does_not_crash(self, full_session):
        """Metadata in completed_tasks entries must not cause formatter errors."""
        full_session["completed_tasks"][0]["metadata"] = {
            "target_key": "http://example.com",
            "origin_key": "recon://scenario-1",
            "schema_version": 1,
            "lifecycle_status": "admitted",
        }
        full_session["completed_tasks"][1]["metadata"] = {
            "target_key": "http://example.com/api",
            "correlation_id": "corr-abc",
        }

        formatter = RunNarrativeFormatter()
        report = formatter.format(full_session)

        assert isinstance(report, str)
        assert len(report) > 0

    def test_metadata_in_task_queue_does_not_crash(self, full_session):
        """Metadata in task_queue entries must not cause formatter errors."""
        full_session["task_queue"][0]["metadata"] = {
            "target_key": "http://example.com",
            "lifecycle_status": "admitted",
            "lifecycle_reason": "scope_verified",
        }

        formatter = RunNarrativeFormatter()
        report = formatter.format(full_session)

        assert isinstance(report, str)
        assert len(report) > 0

    def test_metadata_in_both_queue_and_completed_does_not_crash(self, full_session):
        """Metadata in both task_queue and completed_tasks must not cause errors."""
        full_session["completed_tasks"][0]["metadata"] = {"target_key": "http://example.com"}
        full_session["task_queue"][0]["metadata"] = {"origin_key": "recon://scenario-1"}

        formatter = RunNarrativeFormatter()
        report = formatter.format(full_session)

        assert isinstance(report, str)
        assert len(report) > 0

    def test_empty_metadata_in_tasks_does_not_crash(self, full_session):
        """Empty metadata dicts must not cause formatter errors."""
        full_session["completed_tasks"][0]["metadata"] = {}
        full_session["completed_tasks"][1]["metadata"] = {}
        full_session["task_queue"][0]["metadata"] = {}

        formatter = RunNarrativeFormatter()
        report = formatter.format(full_session)

        assert isinstance(report, str)
        assert len(report) > 0

    def test_minimal_session_with_only_metadata_does_not_crash(self):
        """A minimal session with only metadata in tasks must not crash."""
        session = {
            "start_time": 100.0,
            "timestamp": 200.0,
            "context": {"target_info": {"url": "http://example.com"}},
            "completed_tasks": [
                {
                    "id": "task-1",
                    "name": "Test Task",
                    "state": "success",
                    "metadata": {
                        "target_key": "http://example.com",
                        "origin_key": "recon://scenario-1",
                        "schema_version": 1,
                        "lifecycle_status": "admitted",
                        "correlation_id": "corr-abc",
                    },
                }
            ],
            "task_queue": [],
        }

        formatter = RunNarrativeFormatter()
        report = formatter.format(session)

        assert isinstance(report, str)
        assert len(report) > 0


# ============================================================================
# Step 0 (SGK-2026-0317 Phase 8 pre-flight):
#   decision_type in {task_retired, task_superseded, task_invalidated} の区別表示
# ============================================================================

_RETIRED_LIKE_TYPES = frozenset({"task_retired", "task_superseded", "task_invalidated"})
_EXPECTED_JA = {
    "task_retired": "退役",
    "task_superseded": "差替",
    "task_invalidated": "無効化",
}


class TestStep0DecisionTypeMapping:
    """Verify _DECISION_TYPE_JA has retired-like mappings (TDD: write before impl)."""

    def test_decisions_ja_has_retired_types(self):
        """T-0.1a: _DECISION_TYPE_JA contains task_retired/superseded/invalidated."""
        for dt, ja in _EXPECTED_JA.items():
            assert dt in _DECISION_TYPE_JA, (
                f"Missing _DECISION_TYPE_JA entry for {dt}"
            )

    def test_decisions_ja_has_correct_labels(self):
        """T-0.1b: _DECISION_TYPE_JA labels match expected Japanese."""
        for dt, expected_ja in _EXPECTED_JA.items():
            assert _DECISION_TYPE_JA.get(dt) == expected_ja, (
                f"Wrong label for {dt}: expected={expected_ja!r}, got={_DECISION_TYPE_JA.get(dt)!r}"
            )


class TestStep0UnimplementedRetiredSection:
    """Verify retired-like decisions are separated into '未実施（不要化）' section."""

    @pytest.fixture
    def mixed_decision_session(self):
        """Session with regular decisions + retired-like decisions."""
        regular = [
            {"decision_id": "dec_reg_01", "decision_type": "skip_task",
             "reasoning": "優先度低", "selected_option": "skip", "outcome": "skipped",
             "was_successful": True},
            {"decision_id": "dec_reg_02", "decision_type": "replan",
             "reasoning": "リソース不足", "selected_option": "reduce_scope", "outcome": "rescheduled",
             "was_successful": False},
        ]
        retired_like = [
            {"decision_id": "dec_ret_01", "decision_type": "task_retired",
             "reasoning": "価値喪失", "selected_option": "retire", "outcome": "retired",
             "was_successful": True},
            {"decision_id": "dec_sup_01", "decision_type": "task_superseded",
             "reasoning": "代替タスクあり", "selected_option": "supersede", "outcome": "superseded",
             "was_successful": True},
            {"decision_id": "dec_inv_01", "decision_type": "task_invalidated",
             "reasoning": "スナップショット古い", "selected_option": "invalidate", "outcome": "invalidated",
             "was_successful": True},
        ]
        return {"decision_traces": regular + retired_like}

    def test_unimplemented_section_header_exists(self, mixed_decision_session):
        """T-0.1c: '未実施（不要化）' section header appears in output."""
        result = _format(mixed_decision_session)
        assert "未実施（不要化）" in result, (
            "Expected '未実施（不要化）' section header not found"
        )

    def test_retired_types_not_in_regular_decision_list(self, mixed_decision_session):
        """T-0.1d: retired-like types do NOT appear as regular '判断 N:' headings."""
        result = _format(mixed_decision_session)

        # The retired-like decision IDs must NOT appear under "### 判断 N:"
        # (they should be in the "未実施（不要化）" sub-section)
        lines = result.split("\n")
        in_regular_section = False
        in_retired_subsection = False
        regular_heading_ids = set()
        retired_subsection_ids = set()

        for line in lines:
            if line.startswith("## 判断根拠"):
                in_regular_section = True
                in_retired_subsection = False
                continue
            if "### 未実施（不要化）" in line:
                in_retired_subsection = True
                continue
            if in_regular_section and not in_retired_subsection and line.startswith("### 判断 "):
                # capture decision IDs in regular section
                if "dec_ret_" in line or "dec_sup_" in line or "dec_inv_" in line:
                    regular_heading_ids.add(line.strip())
            if in_retired_subsection:
                if "dec_ret_" in line or "dec_sup_" in line or "dec_inv_" in line:
                    retired_subsection_ids.add(line.strip())

        assert len(regular_heading_ids) == 0, (
            f"Retired-like decision IDs found in regular section: {regular_heading_ids}"
        )
        # The retired-like IDs should appear in the retired subsection
        assert len(retired_subsection_ids) >= 3, (
            f"Retired-like decision IDs missing from '未実施（不要化）' section: {retired_subsection_ids}"
        )

    def test_retired_like_labels_appear(self, mixed_decision_session):
        """T-0.1e: Japanese labels '退役','差替','無効化' appear in output."""
        result = _format(mixed_decision_session)
        for expected_ja in _EXPECTED_JA.values():
            assert expected_ja in result, (
                f"Expected label '{expected_ja}' not found in output"
            )

    def test_regular_decisions_still_work(self, mixed_decision_session):
        """T-0.1f: Regular decisions like skip_task/replan still appear normally."""
        result = _format(mixed_decision_session)
        # Regular decision labels still present (existing behavior preserved)
        assert "タスクスキップ" in result
        assert "再計画" in result
        # Regular decision IDs appear as "### 判断 N:"
        assert "dec_reg_01" in result
        assert "dec_reg_02" in result

    def test_no_retired_subsection_when_none_present(self):
        """T-0.1g: No '未実施（不要化）' section when no retired-like types exist."""
        session = {
            "decision_traces": [
                {"decision_id": "dec_001", "decision_type": "skip_task",
                 "reasoning": "test", "selected_option": "skip", "outcome": "skipped",
                 "was_successful": True},
            ],
        }
        result = _format(session)
        assert "未実施（不要化）" not in result

    def test_only_retired_like_types_produces_unimplemented_section(self):
        """T-0.1h: Session with ONLY retired-like decisions still renders correctly."""
        session = {
            "decision_traces": [
                {"decision_id": "dec_ret_99", "decision_type": "task_retired",
                 "reasoning": "stale", "selected_option": "retire", "outcome": "retired",
                 "was_successful": True},
                {"decision_id": "dec_sup_99", "decision_type": "task_superseded",
                 "reasoning": "replaced", "selected_option": "supersede", "outcome": "superseded",
                 "was_successful": True},
            ],
        }
        result = _format(session)
        assert "未実施（不要化）" in result
        assert "退役" in result
        assert "差替" in result
        # No regular decision headings (all are retired-like)
        lines = result.split("\n")
        regular_headings = [l for l in lines if l.startswith("### 判断 ") and "dec_ret_" in l]
        assert len(regular_headings) == 0
