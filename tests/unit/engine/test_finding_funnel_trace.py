"""
SGK-2026-0440 Lane A — finding-funnel trace recorder unit tests.

Covers (measurement-only, additive, default-off):
- disabled recorder / disabled config -> no events, no section, call sites
  no-op (get_finding_funnel() returns None)
- record/attach merge: fingerprint-keyed F0/F1 events merge into the finding
  entry via attach()
- first-failure rule (0425 convention): the earliest failure stage wins and
  later success never overwrites it
- idempotency: duplicate same stage+outcome records keep the first
- strict vocabulary validation (ValueError, like vdp_diagnostic_trace)
- deterministic to_section ordering + summary counts
- reset() clears everything
- integration: a MasterConductor with diagnostics disabled produces no
  finding_funnel section in the session payload
"""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from src.core.engine.finding_funnel_trace import (
    FindingFunnelRecorder,
    get_finding_funnel,
    url_fingerprint,
)
from src.core.engine.master_conductor import MasterConductor


async def _async_noop(*args, **kwargs):
    pass


def _patch_settings(monkeypatch, *, enabled: bool):
    from src.core.config.settings import DiagnosticsSettings

    monkeypatch.setattr(
        "src.core.config.settings.get_settings",
        lambda: SimpleNamespace(
            diagnostics=DiagnosticsSettings(enabled=enabled, required=False)
        ),
    )


# ---------------------------------------------------------------------------
# Disabled behavior
# ---------------------------------------------------------------------------


class TestDisabled:
    def test_disabled_recorder_is_noop(self):
        rec = FindingFunnelRecorder(enabled=False)
        rec.record("f-1", "F0", "reached")
        rec.record_task_event(url_fingerprint("https://a.example/x"), "F1", "reached")
        rec.attach("f-1", url_fingerprint("https://a.example/x"))
        assert rec.to_section() is None

    def test_config_disabled_returns_none_accessor(self, monkeypatch):
        _patch_settings(monkeypatch, enabled=False)
        assert get_finding_funnel() is None

    def test_config_none_returns_none_accessor(self, monkeypatch):
        monkeypatch.setattr(
            "src.core.config.settings.get_settings",
            lambda: SimpleNamespace(diagnostics=None),
        )
        assert get_finding_funnel() is None

    def test_accessor_exception_fail_closed(self, monkeypatch):
        def _boom():
            raise RuntimeError("settings down")

        monkeypatch.setattr("src.core.config.settings.get_settings", _boom)
        assert get_finding_funnel() is None


# ---------------------------------------------------------------------------
# record / attach merge
# ---------------------------------------------------------------------------


class TestRecordAttachMerge:
    def test_fingerprint_events_merge_into_finding_entry(self):
        rec = FindingFunnelRecorder(enabled=True)
        fp = url_fingerprint("https://a.example/scan?id=1")
        rec.record_task_event(fp, "F0", "reached")
        rec.record_task_event(fp, "F1", "reached")
        rec.attach("f-1", fp)
        rec.record("f-1", "F2", "reached", producer="InjectionManager")
        section = rec.to_section()
        assert section is not None
        assert len(section["entries"]) == 1
        entry = section["entries"][0]
        assert entry["finding_id"] == "f-1"
        assert entry["stages"] == {
            "F0": "reached", "F1": "reached", "F2": "reached",
        }
        assert entry["max_stage_reached"] == "F2"
        assert entry["first_failure_stage"] is None
        assert entry["producer"] == "InjectionManager"

    def test_attach_after_finding_record_keeps_finding_first(self):
        rec = FindingFunnelRecorder(enabled=True)
        fp = url_fingerprint("https://a.example/scan?id=1")
        rec.record_task_event(fp, "F0", "skipped", reason_code="url_skipped_dedupe")
        rec.record("f-1", "F2", "reached")
        # attach() merges the pending F0 (skipped) into the entry but must
        # never overwrite the finding's own F2 reached.
        rec.attach("f-1", fp)
        section = rec.to_section()
        entry = section["entries"][0]
        assert entry["stages"] == {"F0": "skipped", "F2": "reached"}
        assert entry["first_failure_stage"] == "F0"
        assert entry["first_failure_reason"] == "url_skipped_dedupe"

    def test_later_task_events_reach_attached_finding(self):
        rec = FindingFunnelRecorder(enabled=True)
        fp = url_fingerprint("https://a.example/scan?id=1")
        rec.record_task_event(fp, "F0", "reached")
        rec.attach("f-1", fp)
        # Retry iteration: a second F1 record after attach (first-wins no-op).
        rec.record_task_event(fp, "F1", "reached")
        rec.record_task_event(fp, "F1", "reached")
        rec.record("f-1", "F2", "reached")
        entry = rec.to_section()["entries"][0]
        assert entry["stages"] == {"F0": "reached", "F1": "reached", "F2": "reached"}


# ---------------------------------------------------------------------------
# First-failure rule (0425 convention)
# ---------------------------------------------------------------------------


class TestFirstFailureRule:
    def test_earliest_failure_wins_and_success_never_overwrites(self):
        rec = FindingFunnelRecorder(enabled=True)
        rec.record("f-1", "F0", "reached")
        rec.record("f-1", "F1", "reached")
        rec.record("f-1", "F2", "reached")
        rec.record(
            "f-1", "F3", "skipped",
            reason_code="phase2_skipped_early_return",
            block_reasons=["no_tool_error", "risk_not_met"],
        )
        section = rec.to_section()
        entry = section["entries"][0]
        assert entry["first_failure_stage"] == "F3"
        assert entry["first_failure_reason"] == "phase2_skipped_early_return"
        assert entry["block_reasons"] == ["no_tool_error", "risk_not_met"]
        assert entry["max_stage_reached"] == "F3"

        # A later success at F6 must NOT overwrite the F3 failure.
        rec.record("f-1", "F6", "reached")
        section = rec.to_section()
        entry = section["entries"][0]
        assert entry["first_failure_stage"] == "F3"
        assert entry["first_failure_reason"] == "phase2_skipped_early_return"
        assert entry["stages"]["F3"] == "skipped"
        assert entry["max_stage_reached"] == "F6"

    def test_failure_supersedes_earlier_non_failure_at_same_stage(self):
        rec = FindingFunnelRecorder(enabled=True)
        rec.record("f-1", "F4", "reached")  # auto-reverification evidence
        rec.record(
            "f-1", "F4", "skipped", reason_code="finding_validator_rejected"
        )
        entry = rec.to_section()["entries"][0]
        assert entry["stages"]["F4"] == "skipped"
        assert entry["first_failure_stage"] == "F4"
        assert entry["first_failure_reason"] == "finding_validator_rejected"


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


class TestIdempotency:
    def test_duplicate_same_stage_outcome_keeps_first(self):
        rec = FindingFunnelRecorder(enabled=True)
        rec.record("f-1", "F2", "reached")
        rec.record("f-1", "F2", "reached")
        rec.record("f-1", "F2", "reached")
        section = rec.to_section()
        assert section is not None
        assert len(section["entries"]) == 1
        assert section["entries"][0]["stages"] == {"F2": "reached"}

    def test_duplicate_task_events_single_pending(self):
        rec = FindingFunnelRecorder(enabled=True)
        fp = url_fingerprint("https://a.example/x")
        rec.record_task_event(fp, "F0", "reached")
        rec.record_task_event(fp, "F0", "reached")
        rec.attach("f-1", fp)
        entry = rec.to_section()["entries"][0]
        assert entry["stages"] == {"F0": "reached"}

    def test_suppressed_tasks_counted_once_per_record(self):
        rec = FindingFunnelRecorder(enabled=True)
        fp = url_fingerprint("https://a.example/x")
        rec.record_task_event(
            fp, "F0", "blocked", reason_code="task_suppressed_ownership"
        )
        rec.record_task_event(
            fp, "F0", "blocked", reason_code="task_suppressed_ownership"
        )
        # A candidate entry is required for the section; the suppressed task
        # itself stays task-level (visible via the summary counter).
        rec.record("c-1", "F2", "reached")
        section = rec.to_section()
        assert section["summary"]["suppressed_tasks"] == 1


# ---------------------------------------------------------------------------
# Vocabulary validation (strict, like vdp_diagnostic_trace)
# ---------------------------------------------------------------------------


class TestVocabValidation:
    def _rec(self) -> FindingFunnelRecorder:
        return FindingFunnelRecorder(enabled=True)

    def test_unknown_stage_raises(self):
        with pytest.raises(ValueError):
            self._rec().record("f-1", "F9", "reached")

    def test_unknown_outcome_raises(self):
        with pytest.raises(ValueError):
            self._rec().record("f-1", "F0", "confirmed")

    def test_unknown_reason_raises(self):
        with pytest.raises(ValueError):
            self._rec().record(
                "f-1", "F3", "skipped", reason_code="not_a_real_reason"
            )

    def test_unknown_vocab_raises_in_task_events(self):
        with pytest.raises(ValueError):
            self._rec().record_task_event("fp", "F9", "reached")
        with pytest.raises(ValueError):
            self._rec().record_task_event("fp", "F1", "reached", reason_code="bogus")


# ---------------------------------------------------------------------------
# Deterministic serialization + summary
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_entries_sorted_by_finding_id(self):
        rec = FindingFunnelRecorder(enabled=True)
        rec.record("z-find", "F2", "reached")
        rec.record("a-find", "F2", "reached")
        rec.record("m-find", "F2", "reached")
        entries = rec.to_section()["entries"]
        assert [e["finding_id"] for e in entries] == ["a-find", "m-find", "z-find"]

    def test_summary_counts(self):
        rec = FindingFunnelRecorder(enabled=True)
        # candidate A: F0..F2 reached, F3 skipped phase2_skipped_early_return
        fp_a = url_fingerprint("https://a.example/x")
        rec.record_task_event(fp_a, "F0", "reached")
        rec.attach("a", fp_a)
        rec.record("a", "F1", "reached")
        rec.record("a", "F2", "reached")
        rec.record(
            "a", "F3", "skipped",
            reason_code="phase2_skipped_early_return",
            block_reasons=["risk_not_met"],
        )
        # candidate B: F0..F4 reached (no failure)
        fp_b = url_fingerprint("https://b.example/y")
        rec.record_task_event(fp_b, "F0", "reached")
        rec.attach("b", fp_b)
        rec.record("b", "F1", "reached")
        rec.record("b", "F2", "reached")
        rec.record("b", "F3", "reached")
        rec.record("b", "F4", "reached")
        # candidate C: F0 blocked by ownership suppression
        fp_c = url_fingerprint("https://c.example/z")
        rec.record_task_event(
            fp_c, "F0", "blocked", reason_code="task_suppressed_ownership"
        )
        rec.attach("c", fp_c)

        section = rec.to_section()
        summary = section["summary"]
        assert summary["total_candidates"] == 3
        assert summary["suppressed_tasks"] == 1
        assert summary["by_stage"]["F0"] == 3
        assert summary["by_stage"]["F1"] == 2
        assert summary["by_stage"]["F2"] == 2
        assert summary["by_stage"]["F3"] == 2
        assert summary["by_stage"]["F4"] == 1
        assert summary["by_reason"] == {
            "phase2_skipped_early_return": 1,
            "task_suppressed_ownership": 1,
        }

    def test_section_is_json_stable(self):
        import json

        rec = FindingFunnelRecorder(enabled=True)
        rec.record("a", "F0", "reached")
        rec.record("a", "F3", "skipped", reason_code="budget_exhausted")
        first = json.dumps(rec.to_section(), sort_keys=True)
        second = json.dumps(rec.to_section(), sort_keys=True)
        assert first == second


# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------


class TestReset:
    def test_reset_clears_entries_and_summary(self):
        rec = FindingFunnelRecorder(enabled=True)
        rec.record("a", "F0", "reached")
        rec.record_task_event(
            url_fingerprint("https://a.example/x"),
            "F0", "blocked", reason_code="task_suppressed_ownership",
        )
        assert rec.to_section() is not None
        rec.reset()
        assert rec.to_section() is None
        # still usable after reset
        rec.record("b", "F2", "reached")
        assert rec.to_section()["summary"]["total_candidates"] == 1

    def test_reset_preserves_enabled_flag(self):
        rec = FindingFunnelRecorder(enabled=True)
        rec.reset()
        rec.record("b", "F2", "reached")
        assert rec.to_section() is not None


# ---------------------------------------------------------------------------
# MasterConductor integration: diagnostics disabled -> no funnel section
# ---------------------------------------------------------------------------


def _new_mc(**overrides) -> MasterConductor:
    """Minimal MC via ``__new__`` (existing test pattern)."""
    mc = object.__new__(MasterConductor)
    mc.project_manager = SimpleNamespace(
        project_dir="/tmp/shigoku-funnel-off",
        save_session=_async_noop,
    )
    mc.task_queue = []
    mc.completed_tasks = []
    mc.pending_hitl = []
    mc._vdp_state = {
        "vdp_active": False,
        "hypotheses": [],
        "attempts": [],
        "evidence_records": [],
        "verdicts": [],
        "next_actions": [],
        "budget_snapshot": {},
        "run_health": {},
    }
    mc._current_session = SimpleNamespace(session_id="test-funnel-off")
    mc.run_ledger_recorder = SimpleNamespace(
        prepare_for_session=lambda spool_dir=None: {},
        run_id="test-run",
    )
    mc.decision_tracer = None
    mc.execution_log = SimpleNamespace(to_list=lambda: [])
    mc.context = SimpleNamespace(
        _total_attempts=0, _successful_attempts=0,
        bypass_methods=[], discovered_assets=[],
        target_info={"start_time": time.time()},
    )
    mc._ensure_task_reason_code = lambda task: None
    mc._evaluate_vuln_family_coverage = lambda: {}
    mc._evaluate_intervention_scenario_coverage = lambda: {}
    for key, value in overrides.items():
        setattr(mc, key, value)
    return mc


class TestMasterConductorDisabled:
    async def test_disabled_run_has_no_finding_funnel_section(self, monkeypatch):
        _patch_settings(monkeypatch, enabled=False)
        captured = {}

        async def _capture_save(payload, filename=None):
            captured["payload"] = payload

        mc = _new_mc()
        mc.project_manager = SimpleNamespace(
            project_dir="/tmp/shigoku-funnel-off", save_session=_capture_save
        )

        # Disabled accessor -> call sites no-op, and the run-start reset is a
        # no-op too (never raises on a __new__-built conductor).
        assert get_finding_funnel() is None
        mc._reset_finding_funnel()
        mc._finding_funnel_task_event("https://a.example/x", "F0", "reached")

        await mc.async_save_session("funnel_off.json")
        payload = captured["payload"]
        assert "finding_funnel_v1" not in payload
        assert "finding_funnel_v1" not in payload.get("vdp_contract", {})

    async def test_enabled_run_start_reset_clears_prior_state(self, monkeypatch):
        _patch_settings(monkeypatch, enabled=True)
        funnel = get_finding_funnel()
        assert funnel is not None
        funnel.reset()
        try:
            # Simulate stale state from a previous run.
            funnel.record("stale-1", "F0", "reached")
            assert funnel.to_section() is not None

            mc = _new_mc()
            mc._reset_finding_funnel()
            assert funnel.to_section() is None
        finally:
            funnel.reset()
