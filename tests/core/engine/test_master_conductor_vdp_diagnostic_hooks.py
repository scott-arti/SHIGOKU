"""
SGK-2026-0425 M1 part 2: MasterConductor diagnostic collector wiring.

- (a) diagnostics disabled (default) → the VDP hypothesis flow produces NO
  ``vdp_diagnostics_v1`` section in the saved session payload and NO
  diagnostic events (flag-off invariance).
- (b) diagnostics enabled → the flow emits S00/S01/S02/S03 events and the
  saved session payload carries ``vdp_diagnostics_v1`` that passes
  ``validate_diagnostic_section``.
- (c) required=True + a collector hook failure → ``_dispatch_vdp_follow_up``
  returns blocked ``diagnostic_telemetry_hook_failure`` and the fake
  network client is NEVER called.
"""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from src.core.domain.model.task import Task
from src.core.engine.master_conductor import MasterConductor
from src.core.engine.vdp_diagnostic_trace import validate_diagnostic_section
from src.core.engine.vdp_follow_up import build_next_action_record, classify_reason_code
from src.core.engine.vdp_follow_up_executor import build_follow_up_spec
from src.core.models.vdp_contract import HypothesisRecord


async def _async_noop(*args, **kwargs):
    pass


def _new_mc(**overrides) -> MasterConductor:
    """Minimal MC via ``__new__`` (existing test pattern)."""
    mc = object.__new__(MasterConductor)
    mc.project_manager = SimpleNamespace(
        project_dir="/tmp/shigoku-vdp-diag-hooks",
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
    mc._current_session = SimpleNamespace(session_id="test-diag")
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


def _signal_bundle() -> dict:
    return {
        "_endpoint_signals": [
            {
                "signal_id": "sig-diag-1",
                "entity_type": "endpoint",
                "url": "https://api.example.com/items",
                "method": "GET",
                "primary_label": "items",
                "candidate_labels": ["object"],
                "confidence": 0.9,
                "auth_context": None,
                "params": [{"name": "id", "location": "query"}],
                "status": "active",
            }
        ]
    }


def _patch_settings(monkeypatch, *, enabled: bool, required: bool):
    from src.core.config.settings import DiagnosticsSettings

    monkeypatch.setattr(
        "src.core.config.settings.get_settings",
        lambda: SimpleNamespace(
            diagnostics=DiagnosticsSettings(enabled=enabled, required=required)
        ),
    )


def _follow_up_task() -> Task:
    """A dispatch-ready vdp_follow_up task (read-only payload mismatch)."""
    hyp = HypothesisRecord(
        hypothesis_id="hyp-diag-1",
        observation_id="obs-diag-1",
        asset="https://api.example.com/items",
        capability="follow_up_probe",
        hypothesis_text="t",
        trust_boundary="unauthenticated",
        actors=["unauth"],
        risk_class="read_only",
    )
    na = build_next_action_record("vrd-diag-1", hyp, "payload_request_mismatch")
    plan = classify_reason_code("payload_request_mismatch")
    spec = build_follow_up_spec(
        na.next_action_id,
        hyp,
        url="https://api.example.com/items",
        method="GET",
        param_names=(),
        actor="unauth",
        plan=plan,
    )
    spec["scope_domains"] = ["api.example.com"]
    spec["scope_out_domains"] = []
    spec["scope_rate_limit"] = 1000
    return Task(
        id=spec["task_id"],
        name="vdp_follow_up:payload_request_mismatch",
        agent_type="vdp_follow_up",
        action="run",
        params={"vdp_follow_up_spec": spec},
    )


class _FakeNetwork:
    def __init__(self):
        self.calls = []

    async def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError("network must never be called in a required hook-failure run")


class TestFlagOffInvariance:
    """(a) diagnostics disabled → no collector, no section, no events."""

    async def test_disabled_flow_has_no_diagnostic_section(self, monkeypatch):
        _patch_settings(monkeypatch, enabled=False, required=False)
        captured = {}

        async def _capture_save(payload, filename=None):
            captured["payload"] = payload

        mc = _new_mc()
        mc.project_manager = SimpleNamespace(
            project_dir="/tmp/shigoku-vdp-diag-off", save_session=_capture_save
        )
        mc._vdp_mode = SimpleNamespace(mode="record_only", label_leakage_denylist=[])

        mc._generate_vdp_hypotheses({"_signal_bundle": _signal_bundle()})
        assert mc._vdp_state["vdp_active"] is True
        assert mc._ensure_vdp_diagnostics() is None
        assert getattr(mc, "_vdp_diagnostics", None) is None

        await mc.async_save_session("diag_off.json")
        assert "vdp_diagnostics_v1" not in captured["payload"]


class TestFlagOnFlow:
    """(b) diagnostics enabled → S00..S03 events + valid saved section."""

    async def test_enabled_flow_emits_s00_s03_and_saves_valid_section(self, monkeypatch):
        _patch_settings(monkeypatch, enabled=True, required=False)
        captured = {}

        async def _capture_save(payload, filename=None):
            captured["payload"] = payload

        mc = _new_mc()
        mc.project_manager = SimpleNamespace(
            project_dir="/tmp/shigoku-vdp-diag-on", save_session=_capture_save
        )
        mc._vdp_mode = SimpleNamespace(mode="record_only", label_leakage_denylist=[])

        mc._generate_vdp_hypotheses({"_signal_bundle": _signal_bundle()})
        assert mc._vdp_state["vdp_active"] is True

        collector = mc._ensure_vdp_diagnostics()
        assert collector is not None
        assert collector.is_enabled()
        section = collector.to_section()
        assert section is not None
        stages = {(ev["stage_id"], ev["outcome"]) for ev in section["events"]}
        assert ("S00", "reached") in stages
        assert ("S01", "reached") in stages
        assert ("S02", "reached") in stages
        assert ("S03", "reached") in stages
        assert all(ev["run_id"] == "test-run" for ev in section["events"])

        await mc.async_save_session("diag_on.json")
        saved = captured["payload"].get("vdp_diagnostics_v1")
        assert saved is not None
        result = validate_diagnostic_section(saved)
        assert result.passed, result.detail


class TestRequiredKillSwitch:
    """(c) required=True + hook failure → dispatch blocked, zero network."""

    async def test_required_hook_failure_blocks_dispatch_without_network(self, monkeypatch):
        _patch_settings(monkeypatch, enabled=True, required=True)
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce",
                label_leakage_denylist=[],
                kill_switch=False,
                capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        collector = mc._ensure_vdp_diagnostics()
        assert collector is not None and collector.required
        collector.mark_hook_failed("boom")

        task = _follow_up_task()
        result = await mc._dispatch_vdp_follow_up(task)
        assert result["data"]["status"] == "blocked"
        assert result["data"]["reason"] == "diagnostic_telemetry_hook_failure"
        assert net.calls == []

        # The kill-switch path itself records the S08 blocked hold event.
        section = collector.to_section()
        assert section is not None
        blocked = [
            ev
            for ev in section["events"]
            if ev["stage_id"] == "S08" and ev["outcome"] == "blocked"
        ]
        assert blocked, section["events"]
