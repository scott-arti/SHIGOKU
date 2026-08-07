"""
SGK-2026-0423 Lane C/E — staged rollout gate unit tests (TDD).

Covers ``VdpRolloutGate`` (effective stage derivation, PRODUCTION raise
path to M3b/M3c/M4 via verified progression evidence, caps, fail-closed
state-error, pre-communication checks), ``RolloutStateStore`` (persistence
+ rollback), ``ShadowDiffRecorder``, ``KillSwitchGuard``,
``RolloutDecisionRecord``, and ``load_progression_records``.

Lane E semantics (SGK-2026-0423):
- The effective stage can RAISE from the mode vocabulary ONLY through
  verified progression evidence artifacts (never config alone): a raise
  requires an enforce-mode baseline (M3a+), progression records for ALL
  prior stages, and — for M4 — the frozen thresholds artifact.
- A corrupt/unreadable rollout state store fails CLOSED: effective M0 with
  ``rollout_state_unreadable`` (communication-disabled).
- Every m3b/m3c/m4 reachability test uses REAL ``VdpModeSettings`` config
  with artifact files — no monkeypatching of stage derivation anywhere.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

import pytest

import src.core.engine.vdp_rollout as vdp_rollout
from src.core.config.settings import VDP_STAGES, VdpModeSettings
from src.core.engine.vdp_rollout import (
    KillSwitchGuard,
    RolloutDecisionRecord,
    RolloutStateError,
    RolloutStateStore,
    ShadowDiffRecorder,
    StageVerdict,
    VdpRolloutGate,
    load_decision_records,
    load_progression_records,
    write_decision_record,
)
from src.core.models.vdp_contract import canonical_json_bytes
from src.reporting.vdp_dataset import ThresholdMetric, freeze_thresholds
from src.reporting.vdp_holdout_runner import (
    run_holdout_evaluation,
    save_evaluation_result,
)
from tests.unit.reporting.test_vdp_holdout_runner import (
    _confirmed_summary,
    _gt,
    _labels,
)


def _settings(mode="off", **kw) -> SimpleNamespace:
    """Duck-typed mode settings namespace (getattr-safe, no new fields)."""
    base = {
        "mode": mode,
        "label_leakage_denylist": [],
        "kill_switch": False,
        "capability_rules": {},
        "stage": "",
        "stage_flags": {},
        "key_provider": "env",
        "key_env_var": "SHIGOKU_VDP_SIGNING_KEY",
        "key_file_path": "",
        "key_registry_path": "",
        "progression_records_path": "",
        "thresholds_path": "",
        "rollout_state_path": "",
    }
    base.update(kw)
    return SimpleNamespace(**base)


def _records(*stages) -> list[dict]:
    return [
        {"stage": s, "drill_id": f"drill-{s}", "passed": True,
         "recorded_at": "2026-08-01T00:00:00Z"}
        for s in stages
    ]


def _progression_path(tmp_path, *stages) -> str:
    """Write a real progression evidence artifact file."""
    path = tmp_path / "progression.json"
    path.write_text(json.dumps(_records(*stages)))
    return str(path)


def _thresholds_path(tmp_path, *, valid=True) -> str:
    """Write a frozen thresholds artifact file (valid or malformed)."""
    path = tmp_path / "thresholds.json"
    if valid:
        path.write_text(json.dumps({
            "schema_version": 1,
            "eval_version": "v1",
            "decided_at": "2026-08-01T00:00:00Z",
            "metrics": [
                {"name": "hidden_holdout_f1", "value": 0.9,
                 "formula": "f1", "target_set": "hidden_holdout"},
            ],
        }))
    else:
        path.write_text("{broken")
    return str(path)


def _m3b_settings(tmp_path, **kw) -> VdpModeSettings:
    """Real config whose stage raise to m3b is fully proven."""
    return VdpModeSettings(
        mode="readonly_enforce",
        stage="m3b",
        progression_records_path=_progression_path(tmp_path, "m0", "m1", "m2", "m3a"),
        **kw,
    )


def _real_settings(tmp_path, stage: str) -> VdpModeSettings:
    """Real ``VdpModeSettings`` that reaches ``stage`` (no monkeypatch)."""
    if stage == "m0":
        return VdpModeSettings(mode="off")
    if stage == "m1":
        return VdpModeSettings(mode="record_only")
    if stage == "m2":
        return VdpModeSettings(mode="shadow")
    if stage == "m3a":
        return VdpModeSettings(mode="readonly_enforce")
    if stage == "m3b":
        return _m3b_settings(tmp_path)
    if stage == "m3c":
        return VdpModeSettings(
            mode="readonly_enforce",
            stage="m3c",
            progression_records_path=_progression_path(
                tmp_path, "m0", "m1", "m2", "m3a", "m3b"
            ),
        )
    # Lane J-1 (audit wave 3): real M4 reach requires the FULL Go evidence —
    # holdout result, holdout decision record and gate result on top of
    # progression + thresholds.
    return VdpModeSettings(
        mode="readonly_enforce",
        stage="m4",
        progression_records_path=_progression_path(
            tmp_path, "m0", "m1", "m2", "m3a", "m3b", "m3c"
        ),
        thresholds_path=_m4_thresholds_eval_path(tmp_path),
        holdout_result_path=_holdout_result_path(tmp_path, name="holdout_pass.json"),
        decision_records_path=_decision_path(tmp_path, name="decisions_pass.json"),
        gate_result_path=_gate_result_path(tmp_path, name="gate_pass.json"),
    )


class TestRolloutStageEnum:
    def test_members_match_vdp_stages(self):
        assert {s.value for s in vdp_rollout.RolloutStage} == set(VDP_STAGES)
        assert vdp_rollout.RolloutStage.M0.value == "m0"
        assert vdp_rollout.RolloutStage.M3A.value == "m3a"
        assert vdp_rollout.RolloutStage.M4.value == "m4"


class TestStageVerdict:
    def test_allow_ok(self):
        verdict = StageVerdict.allow_ok("m2")
        assert verdict.allow is True
        assert verdict.stage == "m2"
        assert verdict.reason == ""

    def test_deny(self):
        verdict = StageVerdict.deny("hitl_ticket_required", stage="m3b")
        assert verdict.allow is False
        assert verdict.stage == "m3b"
        assert verdict.reason == "hitl_ticket_required"


class TestEffectiveStage:
    """1. mode-only derivation; 2/3. explicit stage cap semantics."""

    def test_record_only_maps_m1(self):
        assert VdpRolloutGate(_settings(mode="record_only")).effective_stage() == "m1"

    def test_shadow_maps_m2(self):
        assert VdpRolloutGate(_settings(mode="shadow")).effective_stage() == "m2"

    def test_readonly_enforce_maps_m3a(self):
        assert VdpRolloutGate(_settings(mode="readonly_enforce")).effective_stage() == "m3a"

    def test_off_maps_m0(self):
        assert VdpRolloutGate(_settings(mode="off")).effective_stage() == "m0"

    def test_mode_stage_and_explicit_stage_defaults(self):
        gate = VdpRolloutGate(_settings(mode="shadow"))
        assert gate.mode_stage() == "m2"
        assert gate.explicit_stage() == "m2"

    def test_explicit_stage_caps_below_mode(self):
        gate = VdpRolloutGate(_settings(mode="readonly_enforce", stage="m2"))
        assert gate.effective_stage() == "m2"

    def test_explicit_stage_above_mode_cannot_raise(self):
        # Lane E: a raise above the mode vocabulary needs verified
        # progression evidence AND an enforce-mode baseline; a record-only
        # mode may not silently start communicating.
        gate = VdpRolloutGate(_settings(mode="shadow", stage="m3a"))
        assert gate.effective_stage() == "m2"
        assert "stage_raise_requires_enforce_mode" in gate.cap_reasons()

    def test_explicit_stage_equal_to_mode_no_change(self):
        gate = VdpRolloutGate(_settings(mode="shadow", stage="m2"))
        assert gate.effective_stage() == "m2"

    def test_unknown_explicit_stage_fails_closed_to_mode(self):
        gate = VdpRolloutGate(_settings(mode="shadow", stage="m9"))
        assert gate.effective_stage() == "m2"


class TestProductionRaisePath:
    """Lane E: real-config reach of m3b/m3c/m4 via progression evidence."""

    def test_real_config_m3b_reach(self, tmp_path):
        gate = VdpRolloutGate(_m3b_settings(tmp_path))
        assert gate.effective_stage() == "m3b"
        assert gate.cap_reasons() == []
        verdict = gate.can_operate_at("m3b")
        assert verdict.allow is True
        assert verdict.reason == ""

    def test_real_config_m3c_reach(self, tmp_path):
        settings = VdpModeSettings(
            mode="readonly_enforce",
            stage="m3c",
            progression_records_path=_progression_path(
                tmp_path, "m0", "m1", "m2", "m3a", "m3b"
            ),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3c"
        assert gate.cap_reasons() == []
        assert gate.can_operate_at("m3c").allow is True

    def test_real_config_m4_reach(self, tmp_path):
        # Lane J-1 (audit wave 3): M4 reach requires the FULL Go evidence —
        # progression + thresholds alone are capped at m3c (see
        # TestM4GoEvidenceGate).
        settings = VdpModeSettings(
            mode="readonly_enforce",
            stage="m4",
            progression_records_path=_progression_path(
                tmp_path, "m0", "m1", "m2", "m3a", "m3b", "m3c"
            ),
            thresholds_path=_m4_thresholds_eval_path(tmp_path),
            holdout_result_path=_holdout_result_path(tmp_path, name="holdout_pass.json"),
            decision_records_path=_decision_path(tmp_path, name="decisions_pass.json"),
            gate_result_path=_gate_result_path(tmp_path, name="gate_pass.json"),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m4"
        assert gate.cap_reasons() == []
        assert gate.can_operate_at("m4").allow is True

    def test_m4_without_thresholds_capped_at_m3c(self, tmp_path):
        settings = VdpModeSettings(
            mode="readonly_enforce",
            stage="m4",
            progression_records_path=_progression_path(
                tmp_path, "m0", "m1", "m2", "m3a", "m3b", "m3c"
            ),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3c"
        assert "m4_requires_thresholds" in gate.cap_reasons()

    def test_m4_with_malformed_thresholds_capped_at_m3c(self, tmp_path):
        settings = VdpModeSettings(
            mode="readonly_enforce",
            stage="m4",
            progression_records_path=_progression_path(
                tmp_path, "m0", "m1", "m2", "m3a", "m3b", "m3c"
            ),
            thresholds_path=_thresholds_path(tmp_path, valid=False),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3c"
        assert "m4_requires_thresholds" in gate.cap_reasons()

    def test_m4_wrong_schema_thresholds_capped_at_m3c(self, tmp_path):
        path = tmp_path / "thresholds.json"
        path.write_text(json.dumps({
            "schema_version": 2,
            "eval_version": "v1",
            "metrics": [{"name": "x", "value": 1, "formula": "f", "target_set": "s"}],
        }))
        settings = VdpModeSettings(
            mode="readonly_enforce",
            stage="m4",
            progression_records_path=_progression_path(
                tmp_path, "m0", "m1", "m2", "m3a", "m3b", "m3c"
            ),
            thresholds_path=str(path),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3c"
        assert "m4_requires_thresholds" in gate.cap_reasons()

    def test_m4_empty_metrics_thresholds_capped_at_m3c(self, tmp_path):
        path = tmp_path / "thresholds.json"
        path.write_text(json.dumps({
            "schema_version": 1,
            "eval_version": "v1",
            "metrics": [],
        }))
        settings = VdpModeSettings(
            mode="readonly_enforce",
            stage="m4",
            progression_records_path=_progression_path(
                tmp_path, "m0", "m1", "m2", "m3a", "m3b", "m3c"
            ),
            thresholds_path=str(path),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3c"
        assert "m4_requires_thresholds" in gate.cap_reasons()

    def test_raise_without_progression_stays_at_mode(self, tmp_path):
        settings = VdpModeSettings(
            mode="readonly_enforce",
            stage="m3b",
            progression_records_path=str(tmp_path / "missing.json"),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3a"
        assert "stage_raise_requires_progression:m3b" in gate.cap_reasons()
        assert gate.can_operate_at("m3b").allow is False

    def test_partial_progression_denies_raise(self, tmp_path):
        settings = VdpModeSettings(
            mode="readonly_enforce",
            stage="m3b",
            progression_records_path=_progression_path(tmp_path, "m0", "m1", "m3a"),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3a"
        assert "stage_raise_requires_progression:m3b" in gate.cap_reasons()

    def test_m4_both_requirements_fail_reports_both(self, tmp_path):
        settings = VdpModeSettings(
            mode="readonly_enforce",
            stage="m4",
            progression_records_path=_progression_path(tmp_path, "m0"),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3a"
        reasons = gate.cap_reasons()
        assert "stage_raise_requires_progression:m4" in reasons
        assert "m4_requires_thresholds" in reasons

    def test_off_mode_is_absolute_even_with_full_evidence(self, tmp_path):
        settings = VdpModeSettings(
            mode="off",
            stage="m4",
            progression_records_path=_progression_path(
                tmp_path, "m0", "m1", "m2", "m3a", "m3b", "m3c"
            ),
            thresholds_path=_thresholds_path(tmp_path),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m0"

    def test_shadow_mode_cannot_raise(self, tmp_path):
        settings = VdpModeSettings(
            mode="shadow",
            stage="m3b",
            progression_records_path=_progression_path(tmp_path, "m0", "m1", "m2", "m3a"),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m2"
        assert "stage_raise_requires_enforce_mode" in gate.cap_reasons()


class TestStateErrorFailClosed:
    """Lane E: corrupt/unreadable rollout state -> effective M0."""

    def test_state_error_returns_m0(self):
        gate = VdpRolloutGate(_settings(mode="readonly_enforce"), state_error=True)
        assert gate.effective_stage() == "m0"
        assert gate.cap_reasons() == ["rollout_state_unreadable"]

    def test_state_error_m0_blocks_every_operation(self):
        gate = VdpRolloutGate(_settings(mode="readonly_enforce"), state_error=True)
        assert gate.can_operate_at("m3a").allow is False
        assert gate.can_operate_at("m3a").reason == "stage_capped"
        assert gate.can_operate_at("m1").allow is False

    def test_state_error_wins_over_raise_evidence(self, tmp_path):
        gate = VdpRolloutGate(_m3b_settings(tmp_path), state_error=True)
        assert gate.effective_stage() == "m0"
        assert "rollout_state_unreadable" in gate.cap_reasons()

    def test_state_error_denies_state_changing_pre_communication(self):
        gate = VdpRolloutGate(_settings(mode="readonly_enforce"), state_error=True)
        verdict = gate.pre_communication_check(
            risk_class="state_changing", capability_level="allowed",
            hitl_ticket="HITL-1", key_active=True,
        )
        assert verdict.allow is False
        assert verdict.reason == "stage_below_m3b_for_state_change"


class TestStageFlagsCascade:
    """4. stage_flags cascade semantics."""

    def test_m3a_flag_false_caps_to_m2(self):
        gate = VdpRolloutGate(
            _settings(mode="readonly_enforce", stage_flags={"m3a": False})
        )
        assert gate.effective_stage() == "m2"

    def test_m2_and_m3a_false_cascade_to_m1(self):
        gate = VdpRolloutGate(
            _settings(
                mode="readonly_enforce",
                stage_flags={"m3a": False, "m2": False},
            )
        )
        assert gate.effective_stage() == "m1"

    def test_unrelated_flag_is_noop(self):
        gate = VdpRolloutGate(
            _settings(mode="readonly_enforce", stage_flags={"m3b": False})
        )
        assert gate.effective_stage() == "m3a"

    def test_empty_flags_noop(self):
        gate = VdpRolloutGate(_settings(mode="readonly_enforce", stage_flags={}))
        assert gate.effective_stage() == "m3a"


class TestStoreCap:
    """5. store rollback lowers; never raises."""

    def test_store_lowers_effective_stage(self):
        gate = VdpRolloutGate(
            _settings(mode="readonly_enforce"),
            state_store=RolloutStateStore(current_stage="m2"),
        )
        assert gate.effective_stage() == "m2"

    def test_store_at_same_stage_no_change(self):
        gate = VdpRolloutGate(
            _settings(mode="readonly_enforce"),
            state_store=RolloutStateStore(current_stage="m3a"),
        )
        assert gate.effective_stage() == "m3a"

    def test_store_above_settings_cannot_raise(self):
        gate = VdpRolloutGate(
            _settings(mode="shadow"),
            state_store=RolloutStateStore(current_stage="m3a"),
        )
        assert gate.effective_stage() == "m2"

    def test_sentinel_empty_store_means_no_cap(self):
        gate = VdpRolloutGate(
            _settings(mode="readonly_enforce"),
            state_store=RolloutStateStore(current_stage=""),
        )
        assert gate.effective_stage() == "m3a"

    def test_store_caps_raised_m3b_down(self, tmp_path):
        gate = VdpRolloutGate(
            _m3b_settings(tmp_path),
            state_store=RolloutStateStore(current_stage="m2"),
        )
        assert gate.effective_stage() == "m2"
        assert "store_rollback_cap" in gate.cap_reasons()


class TestCapReasons:
    """6. cap_reasons populated when capped, empty otherwise."""

    def test_empty_when_no_caps(self):
        gate = VdpRolloutGate(_settings(mode="readonly_enforce"))
        assert gate.cap_reasons() == []

    def test_explicit_stage_cap(self):
        gate = VdpRolloutGate(_settings(mode="readonly_enforce", stage="m2"))
        assert "explicit_stage_cap" in gate.cap_reasons()

    def test_flag_disable(self):
        gate = VdpRolloutGate(
            _settings(mode="readonly_enforce", stage_flags={"m3a": False})
        )
        reasons = gate.cap_reasons()
        assert reasons
        assert any("stage_flag_disabled" in r for r in reasons)

    def test_store_rollback(self):
        gate = VdpRolloutGate(
            _settings(mode="readonly_enforce"),
            state_store=RolloutStateStore(current_stage="m2"),
        )
        assert "store_rollback_cap" in gate.cap_reasons()

    def test_multiple_caps_accumulate(self):
        gate = VdpRolloutGate(
            _settings(mode="readonly_enforce", stage="m2", stage_flags={"m2": False}),
            state_store=RolloutStateStore(current_stage="m0"),
        )
        reasons = gate.cap_reasons()
        assert "explicit_stage_cap" in reasons
        assert any("stage_flag_disabled" in r for r in reasons)
        assert "store_rollback_cap" in reasons


class TestIsEnforce:
    """7. is_enforce for each stage, reached via REAL config (Lane E)."""

    def test_each_stage(self, tmp_path):
        expected = {
            "m0": False, "m1": False, "m2": False,
            "m3a": True, "m3b": True, "m3c": True, "m4": True,
        }
        for stage in VDP_STAGES:
            gate = VdpRolloutGate(_real_settings(tmp_path, stage))
            assert gate.effective_stage() == stage
            assert gate.is_enforce() is expected[stage]


class TestCanOperateAt:
    """8. can_operate_at stage/progression checks (real config)."""

    def test_m2_allowed_at_m2(self):
        gate = VdpRolloutGate(_settings(mode="shadow"))
        verdict = gate.can_operate_at("m2")
        assert verdict.allow is True
        assert verdict.reason == ""

    def test_m3a_allowed_at_m3a_without_progression(self):
        gate = VdpRolloutGate(_settings(mode="readonly_enforce"))
        verdict = gate.can_operate_at("m3a")
        assert verdict.allow is True

    def test_m3b_denied_when_effective_m3a(self):
        gate = VdpRolloutGate(_settings(mode="readonly_enforce"))
        verdict = gate.can_operate_at("m3b")
        assert verdict.allow is False
        assert verdict.reason == "stage_capped"

    def test_m3b_denied_without_progression(self, tmp_path):
        settings = VdpModeSettings(
            mode="readonly_enforce",
            stage="m3b",
            progression_records_path=str(tmp_path / "missing.json"),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3a"
        verdict = gate.can_operate_at("m3b")
        assert verdict.allow is False
        assert verdict.reason == "stage_capped"

    def test_m3b_denied_with_partial_progression(self, tmp_path):
        settings = VdpModeSettings(
            mode="readonly_enforce",
            stage="m3b",
            progression_records_path=_progression_path(tmp_path, "m0"),
        )
        gate = VdpRolloutGate(settings)
        assert gate.can_operate_at("m3b").allow is False

    def test_m3b_allowed_with_full_progression(self, tmp_path):
        gate = VdpRolloutGate(_m3b_settings(tmp_path))
        verdict = gate.can_operate_at("m3b")
        assert verdict.allow is True

    def test_failed_progression_records_do_not_count(self, tmp_path):
        path = tmp_path / "progression.json"
        path.write_text(json.dumps([
            {"stage": s, "drill_id": f"d{s}", "passed": s != "m3a",
             "recorded_at": "2026-08-01T00:00:00Z"}
            for s in ("m0", "m1", "m2", "m3a")
        ]))
        settings = VdpModeSettings(
            mode="readonly_enforce",
            stage="m3b",
            progression_records_path=str(path),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3a"
        assert gate.can_operate_at("m3b").allow is False


class TestPreCommunicationCheck:
    """9. pre_communication_check fail-closed ordering (real config)."""

    def test_read_only_allows(self):
        gate = VdpRolloutGate(_settings(mode="readonly_enforce"))
        verdict = gate.pre_communication_check(
            risk_class="read_only", capability_level="allowed"
        )
        assert verdict.allow is True
        assert verdict.reason == ""

    def test_state_changing_at_m2_denied_stage(self):
        gate = VdpRolloutGate(_settings(mode="shadow"))
        verdict = gate.pre_communication_check(
            risk_class="state_changing", capability_level="allowed",
            hitl_ticket="HITL-1", key_active=True,
        )
        assert verdict.allow is False
        assert verdict.reason == "stage_below_m3b_for_state_change"

    def test_state_changing_at_m3b_without_progression(self, tmp_path):
        settings = VdpModeSettings(
            mode="readonly_enforce",
            stage="m3b",
            progression_records_path=str(tmp_path / "missing.json"),
        )
        gate = VdpRolloutGate(settings)
        verdict = gate.pre_communication_check(
            risk_class="state_changing", capability_level="allowed",
            hitl_ticket="HITL-1", key_active=True,
        )
        assert verdict.allow is False
        assert verdict.reason == "stage_below_m3b_for_state_change"

    def test_state_changing_at_m3b_without_hitl(self, tmp_path):
        gate = VdpRolloutGate(_m3b_settings(tmp_path))
        verdict = gate.pre_communication_check(
            risk_class="state_changing", capability_level="allowed",
            hitl_ticket="", key_active=True,
        )
        assert verdict.allow is False
        assert verdict.reason == "hitl_ticket_required"

    def test_state_changing_with_hitl_but_key_inactive(self, tmp_path):
        gate = VdpRolloutGate(_m3b_settings(tmp_path))
        verdict = gate.pre_communication_check(
            risk_class="state_changing", capability_level="allowed",
            hitl_ticket="HITL-1", key_active=False,
        )
        assert verdict.allow is False
        assert verdict.reason == "signing_key_not_active"

    def test_state_changing_all_requirements_allow(self, tmp_path):
        gate = VdpRolloutGate(_m3b_settings(tmp_path))
        verdict = gate.pre_communication_check(
            risk_class="state_changing", capability_level="allowed",
            hitl_ticket="HITL-1", key_active=True,
        )
        assert verdict.allow is True

    def test_confirmation_required_treated_as_state_changing(self, tmp_path):
        gate = VdpRolloutGate(_m3b_settings(tmp_path))
        verdict = gate.pre_communication_check(
            risk_class="read_only", capability_level="confirmation_required",
            hitl_ticket="", key_active=False,
        )
        assert verdict.allow is False
        assert verdict.reason == "hitl_ticket_required"


class TestKillSwitchGuard:
    """10. KillSwitchGuard.is_active."""

    def test_is_active(self):
        assert KillSwitchGuard.is_active(SimpleNamespace(kill_switch=True)) is True
        assert KillSwitchGuard.is_active(SimpleNamespace(kill_switch=False)) is False
        assert KillSwitchGuard.is_active(SimpleNamespace()) is False
        assert KillSwitchGuard.is_active(None) is False

    def test_reason_constant(self):
        assert KillSwitchGuard.REASON == "kill_switch_active"


class TestRolloutStateStore:
    """11. RolloutStateStore persistence + rollback."""

    def test_save_load_roundtrip(self, tmp_path):
        store = RolloutStateStore(
            current_stage="m2",
            previous_stage="m3a",
            events=[{"ts": "t1", "kind": "rollback", "reason": "drill_failed"}],
        )
        path = tmp_path / "rollout_state.json"
        store.save(path)
        loaded = RolloutStateStore.load(path)
        assert loaded.current_stage == "m2"
        assert loaded.previous_stage == "m3a"
        assert loaded.events == [{"ts": "t1", "kind": "rollback", "reason": "drill_failed"}]

    def test_to_dict_from_dict_roundtrip(self):
        store = RolloutStateStore(current_stage="m1")
        data = store.to_dict()
        assert data == {"current_stage": "m1", "previous_stage": None, "events": []}
        restored = RolloutStateStore.from_dict(data)
        assert restored.current_stage == "m1"

    def test_load_missing_returns_none(self, tmp_path):
        assert RolloutStateStore.load(tmp_path / "missing.json") is None

    def test_load_malformed_json_raises(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{not json")
        with pytest.raises(RolloutStateError):
            RolloutStateStore.load(path)

    def test_from_dict_malformed_raises(self):
        with pytest.raises(RolloutStateError):
            RolloutStateStore.from_dict("nope")
        with pytest.raises(RolloutStateError):
            RolloutStateStore.from_dict({"current_stage": 42})
        with pytest.raises(RolloutStateError):
            RolloutStateStore.from_dict({"current_stage": "m9"})
        with pytest.raises(RolloutStateError):
            RolloutStateStore.from_dict(
                {"current_stage": "m2", "previous_stage": "m9"}
            )
        with pytest.raises(RolloutStateError):
            RolloutStateStore.from_dict(
                {"current_stage": "m2", "events": "not-a-list"}
            )

    def test_rollback_swaps_and_records_event(self):
        store = RolloutStateStore(current_stage="m3a", previous_stage="m2")
        store.rollback("drill_failed")
        assert store.current_stage == "m2"
        assert store.previous_stage is None
        assert store.events
        event = store.events[-1]
        assert event["kind"] == "rollback"
        assert event["reason"] == "drill_failed"
        assert "ts" in event

    def test_rollback_without_previous_uses_sentinel(self):
        store = RolloutStateStore(current_stage="m2")
        store.rollback("drill_failed")
        assert store.current_stage == ""


class TestLoadProgressionRecords:
    """12. load_progression_records fail-closed."""

    def test_missing_returns_empty(self, tmp_path):
        assert load_progression_records(str(tmp_path / "missing.json")) == []

    def test_empty_path_returns_empty(self):
        assert load_progression_records("") == []

    def test_malformed_returns_empty(self, tmp_path):
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("{nope")
        assert load_progression_records(str(bad_json)) == []
        not_list = tmp_path / "notlist.json"
        not_list.write_text('{"stage": "m0"}')
        assert load_progression_records(str(not_list)) == []

    def test_valid_records_kept_as_is(self, tmp_path):
        records = [
            {"stage": "m0", "drill_id": "d0", "passed": True,
             "recorded_at": "2026-08-01T00:00:00Z"},
            {"stage": "m1", "drill_id": "d1", "passed": False,
             "recorded_at": "2026-08-01T00:00:00Z"},
        ]
        path = tmp_path / "progression.json"
        path.write_text(json.dumps(records))
        assert load_progression_records(str(path)) == records

    def test_gate_loads_from_progression_path(self, tmp_path):
        settings = _m3b_settings(tmp_path)
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3b"
        assert gate.can_operate_at("m3b").allow is True


class TestShadowDiffRecorder:
    """13. ShadowDiffRecorder fixed-key append + accumulation."""

    def test_record_appends_fixed_key_entry(self):
        state: dict = {}
        ShadowDiffRecorder.record(
            state,
            next_action_id="nxt-1",
            verdict_id="vrd-1",
            hypothesis_id="hyp-1",
            attempt_id="att-1",
            reason_code="evidence_gap",
            stage="m3a",
            decision="enforced",
            diff_type="matched_shadow",
        )
        assert list(state.keys()) == ["shadow_diff"]
        entry = state["shadow_diff"][0]
        assert list(entry.keys()) == [
            "next_action_id", "verdict_id", "hypothesis_id", "attempt_id",
            "reason_code", "stage", "decision", "diff_type",
        ]
        assert entry["next_action_id"] == "nxt-1"
        assert entry["attempt_id"] == "att-1"
        assert entry["decision"] == "enforced"
        assert entry["diff_type"] == "matched_shadow"

    def test_record_accumulates(self):
        state: dict = {}
        ShadowDiffRecorder.record(
            state, next_action_id="a", decision="enforced", diff_type="matched_shadow"
        )
        ShadowDiffRecorder.record(
            state, next_action_id="b", decision="shadow_only", diff_type="pending"
        )
        assert len(state["shadow_diff"]) == 2
        assert state["shadow_diff"][1]["decision"] == "shadow_only"

    def test_record_defaults_empty_strings(self):
        state: dict = {}
        ShadowDiffRecorder.record(state, decision="enforced", diff_type="matched_shadow")
        entry = state["shadow_diff"][0]
        assert entry["next_action_id"] == ""
        assert entry["verdict_id"] == ""
        assert entry["stage"] == ""


class TestRolloutDecisionRecord:
    """14. RolloutDecisionRecord write/load roundtrip."""

    def test_write_load_roundtrip(self, tmp_path):
        path = tmp_path / "decisions.json"
        write_decision_record(
            path,
            RolloutDecisionRecord(
                stage="m4",
                decision="hold",
                reasons=["hidden_holdout_regression"],
                recorded_at="2026-08-01T00:00:00Z",
                eval_version="v1",
                artifact_hash="abc123",
            ),
        )
        write_decision_record(
            path,
            RolloutDecisionRecord(
                stage="m4",
                decision="go",
                reasons=[],
                recorded_at="2026-08-02T00:00:00Z",
            ),
        )
        loaded = load_decision_records(path)
        assert len(loaded) == 2
        assert loaded[0].stage == "m4"
        assert loaded[0].decision == "hold"
        assert loaded[0].reasons == ["hidden_holdout_regression"]
        assert loaded[0].eval_version == "v1"
        assert loaded[0].artifact_hash == "abc123"
        assert loaded[1].decision == "go"
        assert loaded[1].reasons == []
        assert loaded[1].eval_version == ""

    def test_load_missing_returns_empty(self, tmp_path):
        assert load_decision_records(str(tmp_path / "missing.json")) == []

    def test_load_malformed_returns_empty(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("[{broken")
        assert load_decision_records(str(path)) == []


class TestGateNamespaceCompat:
    """15. SimpleNamespace (mode-only fields) behaves like mode-derived."""

    def test_mode_only_namespace_mode_derived(self):
        ns = SimpleNamespace(
            mode="shadow", label_leakage_denylist=[], kill_switch=False,
            capability_rules={},
        )
        gate = VdpRolloutGate(ns)
        assert gate.effective_stage() == "m2"
        assert gate.cap_reasons() == []
        assert gate.is_enforce() is False

    def test_missing_attributes_safe_defaults(self):
        gate = VdpRolloutGate(SimpleNamespace(mode="readonly_enforce"))
        assert gate.effective_stage() == "m3a"
        assert gate.is_enforce() is True

    def test_none_settings_like_fails_closed_to_m0(self):
        gate = VdpRolloutGate(None)
        assert gate.effective_stage() == "m0"

    def test_real_vdpmode_settings(self):
        settings = VdpModeSettings(mode="readonly_enforce", stage="m2")
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m2"
        assert "explicit_stage_cap" in gate.cap_reasons()


# ---------------------------------------------------------------------------
# Lane J-1 (audit wave 3): M4 reachability requires REAL Go evidence —
# holdout result (outcome "pass" / matching eval_version / intact artifact
# hash), a holdout decision record ("go"), and a real gate result (decision
# "go" / known termination run_state / report-session consistency pass).
# Hand-written progression + thresholds JSONs alone no longer enable M4.
# ---------------------------------------------------------------------------


def _m4_thresholds_eval_path(tmp_path, *, eval_version: str = "v1") -> str:
    """Frozen thresholds artifact used by the M4 gate (valid shape)."""
    path = tmp_path / "thresholds_v1.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "eval_version": eval_version,
        "decided_at": "2026-08-01T00:00:00Z",
        "metrics": [
            {"name": "recall", "value": 0.5,
             "formula": "matched_ground_truth / ground_truth",
             "target_set": "hidden_holdout"},
        ],
    }))
    return str(path)


def _holdout_result_path(
    tmp_path,
    *,
    eval_version: str = "v1",
    outcome: str = "pass",
    name: str = "holdout_result.json",
) -> str:
    """Write a REAL holdout result via the runner so ``artifact_hash`` is
    guaranteed to match ``save_evaluation_result`` semantics.

    Timestamps are normalized AFTER saving so regeneration is deterministic
    (Lane L-1 decision-record binding tests depend on stable hashes across
    helper calls); the hash is recomputed exactly per runner semantics.
    """
    summary = _confirmed_summary(["https://alpha.example.com/items/42"])
    labels = _labels([_gt(endpoint="/items/42")]) if outcome == "pass" else _labels([])
    thresholds = freeze_thresholds(
        eval_version=eval_version, decided_at="2026-08-01T00:00:00Z",
        metrics=[ThresholdMetric(
            name="recall", value=0.5,
            formula="matched_ground_truth / ground_truth",
            target_set="hidden_holdout",
        )],
    )
    result = run_holdout_evaluation(
        summary, labels=labels, thresholds=thresholds,
        eval_version=eval_version, runner_version="test-runner",
        session_ref="sess-m4",
    )
    assert result.outcome == outcome
    path = tmp_path / name
    save_evaluation_result(result, path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["started_at"] = "2026-08-01T00:00:00.000000+00:00"
    data["finished_at"] = "2026-08-01T00:00:01.000000+00:00"
    data["artifact_hash"] = hashlib.sha256(canonical_json_bytes(
        {k: v for k, v in data.items() if k != "artifact_hash"}
    )).hexdigest()
    path.write_text(json.dumps(data, sort_keys=True, ensure_ascii=False, indent=2))
    return str(path)


def _holdout_pass_hash(tmp_path, *, eval_version: str = "v1") -> str:
    """artifact_hash of the default pass holdout result (the evaluation a
    holdout decision record refers to)."""
    data = json.loads(Path(
        _holdout_result_path(
            tmp_path, eval_version=eval_version, name="holdout_pass.json"
        )
    ).read_text(encoding="utf-8"))
    return str(data["artifact_hash"])


def _decision_path(
    tmp_path,
    *,
    stage: str = "holdout",
    decision: str = "go",
    eval_version: str = "v1",
    artifact_hash: Optional[str] = None,
    name: str = "decisions.json",
) -> str:
    """Write one decision record.

    ``artifact_hash=None`` binds the record to the default pass holdout
    result's artifact hash — the evaluation the Go refers to (the M4 gate
    requires the LATEST holdout entry to carry exactly that hash).
    """
    if artifact_hash is None:
        artifact_hash = _holdout_pass_hash(tmp_path)
    path = tmp_path / name
    write_decision_record(path, RolloutDecisionRecord(
        stage=stage, decision=decision, reasons=[],
        recorded_at="2026-08-01T00:00:00Z", eval_version=eval_version,
        artifact_hash=artifact_hash,
    ))
    return str(path)


def _gate_result_path(
    tmp_path,
    *,
    decision: str = "go",
    run_state: str = "succeeded",
    rsc_status: str = "pass",
    consistency_status: str = "consistent",
    name: str = "gate_result.json",
) -> str:
    """Real gate-result artifact shape (mirrors
    workspace/projects/vdp-eval-0423/reports/gate_real_20260804.json)."""
    path = tmp_path / name
    path.write_text(json.dumps({
        "schema_version": 1,
        "profile": "real",
        "status": "pass",
        "reason_codes": [],
        "gates": {
            "termination_state": {
                "status": "pass" if run_state in ("succeeded", "partial") else "fail",
                "run_state": run_state,
            },
            "report_session_consistency": {
                "status": rsc_status,
                "consistency_status": consistency_status,
                "consistency_reason_codes": [],
            },
        },
        "decision": decision,
    }))
    return str(path)


def _m4_full_settings(tmp_path, **kw) -> VdpModeSettings:
    """Real config whose stage raise to m4 is fully proven (per-test overrides).

    The default evidence uses DISTINCT file names so a per-test override
    (e.g. a hold result written to the default ``holdout_result.json``) can
    never be clobbered by the pass baseline.
    """
    base = dict(
        mode="readonly_enforce",
        stage="m4",
        progression_records_path=_progression_path(
            tmp_path, "m0", "m1", "m2", "m3a", "m3b", "m3c"
        ),
        thresholds_path=_m4_thresholds_eval_path(tmp_path),
        holdout_result_path=_holdout_result_path(tmp_path, name="holdout_pass.json"),
        decision_records_path=_decision_path(tmp_path, name="decisions_pass.json"),
        gate_result_path=_gate_result_path(tmp_path, name="gate_pass.json"),
    )
    base.update(kw)
    return VdpModeSettings(**base)


class TestM4GoEvidenceGate:
    """Lane J-1 (audit wave 3): M4 reachability requires REAL Go evidence.

    Hand-written progression + thresholds JSONs alone (the pre-audit state)
    must NOT enable M4: the gate also requires a holdout result (outcome
    "pass", eval_version matching the thresholds artifact, intact recomputed
    artifact_hash), a holdout decision record with decision "go", and a real
    gate result (decision "go", known termination run_state, report/session
    consistency pass). Every unmet piece caps M4 at m3c with its own reason.
    """

    def test_m4_denied_with_only_thresholds_and_progression(self, tmp_path):
        settings = VdpModeSettings(
            mode="readonly_enforce",
            stage="m4",
            progression_records_path=_progression_path(
                tmp_path, "m0", "m1", "m2", "m3a", "m3b", "m3c"
            ),
            thresholds_path=_m4_thresholds_eval_path(tmp_path),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3c"
        reasons = gate.cap_reasons()
        assert "m4_requires_holdout_result" in reasons
        assert "m4_requires_decision_record" in reasons
        assert "m4_requires_gate_result" in reasons
        assert "m4_requires_thresholds" not in reasons
        assert gate.can_operate_at("m4").allow is False
        assert gate.can_operate_at("m4").reason == "stage_capped"

    def test_m4_denied_when_holdout_outcome_not_pass(self, tmp_path):
        hold_path = _holdout_result_path(tmp_path, outcome="hold")
        hold_hash = json.loads(
            Path(hold_path).read_text(encoding="utf-8")
        )["artifact_hash"]
        settings = _m4_full_settings(
            tmp_path,
            holdout_result_path=hold_path,
            decision_records_path=_decision_path(
                tmp_path, artifact_hash=hold_hash, name="decisions_hold.json",
            ),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3c"
        assert gate.cap_reasons() == ["m4_holdout_outcome_not_pass"]

    def test_m4_denied_when_holdout_eval_version_mismatch(self, tmp_path):
        settings = _m4_full_settings(
            tmp_path,
            holdout_result_path=_holdout_result_path(tmp_path, eval_version="v2"),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3c"
        reasons = gate.cap_reasons()
        # a v2 evaluation carries a v2 thresholds fingerprint AND an
        # artifact hash the v1-bound decision record does not refer to
        assert "m4_holdout_eval_version_mismatch" in reasons
        assert "m4_threshold_fingerprint_mismatch" in reasons

    def test_m4_denied_when_holdout_artifact_hash_tampered(self, tmp_path):
        source = Path(_holdout_result_path(tmp_path, name="holdout_orig.json"))
        data = json.loads(source.read_text(encoding="utf-8"))
        data["started_at"] = data["started_at"] + "X"  # tamper AFTER hashing
        tampered = tmp_path / "holdout_tampered.json"
        tampered.write_text(json.dumps(data, sort_keys=True))
        settings = _m4_full_settings(tmp_path, holdout_result_path=str(tampered))
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3c"
        assert gate.cap_reasons() == ["m4_holdout_artifact_hash_mismatch"]

    def test_m4_denied_without_holdout_decision_record(self, tmp_path):
        # the decision-records artifact exists but has no stage=="holdout" entry
        settings = _m4_full_settings(
            tmp_path,
            decision_records_path=_decision_path(tmp_path, stage="m3c"),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3c"
        assert gate.cap_reasons() == ["m4_requires_decision_record"]

    def test_m4_denied_when_holdout_decision_not_go(self, tmp_path):
        settings = _m4_full_settings(
            tmp_path,
            decision_records_path=_decision_path(tmp_path, decision="hold"),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3c"
        assert gate.cap_reasons() == ["m4_decision_record_not_go"]

    def test_m4_denied_when_gate_decision_not_go(self, tmp_path):
        settings = _m4_full_settings(
            tmp_path,
            gate_result_path=_gate_result_path(tmp_path, decision="hold"),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3c"
        assert gate.cap_reasons() == ["m4_gate_decision_not_go"]

    def test_m4_denied_when_gate_termination_unknown(self, tmp_path):
        settings = _m4_full_settings(
            tmp_path,
            gate_result_path=_gate_result_path(tmp_path, run_state="unknown"),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3c"
        assert gate.cap_reasons() == ["m4_gate_termination_unknown"]

    def test_m4_denied_when_gate_consistency_not_consistent(self, tmp_path):
        settings = _m4_full_settings(
            tmp_path,
            gate_result_path=_gate_result_path(
                tmp_path, consistency_status="inconsistent"
            ),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3c"
        assert gate.cap_reasons() == ["m4_gate_consistency_not_consistent"]

    def test_m4_allowed_only_with_all_real_go_evidence(self, tmp_path):
        settings = _m4_full_settings(tmp_path)
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m4"
        assert gate.cap_reasons() == []
        verdict = gate.can_operate_at("m4")
        assert verdict.allow is True
        assert gate.is_enforce() is True

    def test_m4_requires_enforce_mode_reason_kept(self, tmp_path):
        # full evidence present but the mode baseline is not enforce -> the
        # m4-vocabulary reason for the enforce-mode requirement is emitted
        settings = VdpModeSettings(
            mode="off",
            stage="m4",
            progression_records_path=_progression_path(
                tmp_path, "m0", "m1", "m2", "m3a", "m3b", "m3c"
            ),
            thresholds_path=_m4_thresholds_eval_path(tmp_path),
            holdout_result_path=_holdout_result_path(tmp_path),
            decision_records_path=_decision_path(tmp_path),
            gate_result_path=_gate_result_path(tmp_path),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m0"
        reasons = gate.cap_reasons()
        assert "stage_raise_requires_enforce_mode" in reasons
        assert "m4_requires_enforce_mode" in reasons

    def test_m4_requires_progression_reason_kept(self, tmp_path):
        settings = VdpModeSettings(
            mode="readonly_enforce",
            stage="m4",
            progression_records_path=_progression_path(tmp_path, "m0"),
            thresholds_path=_m4_thresholds_eval_path(tmp_path),
            holdout_result_path=_holdout_result_path(tmp_path),
            decision_records_path=_decision_path(tmp_path),
            gate_result_path=_gate_result_path(tmp_path),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3a"
        reasons = gate.cap_reasons()
        assert "stage_raise_requires_progression:m4" in reasons
        assert "m4_requires_progression" in reasons


# ---------------------------------------------------------------------------
# Lane L-1 (audit wave 4, blocker 1): the M4 Go evidence is BOUND —
# thresholds -> holdout result -> decision record — by eval_version AND
# threshold fingerprint / artifact hash. Changing the thresholds under the
# same eval_version, a decision record that does not refer to the evaluated
# artifact, or a stale Go after a later Hold/No-Go, denies M4.
# ---------------------------------------------------------------------------


class TestM4GoEvidenceBinding:
    """Lane L-1 binding semantics for the M4 Go evidence chain.

    Plan §10: 閾値をholdout閲覧前に固定し、後付け調整しない — the holdout
    result must carry the fingerprint of the EXACT thresholds artifact the
    gate now reads, and the LATEST holdout decision record must refer to the
    EXACT evaluated artifact (eval_version + artifact_hash).
    """

    def test_baseline_all_evidence_consistent_allows_m4(self, tmp_path):
        settings = _m4_full_settings(tmp_path)
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m4"
        assert gate.cap_reasons() == []

    def test_thresholds_changed_under_same_eval_version_denies_m4(self, tmp_path):
        """The audit's exact case: thresholds adjusted AFTER the holdout
        evaluation under the SAME eval_version -> fingerprint differs ->
        M4 denied (no post-hoc threshold tuning)."""
        settings = _m4_full_settings(tmp_path)
        thresholds_path = Path(settings.thresholds_path)
        data = json.loads(thresholds_path.read_text(encoding="utf-8"))
        data["metrics"][0]["value"] = 0.99  # post-evaluation adjustment
        thresholds_path.write_text(json.dumps(data, sort_keys=True))
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3c"
        assert gate.cap_reasons() == ["m4_threshold_fingerprint_mismatch"]

    def test_holdout_result_missing_threshold_fingerprint_denies_m4(self, tmp_path):
        # strip the fingerprint field from the pass holdout and re-hash
        # exactly per runner semantics
        source = Path(_holdout_result_path(tmp_path, name="holdout_orig.json"))
        data = json.loads(source.read_text(encoding="utf-8"))
        data.pop("threshold_fingerprint")
        data["artifact_hash"] = hashlib.sha256(canonical_json_bytes(
            {k: v for k, v in data.items() if k != "artifact_hash"}
        )).hexdigest()
        stripped = tmp_path / "holdout_no_fp.json"
        stripped.write_text(
            json.dumps(data, sort_keys=True, ensure_ascii=False, indent=2)
        )
        settings = _m4_full_settings(
            tmp_path,
            holdout_result_path=str(stripped),
            decision_records_path=_decision_path(
                tmp_path, artifact_hash=data["artifact_hash"],
                name="decisions_stripped.json",
            ),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3c"
        assert gate.cap_reasons() == ["m4_threshold_fingerprint_mismatch"]

    def test_decision_eval_version_mismatch_denies_m4(self, tmp_path):
        settings = _m4_full_settings(
            tmp_path,
            decision_records_path=_decision_path(
                tmp_path, eval_version="v2", name="decisions_v2.json",
            ),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3c"
        assert gate.cap_reasons() == ["m4_decision_eval_version_mismatch"]

    def test_decision_artifact_hash_mismatch_denies_m4(self, tmp_path):
        # the Go refers to a DIFFERENT evaluation artifact than the one on disk
        settings = _m4_full_settings(
            tmp_path,
            decision_records_path=_decision_path(
                tmp_path, artifact_hash="stale-hash", name="decisions_stale.json",
            ),
        )
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3c"
        assert gate.cap_reasons() == ["m4_decision_artifact_hash_mismatch"]

    def test_stale_go_not_adopted_after_later_hold(self, tmp_path):
        """Older go then newer hold: the LATEST holdout decision governs —
        a stale Go must not be adopted."""
        holdout_hash = _holdout_pass_hash(tmp_path)
        path = tmp_path / "decisions_stale_go.json"
        write_decision_record(path, RolloutDecisionRecord(
            stage="holdout", decision="go", reasons=[],
            recorded_at="2026-08-01T00:00:00Z", eval_version="v1",
            artifact_hash=holdout_hash,
        ))
        write_decision_record(path, RolloutDecisionRecord(
            stage="holdout", decision="hold", reasons=["hidden_holdout_regression"],
            recorded_at="2026-08-02T00:00:00Z", eval_version="v1",
            artifact_hash=holdout_hash,
        ))
        settings = _m4_full_settings(tmp_path, decision_records_path=str(path))
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3c"
        assert gate.cap_reasons() == ["m4_decision_record_not_go"]

    def test_later_go_after_older_hold_allows_m4(self, tmp_path):
        """Older hold then newer go: the latest decision governs -> allowed."""
        holdout_hash = _holdout_pass_hash(tmp_path)
        path = tmp_path / "decisions_newer_go.json"
        write_decision_record(path, RolloutDecisionRecord(
            stage="holdout", decision="hold", reasons=["hidden_holdout_regression"],
            recorded_at="2026-08-01T00:00:00Z", eval_version="v1",
            artifact_hash=holdout_hash,
        ))
        write_decision_record(path, RolloutDecisionRecord(
            stage="holdout", decision="go", reasons=[],
            recorded_at="2026-08-02T00:00:00Z", eval_version="v1",
            artifact_hash=holdout_hash,
        ))
        settings = _m4_full_settings(tmp_path, decision_records_path=str(path))
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m4"
        assert gate.cap_reasons() == []

    def test_recorded_at_tie_prefers_last_in_file_order(self, tmp_path):
        """Equal ``recorded_at`` values: the LAST holdout entry in file order
        governs (documented tie-break)."""
        holdout_hash = _holdout_pass_hash(tmp_path)
        path = tmp_path / "decisions_tie.json"
        write_decision_record(path, RolloutDecisionRecord(
            stage="holdout", decision="go", reasons=[],
            recorded_at="2026-08-01T00:00:00Z", eval_version="v1",
            artifact_hash=holdout_hash,
        ))
        write_decision_record(path, RolloutDecisionRecord(
            stage="holdout", decision="hold", reasons=["regression"],
            recorded_at="2026-08-01T00:00:00Z", eval_version="v1",
            artifact_hash=holdout_hash,
        ))
        settings = _m4_full_settings(tmp_path, decision_records_path=str(path))
        gate = VdpRolloutGate(settings)
        assert gate.effective_stage() == "m3c"
        assert "m4_decision_record_not_go" in gate.cap_reasons()
