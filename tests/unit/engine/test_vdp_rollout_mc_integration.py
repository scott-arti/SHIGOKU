"""
SGK-2026-0423 Lane C — MasterConductor staged rollout integration (TDD).

Real production path (fake network adapter only), mirroring
``tests.core.engine.test_master_conductor_vdp_follow_up`` helpers:

  - stage ladder caps (explicit stage / stage_flags / state store) gate the
    hypothesis hook, queue injection, and pre-communication dispatch
  - kill switch semantics preserved at queue injection
  - shadow/enforce diff recording (queue phase + dispatch phase)
  - session injector carries ``shadow_diff``
  - rollout store rollback lowers capability only; read-only stays unaffected
  - idempotency dedup unchanged
  - signer resolution is fail-closed without key config, explicit file
    provider resolves a real signer
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from src.core.config.settings import VdpModeSettings
from src.core.domain.model.task import Task
from src.core.engine.master_conductor import MasterConductor
from src.core.engine.master_conductor_session_service import (
    inject_vdp_section_to_session_payload,
)
from src.core.engine.vdp_rollout import RolloutStateStore

from tests.core.engine.test_master_conductor_vdp_follow_up import (
    _FakeNetwork,
    _new_mc,
    _scope,
    _signal_bundle,
)


def _state_changing_spec(task_id: str = "task-sc") -> dict:
    return {
        "task_id": task_id,
        "hypothesis_id": "hyp-sc-1",
        "verdict_id": "",
        "next_action_id": "nxt-sc-1",
        "evidence_gap": "state_change_not_verified",
        "risk_class": "state_changing",
        "action_class": "follow_up_probe",
        "url": "https://api.example.com/items",
        "method": "GET",
        "param_names": [],
        "param_locations": [],
        "header_positions": [],
        "actor": "unauth",
    }


def _read_only_spec(
    task_id: str,
    *,
    next_action_id: str = "nxt-ro-1",
    verdict_id: str = "vrd-ro-1",
    hypothesis_id: str = "hyp-ro-1",
) -> dict:
    return {
        "task_id": task_id,
        "hypothesis_id": hypothesis_id,
        "verdict_id": verdict_id,
        "next_action_id": next_action_id,
        "evidence_gap": "authz_impact_not_proven",
        "risk_class": "read_only",
        "action_class": "follow_up_probe",
        "url": "https://api.example.com/items",
        "method": "GET",
        "param_names": [],
        "param_locations": [],
        "header_positions": [],
        "actor": "unauth",
        "scope_domains": ["api.example.com"],
        "scope_out_domains": [],
        "scope_rate_limit": 1000,
    }


def _vdp_task(spec: dict) -> Task:
    return Task(
        id=spec["task_id"],
        name=f"vdp_follow_up:{spec['evidence_gap']}",
        agent_type="vdp_follow_up",
        action="run",
        params={"vdp_follow_up_spec": spec},
    )


class TestStageCapsInHooks:
    """16-19: hypothesis hook and queue injection respect the ladder."""

    def test_shadow_preserves_existing_behavior(self):
        """16. mode=shadow -> hypotheses+proposals, no queue, no network."""
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="shadow", label_leakage_denylist=[], kill_switch=False,
                capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()}, scope_definition=_scope()
        )
        assert mc._vdp_state["vdp_active"] is True
        assert mc._vdp_state["verdicts"]
        assert mc._vdp_state["next_actions"]
        assert not mc._vdp_state.get("follow_up_pending")
        assert len(mc.task_queue) == 0
        assert net.count == 0

    def test_explicit_m0_cap_degrades_hook(self):
        """17. mode=shadow + stage='m0' -> degraded, vdp_active False."""
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="shadow", label_leakage_denylist=[], kill_switch=False,
                capability_rules={}, stage="m0", stage_flags={},
            ),
        )
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()}, scope_definition=_scope()
        )
        assert mc._vdp_state["vdp_active"] is False
        assert len(mc.task_queue) == 0
        assert net.count == 0
        reasons = [
            d.get("reason")
            for d in getattr(mc, "_shadow_decisions", [])
            if d.get("scope") == "vdp_hypothesis_generation"
        ]
        assert "rollout_stage_below_m1" in reasons

    def test_flag_capped_queue(self):
        """18. readonly_enforce + stage_flags={'m3a': False} -> no queue."""
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[],
                kill_switch=False, capability_rules={"follow_up_probe": "allowed"},
                stage="", stage_flags={"m3a": False},
            ),
        )
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()}, scope_definition=_scope()
        )
        assert mc._vdp_state["vdp_active"] is True
        assert mc._vdp_state["verdicts"]
        assert mc._vdp_state["next_actions"]
        assert not mc._vdp_state.get("follow_up_pending")
        assert len(mc.task_queue) == 0
        assert net.count == 0
        rollout = [
            d for d in getattr(mc, "_shadow_decisions", [])
            if d.get("scope") == "vdp_rollout"
        ]
        assert rollout
        assert rollout[0]["stage"] == "m2"
        assert rollout[0]["reasons"]

    def test_kill_switch_still_blocks_queue(self):
        """19. kill switch at queue injection still blocks (unchanged)."""
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[],
                kill_switch=True, capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()}, scope_definition=_scope()
        )
        assert not mc._vdp_state.get("follow_up_pending")
        assert len(mc.task_queue) == 0
        assert net.count == 0


class TestPreCommunicationBlock:
    """20-21: state-changing dispatch is blocked before the executor."""

    async def test_state_changing_blocked_at_m2(self):
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="shadow", label_leakage_denylist=[], kill_switch=False,
                capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        spec = _state_changing_spec("task-sc-m2")
        mc._vdp_state.setdefault("follow_up_pending", []).append(
            {"task_id": spec["task_id"]}
        )
        result = await mc._dispatch(_vdp_task(spec))
        assert result["success"] is True
        assert result["data"]["status"] == "blocked"
        assert "stage_below_m3b_for_state_change" in result["data"]["reason"]
        assert net.count == 0
        pending = [
            p for p in mc._vdp_state["follow_up_pending"]
            if p.get("task_id") == spec["task_id"]
        ][0]
        assert pending["execution_status"] == "blocked"
        assert pending["execution_reason"] == "stage_below_m3b_for_state_change"
        rollout = [
            d for d in getattr(mc, "_shadow_decisions", [])
            if d.get("scope") == "vdp_rollout" and d.get("task_id") == spec["task_id"]
        ]
        assert rollout
        assert rollout[0]["status"] == "blocked"
        assert rollout[0]["reason"] == "stage_below_m3b_for_state_change"

    async def test_state_changing_blocked_at_m3a_even_with_hitl(self):
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[],
                kill_switch=False, capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        spec = _state_changing_spec("task-sc-m3a")
        spec["hitl_ticket"] = "HITL-42"
        result = await mc._dispatch(_vdp_task(spec))
        assert result["data"]["status"] == "blocked"
        assert result["data"]["reason"] == "stage_below_m3b_for_state_change"
        assert net.count == 0


class TestShadowDiffRecording:
    """22: queue-phase + dispatch-phase shadow/enforce diff records."""

    async def test_queue_and_dispatch_phase_diffs(self):
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[],
                kill_switch=False, capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()}, scope_definition=_scope()
        )
        # queue-phase diff: queued NextActions -> enforced/matched_shadow,
        # unqueued NextActions -> shadow_only/pending
        diffs = mc._vdp_state.get("shadow_diff", [])
        assert diffs
        assert any(
            d["decision"] == "enforced" and d["diff_type"] == "matched_shadow"
            for d in diffs
        )
        assert any(
            d["decision"] == "shadow_only" and d["diff_type"] == "pending"
            for d in diffs
        )
        tasks = [t for t in mc.task_queue if t.agent_type == "vdp_follow_up"]
        assert tasks
        # SGK-2026-0439: the queued payload_request_mismatch spec (render
        # search endpoint) now carries masked request material (mask-at-
        # ingest) and is executable; S07 exact_request_material_unavailable
        # applies only to genuinely material-less payload specs (regression).
        queued_spec = tasks[0].params["vdp_follow_up_spec"]
        assert queued_spec["evidence_gap"] == "payload_request_mismatch"
        assert queued_spec.get("masked_request_url")  # material preserved
        material_less = _vdp_task(
            dict(_read_only_spec("task-pm-dispatch"), evidence_gap="payload_request_mismatch")
        )
        blocked = await mc._dispatch(material_less)
        assert blocked["data"]["status"] == "manual_review"
        assert blocked["data"]["reason"] == "exact_request_material_unavailable"
        # Dispatch-phase record: a HEALTHY executable spec (authz comparison
        # gap from the same generated NextAction set) records the enforced
        # dispatch diff with attempt lineage.
        healthy = _read_only_spec(
            "task-ro-dispatch",
            next_action_id="nxt-b11c7a49f4cd5ab1",
            verdict_id="vrd-a89b08c1de820075",
            hypothesis_id="hyp-ro-1",
        )
        result = await mc._dispatch(_vdp_task(healthy))
        assert result["data"]["status"] == "executed"
        spec = healthy
        # dispatch-phase record carries the same next_action_id lineage + attempt
        dispatch_diffs = [
            d for d in mc._vdp_state.get("shadow_diff", [])
            if d["next_action_id"] == spec["next_action_id"]
            and d["decision"] == "enforced"
        ]
        assert dispatch_diffs
        assert dispatch_diffs[-1]["attempt_id"]
        assert dispatch_diffs[-1]["diff_type"] == "matched_shadow"

    async def test_dispatch_new_spec_records_diff_type_new(self):
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[],
                kill_switch=False, capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()}, scope_definition=_scope()
        )
        spec = _read_only_spec(
            "task-new-1", next_action_id="nxt-never-seen", verdict_id="vrd-never-seen"
        )
        result = await mc._dispatch(_vdp_task(spec))
        assert result["data"]["status"] == "executed"
        entry = [
            d for d in mc._vdp_state["shadow_diff"]
            if d["next_action_id"] == "nxt-never-seen"
        ][0]
        assert entry["decision"] == "enforced"
        assert entry["diff_type"] == "new"


class TestSessionInjectorShadowDiff:
    """23: session payload carries shadow_diff when present."""

    def test_includes_shadow_diff_when_present(self):
        mc = _new_mc()
        mc._vdp_state["shadow_diff"] = [
            {
                "next_action_id": "nxt-1", "verdict_id": "", "hypothesis_id": "",
                "attempt_id": "", "reason_code": "evidence_gap", "stage": "m3a",
                "decision": "enforced", "diff_type": "matched_shadow",
            }
        ]
        payload = inject_vdp_section_to_session_payload({"x": 1}, mc._vdp_state)
        assert payload["vdp_contract"]["shadow_diff"] == mc._vdp_state["shadow_diff"]

    def test_omits_shadow_diff_when_absent(self):
        mc = _new_mc()
        payload = inject_vdp_section_to_session_payload({"x": 1}, mc._vdp_state)
        assert "shadow_diff" not in payload["vdp_contract"]


class TestCorruptRolloutStateFailClosed:
    """Lane E: corrupt/unreadable rollout state -> effective M0 (fail-closed)."""

    def test_corrupt_rollout_state_degrades_hook(self, tmp_path):
        bad_state = tmp_path / "rollout_state.json"
        bad_state.write_text("{not json")
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[],
                kill_switch=False, capability_rules={"follow_up_probe": "allowed"},
                rollout_state_path=str(bad_state),
            ),
        )
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()}, scope_definition=_scope()
        )
        assert mc._vdp_rollout_state_error is True
        assert mc._vdp_rollout_store() is None
        assert mc._vdp_state["vdp_active"] is False
        assert not mc._vdp_state.get("follow_up_pending")
        assert len(mc.task_queue) == 0
        assert net.count == 0
        degraded = [
            d.get("reason")
            for d in getattr(mc, "_shadow_decisions", [])
            if d.get("scope") == "vdp_hypothesis_generation"
            and d.get("status") == "degraded"
        ]
        assert "rollout_state_unreadable" in degraded
        assert "rollout_stage_below_m1" in degraded

    def test_corrupt_rollout_state_blocks_queue_directly(self, tmp_path):
        bad_state = tmp_path / "rollout_state.json"
        bad_state.write_text('{"current_stage": 42}')
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[],
                kill_switch=False, capability_rules={"follow_up_probe": "allowed"},
                rollout_state_path=str(bad_state),
            ),
        )
        mc._queue_vdp_follow_ups(_scope())
        assert mc._vdp_rollout_state_error is True
        assert not mc._vdp_state.get("follow_up_pending")
        assert len(mc.task_queue) == 0
        assert net.count == 0

    def test_valid_rollout_state_clears_error(self, tmp_path):
        store = RolloutStateStore(current_stage="m2")
        store_path = tmp_path / "rollout_state.json"
        store.save(store_path)
        mc = _new_mc(
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[],
                kill_switch=False, capability_rules={"follow_up_probe": "allowed"},
                rollout_state_path=str(store_path),
            ),
        )
        loaded = mc._vdp_rollout_store()
        assert loaded is not None
        assert loaded.current_stage == "m2"
        assert mc._vdp_rollout_state_error is False


class TestRealConfigM3bReachMc:
    """Lane E: MC reaches m3b from REAL VdpModeSettings (production path)."""

    def test_hypothesis_hook_records_m3b_stage(self, tmp_path):
        progression_path = tmp_path / "progression.json"
        progression_path.write_text(json.dumps([
            {"stage": s, "drill_id": f"drill-{s}", "passed": True,
             "recorded_at": "2026-08-01T00:00:00Z"}
            for s in ("m0", "m1", "m2", "m3a")
        ]))
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=VdpModeSettings(
                mode="readonly_enforce",
                stage="m3b",
                progression_records_path=str(progression_path),
                capability_rules={"follow_up_probe": "allowed"},
                rollout_state_path="",
            ),
        )
        assert mc._vdp_rollout_gate().effective_stage() == "m3b"
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()}, scope_definition=_scope()
        )
        assert mc._vdp_state["vdp_active"] is True
        diffs = mc._vdp_state.get("shadow_diff", [])
        assert diffs
        assert all(d["stage"] == "m3b" for d in diffs)
        # progression-proven m3b queues read-only follow-ups (no network yet)
        tasks = [t for t in mc.task_queue if t.agent_type == "vdp_follow_up"]
        assert tasks
        assert net.count == 0

    def test_raise_without_progression_stays_at_m3a(self, tmp_path):
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=VdpModeSettings(
                mode="readonly_enforce",
                stage="m3b",
                progression_records_path=str(tmp_path / "missing.json"),
                capability_rules={"follow_up_probe": "allowed"},
                rollout_state_path="",
            ),
        )
        gate = mc._vdp_rollout_gate()
        assert gate.effective_stage() == "m3a"
        assert "stage_raise_requires_progression:m3b" in gate.cap_reasons()
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()}, scope_definition=_scope()
        )
        # raise denied -> effective m3a: read-only follow-ups still queue
        # (existing M3a behavior), but the state-changing rung is not granted
        assert mc._vdp_state["vdp_active"] is True
        assert mc._vdp_state["next_actions"]
        tasks = [t for t in mc.task_queue if t.agent_type == "vdp_follow_up"]
        assert tasks
        assert net.count == 0


class TestRolloutStoreIntegration:
    """24: store rollback caps the queue; read-only unaffected."""

    async def test_store_cap_rollback_and_read_only_dispatch(self, tmp_path):
        store_path = tmp_path / "rollout_state.json"
        store = RolloutStateStore(current_stage="m2", previous_stage="m2")
        store.save(store_path)

        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[],
                kill_switch=False, capability_rules={"follow_up_probe": "allowed"},
                rollout_state_path=str(store_path),
            ),
        )
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()}, scope_definition=_scope()
        )
        # store caps m3a -> m2: proposals saved, queue NOT injected
        assert mc._vdp_state["verdicts"]
        assert mc._vdp_state["next_actions"]
        assert not mc._vdp_state.get("follow_up_pending")
        assert len(mc.task_queue) == 0
        assert net.count == 0

        # rollback with the same previous stage keeps the cap at m2
        store.rollback("drill_failed")
        assert store.current_stage == "m2"
        assert store.previous_stage is None
        assert store.events[-1]["kind"] == "rollback"
        store.save(store_path)

        # fresh MC still capped: read-only dispatch executes (rollback does
        # not affect the read-only path)...
        mc2 = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[],
                kill_switch=False, capability_rules={"follow_up_probe": "allowed"},
                rollout_state_path=str(store_path),
            ),
        )
        read_only = _read_only_spec("task-ro-rollback")
        ro_result = await mc2._dispatch(_vdp_task(read_only))
        assert ro_result["data"]["status"] == "executed"
        assert net.count > 0

        # ...but a NEW state-changing dispatch stays blocked
        sc_spec = _state_changing_spec("task-sc-rollback")
        sc_spec["hitl_ticket"] = "HITL-99"
        sc_result = await mc2._dispatch(_vdp_task(sc_spec))
        assert sc_result["data"]["status"] == "blocked"
        assert sc_result["data"]["reason"] == "stage_below_m3b_for_state_change"


class TestIdempotencyNoResend:
    """25: same spec dispatched twice -> network called once."""

    async def test_second_dispatch_is_not_executed_duplicate(self):
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[],
                kill_switch=False, capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        spec = _read_only_spec("task-idem-1")
        task = _vdp_task(spec)
        first = await mc._dispatch(task)
        assert first["data"]["status"] == "executed"
        assert net.count == 1
        second = await mc._dispatch(task)
        assert second["data"]["status"] != "executed"
        assert net.count == 1


class TestSignerResolution:
    """26: fail-closed without key config; explicit file provider resolves."""

    def test_signer_fail_closed_without_key_config(self, monkeypatch):
        monkeypatch.delenv("SHIGOKU_VDP_SIGNING_KEY", raising=False)
        mc = _new_mc(
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[],
                kill_switch=False, capability_rules={},
            ),
        )
        assert mc._vdp_evidence_signer() is None

    def test_signer_explicit_file_provider(self, tmp_path, monkeypatch):
        from src.core.config.settings import VdpModeSettings
        from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner
        from src.core.engine.vdp_key_registry import VdpKeyRegistry

        monkeypatch.delenv("SHIGOKU_VDP_SIGNING_KEY", raising=False)
        key_file = tmp_path / "signing.key"
        key_file.write_text("11" * 32)
        # Lane H (SGK-2026-0423): FileKeyProvider now rejects key files with
        # group/other access (default umask would leave 0664), so pin 0600.
        key_file.chmod(0o600)
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("11" * 32))
        registry = VdpKeyRegistry()
        registry.register(signer.key_id, signer.public_key_bytes())
        registry_path = tmp_path / "key_registry.json"
        registry.save(registry_path)
        settings = VdpModeSettings(
            mode="readonly_enforce",
            key_provider="file",
            key_file_path=str(key_file),
            key_registry_path=str(registry_path),
        )
        mc = _new_mc(_vdp_mode=settings)
        resolved = mc._vdp_evidence_signer()
        assert resolved is not None
        assert resolved.key_id == signer.key_id
