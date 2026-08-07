"""
MasterConductor VDP follow-up real-path integration — SGK-2026-0421 Steps 13-14.

Real production path (fake network adapter only):

  0420 Hypothesis/NextAction
    → MasterConductor hook (readonly_enforce)
    → reason mapping
    → pending保存 (checkpoint)
    → queue (real _add_tasks / DynamicTaskQueue)
    → dispatch (real _dispatch_vdp_follow_up)
    → scope再検証 → capability/HITL/budget/idempotency
    → injected fake network adapter
    → AttemptRecord → EvidenceRecord
    → candidate verdict (never confirmed)
    → checkpoint/session保存 → M0 gate → session復元
"""
from __future__ import annotations

import socket
import time
from types import SimpleNamespace

import pytest

from src.core.domain.model.task import Task
from src.core.engine.master_conductor import MasterConductor
from src.core.engine.master_conductor_session_service import (
    build_async_session_payload,
    inject_vdp_section_to_session_payload,
)
from src.core.engine.task_queue import DynamicTaskQueue
from src.core.engine.vdp_m0_gate import VdpM0ContractGate
from src.core.models.vdp_contract import (
    EvidenceVerdictV1,
    HypothesisRecord,
    read_checkpoint,
)
from src.core.security.ethics_guard import ScopeDefinition


async def _async_noop(*args, **kwargs):
    pass


def _new_mc(**overrides) -> MasterConductor:
    mc = object.__new__(MasterConductor)
    mc.project_manager = SimpleNamespace(
        project_dir="/tmp/shigoku-vdp-followup-integ",
        save_session=_async_noop,
    )
    mc.task_queue = DynamicTaskQueue()
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
    mc._injected_task_ids = set()
    mc._derived_task_count = 0
    mc._owned_injection_targets = set()
    mc._current_session = SimpleNamespace(session_id="test-followup")
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
                "signal_id": "uuid-1",
                "entity_type": "endpoint",
                "url": "https://api.example.com/items",
                "method": "GET",
                "primary_label": "items",
                "candidate_labels": ["object"],
                "confidence": 0.9,
                "auth_context": None,
                "params": [{"name": "id", "location": "query"}],
                "status": "active",
            },
            {
                "signal_id": "uuid-2",
                "entity_type": "endpoint",
                "url": "https://api.example.com/login",
                "method": "POST",
                "primary_label": "login",
                "candidate_labels": ["auth"],
                "confidence": 0.9,
                "auth_context": None,
                "params": [{"name": "username", "location": "form"}],
                "status": "active",
            },
            {
                "signal_id": "uuid-3",
                "entity_type": "endpoint",
                "url": "https://api.example.com/search",
                "method": "GET",
                "primary_label": "search",
                "candidate_labels": ["render"],
                "confidence": 0.9,
                "auth_context": None,
                "params": [],
                "status": "active",
            },
        ]
    }


def _scope() -> ScopeDefinition:
    return ScopeDefinition(
        program_name="t",
        in_scope_domains=["api.example.com"],
        out_of_scope_domains=[],
        max_requests_per_minute=1000,
    )


class _FakeNetwork:
    def __init__(self):
        self.calls = []

    async def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return _FakeResponse(200, '{"ok": true}')

    @property
    def count(self) -> int:
        return len(self.calls)


class _FakeResponse:
    def __init__(self, status: int = 200, body: str = '{"ok": true}'):
        self.status = status
        self.body = body
        self.elapsed = 0.01


class TestRealPath:
    def test_capability_matrix_requires_explicit_allow(self):
        mc = _new_mc(
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce",
                label_leakage_denylist=[],
                kill_switch=False,
                capability_rules={},
            )
        )
        assert mc._vdp_capability_matrix().get_level("follow_up_probe").value == "prohibited"

    def test_capability_matrix_uses_explicit_rule(self):
        mc = _new_mc(
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce",
                label_leakage_denylist=[],
                kill_switch=False,
                capability_rules={"follow_up_probe": "allowed"},
            )
        )
        assert mc._vdp_capability_matrix().get_level("follow_up_probe").value == "allowed"

    async def test_full_path_hypothesis_to_restore(self, tmp_path):
        import json
        from pathlib import Path

        from src.core.engine.vdp_session_reader import read_session_compat

        net = _FakeNetwork()
        checkpoint_path = tmp_path / "vdp_checkpoint.json"
        session_path = tmp_path / "session_state.json"

        async def _save_session(session_data, filename=None):
            target = Path(mc.project_manager.project_dir) / (filename or "session_state.json")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                json.dumps(session_data, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )

        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[], kill_switch=False,
                capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        mc.project_manager = SimpleNamespace(
            project_dir=str(tmp_path), save_session=_save_session
        )

        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()},
            scope_definition=_scope(),
            checkpoint_path=str(checkpoint_path),
        )

        # --- reason mapping → pending保存 → queue -------------------------
        assert mc._vdp_state["vdp_active"] is True
        assert mc._vdp_state["next_actions"], "NextActions must be built"
        assert mc._vdp_state["follow_up_pending"], "read-only follow-ups must pend"
        executable = {s["evidence_gap"] for s in mc._vdp_state["follow_up_pending"]}
        # Exact replay has a truthful M3a executor contract.
        assert "payload_request_mismatch" in executable
        # Semantic comparison cannot be replaced by a generic GET.
        assert "authz_impact_not_proven" not in executable
        # cross-account gap is NOT executable in M3a (missing precondition)
        assert "untested_no_second_account" not in executable
        # state-changing gaps are never queued
        assert not any(s["risk_class"] == "state_changing" for s in mc._vdp_state["follow_up_pending"])

        queued_ids = set(mc._vdp_state.get("follow_up_queued", []))
        assert queued_ids, "follow-ups must be queued"
        assert len(queued_ids) == len(mc._vdp_state["follow_up_pending"])
        assert {t.id for t in mc.task_queue} >= queued_ids

        # checkpoint written BEFORE queue holds pending NextActions
        ck = read_checkpoint(checkpoint_path)
        assert ck is not None
        assert ck["pending_next_actions"]  # queue投入前にpending保存
        assert "budget" in ck
        assert "idempotency_guard" in ck
        assert "state_change_guard" in ck
        assert ck["follow_up_pending"]

        # --- dispatch → scope/capability/budget → fake network → records --
        tasks = [t for t in mc.task_queue if t.agent_type == "vdp_follow_up"]
        assert tasks
        for task in tasks:
            result = await mc._dispatch(task)
            assert result["success"] is True, result
            assert result["data"]["status"] == "executed"
        assert net.count > 0
        assert mc._vdp_state["attempts"], "AttemptRecord must be saved"
        assert mc._vdp_state["evidence_records"], "EvidenceRecord must be saved"
        hypothesis_ids = {
            item["hypothesis_id"] for item in mc._vdp_state["hypotheses"]
        }
        verdict_ids = {item["verdict_id"] for item in mc._vdp_state["verdicts"]}
        attempt_ids = {item["attempt_id"] for item in mc._vdp_state["attempts"]}
        assert all(
            item["hypothesis_id"] in hypothesis_ids
            for item in mc._vdp_state["attempts"]
        )
        assert all(
            item["attempt_id"] in attempt_ids
            for item in mc._vdp_state["evidence_records"]
        )
        assert all(
            item["hypothesis_id"] in hypothesis_ids
            for item in mc._vdp_state["verdicts"]
        )
        assert all(
            item["verdict_id"] in verdict_ids
            for item in mc._vdp_state["next_actions"]
        )
        for att in mc._vdp_state["attempts"]:
            assert att["state"] == "evidence_saved"
        # verdicts remain candidate — never confirmed
        for v in mc._vdp_state["verdicts"]:
            assert v["status"] in ("candidate", "untested")

        # post-send checkpoint advances with live budget + idempotency state
        post_send = read_checkpoint(checkpoint_path)
        assert post_send is not None
        assert post_send["budget"]["counters"]["requests_used"] == net.count
        assert post_send["budget"]["counters"]["follow_ups_used"] == len(tasks)
        registered = set(post_send["idempotency_guard"]["registered_ids"])
        assert registered == {item["attempt_id"] for item in mc._vdp_state["attempts"]}

        resumed = _new_mc()
        assert resumed._restore_vdp_runtime_checkpoint(checkpoint_path) is True
        assert resumed._vdp_exec_budget().snapshot()["requests_used"] == net.count
        for attempt_id in registered:
            assert resumed._vdp_idem_guard().is_registered(attempt_id)

        # --- session保存 → M0 gate → restore -----------------------------
        session_path = tmp_path / "session_state.json"
        await mc.async_save_session(str(session_path))
        restored = read_session_compat(session_path)
        assert restored is not None
        vdp = restored.get("vdp_contract", {})
        assert vdp.get("vdp_active") is True
        assert vdp.get("attempts"), "attempts must survive session restore"
        assert vdp.get("evidence_records"), "evidence must survive session restore"
        m0 = VdpM0ContractGate().validate(restored)
        assert m0.passed, f"M0 gate failed: {m0.detail} {m0.reason_codes}"

    def test_shadow_mode_never_touches_queue_or_network(self):
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="shadow", label_leakage_denylist=[], kill_switch=False
            ),
        )
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()}, scope_definition=_scope()
        )
        assert mc._vdp_state["next_actions"]
        assert not mc._vdp_state.get("follow_up_pending")
        assert len(mc.task_queue) == 0
        assert net.count == 0

    def test_readonly_enforce_without_scope_queues_nothing(self):
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[], kill_switch=False,
                capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()}, scope_definition=None
        )
        assert not mc._vdp_state.get("follow_up_pending")
        assert len(mc.task_queue) == 0
        assert net.count == 0

    def test_kill_switch_blocks_queue_injection(self):
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[], kill_switch=True,
                capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()}, scope_definition=_scope()
        )
        assert not mc._vdp_state.get("follow_up_pending")
        assert len(mc.task_queue) == 0

    def test_enqueue_failure_preserves_pending_next_actions(self, tmp_path):
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[], kill_switch=False,
                capability_rules={"follow_up_probe": "allowed"},
            ),
        )

        def _boom(tasks, source="unknown"):
            raise RuntimeError("queue full")

        mc._add_tasks = _boom
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()},
            scope_definition=_scope(),
            checkpoint_path=str(tmp_path / "ck.json"),
        )
        failures = mc._vdp_state.get("follow_up_failures", [])
        assert failures
        assert all(f["reason"] == "follow_up_enqueue_failed" for f in failures)
        assert mc._vdp_state["run_health"]["run_state"] == "degraded"
        # NextActions are NOT lost (constraint H)
        assert mc._vdp_state["next_actions"]
        assert mc._vdp_state["follow_up_pending"]

    def test_partial_enqueue_failure_is_not_marked_queued(self, tmp_path):
        mc = _new_mc(
            network_client=_FakeNetwork(),
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[], kill_switch=False,
                capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        mc._add_tasks = lambda tasks, source="unknown": 0
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()},
            scope_definition=_scope(),
            checkpoint_path=str(tmp_path / "ck.json"),
        )
        assert mc._vdp_state.get("follow_up_pending")
        assert not mc._vdp_state.get("follow_up_queued")
        failures = mc._vdp_state.get("follow_up_failures", [])
        assert failures
        assert all(item["reason"] == "follow_up_enqueue_failed" for item in failures)
        assert mc._vdp_state["run_health"]["run_state"] == "degraded"

    async def test_dispatch_readmits_scope_before_communication(self):
        """queue後も通信直前に再度admission: dispatch時のscope再検証で停止する。"""
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[], kill_switch=False,
                capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()}, scope_definition=_scope()
        )
        tasks = [t for t in mc.task_queue if t.agent_type == "vdp_follow_up"]
        assert tasks
        # Tamper the spec's scope snapshot: dispatch-time revalidation must block
        spec = tasks[0].params["vdp_follow_up_spec"]
        spec["scope_domains"] = ["other.example.com"]
        result = await mc._dispatch(tasks[0])
        assert result["data"]["status"] == "blocked"
        assert net.count == 0

    async def test_dispatch_kill_switch_blocks_communication(self):
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[], kill_switch=False,
                capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()}, scope_definition=_scope()
        )
        tasks = [t for t in mc.task_queue if t.agent_type == "vdp_follow_up"]
        assert tasks
        setattr(mc._vdp_mode, 'kill_switch', True)
        result = await mc._dispatch(tasks[0])
        assert result["data"]["status"] == "blocked"
        assert net.count == 0

    async def test_writer_backpressure_is_persisted_and_degraded(self, tmp_path):
        class _FullWriter:
            async def enqueue_evidence(self, evidence):
                raise RuntimeError("queue full")

        checkpoint_path = tmp_path / "ck.json"
        mc = _new_mc(
            network_client=_FakeNetwork(),
            _vdp_writer=_FullWriter(),
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[], kill_switch=False,
                capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()},
            scope_definition=_scope(),
            checkpoint_path=str(checkpoint_path),
        )
        task = next(t for t in mc.task_queue if t.agent_type == "vdp_follow_up")
        result = await mc._dispatch(task)
        assert result["success"] is True
        assert result["data"]["status"] == "degraded"
        assert mc._vdp_state["attempts"]
        assert mc._vdp_state["evidence_records"]
        assert mc._vdp_state["run_health"]["run_state"] == "degraded"
        checkpoint = read_checkpoint(checkpoint_path)
        assert checkpoint is not None
        assert checkpoint["idempotency_guard"]["registered_ids"]


class TestRealPathNoSockets:
    async def test_full_path_opens_zero_sockets(self, tmp_path, monkeypatch):
        """Fake network adapter only — no real sockets anywhere in the path."""
        import socket as _socket

        real_create = _socket.socket
        calls = []

        def fake_socket(*a, **kw):
            calls.append(a)
            raise AssertionError("socket() must not be called in the real path test")

        monkeypatch.setattr(_socket, "socket", fake_socket)
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[], kill_switch=False,
                capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()},
            scope_definition=_scope(),
            checkpoint_path=str(tmp_path / "ck.json"),
        )
        for task in [t for t in mc.task_queue if t.agent_type == "vdp_follow_up"]:
            result = await mc._dispatch(task)
            assert result["data"]["status"] == "executed"
        assert net.count > 0
        assert calls == [], f"socket() called {len(calls)} times"
