"""
SGK-2026-0423 Lane D — VDP failure drills with recovery oracle (TDD).

Every drill injects a single failure into the REAL production path (fake
transport only — zero sockets) and asserts, per ``DrillSpec``:

- the injection point
- the exact stop position (status / reason)
- the saved state (session / checkpoint / run_health where applicable)
- resumable: the pipeline can continue after recovery without data loss
- resendable: the SAME attempt may be transmitted again (False when
  idempotency or StateChangeGuard blocks the resend)

Drills 1-4, 11, 12 exercise the executor/generator directly (style of
``tests/unit/engine/test_vdp_follow_up_resilience.py``); drills 5-10, 13, 14
exercise MasterConductor hooks (style of
``tests/core/engine/test_master_conductor_vdp_follow_up.py``).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from types import SimpleNamespace

from src.core.domain.scope.vdp_scope_validator import revalidate_scope_for_request
from src.core.engine.vdp_budget import VdpExecutionBudget
from src.core.models.vdp_contract import (
    IdempotencyGuard,
    StateChangeGuard,
    atomic_write_checkpoint,
    read_checkpoint,
)

from tests.core.engine.test_master_conductor_vdp_follow_up import (
    _FakeNetwork,
    _new_mc,
    _scope,
    _signal_bundle,
)
from tests.unit.engine.test_vdp_follow_up_resilience import (
    _Net,
    _Resp,
    _ex,
    _run,
    _spec,
)


@dataclass(frozen=True)
class DrillSpec:
    """Contract for one failure drill (Lane D recovery oracle).

    - drill_id: stable identifier matching the Lane D drill list.
    - injection: what is injected / primed to provoke the failure.
    - expected_stop: exact stop position (status / run_state).
    - reason_code: expected failure reason code.
    - saved_state: the durable state that must survive the failure.
    - resumable: the pipeline can continue after recovery without data loss.
    - resendable: the SAME attempt may be transmitted again (False when
      idempotency / StateChangeGuard blocks the resend).
    """

    drill_id: str
    injection: str
    expected_stop: str
    reason_code: str
    saved_state: str
    resumable: bool
    resendable: bool


_URL = "https://api.example.com/items"


def _m3b_drill_mc(
    tmp_path,
    monkeypatch,
    *,
    suffix: str = "9",
    rollout_state_path: str = "",
    writer=None,
    net=None,
):
    """Real-config m3b drill setup (Lane F / Lane J-2 / Lane L-2 / L-3).

    File key + registry + passed progression file + a seeded
    state-changing NextAction (real producers) + an APPROVED HITL ledger
    ticket targeting that NextAction (real registration path). Returns
    ``(mc, net, observation, na)``; the caller queues with its own
    checkpoint path and dispatches. ``writer`` overrides the evidence
    writer (e.g. a failing writer for backpressure drills); ``net``
    overrides the fake transport (e.g. a remote-applied-then-timeout
    client for the Lane L-3 drill).
    """
    from src.core.config.settings import VdpModeSettings
    from src.core.domain.model.task import Task
    from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner
    from src.core.engine.vdp_follow_up import build_next_action_record
    from src.core.engine.vdp_key_registry import VdpKeyRegistry
    from src.core.engine.vdp_observation_adapter import ObservationAdapter
    from src.core.models.vdp_contract import HypothesisRecord

    monkeypatch.delenv("SHIGOKU_VDP_SIGNING_KEY", raising=False)
    key_file = tmp_path / f"signing{suffix}.key"
    key_file.write_text("11" * 32)
    key_file.chmod(0o600)
    signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("11" * 32))
    registry = VdpKeyRegistry()
    registry.register(signer.key_id, signer.public_key_bytes())
    registry_path = tmp_path / f"key_registry{suffix}.json"
    registry.save(registry_path)
    progression_path = tmp_path / f"progression{suffix}.json"
    progression_path.write_text(
        json.dumps(
            [
                {"stage": s, "drill_id": f"drill-{s}", "passed": True,
                 "recorded_at": "2026-08-01T00:00:00Z"}
                for s in ("m0", "m1", "m2", "m3a")
            ]
        ),
        encoding="utf-8",
    )

    net = net if net is not None else _FakeNetwork()
    mc_kwargs = dict(
        network_client=net,
        _vdp_mode=VdpModeSettings(
            mode="readonly_enforce",
            stage="m3b",
            key_provider="file",
            key_file_path=str(key_file),
            key_registry_path=str(registry_path),
            progression_records_path=str(progression_path),
            capability_rules={"follow_up_probe": "allowed"},
            rollout_state_path=rollout_state_path,
        ),
    )
    if writer is not None:
        mc_kwargs["_vdp_writer"] = writer
    mc = _new_mc(**mc_kwargs)
    observation = ObservationAdapter().adapt_endpoint_signal({
        "url": _URL,
        "method": "POST",
        "entity_type": "endpoint",
        "primary_label": "items",
        "params": [],
    })
    assert observation is not None
    hyp = HypothesisRecord(
        hypothesis_id=f"hyp-drill{suffix}",
        observation_id=observation.observation_id,
        asset=_URL,
        capability="object_read_write_delete",
        hypothesis_text="state change probe",
        trust_boundary="unauthenticated",
        actors=["unauth"],
    )
    mc._vdp_state["vdp_active"] = True
    mc._vdp_state["hypotheses"] = [hyp.to_dict()]
    mc._vdp_state["verdicts"] = [{
        "verdict_id": f"vrd-drill{suffix}",
        "hypothesis_id": f"hyp-drill{suffix}",
        "status": "candidate",
        "schema_version": 1,
    }]
    na = build_next_action_record(
        f"vrd-drill{suffix}", hyp, "state_change_not_verified"
    )
    mc._vdp_state["next_actions"] = [na.to_dict()]
    # APPROVED ledger ticket targeting this NextAction (the REAL registration
    # path — build_pending_hitl_ticket is used internally by the MC).
    ticket_task = Task(
        id=f"task-drill{suffix}",
        name="vdp_follow_up:state_change_not_verified",
        agent_type="vdp_follow_up",
        action="run",
        params={"vdp_follow_up_spec": {"next_action_id": na.next_action_id}},
    )
    ticket_id = mc._register_pending_hitl_ticket(
        ticket_task,
        {
            "scenario_id": "vdp_state_change",
            "reasons": ["state_change_not_verified"],
        },
        "enforce",
    )
    assert mc.set_pending_hitl_status(ticket_id, "approved")
    return mc, net, observation, na


class _SlowNet(_Net):
    """Fake client whose responses report a very high latency (60_000 ms)."""

    async def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        resp = _Resp(self.status, self.body)
        resp.elapsed = 60.0  # 60_000 ms — crosses circuit_breaker_latency_ms_threshold
        return resp


class TestCircuitBreakerDrills:
    """Drills 1-4: 429/5xx/timeout/latency circuit breaker + idempotency."""

    def test_drill_429_spike(self, monkeypatch):
        """429s past threshold → blocked circuit_open_429; resumable after
        cooldown; the same attempt is never resent (idempotency)."""
        import src.core.engine.vdp_budget as vdp_budget_mod

        fake_now = {"t": 1000.0}
        monkeypatch.setattr(vdp_budget_mod.time, "monotonic", lambda: fake_now["t"])
        budget = VdpExecutionBudget(max_requests=100, per_asset_burst=100)
        for _ in range(budget.circuit_breaker_429_threshold):
            budget.record_response(_URL, 429)

        (ex, net, writer, _b) = _ex(budget=budget)
        spec = _spec()
        result = _run(ex.execute(spec))
        assert result.status == "blocked"
        assert "circuit_open_429" in result.reason
        assert net.count == 0  # zero communication while the circuit is open

        # resumable after cooldown: the circuit resets and the SAME pipeline
        # can execute again (a fresh attempt is admitted).
        fake_now["t"] += budget.circuit_breaker_cooldown_seconds + 1
        resumed = _run(ex.execute(spec))
        assert resumed.status == "executed"
        assert net.count == 1

        # resendable=False for the same attempt: idempotency blocks a resend.
        again = _run(ex.execute(spec))
        assert again.status == "manual_review"
        assert "idempotency_duplicate" in again.reason
        assert net.count == 1

        drill = DrillSpec(
            drill_id="drill_429_spike",
            injection="budget primed with 429s past the 429 threshold",
            expected_stop="blocked (no communication)",
            reason_code="circuit_open_429",
            saved_state="circuit open; requests_used 0",
            resumable=True,
            resendable=False,
        )
        assert drill.expected_stop == "blocked (no communication)"
        assert drill.reason_code == "circuit_open_429"
        assert drill.resumable is True
        assert drill.resendable is False

    def test_drill_5xx_spike(self):
        """5xx past threshold → blocked circuit_open_5xx; zero sends."""
        budget = VdpExecutionBudget(max_requests=100, per_asset_burst=100)
        for _ in range(budget.circuit_breaker_5xx_threshold):
            budget.record_response(_URL, 500)

        (ex, net, writer, _b) = _ex(budget=budget)
        result = _run(ex.execute(_spec()))
        assert result.status == "blocked"
        assert "circuit_open_5xx" in result.reason
        assert net.count == 0

        drill = DrillSpec(
            drill_id="drill_5xx_spike",
            injection="budget primed with 5xx past the 5xx threshold",
            expected_stop="blocked (no communication)",
            reason_code="circuit_open_5xx",
            saved_state="circuit open; requests_used 0",
            resumable=True,
            resendable=False,
        )
        assert drill.reason_code == "circuit_open_5xx"
        assert drill.resumable is True
        assert drill.resendable is False

    def test_drill_timeout(self):
        """Transport timeout → degraded network_error; budget records the
        timeout; attempt state failed; no evidence; same attempt NOT resent."""
        class _BoomNet(_Net):
            async def request(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                raise TimeoutError("dependency stopped")

        (ex, net, writer, budget) = _ex(net=_BoomNet())
        spec = _spec()
        result = _run(ex.execute(spec))
        assert result.status == "degraded"
        assert result.reason == "network_error"
        assert result.requests_made == 1
        assert net.count == 1
        # the budget recorded the timeout for the asset (public serialization)
        circuits = budget.to_checkpoint_dict()["circuits"]
        assert circuits[_URL]["timeout_count"] == 1
        # attempt state failed, no evidence produced
        assert result.attempt is not None
        assert result.attempt["state"] == "failed"
        assert result.evidence is None

        # same attempt re-dispatched → NOT resent (idempotency duplicate)
        again = _run(ex.execute(spec))
        assert again.status == "manual_review"
        assert "idempotency_duplicate" in again.reason
        assert net.count == 1

        drill = DrillSpec(
            drill_id="drill_timeout",
            injection="fake client raises TimeoutError on send",
            expected_stop="degraded (attempt failed, no evidence)",
            reason_code="network_error",
            saved_state="budget timeout_count=1; attempt state=failed",
            resumable=True,
            resendable=False,
        )
        assert drill.reason_code == "network_error"
        assert drill.resumable is True
        assert drill.resendable is False

    def test_drill_latency_degradation(self):
        """Very high latency (60_000 ms) crosses the latency threshold →
        subsequent execute blocked circuit_open_latency (pre-communication)."""
        budget = VdpExecutionBudget(
            max_requests=100, per_asset_burst=100,
            circuit_breaker_latency_sample_window=1,
        )
        (ex, net, writer, _b) = _ex(net=_SlowNet(), budget=budget)

        first = _run(ex.execute(_spec(hypothesis_id="hyp-lat-1")))
        assert first.status == "executed"
        assert net.count == 1

        # the latency record opened the circuit → the NEXT attempt is blocked
        # before any communication.
        second = _run(ex.execute(_spec(hypothesis_id="hyp-lat-2")))
        assert second.status == "blocked"
        assert "circuit_open_latency" in second.reason
        assert net.count == 1  # the second attempt never reached the network

        drill = DrillSpec(
            drill_id="drill_latency_degradation",
            injection="fake client reports 60_000 ms elapsed",
            expected_stop="blocked (pre-communication circuit open)",
            reason_code="circuit_open_latency",
            saved_state="high_latency_count crossed sample window",
            resumable=True,
            resendable=False,
        )
        assert drill.reason_code == "circuit_open_latency"
        assert drill.resumable is True
        assert drill.resendable is False


class TestQueueAndCheckpointDrills:
    """Drills 5-10: queue saturation, checkpoint write/read failures,
    interrupt-after-send, checkpoint recovery resume."""

    def test_drill_5_queue_saturation(self, tmp_path):
        """mc._add_tasks raises → follow_up_enqueue_failed in
        follow_up_failures + shadow_decisions; next_actions AND
        follow_up_pending preserved; run_health degraded."""
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
        decisions = [
            d for d in getattr(mc, "_shadow_decisions", [])
            if d.get("scope") == "vdp_follow_up"
        ]
        assert decisions
        assert all(d["reason"] == "follow_up_enqueue_failed" for d in decisions)
        # NextActions and pending follow-ups are NOT lost (constraint H)
        assert mc._vdp_state["next_actions"]
        assert mc._vdp_state["follow_up_pending"]
        assert mc._vdp_state["run_health"]["run_state"] == "degraded"
        assert mc._vdp_state["run_health"]["reason"] == "follow_up_enqueue_failed"
        assert len(mc.task_queue) == 0
        assert net.count == 0

        drill = DrillSpec(
            drill_id="drill_queue_saturation",
            injection="mc._add_tasks raises RuntimeError",
            expected_stop="degraded (queue not injected)",
            reason_code="follow_up_enqueue_failed",
            saved_state="next_actions + follow_up_pending preserved; run_health degraded",
            resumable=True,
            resendable=True,
        )
        assert drill.reason_code == "follow_up_enqueue_failed"
        assert drill.resumable is True
        assert drill.resendable is True  # no communication ever happened

    async def test_drill_6_disk_full_checkpoint(self, tmp_path, monkeypatch):
        """atomic_write_checkpoint raises OSError → save False,
        checkpoint_write_failed degraded, dispatch success False, in-memory
        state consistent, no partial official artifact on disk."""
        from src.core.models import vdp_contract as vdp_contract_mod

        net = _FakeNetwork()
        checkpoint_path = tmp_path / "ck.json"
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
            checkpoint_path=str(checkpoint_path),
        )
        tasks = [t for t in mc.task_queue if t.agent_type == "vdp_follow_up"]
        assert tasks

        def _boom(data, path):
            raise OSError(28, "No space left on device")

        # SGK-2026-0439: the queued render `/search` payload spec now
        # carries masked request material (mask-at-ingest) and is
        # executable; S07 exact_request_material_unavailable applies only to
        # genuinely material-less payload specs (regression). The checkpoint
        # drill dispatches a healthy executable spec to exercise the
        # post-send checkpoint failure path.
        from tests.unit.engine.test_vdp_rollout_mc_integration import (
            _read_only_spec,
            _vdp_task,
        )

        material_less = _vdp_task(
            dict(_read_only_spec("task-pm-ck6"), evidence_gap="payload_request_mismatch")
        )
        blocked = await mc._dispatch(material_less)
        assert blocked["data"]["status"] == "manual_review"
        assert blocked["data"]["reason"] == "exact_request_material_unavailable"
        healthy = _vdp_task(_read_only_spec("task-ro-ck6"))
        monkeypatch.setattr(vdp_contract_mod, "atomic_write_checkpoint", _boom)
        for task in (healthy,):
            result = await mc._dispatch(task)
            assert result["data"]["status"] == "executed"  # send completed
            assert result["success"] is False, result
            assert result["error"] == "checkpoint_write_failed"

        assert mc._vdp_state["run_health"]["run_state"] == "degraded"
        assert mc._vdp_state["run_health"]["reason"] == "checkpoint_write_failed"
        # in-memory state stays consistent — no data loss
        assert mc._vdp_state["attempts"]
        assert mc._vdp_state["evidence_records"]
        # no partial official artifact: the on-disk checkpoint is still the
        # queue-phase one (atomic write never left a torn file)
        on_disk = read_checkpoint(checkpoint_path)
        assert on_disk is not None
        assert on_disk["idempotency_guard"]["registered_ids"] == []

        drill = DrillSpec(
            drill_id="drill_disk_full_checkpoint",
            injection="atomic_write_checkpoint raises OSError",
            expected_stop="dispatch success=False (checkpoint_write_failed)",
            reason_code="checkpoint_write_failed",
            saved_state="attempts/evidence in memory; run_health degraded; no torn artifact",
            resumable=True,
            resendable=False,
        )
        assert drill.reason_code == "checkpoint_write_failed"
        assert drill.resumable is True
        assert drill.resendable is False  # same attempt idempotency-blocked

    def test_drill_7_partial_checkpoint_save(self, tmp_path):
        """Truncated checkpoint JSON → read_checkpoint None →
        _restore_vdp_runtime_checkpoint False → checkpoint_restore_failed,
        queue skipped, no double send."""
        checkpoint_path = tmp_path / "ck.json"
        checkpoint_path.write_text('{"vdp_contract_version": 1, "budget": {', encoding="utf-8")
        assert read_checkpoint(checkpoint_path) is None

        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[], kill_switch=False,
                capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        assert mc._restore_vdp_runtime_checkpoint(str(checkpoint_path)) is False
        assert mc._vdp_state["run_health"]["run_state"] == "degraded"
        assert mc._vdp_state["run_health"]["reason"] == "checkpoint_restore_failed"

        # queue hook skips injection on restore failure — nothing is sent
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()},
            scope_definition=_scope(),
            checkpoint_path=str(checkpoint_path),
        )
        assert not mc._vdp_state.get("follow_up_pending")
        assert len(mc.task_queue) == 0
        assert net.count == 0

        drill = DrillSpec(
            drill_id="drill_partial_checkpoint_save",
            injection="truncated JSON at the checkpoint path",
            expected_stop="queue skipped (restore failed)",
            reason_code="checkpoint_restore_failed",
            saved_state="run_health degraded; no follow-ups queued",
            resumable=True,
            resendable=False,
        )
        assert drill.reason_code == "checkpoint_restore_failed"
        assert drill.resumable is True  # a repaired checkpoint restores cleanly
        assert drill.resendable is False

    def test_drill_8_checkpoint_hash_tamper(self, tmp_path):
        """Valid checkpoint with a corrupted budget dict → budget restore
        None → checkpoint_budget_restore_failed, fail-closed (no
        communication)."""
        from src.core.engine.vdp_session_reader import (
            build_vdp_checkpoint_payload,
            restore_vdp_checkpoint_payload,
        )

        checkpoint_path = tmp_path / "ck.json"
        payload = build_vdp_checkpoint_payload(
            "hyp-ck-1",
            VdpExecutionBudget(max_requests=100, per_asset_burst=100),
            IdempotencyGuard(),
            StateChangeGuard(),
            pending_next_actions=[{"next_action_id": "nxt-ck-1"}],
        )
        atomic_write_checkpoint(payload, checkpoint_path)
        # corrupt the budget section (tampered / hash-mismatched payload)
        data = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        data["budget"]["counters"] = "corrupted"
        checkpoint_path.write_text(json.dumps(data), encoding="utf-8")

        budget, _idem, _scg = restore_vdp_checkpoint_payload(data)
        assert budget is None  # misparse → fail-closed

        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[], kill_switch=False,
                capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        assert mc._restore_vdp_runtime_checkpoint(str(checkpoint_path)) is False
        assert mc._vdp_state["run_health"]["run_state"] == "degraded"
        assert mc._vdp_state["run_health"]["reason"] == "checkpoint_budget_restore_failed"

        # fail-closed: nothing is queued, nothing is sent
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()},
            scope_definition=_scope(),
            checkpoint_path=str(checkpoint_path),
        )
        assert not mc._vdp_state.get("follow_up_pending")
        assert len(mc.task_queue) == 0
        assert net.count == 0

        drill = DrillSpec(
            drill_id="drill_checkpoint_hash_tamper",
            injection="corrupted budget dict inside a valid checkpoint",
            expected_stop="restore False (queue skipped)",
            reason_code="checkpoint_budget_restore_failed",
            saved_state="run_health degraded; no communication",
            resumable=True,
            resendable=False,
        )
        assert drill.reason_code == "checkpoint_budget_restore_failed"
        assert drill.resumable is True
        assert drill.resendable is False

    async def test_drill_9_interrupt_after_send_before_save(self, tmp_path, monkeypatch):
        """Send completed but _save_vdp_runtime_checkpoint returns False
        (interrupt) → resume: re-dispatch the same task → the WRITE-AHEAD
        journal (state "sent") blocks the second send; the StateChangeGuard
        still holds the sent-but-not-confirmed attempt (no auto-resend of
        state changes).

        The sent-but-unsaved state is produced by the REAL production path:
        an m3b follow-up authorized by an APPROVED LEDGER ticket executes
        through the rollout gate; the dispatch writes the durable WAL
        ``begin`` BEFORE the send and the executor/guard record the sent
        fact at the send boundary — this drill performs NO manual guard or
        journal updates."""
        from src.core.engine.vdp_state_change_journal import StateChangeJournal

        mc, net, observation, _na = _m3b_drill_mc(tmp_path, monkeypatch)
        checkpoint_path = tmp_path / "ck.json"
        mc._queue_vdp_follow_ups(
            _scope(),
            checkpoint_path=str(checkpoint_path),
            observations=[observation],
        )
        tasks = [t for t in mc.task_queue if t.agent_type == "vdp_follow_up"]
        assert tasks, "the ledger-approved m3b follow-up must be queued"

        # interrupt: the send happened but the checkpoint save fails
        monkeypatch.setattr(mc, "_save_vdp_runtime_checkpoint", lambda path: False)
        first = await mc._dispatch(tasks[0])
        assert first["data"]["status"] == "executed"
        assert first["success"] is False
        assert first["error"] == "checkpoint_write_failed"
        assert net.count == 1
        attempt_id = first["data"]["attempt_id"]

        # WAL durability: the journal durably recorded begin→sent BEFORE the
        # checkpoint save failed (write-ahead — the crash cannot lose it)
        journal = StateChangeJournal.for_checkpoint(checkpoint_path)
        assert journal.state(attempt_id) == "sent"
        # the in-memory guard mirrors the sent fact (NO manual updates here)
        guard = mc._vdp_state_change_guard()
        assert attempt_id in guard.to_dict()["sent_but_not_confirmed"]
        assert guard.is_safe_to_send(attempt_id) is False
        # the audit trail records the sent-but-not-persisted state change
        holds = [
            d for d in getattr(mc, "_shadow_decisions", [])
            if d.get("reason") == "state_change_sent_but_checkpoint_failed"
        ]
        assert holds

        # resume: re-dispatch the same task → the journal blocks the resend
        second = await mc._dispatch(tasks[0])
        assert second["data"]["status"] == "blocked"
        assert second["data"]["reason"] == "state_change_already_sent"
        assert net.count == 1  # no auto-resend

        drill = DrillSpec(
            drill_id="drill_interrupt_after_send_before_save",
            injection="_save_vdp_runtime_checkpoint returns False after send",
            expected_stop="executed send + failed save; resume blocked",
            reason_code="checkpoint_write_failed",
            saved_state="WAL journal sent + attempt sent-but-not-confirmed; no resend",
            resumable=True,
            resendable=False,
        )
        assert drill.resumable is True
        assert drill.resendable is False

    async def test_drill_10_checkpoint_recovery_resume(self, tmp_path):
        """After a successful dispatch with checkpoint, a NEW MC on the same
        checkpoint path restores budget+idempotency+state_change_guard →
        re-dispatch of the same task is NOT executed twice."""
        net = _FakeNetwork()
        checkpoint_path = tmp_path / "ck.json"
        mc1 = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[], kill_switch=False,
                capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        mc1._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()},
            scope_definition=_scope(),
            checkpoint_path=str(checkpoint_path),
        )
        tasks = [t for t in mc1.task_queue if t.agent_type == "vdp_follow_up"]
        assert tasks
        # SGK-2026-0439: the queued payload_request_mismatch spec now
        # carries masked request material and is executable; S07 blocks only
        # genuinely material-less payload specs (regression). The resume
        # drill exercises the checkpoint roundtrip with a healthy
        # executable spec.
        from tests.unit.engine.test_vdp_rollout_mc_integration import (
            _read_only_spec,
            _vdp_task,
        )

        healthy = _vdp_task(_read_only_spec("task-ro-ck10"))
        material_less = _vdp_task(
            dict(_read_only_spec("task-pm-ck10"), evidence_gap="payload_request_mismatch")
        )
        blocked = await mc1._dispatch(material_less)
        assert blocked["data"]["status"] == "manual_review"
        assert blocked["data"]["reason"] == "exact_request_material_unavailable"
        for task in (healthy,):
            result = await mc1._dispatch(task)
            assert result["data"]["status"] == "executed"
        registered = {item["attempt_id"] for item in mc1._vdp_state["attempts"]}
        assert registered

        # NEW MC with the same checkpoint path (simulated process restart)
        net2 = _FakeNetwork()
        mc2 = _new_mc(
            network_client=net2,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[], kill_switch=False,
                capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        assert mc2._restore_vdp_runtime_checkpoint(str(checkpoint_path)) is True
        assert mc2._vdp_exec_budget().snapshot()["requests_used"] == net.count
        for attempt_id in registered:
            assert mc2._vdp_idem_guard().is_registered(attempt_id)

        # re-dispatch the same tasks → not executed twice (net2 untouched)
        for task in (healthy,):
            result = await mc2._dispatch(task)
            assert result["data"]["status"] != "executed"
            assert "idempotency_duplicate" in result["data"]["reason"]
        assert net2.count == 0
        assert net.count == 1

        drill = DrillSpec(
            drill_id="drill_checkpoint_recovery_resume",
            injection="new MC restored from the post-send checkpoint",
            expected_stop="resume restored; re-dispatch deduplicated",
            reason_code="attempt:idempotency_duplicate",
            saved_state="budget + idempotency + state_change_guard restored",
            resumable=True,
            resendable=False,
        )
        assert drill.resumable is True
        assert drill.resendable is False


class TestScopeAndInputDrills:
    """Drills 11-12: redirect scope drift and malformed LLM proposals."""

    def test_drill_11_scope_drift_redirect(self):
        """302 with a Location out of scope → the redirect is never followed
        automatically (net.count == 1); the next hop would be re-validated as
        redirect_out_of_scope (manual scope review required)."""
        net = _Net(redirect_to="https://outside.example.com/landing")
        (ex, _n, writer, budget) = _ex(net=net)
        result = _run(ex.execute(_spec()))
        # the single initial request only — the redirect is never followed
        assert net.count == 1
        assert result.status == "executed"
        # the redirect was captured as a neutral fact (302), not followed
        assert result.evidence is not None
        assert result.evidence["execution_result"]["http_status"] == 302
        # a follow-up hop to the redirect target would fail scope
        # revalidation → manual scope review before any continuation
        hop = revalidate_scope_for_request(
            "https://outside.example.com/landing",
            scope_definition=_scope(),
            redirect_from=_URL,
        )
        assert hop.allowed is False
        assert hop.verdict == "redirect_out_of_scope"

        drill = DrillSpec(
            drill_id="drill_scope_drift_redirect",
            injection="fake client returns 302 with Location out of scope",
            expected_stop="executed (single hop; redirect never followed)",
            reason_code="redirect_out_of_scope",
            saved_state="evidence http_status=302; no second hop",
            resumable=False,
            resendable=False,
        )
        assert drill.reason_code == "redirect_out_of_scope"
        assert drill.resumable is False  # manual scope review required
        assert drill.resendable is False

    def test_drill_12_llm_malformed_proposal(self):
        """Malformed LLM-style proposal dicts are rejected by the 0420
        deterministic validator and never become hypotheses or tasks."""
        from src.core.engine.vdp_hypothesis_generator import (
            build_shadow_proposals,
            validate_proposal_dict,
        )

        malformed = {
            "capability": "magic_self_promote",
            "action_class": "run_arbitrary_shell",
            "risk_class": "state_changing",
            "scope_verdict": "allowed",
            "hypothesis_text": "x",
            "trust_boundary": "unauthenticated",
            "resource_owner": "account",
        }
        result = validate_proposal_dict(malformed)
        assert result.valid is False
        assert "capability_unknown=magic_self_promote" in result.errors
        assert "action_class_unknown=run_arbitrary_shell" in result.errors

        missing = validate_proposal_dict({})
        assert missing.valid is False
        for err in (
            "capability_missing", "action_class_missing", "risk_class_missing",
            "trust_boundary_missing", "resource_owner_missing",
            "scope_verdict_missing", "hypothesis_text_missing",
        ):
            assert err in missing.errors, err

        # rejected proposals never become tasks (no queue, no network)
        assert build_shadow_proposals([]) == []

        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[], kill_switch=False,
                capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        leaky_bundle = {
            "_signal_bundle": {
                "_endpoint_signals": [
                    {
                        "signal_id": "sig-leak-1",
                        "entity_type": "endpoint",
                        "url": "https://api.example.com/flag=1",
                        "method": "GET",
                        "primary_label": "items",
                        "candidate_labels": [],
                        "confidence": 0.9,
                        "auth_context": None,
                        "params": [],
                        "status": "active",
                    }
                ]
            }
        }
        mc._generate_vdp_hypotheses(leaky_bundle, scope_definition=_scope())
        assert mc._vdp_state["vdp_active"] is False
        assert not mc._vdp_state["hypotheses"]
        assert not mc._vdp_state["verdicts"]
        assert len(mc.task_queue) == 0
        assert net.count == 0
        rejected = [
            d for d in getattr(mc, "_shadow_decisions", [])
            if d.get("scope") == "vdp_rejected"
        ]
        assert rejected
        assert "flag_marker_detected" in rejected[0]["reasons"]

        drill = DrillSpec(
            drill_id="drill_llm_malformed_proposal",
            injection="malformed proposal dict (missing fields / unknown action)",
            expected_stop="rejected (vdp_active False; no queue)",
            reason_code="proposal_invalid",
            saved_state="vdp_active False; task_queue empty",
            resumable=True,
            resendable=False,
        )
        assert drill.resumable is True  # a corrected proposal can be re-run
        assert drill.resendable is False


class TestOperationalStopDrills:
    """Drills 13-14: mid-flight kill switch and key-provider stop."""

    async def test_drill_13_flag_switch_midflight(self):
        """Tasks queued with kill_switch=False, then the switch is flipped
        before dispatch → blocked kill_switch_active, zero communication,
        pending entry records execution_status/reason; resumable after the
        switch is lifted."""
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
        # SGK-2026-0434: the queued render `/search` spec carries the
        # payload_request_mismatch gap (destroyed material) and is honestly
        # blocked at S07; the kill-switch drill exercises the mid-flight
        # switch with a healthy executable gap on the SAME task (real
        # hypothesis/verdict lineage preserved).
        tasks[0].params["vdp_follow_up_spec"]["evidence_gap"] = (
            "authz_impact_not_proven"
        )

        setattr(mc._vdp_mode, "kill_switch", True)  # flipped mid-flight
        result = await mc._dispatch(tasks[0])
        assert result["data"]["status"] == "blocked"
        assert result["data"]["reason"] == "kill_switch_active"
        assert net.count == 0
        pending = [
            p for p in mc._vdp_state["follow_up_pending"]
            if p.get("task_id") == tasks[0].id
        ][0]
        assert pending["execution_status"] == "blocked"
        assert pending["execution_reason"] == "kill_switch_active"

        # resumable: lifting the switch lets the same pipeline continue
        setattr(mc._vdp_mode, "kill_switch", False)
        resumed = await mc._dispatch(tasks[0])
        assert resumed["data"]["status"] == "executed"
        assert net.count == 1

        drill = DrillSpec(
            drill_id="drill_flag_switch_midflight",
            injection="kill_switch flipped True between queue and dispatch",
            expected_stop="blocked (zero communication)",
            reason_code="kill_switch_active",
            saved_state="pending entry execution_status=blocked",
            resumable=True,
            resendable=True,
        )
        assert drill.reason_code == "kill_switch_active"
        assert drill.resumable is True
        assert drill.resendable is True

    async def test_drill_14_key_provider_stop(self, tmp_path, monkeypatch):
        """Signer unavailable (no signing key configured) → executed
        read-only dispatch still leaves the verdict candidate with
        signer_unavailable_hold; the rollout gate denies state-changing
        communication with signing_key_not_active.

        The m3b stage is reached through REAL ``VdpModeSettings`` with a
        passed progression file — NO stage-derivation monkeypatch anywhere;
        the dispatched state-changing task is blocked BEFORE the executor
        (zero state-change communication)."""
        from src.core.config.settings import VdpModeSettings
        from src.core.engine.vdp_evidence_validator import (
            REASON_SIGNER_UNAVAILABLE,
        )
        from tests.core.engine.test_master_conductor_vdp_evidence_validator import (
            _inject_structured_markers,
        )
        from tests.unit.engine.test_vdp_rollout_mc_integration import (
            _read_only_spec,
            _state_changing_spec,
            _vdp_task,
        )

        monkeypatch.delenv("SHIGOKU_VDP_SIGNING_KEY", raising=False)
        progression_path = tmp_path / "progression.json"
        progression_path.write_text(
            json.dumps(
                [
                    {"stage": s, "drill_id": f"drill-{s}", "passed": True,
                     "recorded_at": "2026-08-01T00:00:00Z"}
                    for s in ("m0", "m1", "m2", "m3a")
                ]
            ),
            encoding="utf-8",
        )
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=VdpModeSettings(
                mode="readonly_enforce",
                stage="m3b",
                progression_records_path=str(progression_path),
                capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        assert mc._vdp_rollout_gate().effective_stage() == "m3b"
        checkpoint_path = tmp_path / "ck.json"
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()},
            scope_definition=_scope(),
            checkpoint_path=str(checkpoint_path),
        )
        tasks = [t for t in mc.task_queue if t.agent_type == "vdp_follow_up"]
        assert tasks
        # SGK-2026-0439: the queued render `/search` payload spec now
        # carries masked request material (mask-at-ingest) and is
        # executable; S07 exact_request_material_unavailable applies only to
        # genuinely material-less payload specs (regression). The key-provider
        # drill then exercises the signer path with a healthy executable gap
        # on the SAME task (real hypothesis/verdict lineage preserved).
        material_less = _vdp_task(
            dict(_read_only_spec("task-pm-drill14"), evidence_gap="payload_request_mismatch")
        )
        blocked = await mc._dispatch(material_less)
        assert blocked["data"]["status"] == "manual_review"
        assert blocked["data"]["reason"] == "exact_request_material_unavailable"
        tasks[0].params["vdp_follow_up_spec"]["evidence_gap"] = (
            "authz_impact_not_proven"
        )
        # key provider stopped → no signer, fail-closed (real resolution)
        assert mc._vdp_evidence_signer() is None
        executed_hyp_ids = set()
        for task in tasks:
            result = await mc._dispatch(task)
            assert result["data"]["status"] == "executed"
            executed_hyp_ids.add(task.params["vdp_follow_up_spec"]["hypothesis_id"])

        # structured success markers present but no signer → candidate + hold
        _inject_structured_markers(mc)
        for task in tasks:
            mc._run_canonical_evidence_validator_for_task(task)

        verdicts = mc._vdp_state["verdicts"]
        assert verdicts
        assert not [v for v in verdicts if v.get("status") == "confirmed"]
        evaluated = [
            v for v in verdicts
            if v.get("hypothesis_id") in executed_hyp_ids
        ]
        assert evaluated
        for v in evaluated:
            assert v.get("status") == "candidate"
            assert REASON_SIGNER_UNAVAILABLE in v.get("reason_codes", [])

        # rollout gate (real config): state-changing communication denied
        # without an active key even with stage/progression/HITL in place
        # (progression supplied via the tmp progression file).
        gate = mc._vdp_rollout_gate()
        verdict = gate.pre_communication_check(
            risk_class="state_changing",
            capability_level="confirmation_required",
            hitl_ticket="T-1",
            key_active=False,
        )
        assert verdict.allow is False
        assert verdict.reason == "signing_key_not_active"

        # a dispatched state-changing task is blocked BEFORE the executor
        spec = _state_changing_spec("task-sc-drill14")
        spec["hitl_ticket"] = "T-1"
        sc_result = await mc._dispatch(_vdp_task(spec))
        assert sc_result["data"]["status"] == "blocked"
        assert sc_result["data"]["reason"] == "signing_key_not_active"
        assert net.count == len(tasks)  # read-only sends only — zero state changes

        drill = DrillSpec(
            drill_id="drill_key_provider_stop",
            injection="no signing key configured (key_env_var unset)",
            expected_stop="executed read-only dispatch with candidate verdict; "
                          "state-changing dispatch blocked pre-executor",
            reason_code="signer_unavailable_hold",
            saved_state="verdicts candidate + signer_unavailable_hold",
            resumable=True,
            resendable=False,
        )
        assert drill.reason_code == "signer_unavailable_hold"
        assert drill.resumable is True
        assert drill.resendable is False

    async def test_drill_15_crash_recovery_wal_blocks_resend(self, tmp_path, monkeypatch):
        """WAL durability across a simulated crash (Lane J-2 finding B):

        - MC A dispatches the state-changing task (WAL begin → send →
          journal "sent"). A NEW MC B on the SAME checkpoint/journal paths
          cannot resend: journal "sent" → blocked state_change_already_sent,
          zero network.
        - A journal entry left "in_flight" (the artifact a crash between
          begin and mark leaves) → blocked state_change_outcome_unknown with
          a Hold decision record — outcome-unknown is never auto-resent.
        """
        from src.core.domain.model.task import Task
        from src.core.engine.vdp_follow_up_executor import build_attempt_id
        from src.core.engine.vdp_rollout import load_decision_records
        from src.core.engine.vdp_state_change_journal import StateChangeJournal
        from tests.unit.engine.test_vdp_rollout_mc_integration import _vdp_task

        rollout_state_path = str(tmp_path / "rollout_state.json")
        mc_a, net_a, observation, _na = _m3b_drill_mc(
            tmp_path, monkeypatch, suffix="15a",
            rollout_state_path=rollout_state_path,
        )
        checkpoint_path = tmp_path / "ck15.json"
        mc_a._queue_vdp_follow_ups(
            _scope(),
            checkpoint_path=str(checkpoint_path),
            observations=[observation],
        )
        tasks_a = [t for t in mc_a.task_queue if t.agent_type == "vdp_follow_up"]
        assert tasks_a
        first = await mc_a._dispatch(tasks_a[0])
        assert first["data"]["status"] == "executed"
        assert net_a.count == 1
        attempt_id = first["data"]["attempt_id"]
        journal = StateChangeJournal.for_checkpoint(checkpoint_path)
        assert journal.state(attempt_id) == "sent"

        # simulated crash → NEW MC on the same checkpoint/journal paths with
        # an approved ledger ticket for the same NextAction
        mc_b, net_b, _obs_b, _na_b = _m3b_drill_mc(
            tmp_path, monkeypatch, suffix="15a",
            rollout_state_path=rollout_state_path,
        )
        assert mc_b._restore_vdp_runtime_checkpoint(str(checkpoint_path)) is True
        second = await mc_b._dispatch(tasks_a[0])
        assert second["data"]["status"] == "blocked"
        assert second["data"]["reason"] == "state_change_already_sent"
        assert net_b.count == 0

        # crash variant: an in_flight journal entry (written directly on the
        # WAL path — exactly the artifact a crash between begin and mark
        # leaves) → outcome-unknown Hold, zero network, decision record.
        crash_hyp_id = "hyp-crash-15"
        crash_na_id = "nxt-crash-15"
        crash_task_id = "task-crash-15"
        crash_attempt = build_attempt_id(
            crash_hyp_id, "state_change_not_verified", "unauth"
        )
        journal.begin(
            crash_attempt,
            next_action_id=crash_na_id,
            hypothesis_id=crash_hyp_id,
            task_id=crash_task_id,
        )
        crash_ticket_task = Task(
            id=crash_task_id,
            name="vdp_follow_up:state_change_not_verified",
            agent_type="vdp_follow_up",
            action="run",
            params={"vdp_follow_up_spec": {"next_action_id": crash_na_id}},
        )
        crash_ticket_id = mc_b._register_pending_hitl_ticket(
            crash_ticket_task,
            {"scenario_id": "vdp_state_change", "reasons": []},
            "enforce",
        )
        assert mc_b.set_pending_hitl_status(crash_ticket_id, "approved")
        crash_spec = {
            "task_id": crash_task_id,
            "hypothesis_id": crash_hyp_id,
            "verdict_id": "",
            "next_action_id": crash_na_id,
            "evidence_gap": "state_change_not_verified",
            "risk_class": "state_changing",
            "action_class": "follow_up_probe",
            "url": _URL,
            "method": "POST",
            "param_names": [],
            "param_locations": [],
            "header_positions": [],
            "actor": "unauth",
            "m3b_authorized": True,
            "hitl_ticket": crash_ticket_id,
            "scope_domains": ["api.example.com"],
            "scope_out_domains": [],
            "scope_rate_limit": 1000,
        }
        crash_result = await mc_b._dispatch(_vdp_task(crash_spec))
        assert crash_result["data"]["status"] == "blocked"
        assert crash_result["data"]["reason"] == "state_change_outcome_unknown"
        assert net_b.count == 0
        # Hold audit trail: shadow decision + durable decision record
        holds = [
            d for d in getattr(mc_b, "_shadow_decisions", [])
            if d.get("reason") == "state_change_outcome_unknown"
        ]
        assert holds
        records = load_decision_records(tmp_path / "decision_records.json")
        assert any(
            r.decision == "hold"
            and "state_change_outcome_unknown" in r.reasons
            for r in records
        )

        drill = DrillSpec(
            drill_id="drill_crash_recovery_wal",
            injection="process crash after WAL begin/mark before checkpoint save",
            expected_stop="new MC blocked by journal (sent → already_sent; "
                          "in_flight → outcome-unknown hold)",
            reason_code="state_change_outcome_unknown",
            saved_state="WAL journal persists sent/in_flight; Hold decision record",
            resumable=True,
            resendable=False,
        )
        assert drill.reason_code == "state_change_outcome_unknown"
        assert drill.resumable is True
        assert drill.resendable is False

    async def test_drill_18_network_error_is_outcome_unknown(self, tmp_path, monkeypatch):
        """The Lane L-3 audit scenario: the remote APPLIED the state change
        but the RESPONSE was lost (timeout) — the executor cannot prove
        non-delivery, so the WAL must record outcome-unknown
        (``in_flight``), NEVER ``not_sent``.

        Full production chain, no manual journal/guard manipulation:
        - first dispatch → DEGRADED ``network_error`` with
          ``remote_applied == 1`` (the mutation hit the remote);
        - the journal stays ``in_flight`` on disk even though the
          checkpoint save ALSO fails (lost checkpoint → idempotency gone);
        - a NEW MasterConductor on the same checkpoint/journal paths with
          the same approved ledger ticket re-dispatches → blocked
          ``state_change_outcome_unknown`` and the NEW MC's fake network
          makes ZERO requests — the state change is never applied twice
          (plan §5 timeout drill / 二重状態変更0件)."""

        class _RemoteAppliedThenTimeoutNet(_FakeNetwork):
            """The remote applies the mutation, then the response is lost."""

            def __init__(self):
                super().__init__()
                self.remote_applied = 0

            async def request(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                self.remote_applied += 1  # the remote applied the change
                raise TimeoutError("response lost after remote applied")

        from src.core.engine.vdp_rollout import load_decision_records
        from src.core.engine.vdp_state_change_journal import StateChangeJournal

        rollout_state_path = str(tmp_path / "rollout_state.json")
        remote_net = _RemoteAppliedThenTimeoutNet()
        mc_a, net_a, observation, _na = _m3b_drill_mc(
            tmp_path, monkeypatch, suffix="18",
            rollout_state_path=rollout_state_path,
            net=remote_net,
        )
        checkpoint_path = tmp_path / "ck18.json"
        mc_a._queue_vdp_follow_ups(
            _scope(),
            checkpoint_path=str(checkpoint_path),
            observations=[observation],
        )
        tasks = [t for t in mc_a.task_queue if t.agent_type == "vdp_follow_up"]
        assert tasks

        # checkpoint save ALSO fails — the idempotency state is lost, so the
        # journal is the ONLY protection left for a new process
        monkeypatch.setattr(mc_a, "_save_vdp_runtime_checkpoint", lambda path: False)
        first = await mc_a._dispatch(tasks[0])
        assert first["data"]["status"] == "degraded"
        assert first["data"]["reason"] == "network_error"
        assert remote_net.remote_applied == 1  # the mutation hit the remote
        attempt_id = first["data"]["attempt_id"]
        assert attempt_id
        # THE FIX: network_error is outcome-unknown → in_flight, NOT
        # "not_sent" (the old table would let a new process re-send)
        journal = StateChangeJournal.for_checkpoint(checkpoint_path)
        assert journal.state(attempt_id) == "in_flight"
        # still in_flight on disk after the failed checkpoint save
        assert StateChangeJournal.for_checkpoint(checkpoint_path).state(attempt_id) == "in_flight"

        # simulated restart: NEW MC, same checkpoint/journal paths + ticket
        mc_b, net_b, _obs_b, _na_b = _m3b_drill_mc(
            tmp_path, monkeypatch, suffix="18",
            rollout_state_path=rollout_state_path,
        )
        assert mc_b._restore_vdp_runtime_checkpoint(str(checkpoint_path)) is True
        second = await mc_b._dispatch(tasks[0])
        assert second["data"]["status"] == "blocked"
        assert "state_change_outcome_unknown" in second["data"]["reason"]
        assert net_b.count == 0  # the NEW MC made ZERO requests — no resend
        # Hold audit trail: durable decision record with the hold reason
        records = load_decision_records(tmp_path / "decision_records.json")
        assert any(
            r.decision == "hold"
            and "state_change_outcome_unknown" in r.reasons
            for r in records
        )

        drill = DrillSpec(
            drill_id="drill_network_error_is_outcome_unknown",
            injection="remote applies the mutation, then the response is lost",
            expected_stop="degraded network_error; resume blocked "
                          "state_change_outcome_unknown; new MC net 0",
            reason_code="network_error",
            saved_state="WAL journal in_flight + Hold decision record; no resend",
            resumable=True,
            resendable=False,
        )
        assert drill.reason_code == "network_error"
        assert drill.resumable is True
        assert drill.resendable is False

    async def test_drill_16_backpressure_send_not_lost_on_resume(self, tmp_path, monkeypatch):
        """The Lane L-2 audit scenario: send SUCCEEDED but the evidence
        writer failed (``evidence_write_backpressure``) — the executor had
        already called mark_sent, so the WAL must record "sent", NOT
        "not_sent". A NEW MasterConductor on the same checkpoint/journal
        paths with the same approved ticket then blocks the re-dispatch
        (``state_change_already_sent``) and its OWN fake network makes ZERO
        requests — the sent state change is never re-sent (plan §5/§10).

        No manual guard or journal manipulation anywhere."""

        class _FullWriter:
            async def enqueue_evidence(self, evidence):
                raise RuntimeError("queue full")

        from src.core.engine.vdp_state_change_journal import StateChangeJournal

        mc_a, net_a, observation, _na = _m3b_drill_mc(
            tmp_path, monkeypatch, suffix="16", writer=_FullWriter()
        )
        checkpoint_path = tmp_path / "ck16.json"
        mc_a._queue_vdp_follow_ups(
            _scope(),
            checkpoint_path=str(checkpoint_path),
            observations=[observation],
        )
        tasks = [t for t in mc_a.task_queue if t.agent_type == "vdp_follow_up"]
        assert tasks
        first = await mc_a._dispatch(tasks[0])
        assert first["data"]["status"] == "degraded"
        assert first["data"]["reason"] == "evidence_write_backpressure"
        assert net_a.count == 1  # the HTTP send happened
        attempt_id = first["data"]["attempt_id"]
        assert attempt_id
        # WAL: the sent fact is durable — NOT "not_sent" (the old bug)
        journal = StateChangeJournal.for_checkpoint(checkpoint_path)
        assert journal.state(attempt_id) == "sent"
        # in-memory guard mirrors the sent fact (executor-side mark_sent)
        guard = mc_a._vdp_state_change_guard()
        assert attempt_id in guard.to_dict()["sent_but_not_confirmed"]

        # simulated restart: NEW MC, same checkpoint/journal + approved ticket
        mc_b, net_b, _obs_b, _na_b = _m3b_drill_mc(
            tmp_path, monkeypatch, suffix="16"
        )
        assert mc_b._restore_vdp_runtime_checkpoint(str(checkpoint_path)) is True
        second = await mc_b._dispatch(tasks[0])
        assert second["data"]["status"] == "blocked"
        assert second["data"]["reason"] == "state_change_already_sent"
        assert net_b.count == 0  # the NEW MC made ZERO requests

        drill = DrillSpec(
            drill_id="drill_backpressure_send_not_lost",
            injection="evidence writer raises after the HTTP send",
            expected_stop="degraded dispatch; resume blocked by journal sent",
            reason_code="evidence_write_backpressure",
            saved_state="WAL journal sent + guard sent; new MC net 0",
            resumable=True,
            resendable=False,
        )
        assert drill.reason_code == "evidence_write_backpressure"
        assert drill.resumable is True
        assert drill.resendable is False

    async def test_drill_17_unknown_outcome_stays_hold(self, tmp_path, monkeypatch):
        """An outcome-unknown journal entry (the artifact a crash between
        WAL begin and mark leaves) stays Hold: a NEW MC re-dispatch is
        blocked ``state_change_outcome_unknown`` with zero network, the
        journal entry REMAINS in_flight (never auto-marked), and a durable
        Hold decision record is written to the configured path."""
        from src.core.engine.vdp_follow_up_executor import build_attempt_id
        from src.core.engine.vdp_rollout import load_decision_records
        from src.core.engine.vdp_state_change_journal import StateChangeJournal
        from tests.unit.engine.test_vdp_rollout_mc_integration import _vdp_task

        rollout_state_path = str(tmp_path / "rollout_state.json")
        mc_b, net_b, _obs_b, _na_b = _m3b_drill_mc(
            tmp_path, monkeypatch, suffix="17",
            rollout_state_path=rollout_state_path,
        )
        checkpoint_path = tmp_path / "ck17.json"
        assert mc_b._restore_vdp_runtime_checkpoint(str(checkpoint_path)) is True
        journal = StateChangeJournal.for_checkpoint(checkpoint_path)
        attempt_id = build_attempt_id(
            "hyp-crash-17", "state_change_not_verified", "unauth"
        )
        journal.begin(
            attempt_id,
            next_action_id="nxt-crash-17",
            hypothesis_id="hyp-crash-17",
            task_id="task-crash-17",
        )

        crash_spec = {
            "task_id": "task-crash-17",
            "hypothesis_id": "hyp-crash-17",
            "verdict_id": "",
            "next_action_id": "nxt-crash-17",
            "evidence_gap": "state_change_not_verified",
            "risk_class": "state_changing",
            "action_class": "follow_up_probe",
            "url": _URL,
            "method": "POST",
            "param_names": [],
            "param_locations": [],
            "header_positions": [],
            "actor": "unauth",
            "m3b_authorized": True,
            "hitl_ticket": "T-17",
            "scope_domains": ["api.example.com"],
            "scope_out_domains": [],
            "scope_rate_limit": 1000,
        }
        result = await mc_b._dispatch(_vdp_task(crash_spec))
        assert result["data"]["status"] == "blocked"
        assert result["data"]["reason"] == "state_change_outcome_unknown"
        assert net_b.count == 0
        # the in_flight entry stays untouched (never auto-marked)
        assert journal.state(attempt_id) == "in_flight"
        # Hold audit trail: shadow decision + durable decision record
        holds = [
            d for d in getattr(mc_b, "_shadow_decisions", [])
            if d.get("reason") == "state_change_outcome_unknown"
        ]
        assert holds
        records = load_decision_records(tmp_path / "decision_records.json")
        assert any(
            r.decision == "hold"
            and "state_change_outcome_unknown" in r.reasons
            for r in records
        )

        drill = DrillSpec(
            drill_id="drill_unknown_outcome_stays_hold",
            injection="journal entry left in_flight (crash between begin and mark)",
            expected_stop="new MC blocked state_change_outcome_unknown; net 0",
            reason_code="state_change_outcome_unknown",
            saved_state="journal stays in_flight; Hold decision record written",
            resumable=True,
            resendable=False,
        )
        assert drill.reason_code == "state_change_outcome_unknown"
        assert drill.resumable is True
        assert drill.resendable is False


class TestJournalTransitionDecisionTable:
    """Direct unit coverage of ``_journal_transition_after_dispatch``
    (Lane L-3): the WAL decision table keys off the send fact, and
    ``network_error`` on a state-changing send is outcome-unknown
    (response-loss ambiguity), never provably not-sent — ``mark_failed``
    is reserved for results provably produced BEFORE any communication
    started."""

    def test_network_error_is_hold_not_not_sent(self, tmp_path):
        from src.core.engine.vdp_follow_up_executor import FollowUpExecutionResult
        from src.core.engine.vdp_state_change_journal import StateChangeJournal

        mc = _new_mc()
        journal = StateChangeJournal(tmp_path / "table.json.wal.json")
        gate = SimpleNamespace(effective_stage=lambda: "m3b")
        journal.begin("att-net")
        result = FollowUpExecutionResult(
            "degraded", "network_error", state_change_sent=False
        )
        hold = mc._journal_transition_after_dispatch(
            journal, "att-net", result, gate
        )
        assert hold == "state_change_outcome_unknown"
        assert journal.state("att-net") == "in_flight"  # NOT "not_sent"

    def test_blocked_before_network_is_marked_failed(self, tmp_path):
        from src.core.engine.vdp_follow_up_executor import FollowUpExecutionResult
        from src.core.engine.vdp_state_change_journal import StateChangeJournal

        mc = _new_mc()
        journal = StateChangeJournal(tmp_path / "table.json.wal.json")
        gate = SimpleNamespace(effective_stage=lambda: "m3b")
        journal.begin("att-blk")
        result = FollowUpExecutionResult(
            "blocked", "scope:denied", state_change_sent=False
        )
        hold = mc._journal_transition_after_dispatch(
            journal, "att-blk", result, gate
        )
        assert hold == ""
        assert journal.state("att-blk") == "not_sent"

    def test_manual_review_before_network_is_marked_failed(self, tmp_path):
        from src.core.engine.vdp_follow_up_executor import FollowUpExecutionResult
        from src.core.engine.vdp_state_change_journal import StateChangeJournal

        mc = _new_mc()
        journal = StateChangeJournal(tmp_path / "table.json.wal.json")
        gate = SimpleNamespace(effective_stage=lambda: "m3b")
        journal.begin("att-mr")
        result = FollowUpExecutionResult(
            "manual_review", "hitl_ticket_invalid", state_change_sent=False
        )
        hold = mc._journal_transition_after_dispatch(
            journal, "att-mr", result, gate
        )
        assert hold == ""
        assert journal.state("att-mr") == "not_sent"

    def test_send_fact_true_marks_sent_even_when_degraded(self, tmp_path):
        from src.core.engine.vdp_follow_up_executor import FollowUpExecutionResult
        from src.core.engine.vdp_state_change_journal import StateChangeJournal

        mc = _new_mc()
        journal = StateChangeJournal(tmp_path / "table.json.wal.json")
        gate = SimpleNamespace(effective_stage=lambda: "m3b")
        journal.begin("att-sent")
        result = FollowUpExecutionResult(
            "degraded", "evidence_write_backpressure", state_change_sent=True
        )
        hold = mc._journal_transition_after_dispatch(
            journal, "att-sent", result, gate
        )
        assert hold == ""
        assert journal.state("att-sent") == "sent"

