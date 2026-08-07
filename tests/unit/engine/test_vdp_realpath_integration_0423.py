"""
SGK-2026-0423 Lane D — real-path integration chain (TDD).

The full production chain with a fake transport only (zero sockets):

  config (VdpModeSettings)
    -> MasterConductor hook (_generate_vdp_hypotheses)
    -> session payload (build_async_session_payload +
       inject_vdp_section_to_session_payload + redact_and_write_session)
    -> read_session_compat
    -> M0 contract gate
    -> canonical extractor (extract_vdp_canonical, incl. shadow_diff passthrough)
    -> real gate (evaluate_vdp_real_gate) + decision record roundtrip
    -> offline holdout runner over the same summary

Also proves fail-closed behavior: tampered sessions never pass M0 and
config alone can never enable state-changing communication.
"""
from __future__ import annotations

import json
import re
import socket as _socket
import time
from types import SimpleNamespace

import pytest

from src.core.config.settings import VdpModeSettings
from src.core.engine.master_conductor import MasterConductor
from src.core.engine.master_conductor_session_service import (
    build_async_session_payload,
    inject_vdp_section_to_session_payload,
)
from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner
from src.core.engine.vdp_key_registry import VdpKeyRegistry
from src.core.engine.vdp_m0_gate import VdpM0ContractGate
from src.core.engine.vdp_rollout import (
    RolloutDecisionRecord,
    VdpRolloutGate,
    load_decision_records,
    write_decision_record,
)
from src.core.engine.vdp_session_reader import (
    read_session_compat,
    redact_and_write_session,
)
from src.reporting.vdp_canonical import extract_vdp_canonical
from src.reporting.vdp_dataset import ThresholdMetric, freeze_thresholds
from src.reporting.vdp_gates import evaluate_vdp_real_gate
from src.reporting.vdp_holdout_runner import (
    assert_thresholds_frozen_for_eval_version,
    run_holdout_evaluation,
    save_evaluation_result,
    verify_no_runtime_leakage,
)

from tests.core.engine.test_master_conductor_vdp_evidence_validator import (
    _inject_structured_markers,
)
from tests.core.engine.test_master_conductor_vdp_follow_up import (
    _FakeNetwork,
    _new_mc,
    _scope,
    _signal_bundle,
)


def _build_session_payload(mc: MasterConductor) -> dict:
    """Mirror async_save_session's payload construction (real path)."""
    payload = build_async_session_payload(
        task_queue=list(mc.task_queue),
        completed_tasks=mc.completed_tasks,
        context=mc.context,
        pending_hitl=getattr(mc, "pending_hitl", []),
        coverage_gate={},
        scenario_coverage={},
        timestamp=time.time(),
        default_start_time=time.time(),
        session_id=getattr(getattr(mc, "_current_session", None), "session_id", None),
    )
    return inject_vdp_section_to_session_payload(payload, mc._vdp_state)


async def _run_enforce_session(tmp_path, monkeypatch):
    """Full readonly_enforce real-path run with a REAL key chain.

    Generates hypotheses, queues follow-ups, dispatches every task through
    the M3a executor with a fake network (plain 200).  Returns
    ``(mc, signer, tasks)``.
    """
    monkeypatch.delenv("SHIGOKU_VDP_SIGNING_KEY", raising=False)
    key_file = tmp_path / "signing.key"
    key_file.write_text("11" * 32)
    # Lane H (SGK-2026-0423): FileKeyProvider rejects key files with
    # group/other access (default umask would leave 0644), so pin 0600.
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
        capability_rules={"follow_up_probe": "allowed"},
    )
    mc = _new_mc(network_client=_FakeNetwork(), _vdp_mode=settings)
    mc._generate_vdp_hypotheses(
        {"_signal_bundle": _signal_bundle()},
        scope_definition=_scope(),
        checkpoint_path=str(tmp_path / "vdp_checkpoint.json"),
    )
    tasks = [t for t in mc.task_queue if t.agent_type == "vdp_follow_up"]
    assert tasks
    for task in tasks:
        result = await mc._dispatch(task)
        assert result["success"] is True, result
        assert result["data"]["status"] == "executed"
    return mc, signer, tasks


class TestRealPathChain:
    def test_shadow_path_session_m0_canonical_gate_decision(
        self, tmp_path, monkeypatch
    ):
        """mode=shadow → hypotheses/verdicts/next_actions → session → M0 PASS
        → canonical summary → real gate decision → decision record
        roundtrip. Zero sockets, zero network."""
        calls = []

        def fake_socket(*a, **kw):
            calls.append(a)
            raise AssertionError("socket() must not be called in the real path")

        monkeypatch.setattr(_socket, "socket", fake_socket)
        net = _FakeNetwork()
        mc = _new_mc(
            network_client=net,
            _vdp_mode=VdpModeSettings(mode="shadow"),
        )
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()}, scope_definition=_scope()
        )
        assert mc._vdp_state["vdp_active"] is True
        assert mc._vdp_state["hypotheses"]
        assert mc._vdp_state["verdicts"]
        assert mc._vdp_state["next_actions"]
        assert len(mc.task_queue) == 0

        session_path = tmp_path / "session.json"
        redact_and_write_session(_build_session_payload(mc), session_path)
        restored = read_session_compat(session_path)
        assert restored is not None

        m0 = VdpM0ContractGate().validate(restored)
        assert m0.passed, f"M0 gate failed: {m0.detail} {m0.reason_codes}"

        summary = extract_vdp_canonical(restored)
        assert summary.source_kind == "canonical_vdp"
        assert summary.hypotheses
        assert summary.verdicts
        assert summary.next_actions

        verdict = evaluate_vdp_real_gate(summary)
        assert verdict.profile == "real"
        assert verdict.decision in ("go", "hold", "no_go")

        decisions_path = tmp_path / "decisions.json"
        write_decision_record(
            decisions_path,
            RolloutDecisionRecord(
                stage="m2", decision=verdict.decision, reasons=verdict.reason_codes
            ),
        )
        loaded = load_decision_records(decisions_path)
        assert len(loaded) == 1
        assert loaded[0].stage == "m2"
        assert loaded[0].decision == verdict.decision
        assert loaded[0].reasons == verdict.reason_codes

        assert net.count == 0
        assert calls == [], f"socket() called {len(calls)} times"

    async def test_enforce_readonly_path_with_key_chain(self, tmp_path, monkeypatch):
        """readonly_enforce + file key + ACTIVE registry key: plain 200 →
        candidate; structured success markers → confirmed with Ed25519 proof;
        session → M0 PASS → canonical summary → real gate → decision record.
        The session JSON carries no key material / credential values."""
        mc, signer, tasks = await _run_enforce_session(tmp_path, monkeypatch)
        # plain 200 evidence must NOT confirm (audit I-07)
        assert mc._vdp_state["verdicts"]
        assert not [
            v for v in mc._vdp_state["verdicts"] if v.get("status") == "confirmed"
        ]

        # structured success markers → confirmed with a canonical proof
        _inject_structured_markers(mc)
        for task in tasks:
            mc._run_canonical_evidence_validator_for_task(task)
        confirmed = [
            v for v in mc._vdp_state["verdicts"]
            if isinstance(v, dict) and v.get("status") == "confirmed"
        ]
        assert confirmed
        for v in confirmed:
            assert v["validation_proof"].startswith("ed25519:")

        session_path = tmp_path / "session_state.json"
        redact_and_write_session(_build_session_payload(mc), session_path)
        restored = read_session_compat(session_path)
        assert restored is not None
        m0 = VdpM0ContractGate().validate(
            restored, public_key_provider=signer.public_key_provider()
        )
        assert m0.passed, f"M0 gate failed: {m0.detail} {m0.reason_codes}"

        summary = extract_vdp_canonical(
            restored, public_key_provider=signer.public_key_provider()
        )
        assert summary.confirmed_verdicts
        verdict = evaluate_vdp_real_gate(summary)
        assert verdict.decision in ("go", "hold", "no_go")

        decisions_path = tmp_path / "decisions.json"
        write_decision_record(
            decisions_path,
            RolloutDecisionRecord(
                stage="m3a", decision=verdict.decision, reasons=verdict.reason_codes
            ),
        )
        loaded = load_decision_records(decisions_path)
        assert loaded and loaded[0].stage == "m3a"
        assert loaded[0].decision == verdict.decision

        # secrets never reach the session JSON
        raw = session_path.read_text(encoding="utf-8")
        assert ("11" * 32) not in raw  # private key seed
        assert "Authorization" not in raw
        assert "Cookie" not in raw
        # no credential-named JSON field carries a value (token/api_key/etc.)
        assert re.search(
            r'"(?:authorization|cookie|token|access_token|session_token|'
            r"api_key|secret|password)\"\s*:\s*\"[^\"]+\"",
            raw,
        ) is None

    def test_shadow_diff_report_reproducibility(self, tmp_path):
        """Queue-phase shadow_diff survives session → extractor with the same
        next_action_id/verdict_id/reason_code/decision/diff_type (report-side
        reproducible)."""
        mc = _new_mc(
            network_client=_FakeNetwork(),
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[], kill_switch=False,
                capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()}, scope_definition=_scope()
        )
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

        session_path = tmp_path / "session.json"
        redact_and_write_session(_build_session_payload(mc), session_path)
        restored = read_session_compat(session_path)
        assert restored is not None
        assert restored["vdp_contract"]["shadow_diff"]  # carried by the injector

        summary = extract_vdp_canonical(restored)
        assert summary.shadow_diff, "extractor must pass shadow_diff through"
        recorded = {d["next_action_id"]: d for d in diffs}
        for entry in summary.shadow_diff:
            rec = recorded[entry["next_action_id"]]
            for key in (
                "next_action_id", "verdict_id", "reason_code",
                "decision", "diff_type",
            ):
                assert entry[key] == rec[key], key
        # to_dict() serializes the passthrough as a list
        assert summary.to_dict()["shadow_diff"] == [dict(e) for e in summary.shadow_diff]

    async def test_holdout_runner_on_real_path_summary(self, tmp_path, monkeypatch):
        """Holdout evaluation over a real-path canonical summary: outcome
        recorded, no runtime leakage, save + freeze guard roundtrip, result
        JSON free of secret markers.

        Lane G API: the labels dict carries a ``ground_truth`` list of
        product-independent entries (class/capability/method/endpoint) built
        to match the fixture's confirmed hypotheses 1:1 — the label-based
        formulas then score recall 1.0 / false_promotion 0.0 over the real
        session records."""
        mc, signer, tasks = await _run_enforce_session(tmp_path, monkeypatch)
        # confirm the executed hypotheses (structured markers + the real
        # signer) so the label-based recall/false-promotion formulas have
        # confirmed verdicts to match against
        _inject_structured_markers(mc)
        for task in tasks:
            mc._run_canonical_evidence_validator_for_task(task)
        session_path = tmp_path / "session.json"
        redact_and_write_session(_build_session_payload(mc), session_path)
        restored = read_session_compat(session_path)
        summary = extract_vdp_canonical(
            restored, public_key_provider=signer.public_key_provider()
        )

        confirmed_ids = {
            v.hypothesis_id for v in summary.verdicts if v.status == "confirmed"
        }
        assert confirmed_ids, "the real-path session must carry confirmed verdicts"
        # generic ground-truth entries matching the fixture hypotheses
        # (capability + normalized endpoint; host-agnostic by the runner)
        ground_truth = [
            {"class": h.capability, "capability": h.capability,
             "method": "get", "endpoint": h.asset}
            for h in summary.hypotheses
            if h.hypothesis_id in confirmed_ids
        ]
        labels = {
            "urls": ["https://example.com/private-admin"],  # generic example.com style
            "payloads": ["unique-holdout-payload-xyz"],
            "product_names": ["acme-web-store"],
            "ground_truth": ground_truth,
        }
        thresholds = freeze_thresholds(
            eval_version="ev-holdout-1",
            decided_at="2026-08-01T00:00:00Z",
            metrics=[
                ThresholdMetric(
                    name="funnel:hypothesis_to_attempt",
                    value=0.0,
                    formula="attempts / hypotheses",
                    target_set="hidden_holdout",
                )
            ],
        )
        result = run_holdout_evaluation(
            summary,
            labels,
            thresholds,
            eval_version="ev-holdout-1",
            runner_version="test",
            session_ref="test-session",
        )
        assert result.outcome == "pass"  # no leakage, frozen metric met
        assert result.eval_version == "ev-holdout-1"
        assert result.gaps == []  # ground truth supplied — no no_ground_truth gap
        # label-based formulas over the real-path summary: every confirmed
        # hypothesis matches its own ground-truth entry
        assert result.metrics["recall"]["value"] == pytest.approx(1.0)
        assert result.metrics["false_promotion_rate"]["value"] == pytest.approx(0.0)
        assert verify_no_runtime_leakage(result) is True

        result_path = tmp_path / "holdout_result.json"
        save_evaluation_result(result, result_path)
        assert_thresholds_frozen_for_eval_version(result_path, thresholds)  # no raise
        saved = json.loads(result_path.read_text(encoding="utf-8"))
        assert saved["artifact_hash"]
        assert saved["outcome"] == result.outcome
        # result JSON contains no secret markers
        raw = result_path.read_text(encoding="utf-8")
        assert ("11" * 32) not in raw
        assert "Authorization" not in raw
        assert "acme-web-store" not in raw  # holdout labels never stored

    async def test_m0_fail_closed_on_tampered_session(self, tmp_path, monkeypatch):
        """A tampered verdict (validation_proof removed from a confirmed
        verdict) fails M0 AND is demoted by the canonical extractor —
        fail-closed, no guesswork."""
        mc, signer, tasks = await _run_enforce_session(tmp_path, monkeypatch)
        # promote the executed hypotheses to confirmed (structured markers +
        # the real signer) so the session carries a canonical proof to tamper
        _inject_structured_markers(mc)
        for task in tasks:
            mc._run_canonical_evidence_validator_for_task(task)
        session_path = tmp_path / "session.json"
        redact_and_write_session(_build_session_payload(mc), session_path)
        restored = read_session_compat(session_path)
        vdp = restored["vdp_contract"]
        confirmed = [
            v for v in vdp.get("verdicts", [])
            if isinstance(v, dict) and v.get("status") == "confirmed"
        ]
        assert confirmed, "the enforce session must carry confirmed verdicts"
        tampered_id = confirmed[0]["verdict_id"]
        confirmed[0]["validation_proof"] = ""

        m0 = VdpM0ContractGate().validate(
            restored, public_key_provider=signer.public_key_provider()
        )
        assert m0.passed is False
        assert "parse_error" in m0.reason_codes
        assert tampered_id in m0.detail

        # the canonical extractor is equally fail-closed: the tampered
        # confirmed verdict is demoted to candidate with missing_proof
        summary = extract_vdp_canonical(
            restored, public_key_provider=signer.public_key_provider()
        )
        matching = [v for v in summary.verdicts if v.verdict_id == tampered_id]
        assert matching
        assert matching[0].status == "candidate"
        assert any("missing_proof" in r for r in summary.compatibility_reasons)

    async def test_state_change_requires_hitl_and_key_even_at_m3b(
        self, tmp_path, monkeypatch
    ):
        """Real-config M3b: config alone can never enable state-changing
        sends — the approved HITL LEDGER ticket and the write-ahead journal
        are both mandatory.

        (a) no ledger ticket → the state-changing NextAction is NOT queued;
        (b) a pending (not approved) ticket → still NOT queued;
        (c) an approved+matching ticket → queued; dispatching WITHOUT a
            checkpoint (no WAL) is blocked ``state_change_journal_unavailable``
            with zero communication;
        (d) approved+matching+checkpoint → executed exactly once (net 1),
            the WAL journal records "sent", the StateChangeGuard holds the
            sent fact, and the canonical validator sees neutral-fact
            evidence (candidate — never confirmed without markers).
        """
        from src.core.domain.model.task import Task
        from src.core.engine.vdp_follow_up import build_next_action_record
        from src.core.engine.vdp_observation_adapter import ObservationAdapter
        from src.core.engine.vdp_state_change_journal import StateChangeJournal
        from src.core.models.vdp_contract import HypothesisRecord

        monkeypatch.delenv("SHIGOKU_VDP_SIGNING_KEY", raising=False)
        key_file = tmp_path / "signing.key"
        key_file.write_text("11" * 32)
        key_file.chmod(0o600)
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("11" * 32))
        registry = VdpKeyRegistry()
        registry.register(signer.key_id, signer.public_key_bytes())
        registry_path = tmp_path / "key_registry.json"
        registry.save(registry_path)
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
        settings = VdpModeSettings(
            mode="readonly_enforce",
            stage="m3b",
            key_provider="file",
            key_file_path=str(key_file),
            key_registry_path=str(registry_path),
            progression_records_path=str(progression_path),
            capability_rules={"follow_up_probe": "allowed"},
        )

        observation = ObservationAdapter().adapt_endpoint_signal({
            "url": "https://api.example.com/items",
            "method": "POST",
            "entity_type": "endpoint",
            "primary_label": "items",
            "params": [],
        })
        assert observation is not None

        def _seed_mc(net):
            """Fresh MC seeded with the state-changing NextAction lineage."""
            mc = _new_mc(network_client=net, _vdp_mode=settings)
            assert mc._vdp_rollout_gate().effective_stage() == "m3b"
            assert mc._vdp_evidence_signer() is not None  # ACTIVE key
            hyp = HypothesisRecord(
                hypothesis_id="hyp-sc-1",
                observation_id=observation.observation_id,
                asset="https://api.example.com/items",
                capability="object_read_write_delete",
                hypothesis_text="state change probe",
                trust_boundary="unauthenticated",
                actors=["unauth"],
                required_evidence=["state_change_not_verified"],
                success_condition="independent re-read shows a state difference",
                falsification_condition="no state difference observed",
            )
            mc._vdp_state["hypotheses"] = [hyp.to_dict()]
            mc._vdp_state["vdp_active"] = True  # session consistency for M0
            mc._vdp_state["verdicts"] = [{
                "verdict_id": "vrd-sc-1",
                "hypothesis_id": "hyp-sc-1",
                "status": "candidate",
                "schema_version": 1,
            }]
            na = build_next_action_record(
                "vrd-sc-1", hyp, "state_change_not_verified"
            )
            mc._vdp_state["next_actions"] = [na.to_dict()]
            return mc, na

        def _register_ticket(mc, na, *, ticket_id: str, approved: bool) -> str:
            ticket_task = Task(
                id=f"task-{ticket_id}",
                name="vdp_follow_up:state_change_not_verified",
                agent_type="vdp_follow_up",
                action="run",
                params={"vdp_follow_up_spec": {"next_action_id": na.next_action_id}},
            )
            created = mc._register_pending_hitl_ticket(
                ticket_task,
                {"scenario_id": "vdp_state_change", "reasons": []},
                "enforce",
            )
            if approved:
                assert mc.set_pending_hitl_status(created, "approved")
            return created

        # (a)+(b)+(c) queue-level authorization on ONE MC without checkpoint
        net1 = _FakeNetwork()
        mc1, na1 = _seed_mc(net1)
        mc1._queue_vdp_follow_ups(_scope(), observations=[observation])
        assert not [
            t for t in mc1.task_queue if t.agent_type == "vdp_follow_up"
        ], "(a) no ticket → the state-changing follow-up must NOT be queued"

        _register_ticket(mc1, na1, ticket_id="pending1", approved=False)
        mc1._queue_vdp_follow_ups(_scope(), observations=[observation])
        assert not [
            t for t in mc1.task_queue if t.agent_type == "vdp_follow_up"
        ], "(b) a pending ticket must NOT authorize the queue"

        ticket_c = _register_ticket(mc1, na1, ticket_id="approved1", approved=True)
        mc1._queue_vdp_follow_ups(_scope(), observations=[observation])
        tasks1 = [t for t in mc1.task_queue if t.agent_type == "vdp_follow_up"]
        assert tasks1, "(c) the approved+matching ticket must queue the follow-up"
        spec1 = tasks1[0].params["vdp_follow_up_spec"]
        assert spec1["m3b_authorized"] is True
        assert spec1["hitl_ticket"] == ticket_c
        assert spec1["capability_level"] == "confirmation_required"

        # (c) dispatch WITHOUT a checkpoint: no WAL → blocked, zero sends
        mc1.project_manager = None  # no session-derived checkpoint path either
        result_c = await mc1._dispatch(tasks1[0])
        assert result_c["data"]["status"] == "blocked"
        assert result_c["data"]["reason"] == "state_change_journal_unavailable"
        assert net1.count == 0

        # (d) approved+matching+checkpoint → the M3b real path executes once
        net2 = _FakeNetwork()
        mc2, na2 = _seed_mc(net2)
        _register_ticket(mc2, na2, ticket_id="approved2", approved=True)
        checkpoint_path = tmp_path / "vdp_checkpoint.json"
        mc2._queue_vdp_follow_ups(
            _scope(),
            checkpoint_path=str(checkpoint_path),
            observations=[observation],
        )
        tasks2 = [t for t in mc2.task_queue if t.agent_type == "vdp_follow_up"]
        assert tasks2
        result_d = await mc2._dispatch(tasks2[0])
        assert result_d["success"] is True, result_d
        assert result_d["data"]["status"] == "executed"
        assert net2.count == 1
        attempt_id = result_d["data"]["attempt_id"]
        assert attempt_id

        # WAL journal: begin was written BEFORE the send, mark_sent after
        journal = StateChangeJournal.for_checkpoint(checkpoint_path)
        assert journal.state(attempt_id) == "sent"
        # session/checkpoint records: attempt + evidence persisted
        assert mc2._vdp_state["attempts"]
        assert mc2._vdp_state["evidence_records"]
        # the production executor marked the send at the send boundary
        guard_state = mc2._vdp_state_change_guard().to_dict()
        assert attempt_id in guard_state["sent_but_not_confirmed"]
        # neutral facts + the sent fact only — the success marker is never
        # recorded by the executor (canonical validator stays candidate)
        evidence = mc2._vdp_state["evidence_records"][-1]
        assert evidence["execution_result"]["state_change_sent"] is True
        assert "state_change_verified" not in evidence["execution_result"]

        # the canonical validator evaluated the evidence (executed dispatch)
        verdicts = mc2._vdp_state["verdicts"]
        assert verdicts
        assert not [
            v for v in verdicts if v.get("status") == "confirmed"
        ]

        # session roundtrip: the executed state change survives the session
        session_path = tmp_path / "session_state.json"
        redact_and_write_session(_build_session_payload(mc2), session_path)
        restored = read_session_compat(session_path)
        assert restored is not None
        vdp = restored.get("vdp_contract", {})
        assert vdp.get("attempts")
        assert vdp.get("evidence_records")
        m0 = VdpM0ContractGate().validate(restored)
        assert m0.passed, f"M0 gate failed: {m0.detail} {m0.reason_codes}"
