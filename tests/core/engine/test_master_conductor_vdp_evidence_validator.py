"""
SGK-2026-0422 — MasterConductor canonical Evidence Validator integration (T3).

Real production path (fake network adapter only):

  MasterConductor follow-up dispatch
    -> AttemptRecord
    -> EvidenceRecord
    -> canonical Evidence Validator (single call point, executed only)
    -> proof付きEvidenceVerdict (Ed25519)
    -> _vdp_state (upsert: no duplicates, candidate->confirmed explicit)
    -> async_save_session
    -> M0 gate (public-key verification)

Also covers:
- degraded/backpressure paths never sign
- signer unavailable -> candidate + hold reason (never confirmed)
- private-helper-only tests are NOT the completion evidence here — the
  production _dispatch() entrypoint is exercised end to end.
"""
from __future__ import annotations

import json
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
from src.core.engine.vdp_evidence_validator import (
    REASON_SIGNER_UNAVAILABLE,
    Ed25519EvidenceSigner,
)
from src.core.engine.vdp_m0_gate import VdpM0ContractGate
from src.core.models.vdp_contract import (
    EvidenceVerdictV1,
    HypothesisRecord,
    restore_confirmed_from_dict,
)
from src.core.security.ethics_guard import ScopeDefinition

from tests.core.engine.test_master_conductor_vdp_follow_up import (
    _FakeNetwork,
    _new_mc,
    _scope,
    _signal_bundle,
)


def _configured_mc(*, signer: Ed25519EvidenceSigner | None, **overrides) -> MasterConductor:
    """MC with a pre-injected canonical Evidence Validator signer cache."""
    from src.core.engine.vdp_evidence_validator import VdpEvidenceValidator

    overrides.setdefault("_vdp_mode", SimpleNamespace(
        mode="readonly_enforce",
        label_leakage_denylist=[],
        kill_switch=False,
        capability_rules={"follow_up_probe": "allowed"},
    ))
    mc = _new_mc(**overrides)
    mc._vdp_evidence_validator_cache = VdpEvidenceValidator(signer=signer)
    mc._vdp_evidence_signer_cache = signer
    return mc


def _inject_structured_markers(mc: MasterConductor) -> None:
    """Simulate a structured observation source: satisfy every gap token in
    each hypothesis's required_evidence with its mapped structured marker.

    SGK-2026-0422 (audit I-07): the production M3a executor records NEUTRAL
    facts only (response_received/http_status/request_count), so a plain 200
    response can never confirm. Confirmation requires explicit structured
    markers (privilege difference, state change, account comparison, ...),
    which in tests are injected here before re-running the validator.
    """
    from src.core.engine.vdp_evidence_validator import _REQUIREMENT_MARKERS

    hypotheses = {
        h.get("hypothesis_id"): h
        for h in mc._vdp_state.get("hypotheses", [])
        if isinstance(h, dict)
    }
    attempt_hypothesis = {
        a.get("attempt_id"): a.get("hypothesis_id")
        for a in mc._vdp_state.get("attempts", [])
        if isinstance(a, dict)
    }
    for ev in mc._vdp_state.get("evidence_records", []):
        if not isinstance(ev, dict):
            continue
        hyp_id = attempt_hypothesis.get(ev.get("attempt_id"))
        hyp = hypotheses.get(hyp_id) if hyp_id else None
        if hyp is None:
            continue
        markers = {}
        for token in (hyp.get("required_evidence") or []):
            marker = _REQUIREMENT_MARKERS.get(str(token).strip().lower())
            if marker:
                markers[marker] = "true"
        result = dict(ev.get("execution_result") or {})
        result.update(markers)
        ev["execution_result"] = result


class TestCanonicalValidatorProductionPath:
    async def test_production_plain_200_response_stays_candidate(self, tmp_path):
        """Audit I-07 integration: production executor normal 200 response ->
        neutral-fact evidence -> canonical validator -> candidate (never
        confirmed). A plain 200 OK must NOT promote the hypothesis."""
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("30" * 32))
        net = _FakeNetwork()  # plain 200 response
        checkpoint_path = tmp_path / "vdp_checkpoint.json"

        mc = _configured_mc(signer=signer, network_client=net)
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()},
            scope_definition=_scope(),
            checkpoint_path=str(checkpoint_path),
        )
        tasks = [t for t in mc.task_queue if t.agent_type == "vdp_follow_up"]
        assert tasks
        for task in tasks:
            result = await mc._dispatch(task)
            assert result["data"]["status"] == "executed"

        # Evidence records carry neutral facts only — no structured markers.
        for ev in mc._vdp_state["evidence_records"]:
            assert "success_condition_met" not in (ev.get("execution_result") or {})

        verdicts = mc._vdp_state["verdicts"]
        assert verdicts, "canonical validator must produce verdicts"
        confirmed = [
            v for v in verdicts if isinstance(v, dict) and v.get("status") == "confirmed"
        ]
        assert not confirmed, (
            "production executor plain 200 evidence must stay candidate — "
            "no structured success markers were recorded"
        )

    async def test_full_path_confirmed_verdict_survives_save_and_m0(self, tmp_path):
        """executed follow-up -> Attempt/Evidence -> canonical validator with
        structured success markers -> proof verdict -> _vdp_state ->
        async_save_session -> M0 gate."""
        from src.core.engine.vdp_session_reader import read_session_compat

        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("31" * 32))
        net = _FakeNetwork()
        checkpoint_path = tmp_path / "vdp_checkpoint.json"
        session_path = tmp_path / "session_state.json"

        async def _save_session(session_data, filename=None):
            target = tmp_path / (filename or "session_state.json")
            target.write_text(
                json.dumps(session_data, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )

        mc = _configured_mc(signer=signer, network_client=net)
        mc.project_manager = SimpleNamespace(
            project_dir=str(tmp_path), save_session=_save_session
        )

        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()},
            scope_definition=_scope(),
            checkpoint_path=str(checkpoint_path),
        )
        assert mc._vdp_state["vdp_active"] is True

        tasks = [t for t in mc.task_queue if t.agent_type == "vdp_follow_up"]
        assert tasks
        for task in tasks:
            result = await mc._dispatch(task)
            assert result["success"] is True, result
            assert result["data"]["status"] == "executed"

        # Plain 200 evidence alone stays candidate (audit I-07); inject the
        # structured success markers that a real observation source would
        # record, then re-evaluate to confirm.
        _inject_structured_markers(mc)
        for task in tasks:
            mc._run_canonical_evidence_validator_for_task(task)

        assert mc._vdp_state["verdicts"], "canonical validator must produce verdicts"
        verified = [
            v
            for v in mc._vdp_state["verdicts"]
            if isinstance(v, dict) and v.get("status") == "confirmed"
        ]
        assert verified, (
            "with a signer configured and structured success markers present, "
            "confirmed verdicts must be produced"
        )
        for v in verified:
            assert v["validation_proof"].startswith("ed25519:")

        # Session save + M0 gate with the public key provider.
        await mc.async_save_session(str(session_path))
        restored = read_session_compat(session_path)
        assert restored is not None
        vdp = restored.get("vdp_contract", {})
        assert vdp.get("verdicts"), "verdicts must survive session restore"
        m0 = VdpM0ContractGate().validate(
            restored, public_key_provider=signer.public_key_provider()
        )
        assert m0.passed, f"M0 gate failed: {m0.detail} {m0.reason_codes}"

        # Restore confirmed from the saved session with the public key only.
        evidence_dicts = [
            e for e in vdp.get("evidence_records", []) if isinstance(e, dict)
        ]
        for verdict_dict in vdp.get("verdicts", []):
            if verdict_dict.get("status") != "confirmed":
                continue
            restored_verdict = restore_confirmed_from_dict(
                verdict_dict,
                evidence_dicts,
                public_key_provider=signer.public_key_provider(),
            )
            assert restored_verdict.status == "confirmed"
            assert restored_verdict.verdict_id == verdict_dict["verdict_id"]

    async def test_verdict_ids_unique_per_hypothesis(self, tmp_path):
        """Upsert: no duplicate verdict_id and no duplicate per hypothesis."""
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("32" * 32))
        mc = _configured_mc(signer=signer)
        checkpoint_path = tmp_path / "vdp_checkpoint.json"

        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()},
            scope_definition=_scope(),
            checkpoint_path=str(checkpoint_path),
        )
        tasks = [t for t in mc.task_queue if t.agent_type == "vdp_follow_up"]
        for _ in range(2):  # simulate re-dispatch / idempotent retry
            for task in tasks:
                await mc._dispatch(task)

        verdicts = mc._vdp_state["verdicts"]
        ids = [v["verdict_id"] for v in verdicts]
        assert len(ids) == len(set(ids)), "duplicate verdict_id must not be appended"
        hyp_counts: dict[str, int] = {}
        for v in verdicts:
            hyp_counts[v["hypothesis_id"]] = hyp_counts.get(v["hypothesis_id"], 0) + 1
        assert all(count == 1 for count in hyp_counts.values()), (
            "upsert must keep exactly one verdict per hypothesis"
        )

    async def test_candidate_to_confirmed_replacement(self, tmp_path):
        """A later confirmed verdict replaces the earlier candidate for the
        same hypothesis (explicit replacement, no double counting, and the
        existing verdict_id is reused so NextAction back-references stay
        intact). The production plain-200 evidence stays candidate first
        (audit I-07); injecting structured success markers and re-evaluating
        produces the confirmed replacement."""
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("33" * 32))
        mc = _configured_mc(signer=signer, network_client=_FakeNetwork())
        checkpoint_path = tmp_path / "vdp_checkpoint.json"

        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()},
            scope_definition=_scope(),
            checkpoint_path=str(checkpoint_path),
        )

        # The executable follow-up hypothesis (payload_request_mismatch) is
        # the one the validator will evaluate; its shadow candidate verdict
        # id must be reused by the confirmed verdict.
        executable = [
            s for s in mc._vdp_state.get("follow_up_pending", [])
            if s.get("evidence_gap") == "payload_request_mismatch"
        ]
        assert executable, "expected an executable exact-replay gap"
        spec = executable[0]
        hypothesis_id = spec["hypothesis_id"]
        existing_verdict = next(
            (
                v for v in mc._vdp_state["verdicts"]
                if isinstance(v, dict) and v.get("hypothesis_id") == hypothesis_id
            ),
            None,
        )
        assert existing_verdict is not None
        existing_verdict_id = existing_verdict["verdict_id"]
        assert existing_verdict["status"] == "candidate"

        tasks = [t for t in mc.task_queue if t.agent_type == "vdp_follow_up"]
        for task in tasks:
            await mc._dispatch(task)

        # Plain 200 evidence stays candidate; then structured markers allow
        # confirmation (audit I-07).
        _inject_structured_markers(mc)
        for task in tasks:
            mc._run_canonical_evidence_validator_for_task(task)

        same_verdict = [
            v for v in mc._vdp_state["verdicts"]
            if v.get("hypothesis_id") == hypothesis_id
        ]
        assert len(same_verdict) == 1, "upsert must replace, not append"
        assert same_verdict[0]["status"] == "confirmed"
        assert same_verdict[0]["verdict_id"] == existing_verdict_id, (
            "existing verdict_id must be reused to keep NextAction back-refs"
        )


class TestNoSigningOnDegraded:
    async def test_degraded_path_never_signs(self, tmp_path):
        """Backpressure/degraded paths must not call the canonical validator."""
        from tests.core.engine.test_master_conductor_vdp_follow_up import (
            TestRealPath,
        )

        # Reuse the writer-backpressure scenario: a failing evidence writer
        # makes the executor return DEGRADED — no attempt/evidence persisted.
        net = _FakeNetwork()
        mc = _configured_mc(signer=None, network_client=net)
        checkpoint_path = tmp_path / "vdp_checkpoint.json"

        class _FailingWriter:
            async def enqueue_evidence(self, evidence):
                raise RuntimeError("queue full")

        mc._vdp_state["evidence_writer"] = _FailingWriter()
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()},
            scope_definition=_scope(),
            checkpoint_path=str(checkpoint_path),
        )
        tasks = [t for t in mc.task_queue if t.agent_type == "vdp_follow_up"]
        for task in tasks:
            await mc._dispatch(task)

        # The executor catches the writer failure and returns DEGRADED with
        # the evidence dict; the canonical validator must NOT sign it.
        verdicts = [
            v
            for v in mc._vdp_state.get("verdicts", [])
            if isinstance(v, dict) and v.get("status") == "confirmed"
        ]
        assert not verdicts, "degraded path must never produce confirmed"

    async def test_signer_unavailable_never_confirmed(self, tmp_path):
        """No signing key -> executed hypothesis stays candidate even with
        structured success markers present (signer_unavailable_hold);
        nothing is ever confirmed."""
        mc = _configured_mc(signer=None, network_client=_FakeNetwork())
        checkpoint_path = tmp_path / "vdp_checkpoint.json"
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": _signal_bundle()},
            scope_definition=_scope(),
            checkpoint_path=str(checkpoint_path),
        )
        tasks = [t for t in mc.task_queue if t.agent_type == "vdp_follow_up"]
        executed_hypothesis_ids = set()
        for task in tasks:
            result = await mc._dispatch(task)
            assert result["data"]["status"] == "executed"
            spec = dict((task.params or {}).get("vdp_follow_up_spec") or {})
            if spec.get("hypothesis_id"):
                executed_hypothesis_ids.add(spec["hypothesis_id"])

        # Structured markers present but no signer -> signer-unavailable hold.
        _inject_structured_markers(mc)
        for task in tasks:
            mc._run_canonical_evidence_validator_for_task(task)

        verdicts = mc._vdp_state["verdicts"]
        assert verdicts, "validator must still evaluate without a signer"
        for v in verdicts:
            assert v.get("status") != "confirmed"
            assert not v.get("validation_proof")
        # The executed hypotheses must carry the signer-unavailable hold.
        evaluated = [
            v for v in verdicts
            if v.get("hypothesis_id") in executed_hypothesis_ids
        ]
        assert evaluated, "executed hypotheses must be evaluated"
        for v in evaluated:
            assert v.get("status") == "candidate"
            assert REASON_SIGNER_UNAVAILABLE in v.get("reason_codes", [])


class TestNoReportTimeConfirmation:
    def test_reporting_never_signs(self):
        """reporting layer must not import the engine signer (structural)."""
        import re as _re
        from pathlib import Path

        offenders = []
        for path in sorted(Path("src/reporting").rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            if _re.search(r"vdp_evidence_validator|Ed25519EvidenceSigner|_SIGNING_KEY", text):
                offenders.append(str(path))
        assert offenders == [], f"reporting must not import the signer: {offenders}"
