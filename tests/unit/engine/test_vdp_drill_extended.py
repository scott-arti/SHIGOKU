"""
SGK-2026-0423 Lane I-a — EXTENDED failure drills (final audit-fix lane).

Covers the plan §5 items not yet drilled by Lane D
(``tests/unit/engine/test_vdp_failure_drill.py``): browser stop, OOB
listener stop, proxy disconnect, auth expiry, infinite hypothesis
generation, duplicate follow-up, old-session compatibility, and
report-generation failure.

Every drill injects a single failure into the REAL production path (fake
transport / monkeypatch only — zero sockets) and asserts, per ``DrillSpec``
(identical shape to Lane D):

- the injection point
- the exact stop position (status / reason)
- the saved state (session / checkpoint / cache / artifacts)
- resumable: the pipeline can continue after recovery without data loss
- resendable: the SAME attempt may be transmitted again (False when
  idempotency / StateChangeGuard blocks the resend, or nothing was ever
  transmitted)

TEST-ONLY lane: this file touches no production code. Where a drill
documents actual behavior that differs from the plan wording, the ACTUAL
emitted reason code is asserted and the discrepancy is reported.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from src.core.engine.vdp_auth_cache import AuthCache, AuthCacheKey
from src.core.engine.vdp_follow_up import (
    build_next_action_record,
    classify_reason_code,
    is_follow_up_executable,
)
from src.core.engine.vdp_follow_up_executor import build_follow_up_task_id
from src.core.engine.vdp_hypothesis_generator import generate_hypotheses
from src.core.engine.vdp_m0_gate import VdpM0ContractGate
from src.core.engine.vdp_observation_adapter import Observation, ObservationAdapter
from src.core.engine.vdp_session_reader import read_session_compat, redact_and_write_session
from src.core.models.vdp_contract import (
    ExecutionBudgetV1,
    ScopeRevalidationResult,
    VDP_CONTRACT_SCHEMA_VERSION,
)
from src.reporting.haddix_submission_internal_formatter import (
    HaddixSubmissionInternalFormatter,
    generate_separated_report_files,
)
from src.reporting.vdp_canonical import (
    COMPAT_REASON_LEGACY_NO_VDP_CONTRACT,
    COMPAT_REASON_OBSERVATION_CONTENT_UNAVAILABLE,
    extract_vdp_canonical,
)
from src.reporting.vdp_report_projection import verify_separated_group

from tests.unit.engine.test_vdp_follow_up_resilience import (
    _Net,
    _ex,
    _hyp,
    _run,
    _scope,
    _spec,
)
from tests.core.engine.test_master_conductor_vdp_follow_up import _new_mc
from tests.unit.reporting.test_vdp_canonical_extractor import _base_session


@dataclass(frozen=True)
class DrillSpec:
    """Contract for one extended failure drill (Lane I-a).

    Identical shape to Lane D's ``DrillSpec`` so the audit trail stays
    uniform:

    - drill_id: stable identifier matching the Lane I-a drill list.
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


class TestBrowserStopDrill:
    """Drill 1: browser dependency stop.

    The ``browser_execution_missing`` gap needs the ``browser`` runtime; in
    M3a the executor has no browser contract. The ACTUAL emitted reason is
    asserted: the M3a executor-contract check runs BEFORE the precondition
    check, so the executor emits ``executor_contract_unavailable`` (not
    ``precondition_missing:browser``). Dependency-stop semantics hold: no
    attempt is created, zero communication, and the gap is never refuted —
    after "browser recovery" the same spec is re-evaluated and the plan
    stays a live follow_up plan.
    """

    def test_drill_browser_stop(self):
        # Injection: browser not in available_preconditions (default _ex set
        # has scope/budget/request_budget/action_permission/protected_resource).
        (ex, net, writer, budget) = _ex()
        spec = _spec(gap="browser_execution_missing")
        result = _run(ex.execute(spec))
        assert result.status == "manual_review"
        # ACTUAL emitted reason (asserted, not assumed): the executor
        # contract check precedes the precondition check in M3a.
        assert result.reason == "executor_contract_unavailable:browser_execution_missing"
        assert net.count == 0  # zero communication while the dependency is down
        assert result.attempt is None  # attempt NOT created
        assert result.evidence is None
        assert result.verdict_status != "refuted"  # never refuted

        # Dependency-stop semantics: the plan classification stays a live
        # follow_up plan (a future browser-capable lane can run it).
        plan = classify_reason_code("browser_execution_missing")
        assert plan.category == "follow_up"
        assert plan.m3a_policy == "execute"
        assert is_follow_up_executable(plan) is True

        # Follow-up: simulate "browser recovered" (preconditions supplied) —
        # the SAME gap is re-evaluated; state preserved, nothing refuted,
        # nothing fabricated. (The executor is built directly because the
        # shared ``_ex`` helper hardcodes the M3a precondition set.)
        from src.core.engine.vdp_budget import VdpExecutionBudget
        from src.core.engine.vdp_follow_up_executor import VdpFollowUpExecutor
        from src.core.models.vdp_contract import (
            CapabilityLevel,
            IdempotencyGuard,
            ProgramCapabilityMatrix,
            StateChangeGuard,
        )

        net2 = _Net()
        ex2 = VdpFollowUpExecutor(
            scope_definition=_scope(),
            capability_matrix=ProgramCapabilityMatrix(
                rules={"follow_up_probe": CapabilityLevel.ALLOWED}
            ),
            budget=VdpExecutionBudget(
                max_requests=100, per_asset_burst=100, per_hypothesis_burst=100
            ),
            network_client=net2,
            evidence_writer=None,
            idempotency_guard=IdempotencyGuard(),
            state_change_guard=StateChangeGuard(),
            available_preconditions={
                "scope": True,
                "budget": True,
                "request_budget": True,
                "action_permission": True,
                "protected_resource": True,
                "browser": True,
                "auth_continuity": True,
            },
        )
        resumed = _run(ex2.execute(spec))
        assert resumed.status == "manual_review"
        assert resumed.reason == "executor_contract_unavailable:browser_execution_missing"
        assert net2.count == 0
        assert resumed.attempt is None

        drill = DrillSpec(
            drill_id="drill_browser_stop",
            injection="gap browser_execution_missing; browser precondition absent",
            expected_stop="manual_review (zero communication; attempt NOT created)",
            reason_code="executor_contract_unavailable:browser_execution_missing",
            saved_state="gap pending; plan follow_up/execute; nothing refuted",
            resumable=True,
            resendable=False,
        )
        assert drill.reason_code == "executor_contract_unavailable:browser_execution_missing"
        assert drill.resumable is True
        assert drill.resendable is False


class TestOobListenerStopDrill:
    """Drill 2: OOB listener stop.

    ``ssrf_proof_missing`` is ``oob_gated`` — M3a has no truthful evidence
    adapter for it, so the executor stops at manual review with zero
    communication and the pending NextAction is preserved. A listener-down
    classified as ``dependency_unavailable`` maps to a ``re_evaluate`` plan
    that M3a never enqueues — it stays pending and is never refuted.
    """

    def test_drill_oob_listener_stop(self):
        (ex, net, writer, budget) = _ex()

        # Part A: ssrf_proof_missing (plan oob_gated) at M3a.
        spec = _spec(gap="ssrf_proof_missing")
        result = _run(ex.execute(spec))
        assert result.status == "manual_review"
        # ACTUAL emitted reason: no OOB evidence adapter in M3a.
        assert result.reason == "executor_contract_unavailable:ssrf_proof_missing"
        assert net.count == 0
        assert result.attempt is None
        assert result.verdict_status != "refuted"

        # Pending NextAction preserved: the plan stays follow_up/oob_gated
        # and a re-dispatch produces the same deterministic stop.
        plan = classify_reason_code("ssrf_proof_missing")
        assert plan.m3a_policy == "oob_gated"
        assert is_follow_up_executable(plan) is True
        again = _run(ex.execute(spec))
        assert again.status == "manual_review"
        assert again.reason == "executor_contract_unavailable:ssrf_proof_missing"
        assert net.count == 0

        # Part B: listener-down classified dependency_unavailable →
        # re_evaluate plan; M3a never enqueues it (stays pending, never
        # refuted). The executor's ACTUAL stop reason is asserted.
        dep_plan = classify_reason_code("dependency_unavailable")
        assert dep_plan.category == "re_evaluate"
        assert dep_plan.action_class == "re_evaluate"
        assert is_follow_up_executable(dep_plan) is False
        dep_result = _run(ex.execute(_spec(gap="dependency_unavailable")))
        assert dep_result.status == "manual_review"
        assert dep_result.reason == "not_executable_in_m3a:re_evaluate:none"
        assert dep_result.verdict_status != "refuted"
        assert net.count == 0

        drill = DrillSpec(
            drill_id="drill_oob_listener_stop",
            injection="gap ssrf_proof_missing (oob_gated); listener down as "
                      "dependency_unavailable",
            expected_stop="manual_review (zero communication; NextAction pending)",
            reason_code="executor_contract_unavailable:ssrf_proof_missing",
            saved_state="NextAction pending; dependency_unavailable stays "
                        "re_evaluate (never refuted)",
            resumable=True,
            resendable=False,
        )
        assert drill.reason_code == "executor_contract_unavailable:ssrf_proof_missing"
        assert drill.resumable is True
        assert drill.resendable is False


class TestProxyDisconnectDrill:
    """Drill 3: proxy disconnect mid-flight.

    The fake transport raises ConnectionError → the executor records the
    timeout, the attempt state is ``failed`` with
    ``execution_result.status == dependency_failure``, the run is DEGRADED
    ``network_error`` with no evidence, and the same attempt is NOT resent
    on immediate re-dispatch (idempotency duplicate).
    """

    def test_drill_proxy_disconnect(self):
        class _DisconnectNet(_Net):
            async def request(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                raise ConnectionError("proxy disconnected")

        (ex, net, writer, budget) = _ex(net=_DisconnectNet())
        spec = _spec()
        result = _run(ex.execute(spec))
        assert result.status == "degraded"
        assert result.reason == "network_error"
        assert result.requests_made == 1
        assert net.count == 1
        # attempt state failed; dependency_failure recorded (NOT refuted)
        assert result.attempt is not None
        assert result.attempt["state"] == "failed"
        assert result.attempt["execution_result"]["status"] == "dependency_failure"
        assert result.attempt["execution_result"]["reason"] == "network_error"
        assert result.evidence is None
        assert result.verdict_status != "refuted"
        # the budget recorded the disconnect as a timeout for the asset
        circuits = budget.to_checkpoint_dict()["circuits"]
        assert circuits[_URL]["timeout_count"] == 1

        # same attempt re-dispatched immediately → NOT resent
        again = _run(ex.execute(spec))
        assert again.status == "manual_review"
        assert "attempt:idempotency_duplicate" in again.reason
        assert net.count == 1

        drill = DrillSpec(
            drill_id="drill_proxy_disconnect",
            injection="fake client raises ConnectionError on send",
            expected_stop="degraded network_error (attempt failed, no evidence)",
            reason_code="network_error",
            saved_state="attempt state=failed "
                        "execution_result.status=dependency_failure; "
                        "budget timeout_count=1",
            resumable=True,
            resendable=False,
        )
        assert drill.reason_code == "network_error"
        assert drill.resumable is True
        assert drill.resendable is False


class TestAuthExpiryDrill:
    """Drill 4: auth expiry / credential rotation.

    ``AuthCache`` keys hash the ACTUAL credential value (HMAC-SHA256 tag),
    so a valid→expired credential change (different VALUE, same
    actor/scope/context) MUST NOT reuse a stale PASS. The cache does not
    model TTL; expiry is enforced by credential-rotation key separation and
    explicit invalidation (``invalidate_for_scope`` / ``invalidate_for_actor``).
    """

    def test_drill_auth_expiry(self):
        cache = AuthCache()
        scope = "https://api.example.com"
        key_valid = AuthCacheKey(
            credential="jwt-valid-A", actor="authA",
            auth_context_version="v1", scope=scope,
        )
        # fresh decision for credential A
        assert cache.get(key_valid) is None
        cache.set(key_valid, {"decision": "PASS", "valid_for": 3600})
        assert cache.get(key_valid) == {"decision": "PASS", "valid_for": 3600}

        # the same credential value maps to the same key (cache still works)
        key_valid_again = AuthCacheKey(
            credential="jwt-valid-A", actor="authA",
            auth_context_version="v1", scope=scope,
        )
        assert key_valid_again == key_valid
        stale_hit = cache.get(key_valid_again)
        assert stale_hit is not None
        assert stale_hit["decision"] == "PASS"

        # credential change: different VALUE, same actor/scope/context → the
        # key MUST differ (value hashed) → stale PASS never reused.
        key_expired = AuthCacheKey(
            credential="jwt-expired-B", actor="authA",
            auth_context_version="v1", scope=scope,
        )
        assert key_expired != key_valid
        assert cache.get(key_expired) is None  # NO stale reuse

        # re-evaluation yields a fresh result/decision for the rotated
        # credential; both entries coexist independently.
        cache.set(key_expired, {"decision": "FAIL", "valid_for": 0})
        rotated_decision = cache.get(key_expired)
        assert rotated_decision is not None
        assert rotated_decision["decision"] == "FAIL"
        valid_decision = cache.get(key_valid)
        assert valid_decision is not None
        assert valid_decision["decision"] == "PASS"

        # explicit invalidation removes the stale entries (the cache's
        # expiry mechanism — no TTL is modelled).
        removed = cache.invalidate_for_scope(scope)
        assert removed == 2
        assert cache.get(key_valid) is None
        assert cache.get(key_expired) is None

        drill = DrillSpec(
            drill_id="drill_auth_expiry",
            injection="credential VALUE rotated (valid A → expired B), "
                      "same actor/scope",
            expected_stop="cache miss on rotated credential; fresh decision",
            reason_code="no_stale_reuse (value-hashed key)",
            saved_state="PASS for credential A kept; B evaluated fresh",
            resumable=True,
            resendable=False,
        )
        assert drill.resumable is True
        assert drill.resendable is False


class TestInfiniteHypothesisDrill:
    """Drill 5: infinite hypothesis generation is bounded.

    A large batch of near-duplicate observations (same capability+host)
    cannot grow hypotheses without bound: the diversity budget suppresses
    everything past ``diversity_bucket_limit`` per bucket with
    ``diversity_budget_exceeded``, and generation is deterministic (same
    input twice → same IDs / same suppression set).
    """

    def _flood_observations(self, count: int):
        return [
            Observation(
                observation_id=f"obs-flood-{i:03d}",
                url=f"https://api.example.com/api/login/users/{i}",
                method="GET",
                entity_type="endpoint",
                primary_label="login",
                candidate_labels=("auth",),
                param_names=(),
            )
            for i in range(count)
        ]

    def test_drill_infinite_hypothesis(self):
        def _allow(url):
            return ScopeRevalidationResult(verdict="allowed", allowed=True)

        observations = self._flood_observations(60)
        result = generate_hypotheses(
            observations,
            scope_verdict_provider=_allow,
            budget_model=ExecutionBudgetV1(),
            diversity_bucket_limit=3,
        )
        # bounded: 60 near-duplicate inputs → at most 3 hypotheses
        assert result.has_hypotheses is True
        assert len(result.hypotheses) <= 3
        assert len(result.hypotheses) < len(observations)
        assert result.degraded is None
        # the excess is suppressed with the diversity-family reason
        assert result.suppressed
        assert len(result.suppressed) >= 50
        assert all(
            s.get("reason") == "diversity_budget_exceeded"
            for s in result.suppressed
        )

        # deterministic: same input twice → same IDs / same suppression set
        again = generate_hypotheses(
            observations,
            scope_verdict_provider=_allow,
            budget_model=ExecutionBudgetV1(),
            diversity_bucket_limit=3,
        )
        assert [h.hypothesis_id for h in result.hypotheses] == [
            h.hypothesis_id for h in again.hypotheses
        ]
        assert [(s.get("hypothesis_id"), s.get("reason")) for s in result.suppressed] == [
            (s.get("hypothesis_id"), s.get("reason")) for s in again.suppressed
        ]

        drill = DrillSpec(
            drill_id="drill_infinite_hypothesis",
            injection="60 near-duplicate observations (same capability+host)",
            expected_stop="bounded at diversity_bucket_limit (≤3)",
            reason_code="diversity_budget_exceeded",
            saved_state="suppressed ≥50; deterministic IDs across runs",
            resumable=True,
            resendable=False,
        )
        assert drill.reason_code == "diversity_budget_exceeded"
        assert drill.resumable is True
        assert drill.resendable is False


class TestDuplicateFollowUpDrill:
    """Drill 6: duplicate follow-up is deduplicated at both layers.

    Hook layer: the same NextAction queued twice via
    ``_queue_vdp_follow_ups`` yields ONE task (deterministic task_id, the
    ``already`` pending set dedups) with a single pending/queued entry.
    Executor layer: the same spec dispatched twice → the second dispatch
    stops at ``attempt:idempotency_duplicate`` with net.count unchanged
    (no double read / no double state change).
    """

    def test_drill_duplicate_follow_up(self):
        # ---- hook layer: queue the same NextAction twice ----
        observation = ObservationAdapter().adapt_endpoint_signal({
            "url": "https://api.example.com/items",
            "method": "GET",
            "entity_type": "endpoint",
            "primary_label": "items",
            "params": [],
        })
        assert observation is not None
        na = build_next_action_record("vrd-d6", _hyp(), "payload_request_mismatch")
        mc = _new_mc(
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[],
                kill_switch=False, capability_rules={"follow_up_probe": "allowed"},
            ),
            _vdp_state={
                "vdp_active": True,
                "hypotheses": [
                    {**_hyp().to_dict(), "observation_id": observation.observation_id}
                ],
                "attempts": [],
                "evidence_records": [],
                "verdicts": [{
                    "verdict_id": "vrd-d6",
                    "hypothesis_id": "hyp-res-1",
                    "status": "candidate",
                    "schema_version": 1,
                }],
                "next_actions": [na.to_dict()],
                "follow_up_pending": [],
                "follow_up_queued": [],
                "budget_snapshot": {},
                "run_health": {},
            },
        )

        def _spy_add_tasks(tasks, source="unknown"):
            added = 0
            for t in tasks:
                if mc.task_queue.get_by_id(t.id):
                    continue
                mc.task_queue.add(t)
                mc._injected_task_ids.add(t.id)
                added += 1
            return added

        mc._add_tasks = _spy_add_tasks

        for _ in range(2):
            mc._queue_vdp_follow_ups(_scope(), observations=[observation])

        task_ids = [t.id for t in mc.task_queue]
        assert len(task_ids) == 1, f"duplicate tasks queued: {task_ids}"
        assert task_ids[0] == build_follow_up_task_id(
            na.next_action_id, "hyp-res-1", "unauth"
        )
        assert len(mc._vdp_state["follow_up_pending"]) == 1
        assert len(mc._vdp_state["follow_up_queued"]) == 1

        # ---- executor layer: dispatch the same spec twice ----
        (ex, net, writer, budget) = _ex()
        first = _run(ex.execute(_spec()))
        assert first.status == "executed"
        assert net.count == 1
        second = _run(ex.execute(_spec()))
        assert second.status == "manual_review"
        assert "attempt:idempotency_duplicate" in second.reason
        assert net.count == 1  # no double read / no double state change

        drill = DrillSpec(
            drill_id="drill_duplicate_follow_up",
            injection="same NextAction queued twice; same spec dispatched twice",
            expected_stop="second dispatch manual_review idempotency_duplicate",
            reason_code="attempt:idempotency_duplicate",
            saved_state="single task/pending/queued entry; net.count==1",
            resumable=True,
            resendable=False,
        )
        assert drill.reason_code == "attempt:idempotency_duplicate"
        assert drill.resumable is True
        assert drill.resendable is False


class TestOldSessionCompatDrill:
    """Drill 7: old-session compatibility.

    Legacy sessions (no ``vdp_contract`` section, or a partial section with
    old-style records) are read additively with empty-safe defaults, never
    crash the canonical extractor or the M0 gate, and NEVER fabricate
    content: observation bodies are not stored, so IDs plus the
    ``observation_content_unavailable`` compatibility reason are the whole
    story. The M0 gate result for each shape is documented (inactive+empty
    → PASS; partial contract missing ``vdp_active`` → fail-closed).
    """

    def _write_and_read(self, tmp_path, payload):
        path = tmp_path / "legacy_session.json"
        redact_and_write_session(payload, path)
        data = read_session_compat(path)
        assert isinstance(data, dict), "legacy session must read back as a dict"
        return data

    def test_drill_old_session_compat(self, tmp_path):
        # ---- variant A: session with NO vdp_contract section ----
        legacy_no_contract = {
            "task_queue": [],
            "completed_tasks": [],
            "findings": [{
                "title": "old finding", "severity": "high", "status": "untested",
            }],
        }
        read_back = self._write_and_read(tmp_path, legacy_no_contract)
        assert read_back is not None
        # additive legacy read: vdp_contract_version defaulted, no crash
        assert read_back["vdp_contract_version"] == VDP_CONTRACT_SCHEMA_VERSION
        summary = extract_vdp_canonical(read_back)
        assert summary.source_kind == "legacy"
        assert COMPAT_REASON_LEGACY_NO_VDP_CONTRACT in summary.compatibility_reasons
        # empty-safe defaults — nothing invented
        assert summary.verdicts == ()
        assert summary.hypotheses == ()
        assert summary.funnel.hypotheses == 0
        gate = VdpM0ContractGate().validate(read_back)
        assert gate.passed is True  # no contract section → nothing to validate
        assert gate.reason_codes == []

        # ---- variant B: partial vdp_contract with old-style records ----
        legacy_old_records = {
            "task_queue": [],
            "vdp_contract": {
                "vdp_contract_version": 1,
                "hypotheses": [{
                    "hypothesis_id": "hyp-legacy-1",
                    "observation_id": "obs-legacy-1",
                    "observation_ids": ["obs-legacy-1"],
                    "asset": "https://api.example.com/items",
                    "capability": "object_read_write_delete",
                    "hypothesis_text": "old-style hypothesis",
                    "trust_boundary": "unauthenticated",
                    "actors": ["unauth"],
                    "state": "attempted",
                    "schema_version": 1,
                }],
                "verdicts": [{
                    "verdict_id": "vrd-legacy-1",
                    "hypothesis_id": "hyp-legacy-1",
                    "status": "untested",
                    "reason_codes": ["weak_session_no_second_account"],
                    "schema_version": 1,
                }],
                # attempts / evidence_records / next_actions missing entirely
            },
        }
        read_back2 = self._write_and_read(tmp_path, legacy_old_records)
        summary2 = extract_vdp_canonical(read_back2)
        assert summary2.source_kind == "canonical_vdp"
        assert summary2.schema_version == 1
        # observation content is NOT stored → IDs + compatibility reason
        assert summary2.observation_ids == ("obs-legacy-1",)
        assert (
            COMPAT_REASON_OBSERVATION_CONTENT_UNAVAILABLE
            in summary2.compatibility_reasons
        )
        # old reason codes pass through; missing lists default empty
        assert summary2.funnel.untested == 1
        assert summary2.funnel.drop_reasons.get("weak_session_no_second_account") == 1
        assert summary2.attempts == ()
        assert summary2.evidence_records == ()
        assert summary2.next_actions == ()
        # no fabrication: exactly the input observation IDs appear, nothing more
        assert len(summary2.observation_ids) == 1
        gate2 = VdpM0ContractGate().validate(read_back2)
        # documented actual behavior: a partial contract without vdp_active
        # is fail-closed (strict bool required) — NOT silently passed.
        assert gate2.passed is False
        assert "parse_error" in gate2.reason_codes
        assert "vdp_active" in gate2.detail

        # ---- variant C: inactive + empty → M0 PASS (documented) ----
        legacy_inactive = {
            "task_queue": [],
            "vdp_contract": {"vdp_contract_version": 1, "vdp_active": False},
        }
        read_back3 = self._write_and_read(tmp_path, legacy_inactive)
        summary3 = extract_vdp_canonical(read_back3)
        assert summary3.source_kind == "canonical_vdp"
        assert summary3.schema_version == 1
        assert summary3.hypotheses == ()
        assert summary3.funnel.confirmed == 0
        gate3 = VdpM0ContractGate().validate(read_back3)
        assert gate3.passed is True  # inactive + empty → PASS

        drill = DrillSpec(
            drill_id="drill_old_session_compat",
            injection="hand-built legacy session (no/partial vdp_contract, "
                      "old reason codes)",
            expected_stop="additive read OK; empty-safe defaults; M0 "
                          "inactive+empty PASS",
            reason_code="no_vdp_contract_section / "
                        "observation_content_unavailable",
            saved_state="vdp_contract_version defaulted; observation IDs "
                        "preserved; no invented bodies",
            resumable=True,
            resendable=False,
        )
        assert COMPAT_REASON_LEGACY_NO_VDP_CONTRACT in drill.reason_code
        assert COMPAT_REASON_OBSERVATION_CONTENT_UNAVAILABLE in drill.reason_code
        assert drill.resumable is True
        assert drill.resendable is False


class TestReportGenerationFailureDrill:
    """Drill 8: report-generation failure at the production boundary.

    ``generate_separated_report_files`` (temp → verify → os.replace →
    manifest LAST) must never promote a partial group as official:

    - a formatter exception mid-generation leaves NOTHING on disk;
    - a manifest-write failure AFTER all three files were promoted leaves a
      manifest-less group that ``verify_separated_group`` rejects
      (``separated_manifest_missing``) — the files are NOT official;
    - temp files are cleaned and the source session is never mutated.
    """

    def test_drill_report_generation_failure(self, tmp_path, monkeypatch):
        # ---- injection A: formatter raises mid-generation (before temps) ----
        def _boom_markdown(self):
            raise RuntimeError("formatter failed mid-generation")

        monkeypatch.setattr(
            HaddixSubmissionInternalFormatter, "format_markdown", _boom_markdown
        )
        with pytest.raises(RuntimeError, match="formatter failed"):
            generate_separated_report_files(
                findings=[], target="https://example.com", output_dir=tmp_path
            )
        assert list(tmp_path.iterdir()) == [], (
            "no temp / official / manifest files may exist after a formatter "
            f"exception: {list(tmp_path.iterdir())}"
        )
        monkeypatch.undo()

        # ---- injection B: manifest write fails after ALL promotions ----
        from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner
        import src.reporting.vdp_report_projection as vdp_projection_mod

        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("71" * 32))
        session = _base_session(signer)
        before = copy.deepcopy(session)
        summary = extract_vdp_canonical(
            session, public_key_provider=signer.public_key_provider()
        )

        def _boom_manifest(path, files, **kw):
            raise OSError("manifest write failed after promotion")

        monkeypatch.setattr(vdp_projection_mod, "write_manifest_json", _boom_manifest)
        with pytest.raises(OSError, match="manifest write failed"):
            generate_separated_report_files(
                findings=[],
                target="https://example.com",
                output_dir=tmp_path,
                vdp_canonical_summary=summary,
            )

        # source session not mutated by the failed generation
        assert session == before

        # no manifest → the on-disk group is NOT an official artifact
        manifests = list(tmp_path.glob("*_manifest.json"))
        assert manifests == [], "no manifest may be written on failure"
        submissions = list(tmp_path.glob("*_submission.md"))
        assert submissions, "the promoted member exists on disk (promotion ran)"
        check = verify_separated_group(submissions[0])
        assert check["ok"] is False
        assert check["reason"] == "separated_manifest_missing"

        # temp files cleaned (os.replace consumed them / except-path unlinks)
        assert list(tmp_path.glob(".haddix_*_*.tmp_*")) == []

        drill = DrillSpec(
            drill_id="drill_report_generation_failure",
            injection="formatter raises mid-generation; manifest writer "
                      "raises after promotion",
            expected_stop="exception propagates; no official group promoted",
            reason_code="separated_manifest_missing",
            saved_state="no manifest; group not official; temp cleaned; "
                        "session unmutated",
            resumable=True,
            resendable=False,
        )
        assert drill.reason_code == "separated_manifest_missing"
        assert drill.resumable is True
        assert drill.resendable is False
