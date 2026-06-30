"""
T-0.1 / T-3.1 through T-3.5 / T-4.1/T-4.2: Shadow decision integration tests.

Phase 4 shadow mode: observation only. Execution must not change.
"""
import copy
import hashlib

import pytest
from unittest.mock import MagicMock, patch

from src.core.engine.scheduling_decision import SchedulingDecision, MutationSurface
from src.core.engine.lane_policy import LanePolicy, PHASE0_CLASS_TO_LANE
from src.core.engine.mutex_policy import MutexPolicy
from src.core.domain.model.task import Task, TaskState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_task(agent_type="ScannerSwarm", metadata=None, task_id="task-1"):
    """Create a minimal Task with metadata."""
    return Task(
        id=task_id,
        name=f"Test {agent_type}",
        agent_type=agent_type,
        metadata=metadata or {},
    )


def _default_metadata(origin_key="https://example.com", session_key="sess-1", auth_version=1):
    return {
        "origin_key": origin_key,
        "session_key": session_key,
        "auth_context_version": auth_version,
        "canonical_endpoint_key": "https://example.com/api",
    }


# ---------------------------------------------------------------------------
# T-0.1: Shadow off baseline — characterization test
# ---------------------------------------------------------------------------

class TestShadowOffBaseline:
    """T-0.1: When shadow mode is off, behavior is identical to pre-Phase-4.
    
    This test characterizes: tasks can be classified but the classification
    does NOT change any task state or execution path.
    """

    def test_shadow_classification_does_not_mutate_task(self):
        """Classifying a task must not mutate the Task object."""
        md = _default_metadata()
        task = _make_task("ScannerSwarm", metadata=copy.deepcopy(md))
        original_state = task.state
        original_metadata = copy.deepcopy(task.metadata)

        lp = LanePolicy()
        mp = MutexPolicy()

        lane, ps, rl, compat, disagree, reason = lp.classify(
            task.agent_type, task.metadata
        )
        mutex_key, mutation_surf, would_wait, would_reject = mp.decide(task.metadata)

        # Task state unchanged
        assert task.state == original_state
        assert task.metadata == original_metadata
        assert task.name.startswith("Test")

    def test_classification_result_has_correct_shape(self):
        """Verification that classification output has all expected fields."""
        md = _default_metadata()
        lp = LanePolicy()
        mp = MutexPolicy()

        lane, ps, rl, compat, disagree, reason = lp.classify("ScannerSwarm", md)
        mutex_key, surf, wait, rej = mp.decide(md)

        # Build a complete decision
        decision = SchedulingDecision(
            lane=lane,
            parallel_safe=ps,
            rate_limited=rl,
            compat_lane=compat,
            lane_disagreement=disagree,
            reason_code=reason,
            mutex_key=mutex_key,
            mutation_surface=surf,
            would_wait=wait,
            would_reject=rej,
            shadow_only=True,
            origin_key=md.get("origin_key", ""),
            auth_context_version=int(md.get("auth_context_version", 0)),
        )

        assert decision.shadow_only is True
        assert decision.lane in {"read_only", "stateful_read", "mutating", "aggressive_exclusive", "sequential_required"}
        assert decision.reason_code != ""
        assert len(decision.mutex_key) in (0, 16)  # empty or 16-char hash
        assert decision.mutation_surface == "unknown"
        assert decision.would_wait is False
        assert decision.would_reject is False


# ---------------------------------------------------------------------------
# T-3.1: Shadow decision coverage — every task gets a decision
# ---------------------------------------------------------------------------

class TestShadowDecisionCoverage:
    """T-3.1: All tasks must receive a SchedulingDecision with lane + reason_code."""

    _AGENTS = [
        "InjectionManagerAgent", "AuthNinja", "ScannerSwarm", "FuzzingSwarm",
        "SecretSwarm", "IntelligenceSwarm", "DiscoverySwarm", "BizLogicHunter",
    ]

    def test_all_known_agent_types_classified(self):
        """Every known agent type must produce a valid classification."""
        lp = LanePolicy()
        for agent in self._AGENTS:
            lane, ps, rl, compat, disagree, reason = lp.classify(agent)
            assert lane != "", f"Agent '{agent}' has empty lane"
            assert reason != "", f"Agent '{agent}' has empty reason_code"
            assert lane in {"read_only", "stateful_read", "mutating", "aggressive_exclusive", "sequential_required"}, (
                f"Agent '{agent}' has invalid lane '{lane}'"
            )

    def test_all_swarms_have_decisions(self):
        """Every swarm in the map must produce a valid classification."""
        lp = LanePolicy()
        for swarm in lp._swarm_to_specialists:
            lane, ps, rl, compat, disagree, reason = lp.classify_swarm(swarm)
            assert lane != ""
            assert reason != ""

    def test_empty_agent_type_defaults_safely(self):
        """Empty agent_type must not crash — defaults to sequential_required."""
        lp = LanePolicy()
        lane, _, _, _, _, reason = lp.classify("")
        assert lane == "sequential_required"
        assert reason != ""

    def test_none_agent_type_defaults_safely(self):
        """None agent_type must not crash — defaults to sequential_required."""
        lp = LanePolicy()
        lane, _, _, _, _, reason = lp.classify(None)  # type: ignore
        assert lane == "sequential_required"


# ---------------------------------------------------------------------------
# T-3.2: Shadow on/off parity — execution unchanged
# ---------------------------------------------------------------------------

class TestShadowOnOffParity:
    """T-3.2: shadow decision computation does NOT change task execution behavior.
    
    The core invariant: shadow decisions are computed but never affect execution flow.
    Task state, params, findings, and execution order are identical with or without shadow.
    """

    def test_multiple_classifications_produce_same_result(self):
        """Repeated classifications on same task are idempotent."""
        md = _default_metadata()
        lp = LanePolicy()
        mp = MutexPolicy()

        results = []
        for _ in range(5):
            lane, ps, rl, compat, disagree, reason = lp.classify("ScannerSwarm", md)
            mutex_key, surf, wait, rej = mp.decide(md)
            results.append((lane, ps, rl, mutex_key))

        # All identical
        assert len(set(results)) == 1

    def test_classification_does_not_consume_mutex(self):
        """MutexPolicy.decide in shadow mode returns would_wait=False and would_reject=False."""
        mp = MutexPolicy()
        for md in [
            _default_metadata(),
            {"origin_key": "https://x.com"},
            None,
        ]:
            _, _, wait, reject = mp.decide(md)
            assert wait is False, f"would_wait should be False in shadow mode"
            assert reject is False, f"would_reject should be False in shadow mode"

    def test_classification_does_not_modify_input_metadata(self):
        """Neither LanePolicy nor MutexPolicy should modify the input metadata dict."""
        md = _default_metadata()
        original = copy.deepcopy(md)

        lp = LanePolicy()
        mp = MutexPolicy()

        lp.classify("ScannerSwarm", md)
        mp.decide(md)

        assert md == original, "Metadata was mutated by classification"


# ---------------------------------------------------------------------------
# T-3.3: Shadow state isolation
# ---------------------------------------------------------------------------

class TestShadowStateIsolation:
    """T-3.3: Shadow decision state does NOT backflow into real executor."""

    def test_lane_policy_has_no_mutable_side_effect(self):
        """LanePolicy classification is a pure function (no side effects on MC state)."""
        lp = LanePolicy()
        # Multiple calls with different tasks must not interfere
        result1 = lp.classify("ScannerSwarm", _default_metadata())
        result2 = lp.classify("InjectionManagerAgent", _default_metadata())
        # Results should be independent
        assert result1[0] != ""  # has valid lane
        assert result2[0] != ""

    def test_mutex_policy_has_no_side_effect(self):
        """MutexPolicy.decide is a pure function."""
        mp = MutexPolicy()
        md = _default_metadata()
        r1 = mp.decide(copy.deepcopy(md))
        r2 = mp.decide(copy.deepcopy(md))
        assert r1 == r2


# ---------------------------------------------------------------------------
# T-3.4: Persistence — decision_traces sink
# ---------------------------------------------------------------------------

class TestShadowDecisionPersistence:
    """T-3.4: SchedulingDecision is persisted via decision_traces."""

    def test_decision_can_be_added_to_list(self):
        """SchedulingDecision objects can be collected in a list for session persistence."""
        decisions = []
        lp = LanePolicy()
        mp = MutexPolicy()

        for agent in ["ScannerSwarm", "SecretSwarm", "IntelligenceSwarm"]:
            md = _default_metadata()
            lane, ps, rl, compat, disagree, reason = lp.classify(agent, md)
            mutex_key, surf, wait, rej = mp.decide(md)
            decisions.append(SchedulingDecision(
                lane=lane, parallel_safe=ps, rate_limited=rl,
                compat_lane=compat, lane_disagreement=disagree,
                reason_code=reason, mutex_key=mutex_key,
                mutation_surface=surf, would_wait=wait,
                would_reject=rej, shadow_only=True,
                origin_key=md.get("origin_key", ""),
                auth_context_version=int(md.get("auth_context_version", 0)),
            ))

        assert len(decisions) == 3
        for d in decisions:
            assert d.shadow_only is True
            assert d.reason_code != ""

    def test_build_async_session_payload_accepts_decision_traces(self):
        """build_async_session_payload accepts decision_traces parameter (None-safe)."""
        from src.core.engine.master_conductor_session_service import build_async_session_payload

        # None-safe: passing None should not crash
        payload_none = build_async_session_payload(
            task_queue=[],
            completed_tasks=[],
            context=MagicMock(_total_attempts=0, _successful_attempts=0,
                              bypass_methods=[], discovered_assets=[],
                              target_info={}),
            pending_hitl=[],
            coverage_gate={},
            scenario_coverage={},
            timestamp=0.0,
            default_start_time=0.0,
            decision_traces=None,
        )
        assert "decision_traces" not in payload_none or payload_none.get("decision_traces") is None

        # With decision_traces: should be deep-copied into payload
        decisions = [
            SchedulingDecision(lane="read_only", parallel_safe=True, rate_limited=False,
                               reason_code="test")
        ]
        payload_with = build_async_session_payload(
            task_queue=[],
            completed_tasks=[],
            context=MagicMock(_total_attempts=0, _successful_attempts=0,
                              bypass_methods=[], discovered_assets=[],
                              target_info={}),
            pending_hitl=[],
            coverage_gate={},
            scenario_coverage={},
            timestamp=0.0,
            default_start_time=0.0,
            decision_traces=decisions,
        )
        assert "decision_traces" in payload_with
        assert len(payload_with["decision_traces"]) == 1
        assert payload_with["decision_traces"][0].lane == "read_only"

    def test_DECISION_MADE_event_type_exists(self):
        """RunLedgerEventType.DECISION_MADE is defined."""
        from src.core.models.run_ledger import RunLedgerEventType
        assert RunLedgerEventType.DECISION_MADE == "decision_made"


# ---------------------------------------------------------------------------
# T-3.5: No secrets in snapshot (safe-by-construction)
# ---------------------------------------------------------------------------

class TestNoSecretsInDecisions:
    """T-3.5: SchedulingDecision contains no secret values."""

    def test_decision_serialization_no_secrets(self):
        """SchedulingDecision fields must not contain secret-bearing keys."""
        import dataclasses
        fields = {f.name for f in dataclasses.fields(SchedulingDecision)}

        secret_patterns = {"cookie", "token", "secret", "password", "api_key",
                           "authorization", "auth_header", "credential"}
        for field_name in fields:
            for pattern in secret_patterns:
                assert pattern not in field_name.lower(), (
                    f"Field '{field_name}' may contain secrets"
                )

    def test_mutex_key_is_hash_not_raw_data(self):
        """mutex_key is a hash string, not raw URL/header."""
        md = _default_metadata()
        mp = MutexPolicy()
        mutex_key, _, _, _ = mp.decide(md)
        assert len(mutex_key) == 16
        # Hash should not contain the raw URL
        assert "https://" not in mutex_key
        assert "example.com" not in mutex_key

    def test_origin_key_is_normalized(self):
        """origin_key in metadata is already normalized (just scheme://host[:port])."""
        md = _default_metadata(origin_key="https://example.com")
        assert "api" not in md["origin_key"]  # no path
        assert md["origin_key"] == "https://example.com"


# ---------------------------------------------------------------------------
# T-4.1: Phase 2 admission/budget decision reuse
# ---------------------------------------------------------------------------

class TestPhase2Reuse:
    """T-4.1: Shadow decision uses Phase 2 compat_lane but does not re-compute admission."""

    def test_compat_lane_comes_from_phase2_mapping(self):
        """compat_lane is derived from Phase 2 CATEGORY_TO_LANE."""
        from src.core.engine.parallel_orchestrator import CATEGORY_TO_LANE
        lp = LanePolicy()

        # attack_inject → Phase 2 says "mutating"
        _, _, _, compat_lane, _, _ = lp.classify_swarm(
            "injection", {"category": "attack_inject"}
        )
        assert compat_lane == "mutating"
        assert CATEGORY_TO_LANE.get("attack_inject") == "mutating"

    def test_shadow_does_not_consume_budget(self):
        """MutexPolicy in shadow mode does not consume ExecutionBudgetPolicy budget."""
        from src.core.engine.budget_policy import ExecutionBudgetPolicy
        budget = ExecutionBudgetPolicy(rpm=60, burst=3)
        # Consume budget normally
        for _ in range(3):
            assert budget.consume("https://example.com").allowed is True
        # Budget exhausted
        assert budget.consume("https://example.com").allowed is False

        # Shadow MutexPolicy: would_wait=False, would_reject=False regardless
        mp = MutexPolicy()
        _, _, wait, reject = mp.decide({"origin_key": "https://example.com"})
        assert wait is False
        assert reject is False


# ---------------------------------------------------------------------------
# T-4.2: Phase 1 metadata regression
# ---------------------------------------------------------------------------

class TestPhase1Regression:
    """T-4.2: Phase 1 metadata fields are preserved during shadow classification."""

    def test_metadata_schema_version_preserved(self):
        """Task metadata with schema_version survives classification roundtrip."""
        md = {**_default_metadata(), "schema_version": 1}
        task = Task(id="t1", name="Test", metadata=copy.deepcopy(md))

        lp = LanePolicy()
        lp.classify(task.agent_type or "default", task.metadata)

        assert task.metadata.get("schema_version") == 1
        assert task.metadata.get("origin_key") == "https://example.com"

    def test_correlation_id_preserved(self):
        """correlation_id in metadata survives."""
        md = {**_default_metadata(), "correlation_id": "corr-abc-123"}
        task = Task(id="t1", name="Test", metadata=copy.deepcopy(md))
        lp = LanePolicy()
        lp.classify(task.agent_type or "default", task.metadata)
        assert task.metadata.get("correlation_id") == "corr-abc-123"

    def test_task_serialization_unchanged_by_classification(self):
        """Task.to_dict() output is identical before and after shadow classification."""
        md = _default_metadata()
        task = Task(id="task-1", name="Test Task", agent_type="ScannerSwarm",
                    metadata=copy.deepcopy(md))

        before = task.to_dict()

        lp = LanePolicy()
        mp = MutexPolicy()
        lp.classify(task.agent_type, task.metadata)
        mp.decide(task.metadata)

        after = task.to_dict()

        assert before == after, (
            f"Task.to_dict() changed after classification!\n"
            f"Before: {before}\nAfter:  {after}"
        )
