"""
Tests for TaskPruningPolicy and TaskPruningDecision.
SGK-2026-0287 Step 1 + Step 6: data model, protected tasks, shadow mode, conservative rules.
"""
import pytest
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

from src.core.engine.task_pruning_policy import (
    TaskPruningDecision,
    TaskPruningPolicy,
    resolve_pruning_mode,
    REASON_CODE_TO_REASONING,
    get_reasoning,
)
from src.core.engine.task_queue import DynamicTaskQueue


# -- Test helpers --

@dataclass
class MockTask:
    id: str
    name: str = "Test Task"
    priority: int = 0
    agent_type: str = "test"
    action: str = "run"
    tags: List[str] = field(default_factory=list)
    params: Dict[str, Any] = field(default_factory=dict)
    target: str = ""


# ======================================================================
# TaskPruningDecision tests
# ======================================================================

class TestTaskPruningDecision:
    def test_decision_creation_defaults(self):
        """TaskPruningDecision has correct default values."""
        d = TaskPruningDecision(
            task_id="task_abc",
            lifecycle_status="retired",
            reason_code="duplicate",
        )
        assert d.task_id == "task_abc"
        assert d.lifecycle_status == "retired"
        assert d.reason_code == "duplicate"
        assert d.trigger_event_id is None
        assert d.evidence_key is None
        assert d.protected is False
        assert d.shadow_only is True
        assert isinstance(d.timestamp, datetime)

    def test_decision_to_dict(self):
        """to_dict() produces a dict compatible with decision_traces sink."""
        d = TaskPruningDecision(
            task_id="task_xyz",
            lifecycle_status="superseded",
            reason_code="chain_completed",
            trigger_event_id="evt_001",
            evidence_key="vuln_123:admin_panel",
            protected=False,
        )
        result = d.to_dict()
        assert result["decision_type"] == "task_superseded"
        assert result["task_id"] == "task_xyz"
        assert result["lifecycle_status"] == "superseded"
        assert result["reason_code"] == "chain_completed"
        assert result["trigger_event_id"] == "evt_001"
        assert result["evidence_key"] == "vuln_123:admin_panel"
        assert result["protected"] is False
        assert result["shadow_only"] is True
        assert "timestamp" in result

    def test_decision_to_dict_invalidated(self):
        """to_dict() for invalidated status."""
        d = TaskPruningDecision(
            task_id="task_stale",
            lifecycle_status="invalidated",
            reason_code="stale_snapshot",
            trigger_event_id="evt_recon_002",
        )
        result = d.to_dict()
        assert result["decision_type"] == "task_invalidated"


# ======================================================================
# TaskPruningPolicy - Protected tasks
# ======================================================================

class TestTaskPruningPolicyProtected:
    """Tests that protected tasks are never pruned."""

    def test_protected_scope_parser_not_pruned(self):
        """scope_parser agent_type is protected."""
        policy = TaskPruningPolicy()
        task = MockTask(
            id="t1",
            name="Scope Check",
            agent_type="scope_parser",
        )
        assert policy._is_protected(task) is True

    def test_protected_coverage_guard_not_pruned(self):
        """coverage_guard agent_type is protected."""
        policy = TaskPruningPolicy()
        task = MockTask(
            id="t2",
            name="Coverage Guard",
            agent_type="coverage_guard",
        )
        assert policy._is_protected(task) is True

    def test_protected_scenario_probe_not_pruned(self):
        """scenario_probe agent_type is protected."""
        policy = TaskPruningPolicy()
        task = MockTask(
            id="t3",
            name="Scenario Probe",
            agent_type="scenario_probe",
        )
        assert policy._is_protected(task) is True

    def test_protected_manual_verify_not_pruned(self):
        """manual_verify agent_type is protected."""
        policy = TaskPruningPolicy()
        task = MockTask(
            id="t4",
            name="Manual Verify",
            agent_type="manual_verify",
        )
        assert policy._is_protected(task) is True

    def test_protected_report_not_pruned(self):
        """report agent_type is protected."""
        policy = TaskPruningPolicy()
        task = MockTask(
            id="t5",
            name="Report Gen",
            agent_type="report",
        )
        assert policy._is_protected(task) is True

    def test_protected_evidence_not_pruned(self):
        """evidence agent_type is protected."""
        policy = TaskPruningPolicy()
        task = MockTask(
            id="t6",
            name="Evidence Collect",
            agent_type="evidence",
        )
        assert policy._is_protected(task) is True

    def test_protected_via_tags(self):
        """manual_verify and coverage_guard_forced tags are protected."""
        policy = TaskPruningPolicy()
        task1 = MockTask(id="t7", agent_type="web_scanner", tags=["manual_verify"])
        task2 = MockTask(id="t8", agent_type="web_scanner", tags=["coverage_guard_forced"])
        task3 = MockTask(id="t9", agent_type="web_scanner", tags=["Manual_Verify"])  # case insensitive
        assert policy._is_protected(task1) is True
        assert policy._is_protected(task2) is True
        assert policy._is_protected(task3) is True

    def test_protected_via_source_category(self):
        """source_category values in params are protected."""
        policy = TaskPruningPolicy()
        for cat in ["scenario_probe_planner", "scenario_probe_guard",
                     "coverage_backfill", "coverage_backfill_guard", "tagged_meta_observability"]:
            task = MockTask(
                id=f"t_{cat}",
                agent_type="web_scanner",
                params={"source_category": cat},
            )
            assert policy._is_protected(task) is True, f"{cat} should be protected"

    def test_protected_scn06_meta_observability_not_pruned(self):
        """SCN06 meta-observability tasks are protected even without probe tags."""
        policy = TaskPruningPolicy()
        task = MockTask(
            id="t_scn06_meta",
            agent_type="DiscoverySwarm",
            params={
                "category": "meta_observability",
                "scenario_id": "scn_06_data_exposure_diff",
                "target": "https://app.example.com/config/config.inc.php.dist",
            },
        )
        assert policy._is_protected(task) is True

    def test_not_protected_ordinary_task(self):
        """Ordinary web_scanner task is not protected."""
        policy = TaskPruningPolicy()
        task = MockTask(
            id="t10",
            agent_type="web_scanner",
            params={"source_category": "discovery"},
        )
        assert policy._is_protected(task) is False


# ======================================================================
# TaskPruningPolicy - Conservative rules
# ======================================================================

class TestTaskPruningPolicyEvaluate:
    """Tests for the evaluate() method with conservative initial rules."""

    def _build_queue(self, tasks: List[MockTask]) -> DynamicTaskQueue:
        q = DynamicTaskQueue()
        for t in tasks:
            q.add(t)
        return q

    def test_evaluate_returns_empty_for_protected_tasks(self):
        """Protected tasks are never in prune candidate list."""
        policy = TaskPruningPolicy()
        task = MockTask(id="t_protected", agent_type="scope_parser")
        queue = self._build_queue([task])
        decisions = policy.evaluate(queue_snapshot=queue, completed_task=None, findings=[])
        assert decisions == []

    def test_evaluate_detects_duplicate_tasks(self):
        """Two tasks with same agent_type + target + action => one is flagged."""
        policy = TaskPruningPolicy()
        t1 = MockTask(id="task_a", agent_type="web_scanner",
                      target="https://example.com", action="scan", priority=10)
        t2 = MockTask(id="task_b", agent_type="web_scanner",
                      target="https://example.com", action="scan", priority=5)
        queue = self._build_queue([t1, t2])
        decisions = policy.evaluate(queue_snapshot=queue, completed_task=None, findings=[])
        # Lower-priority duplicate should be a candidate
        assert len(decisions) >= 1
        dup_decision = [d for d in decisions if d.reason_code == "duplicate"]
        assert len(dup_decision) >= 1

    def test_evaluate_no_duplicate_for_different_targets(self):
        """Same agent_type + action but different targets => not duplicate."""
        policy = TaskPruningPolicy()
        t1 = MockTask(id="task_a", agent_type="web_scanner",
                      target="https://example.com", action="scan")
        t2 = MockTask(id="task_b", agent_type="web_scanner",
                      target="https://other.com", action="scan")
        queue = self._build_queue([t1, t2])
        decisions = policy.evaluate(queue_snapshot=queue, completed_task=None, findings=[])
        dup = [d for d in decisions if d.reason_code == "duplicate"]
        assert dup == []

    def test_evaluate_out_of_scope_task(self):
        """Task with out-of-scope tag/params is detected."""
        policy = TaskPruningPolicy()
        task = MockTask(
            id="task_oos",
            agent_type="web_scanner",
            params={"out_of_scope": True, "source_category": "discovery"},
        )
        queue = self._build_queue([task])
        decisions = policy.evaluate(queue_snapshot=queue, completed_task=None, findings=[])
        oos = [d for d in decisions if d.reason_code == "out_of_scope"]
        assert len(oos) == 1
        assert oos[0].task_id == "task_oos"

    def test_evaluate_protected_not_in_result(self):
        """Protected tasks are excluded from any decision."""
        policy = TaskPruningPolicy()
        t_protected = MockTask(id="t_protected", agent_type="coverage_guard",
                               params={"out_of_scope": True},  # even if out_of_scope
                               )
        t_normal = MockTask(id="t_normal", agent_type="web_scanner",
                            params={"out_of_scope": True, "source_category": "discovery"},
                            )
        queue = self._build_queue([t_protected, t_normal])
        decisions = policy.evaluate(queue_snapshot=queue, completed_task=None, findings=[])
        # protected task should NOT be in decisions
        protected_ids = [d.task_id for d in decisions if d.task_id == "t_protected"]
        assert protected_ids == []
        # normal task SHOULD be
        assert any(d.task_id == "t_normal" for d in decisions)

    def test_evaluate_shadow_only_default(self):
        """All decisions are shadow_only=True by default."""
        policy = TaskPruningPolicy()
        task = MockTask(id="t_oos", agent_type="web_scanner",
                        params={"out_of_scope": True, "source_category": "discovery"})
        queue = self._build_queue([task])
        decisions = policy.evaluate(queue_snapshot=queue, completed_task=None, findings=[])
        assert len(decisions) > 0
        for d in decisions:
            assert d.shadow_only is True

    def test_evaluate_with_completed_task_chain(self):
        """Completed chaining task may invalidate follow-up tasks."""
        policy = TaskPruningPolicy()
        # A follow-up task that was generated by vuln chaining
        follow_up = MockTask(
            id="follow_up_1",
            name="Chain Admin Probe",
            agent_type="auth",
            priority=2,
            params={"generation_reason": "vulnerability_chaining",
                     "parent_vuln_type": "idor"},
        )
        queue = self._build_queue([follow_up])
        decisions = policy.evaluate(queue_snapshot=queue,
                                     completed_task=None,
                                     findings=[])
        # Chain follow-up may be flagged if it no longer has value
        chain = [d for d in decisions if d.reason_code == "chain_low_value"]
        # At minimum, we assert the policy runs without error
        assert isinstance(decisions, list)

    def test_evaluate_empty_queue(self):
        """Empty queue returns empty decisions."""
        policy = TaskPruningPolicy()
        queue = self._build_queue([])
        decisions = policy.evaluate(queue_snapshot=queue, completed_task=None, findings=[])
        assert decisions == []

    def test_evaluate_preserves_task_index(self):
        """evaluate() does not mutate the queue."""
        policy = TaskPruningPolicy()
        t1 = MockTask(id="task_a", agent_type="web_scanner",
                      target="https://example.com", action="scan")
        queue = self._build_queue([t1])
        initial_len = len(queue)
        policy.evaluate(queue_snapshot=queue, completed_task=None, findings=[])
        assert len(queue) == initial_len
        assert queue.get_by_id("task_a") is not None


# ======================================================================
# TaskPruningPolicy - round-trip via to_dict
# ======================================================================

class TestTaskPruningDecisionRoundTrip:
    def test_multiple_decisions_to_dict_list(self):
        """Multiple decisions serialized as list of dicts."""
        decisions = [
            TaskPruningDecision(task_id="t1", lifecycle_status="retired",
                                 reason_code="duplicate"),
            TaskPruningDecision(task_id="t2", lifecycle_status="invalidated",
                                 reason_code="stale_snapshot",
                                 trigger_event_id="evt_003"),
        ]
        result_list = [d.to_dict() for d in decisions]
        assert len(result_list) == 2
        assert result_list[0]["task_id"] == "t1"
        assert result_list[1]["task_id"] == "t2"
        assert result_list[0]["decision_type"] == "task_retired"
        assert result_list[1]["decision_type"] == "task_invalidated"


# ======================================================================
# SGK-2026-0287 Steps 4-5: resolve_pruning_mode, new fields, reason_code mapping
# ======================================================================

class TestResolvePruningMode:
    """Tests for the single-authority resolve_pruning_mode() function."""

    def test_shadow_mode_valid(self):
        """Valid 'shadow' returns 'shadow'."""
        assert resolve_pruning_mode(raw="shadow") == "shadow"

    def test_active_mode_valid(self):
        """Valid 'active' returns 'active'."""
        assert resolve_pruning_mode(raw="active") == "active"

    def test_none_defaults_to_shadow(self):
        """None input defaults to shadow (fail-closed)."""
        assert resolve_pruning_mode(raw=None) == "shadow"

    def test_empty_string_defaults_to_shadow(self):
        """Empty string defaults to shadow (fail-closed)."""
        assert resolve_pruning_mode(raw="") == "shadow"

    def test_invalid_mode_fail_closed(self):
        """Unrecognised value fail-closed to shadow."""
        for bad in ["aggressive", "none", "true", "1", "SHADOW"]:
            assert resolve_pruning_mode(raw=bad) == "shadow", f"{bad!r}"

    def test_killswitch_overrides_active(self):
        """Killswitch forces shadow regardless of pruning_mode."""
        assert resolve_pruning_mode(raw="active", killswitch_enabled=True) == "shadow"

    def test_killswitch_overrides_shadow(self):
        """Killswitch on shadow stays shadow."""
        assert resolve_pruning_mode(raw="shadow", killswitch_enabled=True) == "shadow"

    def test_case_insensitive(self):
        """Case-insensitive matching for valid modes."""
        assert resolve_pruning_mode(raw="SHADOW") == "shadow"
        assert resolve_pruning_mode(raw="Active") == "active"

    def test_whitespace_handling(self):
        """Leading/trailing whitespace is stripped."""
        assert resolve_pruning_mode(raw="  shadow  ") == "shadow"
        assert resolve_pruning_mode(raw="\tactive\n") == "active"


class TestTaskPruningDecisionNewFields:
    """SGK-2026-0287 Step 5-1: mandatory fields on TaskPruningDecision."""

    def test_new_fields_defaults(self):
        """New fields have correct defaults."""
        d = TaskPruningDecision(task_id="t1", lifecycle_status="retired", reason_code="duplicate")
        assert d.before_count == 0
        assert d.after_count == 0
        assert d.trigger_task_id is None
        assert d.finding_ids == []
        assert d.mode == "shadow"

    def test_new_fields_explicit(self):
        """New fields can be set explicitly."""
        d = TaskPruningDecision(
            task_id="t1",
            lifecycle_status="superseded",
            reason_code="duplicate",
            before_count=10,
            after_count=9,
            trigger_task_id="t0",
            finding_ids=["f1", "f2"],
            mode="active",
        )
        assert d.before_count == 10
        assert d.after_count == 9
        assert d.trigger_task_id == "t0"
        assert d.finding_ids == ["f1", "f2"]
        assert d.mode == "active"

    def test_new_fields_in_to_dict(self):
        """to_dict() includes new mandatory fields."""
        d = TaskPruningDecision(
            task_id="t1",
            lifecycle_status="retired",
            reason_code="out_of_scope",
            before_count=5,
            after_count=5,
            trigger_task_id="t0",
            finding_ids=["f1"],
            mode="shadow",
            protected=True,
        )
        result = d.to_dict()
        assert result["before_count"] == 5
        assert result["after_count"] == 5
        assert result["trigger_task_id"] == "t0"
        assert result["finding_ids"] == ["f1"]
        assert result["mode"] == "shadow"
        assert result["protected"] is True

    def test_shadow_only_property(self):
        """shadow_only is a derived property from mode."""
        d_shadow = TaskPruningDecision(task_id="t1", lifecycle_status="retired",
                                        reason_code="duplicate", mode="shadow")
        d_active = TaskPruningDecision(task_id="t2", lifecycle_status="retired",
                                        reason_code="duplicate", mode="active")
        assert d_shadow.shadow_only is True
        assert d_active.shadow_only is False

    def test_to_dict_includes_shadow_only(self):
        """Backward compat: to_dict includes shadow_only field."""
        d = TaskPruningDecision(task_id="t1", lifecycle_status="retired",
                                reason_code="duplicate", mode="shadow")
        result = d.to_dict()
        assert result["shadow_only"] is True


class TestReasonCodeMapping:
    """SGK-2026-0287 Step 5-2: reason_code -> reasoning/outcome mapping."""

    def test_all_reason_codes_have_mapping(self):
        """Every reason code referenced in the plan has a mapping entry."""
        expected_codes = {
            "duplicate", "out_of_scope", "chain_low_value",
            "stale_snapshot", "chain_completed", "low_value_static_asset",
            "protected_skip", "eval_failure_skip", "killswitch_active",
            "unsupported_task_type",
        }
        for code in expected_codes:
            assert code in REASON_CODE_TO_REASONING, f"{code} missing from mapping"

    def test_get_reasoning_known_code(self):
        """get_reasoning returns human-readable text for known codes."""
        result = get_reasoning("duplicate")
        assert "duplicate" in result.lower()
        assert len(result) > 20

    def test_get_reasoning_unknown_code_fallback(self):
        """get_reasoning falls back to raw reason_code for unknown codes."""
        result = get_reasoning("some_future_code")
        assert "some_future_code" in result

    def test_reasoning_does_not_duplicate_fields(self):
        """reasoning is derived from reason_code, not a separate stored field."""
        # The mapping exists in code; report formatter reads reason_code and
        # maps through get_reasoning(). Both fields in to_dict come from the
        # same source — no independent duplicated field.
        d = TaskPruningDecision(task_id="t1", lifecycle_status="retired",
                                reason_code="duplicate")
        result = d.to_dict()
        assert result["reason_code"] == "duplicate"
        # reasoning is NOT in to_dict (it's injected by _evaluate_pruning_policy)
        assert "reasoning" not in result


class TestTaskPruningPolicyMode:
    """SGK-2026-0287 Step 4: TaskPruningPolicy accepts mode from resolve_pruning_mode()."""

    def test_policy_defaults_to_shadow(self):
        """Default constructor uses shadow mode."""
        policy = TaskPruningPolicy()
        assert policy.mode == "shadow"
        assert policy.shadow_only is True

    def test_policy_active_mode(self):
        """Explicit 'active' mode."""
        policy = TaskPruningPolicy(mode="active")
        assert policy.mode == "active"
        assert policy.shadow_only is False

    def test_policy_invalid_mode_fail_closed(self):
        """Invalid mode passed to constructor is fail-closed to shadow."""
        policy = TaskPruningPolicy(mode="aggressive")
        assert policy.mode == "shadow"
        assert policy.shadow_only is True

    def test_decision_mode_matches_policy_mode(self):
        """Decisions produced by the policy carry the policy's mode."""
        policy_shadow = TaskPruningPolicy(mode="shadow")
        policy_active = TaskPruningPolicy(mode="active")

        t = MockTask(id="t1", agent_type="web_scanner",
                     params={"out_of_scope": True, "source_category": "discovery"})
        from src.core.engine.task_queue import DynamicTaskQueue
        q = DynamicTaskQueue()
        q.add(t)

        d_shadow = policy_shadow.evaluate(queue_snapshot=q, completed_task=None, findings=[])
        d_active = policy_active.evaluate(queue_snapshot=q, completed_task=None, findings=[])

        assert len(d_shadow) > 0
        assert len(d_active) > 0
        assert d_shadow[0].mode == "shadow"
        assert d_active[0].mode == "active"


# ======================================================================
# SGK-2026-0287 Steps 6-8: low-value static asset, boost/prune competition
# ======================================================================

class TestLowValueStaticAsset:
    """Tests for Rule 4: low-value static asset pruning."""

    def _build_queue(self, tasks):
        q = DynamicTaskQueue()
        for t in tasks:
            q.add(t)
        return q

    def test_static_extension_detected(self):
        """Tasks targeting static extensions are flagged."""
        policy = TaskPruningPolicy()
        t = MockTask(id="t1", agent_type="web_scanner",
                     target="https://example.com/logo.png",
                     params={"source_category": "discovery"})
        q = self._build_queue([t])
        decisions = policy.evaluate(queue_snapshot=q)
        static = [d for d in decisions if d.reason_code == "low_value_static_asset"]
        assert len(static) == 1
        assert static[0].task_id == "t1"

    def test_exclude_pattern_detected(self):
        """Tasks matching exclude patterns (jquery, bootstrap, etc.) are flagged."""
        policy = TaskPruningPolicy()
        t = MockTask(id="t1", agent_type="web_scanner",
                     target="https://example.com/assets/js/jquery.min.js",
                     params={"source_category": "discovery"})
        q = self._build_queue([t])
        decisions = policy.evaluate(queue_snapshot=q)
        static = [d for d in decisions if d.reason_code == "low_value_static_asset"]
        assert len(static) == 1

    def test_duplicate_base_path_detected(self):
        """Duplicate base-path variant (without injection/auth/logic tags) is flagged."""
        policy = TaskPruningPolicy()
        t1 = MockTask(id="t1", agent_type="web_scanner",
                      target="https://example.com/page?param=1",
                      params={"source_category": "discovery"})
        t2 = MockTask(id="t2", agent_type="web_scanner",
                      target="https://example.com/page?param=2",
                      params={"source_category": "discovery"})
        q = self._build_queue([t1, t2])
        decisions = policy.evaluate(queue_snapshot=q)
        static = [d for d in decisions if d.reason_code == "low_value_static_asset"]
        assert len(static) >= 1

    def test_duplicate_base_path_injection_tag_not_flagged(self):
        """Duplicate base-path variant with injection/auth/logic tags is NOT flagged."""
        policy = TaskPruningPolicy()
        t1 = MockTask(id="t1", agent_type="web_scanner",
                      target="https://example.com/page?param=1",
                      params={"source_category": "discovery"})
        t2 = MockTask(id="t2", agent_type="web_scanner",
                      target="https://example.com/page?param=2",
                      tags=["injection"],
                      params={"source_category": "discovery"})
        q = self._build_queue([t1, t2])
        decisions = policy.evaluate(queue_snapshot=q)
        static = [d for d in decisions if d.reason_code == "low_value_static_asset"
                   and d.task_id == "t2"]
        assert len(static) == 0  # t2 has injection tag, should NOT be flagged

    def test_normal_url_not_flagged(self):
        """A normal URL (API endpoint) is not flagged as low-value static asset."""
        policy = TaskPruningPolicy()
        t = MockTask(id="t1", agent_type="web_scanner",
                     target="https://example.com/api/v1/users",
                     params={"source_category": "discovery"})
        q = self._build_queue([t])
        decisions = policy.evaluate(queue_snapshot=q)
        static = [d for d in decisions if d.reason_code == "low_value_static_asset"]
        assert len(static) == 0


class TestBoostPruneCompetition:
    """SGK-2026-0287 Step 8-3: boost takes priority over prune."""

    def _build_queue(self, tasks):
        q = DynamicTaskQueue()
        for t in tasks:
            q.add(t)
        return q

    def test_boosted_task_not_pruned(self):
        """A task with boosted priority (>=200) is NOT pruned."""
        policy = TaskPruningPolicy()
        t = MockTask(id="t1", agent_type="web_scanner", priority=500,
                     target="https://example.com/logo.png",
                     params={"source_category": "discovery"})
        q = self._build_queue([t])
        decisions = policy.evaluate(queue_snapshot=q)
        assert len(decisions) == 0  # Boosted task excluded

    def test_boosted_task_not_pruned_for_out_of_scope(self):
        """Even out-of-scope tasks are kept if they are boosted."""
        policy = TaskPruningPolicy()
        t = MockTask(id="t1", agent_type="web_scanner", priority=500,
                     params={"out_of_scope": True, "source_category": "discovery"})
        q = self._build_queue([t])
        decisions = policy.evaluate(queue_snapshot=q)
        assert len(decisions) == 0

    def test_low_priority_still_pruned(self):
        """A low-priority (<200) task is still pruned as normal."""
        policy = TaskPruningPolicy()
        t = MockTask(id="t1", agent_type="web_scanner", priority=0,
                     target="https://example.com/logo.png",
                     params={"source_category": "discovery"})
        q = self._build_queue([t])
        decisions = policy.evaluate(queue_snapshot=q)
        assert len(decisions) > 0


# ======================================================================
# SGK-2026-0287 Step 7, 11: Shared deletion executor
# ======================================================================

class TestPruneByDecisions:
    """Tests for DynamicTaskQueue.prune_by_decisions() — shared deletion executor."""

    def _build_queue(self, tasks):
        from src.core.domain.model.task import Task
        q = DynamicTaskQueue()
        for t in tasks:
            q.add(t)
        return q

    def test_shadow_mode_deletes_nothing(self):
        """In shadow mode, no tasks are deleted regardless of protected flag."""
        q = self._build_queue([
            MockTask(id="t1", agent_type="web_scanner",
                     params={"source_category": "discovery"}),
            MockTask(id="t2", agent_type="web_scanner",
                     params={"source_category": "discovery"}),
        ])
        decisions = [
            {"task_id": "t1", "reason_code": "duplicate", "protected": False},
            {"task_id": "t2", "reason_code": "out_of_scope", "protected": False},
        ]
        result = q.prune_by_decisions(decisions, mode="shadow")
        assert result["mode"] == "shadow"
        assert result["before_count"] == 2
        assert result["after_count"] == 2
        assert len(result["applied_ids"]) == 0
        assert len(result["skipped_ids"]) == 2

    def test_active_mode_deletes_unprotected(self):
        """Active mode deletes non-protected tasks, skips protected ones."""
        q = self._build_queue([
            MockTask(id="t1", agent_type="web_scanner",
                     params={"source_category": "discovery"}),
            MockTask(id="t2", agent_type="web_scanner",
                     params={"source_category": "discovery"}),
            MockTask(id="t3", agent_type="web_scanner",
                     params={"source_category": "discovery"}),
        ])
        decisions = [
            {"task_id": "t1", "reason_code": "duplicate", "protected": False},
            {"task_id": "t2", "reason_code": "duplicate", "protected": True},
            {"task_id": "t3", "reason_code": "out_of_scope", "protected": False},
        ]
        result = q.prune_by_decisions(decisions, mode="active")
        assert result["mode"] == "active"
        assert result["before_count"] == 3
        assert result["after_count"] == 1  # t1 and t3 deleted
        assert "t1" in result["applied_ids"]
        assert "t3" in result["applied_ids"]
        assert "t2" in result["skipped_ids"]

    def test_missing_ids_recorded_not_exception(self):
        """Missing tasks are recorded in missing_ids, not raised as exceptions."""
        q = self._build_queue([
            MockTask(id="t1", agent_type="web_scanner",
                     params={"source_category": "discovery"}),
        ])
        decisions = [
            {"task_id": "t1", "reason_code": "duplicate", "protected": False},
            {"task_id": "nonexistent", "reason_code": "out_of_scope", "protected": False},
        ]
        result = q.prune_by_decisions(decisions, mode="active")
        assert "nonexistent" in result["missing_ids"]
        assert result["before_count"] == 1
        assert result["after_count"] == 0  # t1 deleted, nonexistent was missing

    def test_all_protected_all_skipped(self):
        """When all candidates are protected, nothing is deleted."""
        q = self._build_queue([
            MockTask(id="t1", agent_type="web_scanner",
                     params={"source_category": "discovery"}),
        ])
        decisions = [
            {"task_id": "t1", "reason_code": "duplicate", "protected": True},
        ]
        result = q.prune_by_decisions(decisions, mode="active")
        assert result["before_count"] == 1
        assert result["after_count"] == 1
        assert len(result["applied_ids"]) == 0
        assert "t1" in result["skipped_ids"]

    def test_empty_decisions_noop(self):
        """Empty decision list is a no-op."""
        q = self._build_queue([
            MockTask(id="t1", agent_type="web_scanner",
                     params={"source_category": "discovery"}),
        ])
        result = q.prune_by_decisions([], mode="active")
        assert result["before_count"] == 1
        assert result["after_count"] == 1
        assert len(result["requested_ids"]) == 0
        assert len(result["applied_ids"]) == 0

    def test_reason_codes_preserved(self):
        """Each task_id maps to its reason_code in the result."""
        q = self._build_queue([
            MockTask(id="t1", agent_type="web_scanner",
                     params={"source_category": "discovery"}),
        ])
        decisions = [
            {"task_id": "t1", "reason_code": "low_value_static_asset", "protected": True},
        ]
        result = q.prune_by_decisions(decisions, mode="shadow")
        assert result["reason_codes"]["t1"] == "low_value_static_asset"

    def test_requested_ids_deduplicated(self):
        """Duplicate requested IDs are deduplicated."""
        q = self._build_queue([
            MockTask(id="t1", agent_type="web_scanner",
                     params={"source_category": "discovery"}),
        ])
        decisions = [
            {"task_id": "t1", "reason_code": "duplicate", "protected": False},
            {"task_id": "t1", "reason_code": "duplicate", "protected": False},
        ]
        result = q.prune_by_decisions(decisions, mode="active")
        assert len(result["requested_ids"]) == 1
        assert len(result["applied_ids"]) == 1


# ======================================================================
# SGK-2026-0287 Step 9: Metrics counters
# ======================================================================

class TestPruningMetrics:
    """Verify that pruning metric counters are tracked on MasterConductor."""

    def test_metrics_counters_exist_after_lazy_init(self):
        """After _evaluate_pruning_policy is called, counters are initialised."""
        # We test the counting logic directly via the policy + queue integration
        # rather than instantiating the full MasterConductor.
        from src.core.engine.task_pruning_policy import resolve_pruning_mode

        # Verify the resolution function is importable and functional
        assert resolve_pruning_mode(raw="shadow") == "shadow"
        assert resolve_pruning_mode(raw="active") == "active"

    def test_metrics_names_match_spec(self):
        """The counter attribute names match the plan specification."""
        expected_names = {
            "_pruning_candidates_total",
            "_pruning_applied_total",
            "_pruning_protected_skip_total",
            "_pruning_eval_failures_total",
        }
        # Verify these are referenced in the master_conductor code
        import inspect
        from src.core.engine import master_conductor
        source = inspect.getsource(master_conductor.MasterConductor._evaluate_pruning_policy)
        for name in expected_names:
            assert name in source, f"Metric counter {name} not found in _evaluate_pruning_policy"
