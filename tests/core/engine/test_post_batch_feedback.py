"""
Phase 6 M3 + M4: PostBatchFeedback dataclass + DecisionType enum tests.
T-3.1: PostBatchFeedback dataclass has all expected fields.
T-5.1: Pruning decision persistence to decision_traces.
"""
import pytest
from dataclasses import dataclass, field
from typing import Any, Dict, List

from src.core.engine.post_batch_feedback import PostBatchFeedback
from src.core.models.decision_trace import DecisionType
from src.core.engine.task_pruning_policy import TaskPruningDecision


class TestPostBatchFeedbackDataclass:
    """T-3.1: PostBatchFeedback dataclass migration."""

    def test_all_fields_exist_with_defaults(self):
        """All 10 fields exist with correct defaults."""
        fb = PostBatchFeedback()
        assert fb.deferred_findings == []
        assert fb.deferred_critical_actions == []
        assert fb.deferred_boost_event is None
        assert fb.deferred_new_assets is None
        assert fb.deferred_react_tasks is None
        assert fb.deferred_handoff is None
        assert fb.deferred_new_context is None
        assert fb.deferred_decision_enhancer_tasks == []
        # Phase 6 additions
        assert fb.event_emissions == []
        assert fb.pruning_decisions == []

    def test_is_empty_returns_true_for_default(self):
        """Default instance is empty."""
        fb = PostBatchFeedback()
        assert fb.is_empty() is True

    def test_is_empty_returns_false_with_content(self):
        """Instance with content is not empty."""
        fb = PostBatchFeedback(deferred_findings=[{"title": "test"}])
        assert fb.is_empty() is False

    def test_typo_key_raises_attribute_error(self):
        """Accessing non-existent attribute raises AttributeError (type safety)."""
        fb = PostBatchFeedback()
        with pytest.raises(AttributeError):
            _ = fb.defered_findings  # typo: missing 'r'

    def test_event_emissions_field_writable(self):
        """Phase 6 event_emissions field is writable."""
        fb = PostBatchFeedback()
        fb.event_emissions.append({"type": "test", "payload": {}})
        assert len(fb.event_emissions) == 1

    def test_pruning_decisions_field_writable(self):
        """Phase 6 pruning_decisions field is writable."""
        fb = PostBatchFeedback()
        fb.pruning_decisions.append({"task_id": "t1", "lifecycle_status": "retired"})
        assert len(fb.pruning_decisions) == 1


class TestProducerEmitsDataclass:
    """N4 regression guard: producer (_execute_single_task_full_flow) MUST emit
    PostBatchFeedback, not a dict.

    If the producer reverts to ``_post_fb: dict = {}`` + ``_post_fb["..."] = ...``,
    the consumer's isinstance(fb, PostBatchFeedback) branch becomes dead code and
    C3's typo-prevention purpose is lost (typo'd keys silently create new dict
    keys instead of raising AttributeError). This test locks in the dataclass
    producer contract via source-structure assertions.
    """

    PRODUCER_PATH = "src/core/engine/master_conductor.py"

    def _read_producer(self) -> str:
        from pathlib import Path
        # tests/core/engine/test_post_batch_feedback.py → parents[3] = repo root
        repo_root = Path(__file__).resolve().parents[3]
        with open(repo_root / self.PRODUCER_PATH, "r", encoding="utf-8") as f:
            return f.read()

    def test_postbatchfeedback_is_imported(self):
        """PostBatchFeedback is imported in master_conductor.py."""
        src = self._read_producer()
        assert "from src.core.engine.post_batch_feedback import PostBatchFeedback" in src, \
            "PostBatchFeedback must be imported so the producer can construct it"

    def test_producer_constructs_dataclass_not_dict(self):
        """Producer constructs ``_post_fb = PostBatchFeedback()`` (N4 fix).

        The dict literal ``_post_fb: dict = {}`` must NOT reappear — it would
        make the consumer's dataclass branch dead code.
        """
        src = self._read_producer()
        assert "_post_fb = PostBatchFeedback()" in src, \
            "Producer must construct PostBatchFeedback() (N4); _post_fb: dict = {} must not return"
        assert "_post_fb: dict = {}" not in src, \
            "Producer must NOT use dict construction (N4 regression)"

    def test_no_dict_key_access_on_post_fb(self):
        """No ``_post_fb[...]`` dict-style access remains (N4 fix).

        All assignments must be attribute accesses (``_post_fb.deferred_* = ...``)
        so that typo'd field names raise AttributeError instead of silently
        creating new dict keys.
        """
        src = self._read_producer()
        # Allow the substring only in comments/asserts; the assignment form is banned.
        lines = src.splitlines()
        offenders = [
            ln for ln in lines
            if "_post_fb[" in ln and "_post_fb[" in ln.split("#", 1)[0]
        ]
        assert not offenders, (
            "Producer must use attribute access (_post_fb.deferred_*), "
            "not dict access (_post_fb[...]). Offending lines: %r" % offenders
        )

    def test_producer_writes_all_expected_attributes(self):
        """Producer populates the expected deferred_* attributes (N4 fix scope)."""
        src = self._read_producer()
        expected_attrs = [
            "deferred_decision_enhancer_tasks",
            "deferred_findings",
            "deferred_critical_actions",
            "deferred_boost_event",
            "deferred_new_assets",
            "deferred_react_tasks",
            "deferred_handoff",
            "deferred_new_context",
        ]
        missing = [a for a in expected_attrs if f"_post_fb.{a}" not in src]
        assert not missing, (
            "Producer must assign all expected deferred_* attributes. "
            "Missing: %r" % missing
        )


class TestDecisionTypeEnum:
    """T-5.1: DecisionType enum has pruning lifecycle values."""

    def test_task_retired_enum_exists(self):
        """TASK_RETIRED enum value exists."""
        assert hasattr(DecisionType, 'TASK_RETIRED')
        assert DecisionType.TASK_RETIRED.value == "task_retired"

    def test_task_superseded_enum_exists(self):
        """TASK_SUPERSEDED enum value exists."""
        assert hasattr(DecisionType, 'TASK_SUPERSEDED')
        assert DecisionType.TASK_SUPERSEDED.value == "task_superseded"

    def test_task_invalidated_enum_exists(self):
        """TASK_INVALIDATED enum value exists."""
        assert hasattr(DecisionType, 'TASK_INVALIDATED')
        assert DecisionType.TASK_INVALIDATED.value == "task_invalidated"

    def test_decision_to_dict_matches_enum_values(self):
        """Pruning decision to_dict output matches DecisionType enum values."""
        d = TaskPruningDecision(
            task_id="t1", lifecycle_status="retired", reason_code="duplicate"
        )
        result = d.to_dict()
        assert result["decision_type"] == DecisionType.TASK_RETIRED.value

    def test_superseded_decision_matches_enum(self):
        """Superseded decision type matches enum."""
        d = TaskPruningDecision(
            task_id="t2", lifecycle_status="superseded", reason_code="chain_completed"
        )
        assert d.to_dict()["decision_type"] == DecisionType.TASK_SUPERSEDED.value

    def test_invalidated_decision_matches_enum(self):
        """Invalidated decision type matches enum."""
        d = TaskPruningDecision(
            task_id="t3", lifecycle_status="invalidated",
            reason_code="stale_snapshot"
        )
        assert d.to_dict()["decision_type"] == DecisionType.TASK_INVALIDATED.value

    def test_existing_enums_unaffected(self):
        """Existing DecisionType values are unchanged."""
        assert DecisionType.RECON_DISPATCH.value == "recon_dispatch"
        assert DecisionType.VULN_HUNTER_DISPATCH.value == "vuln_hunter_dispatch"
        assert DecisionType.PRIORITY_BOOST.value == "priority_boost"
        assert DecisionType.FALLBACK.value == "fallback"


class TestDecisionTraceCompatibility:
    """Verify pruning decisions are compatible with decision_traces sink."""

    def test_pruning_decision_has_all_required_keys(self):
        """Decision dict has all keys expected by decision_traces readers."""
        d = TaskPruningDecision(
            task_id="t1", lifecycle_status="retired", reason_code="duplicate"
        )
        result = d.to_dict()
        required = {"decision_type", "task_id", "lifecycle_status",
                     "reason_code", "timestamp", "shadow_only", "protected"}
        for key in required:
            assert key in result, f"Missing key: {key}"

    def test_unknown_decision_type_is_readable(self):
        """Unknown decision_type values are still human-readable strings."""
        # The fallback in run_narrative_formatter outputs the raw string
        # for unknown types, so our decision_type must be a string.
        d = TaskPruningDecision(
            task_id="t_unknown", lifecycle_status="retired", reason_code="test"
        )
        result = d.to_dict()
        assert isinstance(result["decision_type"], str)
        assert len(result["decision_type"]) > 0
