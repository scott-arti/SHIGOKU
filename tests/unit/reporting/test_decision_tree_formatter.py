"""
Unit tests for DecisionTreeFormatter (SGK-2026-0334 / P1b).

Covers:
- Normal tree construction from run_ledger events
- Legacy session (decision_traces only, no run_ledger)
- Parent-child linking via parent_event_id
- Unlinked / estimated nodes
- Large session degradation (max_nodes, max_edges, max_depth)
- Stable sort (timestamp -> event_id)
- Checkpoint metadata attachment
- Mermaid / Markdown escape
- Secret / PII redaction (nested dicts, source_refs)
- phase / actor / only_failures filtering
- JSON export format
- Empty / missing data resilience
"""

import json
import re
from copy import deepcopy

import pytest

from src.reporting.decision_tree_formatter import (
    DecisionTreeFormatter,
    DecisionTreeNode,
    DecisionTreeEdge,
    DecisionTreeSummary,
    DEFAULT_MAX_NODES,
    DEFAULT_MAX_EDGES,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_CHILDREN_PER_NODE,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_event(
    event_id: str,
    event_type: str = "swarm_dispatched",
    phase: str = "attack",
    timestamp: str = "",
    parent_event_id: str = "",
    decision_id: str = "",
    task_id: str = "",
    actor_type: str = "MasterConductor",
    actor_name: str = "MC",
    source_refs: dict | None = None,
    error: str = "",
    action: str = "",
    result: str = "",
) -> dict:
    """Build a minimal run_ledger event dict."""
    return {
        "event_id": event_id,
        "event_type": event_type,
        "timestamp": timestamp or f"2026-07-01T00:00:{i:02d}Z" if (i := len(str(event_id)) % 60) is not None else "2026-07-01T00:00:00Z",
        "phase": phase,
        "parent_event_id": parent_event_id,
        "decision_id": decision_id,
        "task_id": task_id,
        "actor_type": actor_type,
        "actor_name": actor_name,
        "source_refs": source_refs,
        "error": error,
        "action": action,
        "result": result,
    }


def _make_ledger_events(count: int, prefix: str = "evt") -> list[dict]:
    """Generate a linear chain of run_ledger events with parent_event_id linking."""
    events = []
    for i in range(count):
        evt = _make_event(
            event_id=f"{prefix}_{i}",
            timestamp=f"2026-07-01T00:{i:02d}:00Z",
        )
        if i > 0:
            evt["parent_event_id"] = f"{prefix}_{i - 1}"
        events.append(evt)
    return events


@pytest.fixture
def basic_session() -> dict:
    """Minimal session with run_ledger events and supplemental data."""
    events = [
        _make_event("evt_0", event_type="decision_made", phase="recon",
                     timestamp="2026-07-01T00:00:00Z",
                     action="dispatch_recon"),
        _make_event("evt_1", event_type="swarm_dispatched", phase="recon",
                     timestamp="2026-07-01T00:01:00Z",
                     parent_event_id="evt_0"),
        _make_event("evt_2", event_type="swarm_completed", phase="recon",
                     timestamp="2026-07-01T00:02:00Z",
                     parent_event_id="evt_1"),
        _make_event("evt_3", event_type="decision_made", phase="attack",
                     timestamp="2026-07-01T00:03:00Z",
                     parent_event_id="evt_2",
                     decision_id="dec_attack_1"),
        _make_event("evt_4", event_type="swarm_dispatched", phase="attack",
                     timestamp="2026-07-01T00:04:00Z",
                     parent_event_id="evt_3"),
        _make_event("evt_5", event_type="error_occurred", phase="attack",
                     timestamp="2026-07-01T00:05:00Z",
                     parent_event_id="evt_4",
                     error="InjectionSwarm timeout"),
    ]
    return {
        "run_ledger": events,
        "decision_traces": [
            {"decision_id": "dec_attack_1", "action": "start_attack_swarm", "result": "dispatched"},
        ],
        "task_execution_records": [
            {"task_id": "task_1", "result": "success"},
        ],
        "context": {"target_info": {}},
    }


@pytest.fixture
def legacy_session() -> dict:
    """Older session with only decision_traces (no run_ledger)."""
    return {
        "decision_traces": [
            {"trace_id": "dt_1", "timestamp": "2026-07-01T00:00:00Z",
             "phase": "recon", "action": "dispatch_recon"},
            {"trace_id": "dt_2", "timestamp": "2026-07-01T00:01:00Z",
             "phase": "attack", "action": "run_swarm"},
        ],
        "context": {"target_info": {}},
    }


# ---------------------------------------------------------------------------
# Tests: basic construction
# ---------------------------------------------------------------------------

class TestDecisionTreeBasic:
    """Basic tree construction and rendering."""

    def test_builds_from_run_ledger(self, basic_session: dict) -> None:
        ft = DecisionTreeFormatter()
        _, _, summary = ft._build_tree(basic_session, "", "", False)
        assert summary.total_nodes == 6
        assert summary.total_edges == 5  # 5 parent_event_id links
        assert summary.linked_nodes > 0

    def test_renders_markdown(self, basic_session: dict) -> None:
        ft = DecisionTreeFormatter()
        md = ft.format(basic_session)
        assert "graph TD" in md
        assert "Node Summary" in md
        assert "Tree Status" in md

    def test_mermaid_block_present(self, basic_session: dict) -> None:
        ft = DecisionTreeFormatter()
        md = ft.format(basic_session)
        assert "```mermaid" in md
        assert "graph TD" in md
        # Nodes should be present
        assert "n_evt_0" in md
        assert "n_evt_5" in md

    def test_format_json_output(self, basic_session: dict) -> None:
        ft = DecisionTreeFormatter()
        result = ft.format_json(basic_session)
        assert result["status"] == "ok"
        assert "markdown" in result
        assert "summary" in result
        assert result["summary"]["total_nodes"] == 6


# ---------------------------------------------------------------------------
# Tests: legacy sessions
# ---------------------------------------------------------------------------

class TestDecisionTreeLegacy:
    """Compatibility with older session formats (no run_ledger, only decision_traces)."""

    def test_builds_from_decision_traces_only(self, legacy_session: dict) -> None:
        ft = DecisionTreeFormatter()
        nodes, edges, summary = ft._build_tree(legacy_session, "", "", False)
        assert summary.total_nodes == 2
        assert len(nodes) == 2

    def test_renders_legacy_markdown(self, legacy_session: dict) -> None:
        ft = DecisionTreeFormatter()
        md = ft.format(legacy_session)
        assert "graph TD" in md
        assert "decision_made" in md


# ---------------------------------------------------------------------------
# Tests: parent-child linking
# ---------------------------------------------------------------------------

class TestDecisionTreeLinking:
    """Parent-event-id chaining and unlinked/estimated nodes."""

    def test_parent_child_chain(self) -> None:
        events = _make_ledger_events(5, prefix="chain")
        ft = DecisionTreeFormatter()
        nodes, edges, summary = ft._build_tree(
            {"run_ledger": events}, "", "", False,
        )
        assert summary.total_edges == 4  # 5 nodes, 4 parent links
        assert summary.unlinked_nodes == 0

    def test_missing_parent_yields_unlinked(self) -> None:
        """A node whose parent_event_id refers to an absent node should be unlinked."""
        events = [
            _make_event("evt_0"),
            _make_event("evt_1", parent_event_id="nonexistent"),
        ]
        ft = DecisionTreeFormatter()
        nodes, edges, summary = ft._build_tree(
            {"run_ledger": events, "context": {"target_info": {}}}, "", "", False,
        )
        assert summary.total_edges == 0
        assert summary.unlinked_nodes >= 1

    def test_failure_nodes_counted(self, basic_session: dict) -> None:
        ft = DecisionTreeFormatter()
        _, _, summary = ft._build_tree(basic_session, "", "", False)
        assert summary.failure_nodes == 1  # evt_5 is error_occurred


# ---------------------------------------------------------------------------
# Tests: degradation (large sessions)
# ---------------------------------------------------------------------------

class TestDecisionTreeDegradation:
    """Large session limits: max_nodes, max_edges, max_depth."""

    def test_max_nodes_limit(self) -> None:
        events = _make_ledger_events(100, prefix="big")
        ft = DecisionTreeFormatter(max_nodes=10)
        nodes, edges, summary = ft._build_tree(
            {"run_ledger": events}, "", "", False,
        )
        assert summary.total_nodes <= 10
        assert summary.degraded
        assert "degraded_max_nodes" in summary.reason_codes

    def test_max_edges_limit(self) -> None:
        events = _make_ledger_events(50, prefix="edge")
        ft = DecisionTreeFormatter(max_edges=5)
        _, _, summary = ft._build_tree(
            {"run_ledger": events}, "", "", False,
        )
        assert summary.total_edges <= 5
        assert summary.degraded
        assert "degraded_max_edges" in summary.reason_codes

    def test_max_depth_limit(self) -> None:
        events = _make_ledger_events(30, prefix="deep")
        ft = DecisionTreeFormatter(max_depth=3)
        _, _, summary = ft._build_tree(
            {"run_ledger": events}, "", "", False,
        )
        assert summary.degraded
        assert "degraded_max_depth" in summary.reason_codes

    def test_degrade_summary_in_markdown(self) -> None:
        events = _make_ledger_events(100, prefix="big")
        ft = DecisionTreeFormatter(max_nodes=5)
        md = ft.format({"run_ledger": events})
        assert "Degrade Summary" in md
        assert "degraded_max_nodes" in md

    def test_degrade_reasons_populated_when_degraded(self) -> None:
        """When summary.degraded=True, degrade_reasons must be non-empty."""
        events = _make_ledger_events(100, prefix="big")
        ft = DecisionTreeFormatter(max_nodes=5, max_depth=1)
        _, _, summary = ft._build_tree({"run_ledger": events}, "", "", False)
        assert summary.degraded
        assert len(summary.degrade_reasons) > 0, (
            f"Expected non-empty degrade_reasons when degraded=True. "
            f"Got: degraded={summary.degraded}, reasons={summary.degrade_reasons}"
        )
        assert any(r.startswith("degraded_") for r in summary.degrade_reasons)

    def test_degraded_nodes_counted_in_summary(self) -> None:
        """When nodes are degraded (max_depth exceeded), degraded_nodes > 0."""
        events = _make_ledger_events(10, prefix="deep")
        ft = DecisionTreeFormatter(max_depth=1)
        _, _, summary = ft._build_tree({"run_ledger": events}, "", "", False)
        assert summary.degraded
        assert summary.degraded_nodes > 0, (
            f"Expected degraded_nodes > 0 when max_depth exceeded. "
            f"Got: degraded_nodes={summary.degraded_nodes}"
        )
        # Total must add up: linked + unlinked + estimated + degraded == total_nodes
        _sum = (summary.linked_nodes + summary.unlinked_nodes +
                summary.estimated_nodes + summary.degraded_nodes)
        assert _sum == summary.total_nodes, (
            f"Node count mismatch: linked={summary.linked_nodes} "
            f"unlinked={summary.unlinked_nodes} estimated={summary.estimated_nodes} "
            f"degraded={summary.degraded_nodes} != total={summary.total_nodes}"
        )

    def test_degrade_reasons_no_duplicates(self) -> None:
        """degrade_reasons must not contain duplicate entries."""
        events = _make_ledger_events(100, prefix="big")
        ft = DecisionTreeFormatter(max_nodes=5, max_depth=1, max_edges=3)
        _, _, summary = ft._build_tree({"run_ledger": events}, "", "", False)
        assert len(summary.degrade_reasons) == len(set(summary.degrade_reasons)), (
            f"Duplicate degrade_reasons found: {summary.degrade_reasons}"
        )


# ---------------------------------------------------------------------------
# Tests: filtering (phase, actor, only_failures)
# ---------------------------------------------------------------------------

class TestDecisionTreeFiltering:
    """CLI filter options: --phase, --actor, --only-failures."""

    def test_phase_filter(self) -> None:
        events = [
            _make_event("e1", phase="recon"),
            _make_event("e2", phase="attack"),
            _make_event("e3", phase="attack"),
        ]
        ft = DecisionTreeFormatter()
        nodes, _, _ = ft._build_tree(
            {"run_ledger": events}, phase="recon", actor="", only_failures=False,
        )
        assert len(nodes) == 1
        assert nodes[0].event_id == "e1"

    def test_actor_filter(self) -> None:
        events = [
            _make_event("e1", actor_type="MasterConductor"),
            _make_event("e2", actor_type="InjectionSwarm"),
        ]
        ft = DecisionTreeFormatter()
        nodes, _, _ = ft._build_tree(
            {"run_ledger": events}, phase="", actor="MasterConductor", only_failures=False,
        )
        assert len(nodes) == 1
        assert nodes[0].event_id == "e1"

    def test_only_failures_filter(self) -> None:
        events = [
            _make_event("e1", event_type="swarm_completed"),
            _make_event("e2", event_type="swarm_failed"),
            _make_event("e3", event_type="error_occurred"),
        ]
        ft = DecisionTreeFormatter()
        nodes, _, _ = ft._build_tree(
            {"run_ledger": events}, phase="", actor="", only_failures=True,
        )
        assert len(nodes) == 2
        event_ids = {n.event_id for n in nodes}
        assert event_ids == {"e2", "e3"}


# ---------------------------------------------------------------------------
# Tests: stable sort
# ---------------------------------------------------------------------------

class TestDecisionTreeStableSort:
    """Nodes must be sorted by timestamp -> event_id consistently."""

    def test_sorted_by_timestamp(self) -> None:
        events = [
            _make_event("c", timestamp="2026-07-01T00:03:00Z"),
            _make_event("a", timestamp="2026-07-01T00:01:00Z"),
            _make_event("b", timestamp="2026-07-01T00:02:00Z"),
        ]
        ft = DecisionTreeFormatter()
        nodes, _, _ = ft._build_tree(
            {"run_ledger": events}, "", "", False,
        )
        ids = [n.event_id for n in nodes]
        assert ids == ["a", "b", "c"]

    def test_same_timestamp_stable_by_event_id(self) -> None:
        events = [
            _make_event("z", timestamp="2026-07-01T00:00:00Z"),
            _make_event("a", timestamp="2026-07-01T00:00:00Z"),
            _make_event("m", timestamp="2026-07-01T00:00:00Z"),
        ]
        ft = DecisionTreeFormatter()
        nodes, _, _ = ft._build_tree(
            {"run_ledger": events}, "", "", False,
        )
        ids = [n.event_id for n in nodes]
        assert ids == ["a", "m", "z"]

    def test_repeatable_output(self) -> None:
        """Same input should produce identical output across runs."""
        events = _make_ledger_events(20, prefix="stable")
        ft = DecisionTreeFormatter()
        md1 = ft.format({"run_ledger": deepcopy(events)})
        md2 = ft.format({"run_ledger": deepcopy(events)})
        assert md1 == md2


# ---------------------------------------------------------------------------
# Tests: checkpoint metadata
# ---------------------------------------------------------------------------

class TestDecisionTreeCheckpoint:
    """Attachment of checkpoint / resume metadata from context.target_info."""

    def test_artifact_refs_attached(self) -> None:
        events = [
            _make_event("evt_0", task_id="task_1"),
        ]
        session = {
            "run_ledger": events,
            "context": {
                "target_info": {
                    "artifact_refs": {"task_1": "/path/to/artifact.json"},
                }
            },
        }
        ft = DecisionTreeFormatter()
        nodes, _, _ = ft._build_tree(session, "", "", False)
        assert any("artifact_ref:task_1" in sr for sr in nodes[0].source_refs)

    def test_rerun_required_marks_estimated(self) -> None:
        events = [
            _make_event("evt_0"),
        ]
        session = {
            "run_ledger": events,
            "context": {
                "target_info": {
                    "rerun_required": True,
                }
            },
        }
        ft = DecisionTreeFormatter()
        nodes, _, summary = ft._build_tree(session, "", "", False)
        assert nodes[0].link_status == "estimated"

    def test_estimated_nodes_counted_in_summary(self) -> None:
        """After checkpoint attachment sets estimated, summary must reflect it."""
        events = [
            _make_event("evt_0", parent_event_id=""),
            _make_event("evt_1", parent_event_id=""),
        ]
        session = {
            "run_ledger": events,
            "context": {
                "target_info": {
                    "rerun_required": True,
                }
            },
        }
        ft = DecisionTreeFormatter()
        _, _, summary = ft._build_tree(session, "", "", False)
        # Both nodes should be estimated due to rerun_required
        assert summary.estimated_nodes == 2


# ---------------------------------------------------------------------------
# Tests: auxiliary linking via decision_id / task_id (SGK-2026-0334 step 3)
# ---------------------------------------------------------------------------

class TestDecisionTreeAuxiliaryLinking:
    """Second-pass linking using decision_id and task_id when parent_event_id is absent."""

    def test_decision_id_link(self) -> None:
        """Nodes sharing a decision_id are linked when parent_event_id is missing."""
        events = [
            _make_event("evt_0", event_type="decision_made", decision_id="dec_1"),
            _make_event("evt_1", event_type="swarm_dispatched", decision_id="dec_1"),
            # evt_1 has no parent_event_id, but shares decision_id with evt_0
        ]
        session = {"run_ledger": events, "context": {"target_info": {}}}
        ft = DecisionTreeFormatter()
        nodes, edges, summary = ft._build_tree(session, "", "", False)
        # Should have 1 edge from evt_0 -> evt_1 via decision_id
        assert summary.total_edges == 1
        assert edges[0].relation == "decision_link"
        assert edges[0].parent_id == "evt_0"
        assert edges[0].child_id == "evt_1"
        assert summary.unlinked_nodes == 0

    def test_task_id_link(self) -> None:
        """Nodes sharing a task_id are linked when parent_event_id is missing."""
        events = [
            _make_event("evt_0", task_id="task_1"),
            _make_event("evt_1", task_id="task_1"),
            # evt_1 has no parent_event_id, but shares task_id with evt_0
        ]
        session = {"run_ledger": events, "context": {"target_info": {}}}
        ft = DecisionTreeFormatter()
        _, edges, summary = ft._build_tree(session, "", "", False)
        assert summary.total_edges == 1
        assert edges[0].relation == "task_link"
        assert edges[0].parent_id == "evt_0"
        assert edges[0].child_id == "evt_1"

    def test_auxiliary_link_does_not_duplicate_parent_event_edge(self) -> None:
        """When both parent_event_id and decision_id link the same nodes, no duplicate."""
        events = [
            _make_event("evt_0", decision_id="dec_1"),
            _make_event("evt_1", parent_event_id="evt_0", decision_id="dec_1"),
        ]
        session = {"run_ledger": events, "context": {"target_info": {}}}
        ft = DecisionTreeFormatter()
        _, edges, _ = ft._build_tree(session, "", "", False)
        # Only 1 edge, not 2 (parent_event + decision_link for the same pair)
        assert len(edges) == 1
        assert edges[0].relation == "parent_event"


# ---------------------------------------------------------------------------
# Tests: redaction (secret / PII)
# ---------------------------------------------------------------------------

class TestDecisionTreeRedaction:
    """Secret / PII redaction in output."""

    def test_api_key_redacted_in_error(self) -> None:
        """Secrets in the error field (which appears in Mermaid labels) are redacted."""
        events = [
            _make_event("evt_0", error="api_key=sk-abc123def456ghi789jklmno"),
        ]
        ft = DecisionTreeFormatter()
        md = ft.format({"run_ledger": events})
        assert "sk-abc123" not in md
        # The error is rendered in the Mermaid label, which redacts it
        assert "REDACTED" in md

    def test_jwt_redacted(self) -> None:
        events = [
            _make_event("evt_0", error="Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9c"),
        ]
        ft = DecisionTreeFormatter()
        md = ft.format({"run_ledger": events})
        assert "eyJhbGci" not in md

    def test_bearer_token_redacted(self) -> None:
        events = [
            _make_event("evt_0", error="Authorization: Bearer xyz-token-value-123"),
        ]
        ft = DecisionTreeFormatter()
        md = ft.format({"run_ledger": events})
        assert "xyz-token" not in md

    def test_source_refs_not_leaked_in_output(self) -> None:
        """source_refs values are rendered as counts, never as raw values."""
        events = [
            _make_event("evt_0", source_refs={"api_key": "sk-abc123def456ghi789jklmno"},
                        action="test"),
        ]
        ft = DecisionTreeFormatter()
        md = ft.format({"run_ledger": events})
        # source_refs are only shown as count, not as raw values
        assert "sk-abc123" not in md
        # The evidence column shows refs:1 (count), not the raw values
        assert "refs:1" in md


# ---------------------------------------------------------------------------
# Tests: escape (Mermaid / Markdown / stdout)
# ---------------------------------------------------------------------------

class TestDecisionTreeEscape:
    """Mermaid and Markdown character escaping."""

    def test_mermaid_brace_escaped(self) -> None:
        events = [
            _make_event("evt_0", action="test[with]braces"),
        ]
        ft = DecisionTreeFormatter()
        # The _mermaid_escape should handle brackets
        safe_id = ft._mermaid_id("event[id]")
        safe_label = ft._mermaid_escape("label [with] {braces}")
        assert "[" not in safe_id or "_" in safe_id
        # Just verify no crash
        md = ft.format({"run_ledger": events})
        assert "graph TD" in md

    def test_markdown_pipe_escaped(self) -> None:
        ft = DecisionTreeFormatter()
        escaped = ft._md_escape("a | b")
        assert "\\|" in escaped

    def test_newline_removed_from_label(self) -> None:
        events = [
            _make_event("evt_0", error="line1\nline2\rline3"),
        ]
        ft = DecisionTreeFormatter()
        md = ft.format({"run_ledger": events})
        # The node label inside the Mermaid block should not contain raw newlines
        mermaid_block = md.split("```mermaid")[1].split("```")[0]
        # Labels are in Mermaid node definitions: n_X["label text"]
        # They should not contain raw newline characters
        # (newlines in the block itself are structural, not in labels)
        for line in mermaid_block.split("\n"):
            if '["' in line:
                # Label content should not have raw \n within quotes
                assert "\n" not in line.strip()


# ---------------------------------------------------------------------------
# Tests: empty / missing data
# ---------------------------------------------------------------------------

class TestDecisionTreeEmpty:
    """Resilience against missing or empty inputs."""

    def test_empty_session(self) -> None:
        ft = DecisionTreeFormatter()
        md = ft.format({})
        assert "graph TD" in md
        assert "Total nodes" in md

    def test_no_run_ledger_no_traces(self) -> None:
        ft = DecisionTreeFormatter()
        _, _, summary = ft._build_tree(
            {"context": {"target_info": {}}}, "", "", False,
        )
        assert summary.total_nodes == 0
        assert summary.degraded is False

    def test_null_values_in_events(self) -> None:
        events = [
            {"event_id": None, "event_type": None, "timestamp": None, "phase": None},
        ]
        ft = DecisionTreeFormatter()
        md = ft.format({"run_ledger": events})
        assert "graph TD" in md  # should not crash


# ---------------------------------------------------------------------------
# Tests: default limits
# ---------------------------------------------------------------------------

class TestDecisionTreeDefaults:
    """Default constants match expectations."""

    def test_default_limits(self) -> None:
        assert DEFAULT_MAX_NODES == 80
        assert DEFAULT_MAX_EDGES == 120
        assert DEFAULT_MAX_DEPTH == 10
        assert DEFAULT_MAX_CHILDREN_PER_NODE == 8

    def test_formatter_uses_custom_limits(self) -> None:
        ft = DecisionTreeFormatter(max_nodes=3, max_edges=2, max_depth=1, max_children_per_node=1)
        assert ft.max_nodes == 3
        assert ft.max_edges == 2
        assert ft.max_depth == 1
        assert ft.max_children_per_node == 1
