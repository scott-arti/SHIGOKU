"""
Attack Path Node/Edge/Graph contract definitions.

Machine-readable contracts for attack path visualisation and Neo4j export.
Used by ``attack_path_formatter.py``.  Ad-hoc dict construction is avoided
in favour of these typed dataclasses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Evidence state vocabulary (single source of truth)
# ---------------------------------------------------------------------------

EVIDENCE_STATE_CONFIRMED = "confirmed"
EVIDENCE_STATE_CANDIDATE = "candidate"
EVIDENCE_STATE_BLOCKED = "blocked"
EVIDENCE_STATE_BACKFILL = "backfill"

EVIDENCE_STATES: frozenset[str] = frozenset({
    EVIDENCE_STATE_CONFIRMED,
    EVIDENCE_STATE_CANDIDATE,
    EVIDENCE_STATE_BLOCKED,
    EVIDENCE_STATE_BACKFILL,
})

# Node types per plan contract
NODE_TYPE_TARGET = "Target"
NODE_TYPE_ENDPOINT = "Endpoint"
NODE_TYPE_PARAMETER = "Parameter"
NODE_TYPE_FINDING = "Finding"
NODE_TYPE_TASK = "Task"
NODE_TYPE_DECISION = "Decision"
NODE_TYPE_TOOLRUN = "ToolRun"
NODE_TYPE_ATTACK_PATH = "AttackPath"

NODE_TYPES: frozenset[str] = frozenset({
    NODE_TYPE_TARGET,
    NODE_TYPE_ENDPOINT,
    NODE_TYPE_PARAMETER,
    NODE_TYPE_FINDING,
    NODE_TYPE_TASK,
    NODE_TYPE_DECISION,
    NODE_TYPE_TOOLRUN,
    NODE_TYPE_ATTACK_PATH,
})

# Edge types per plan contract
EDGE_HAS_ENDPOINT = "HAS_ENDPOINT"
EDGE_HAS_PARAM = "HAS_PARAM"
EDGE_PRODUCED_FINDING = "PRODUCED_FINDING"
EDGE_SUPPORTS_PATH = "SUPPORTS_PATH"
EDGE_DEPENDS_ON = "DEPENDS_ON"
EDGE_BLOCKED_BY = "BLOCKED_BY"
EDGE_NEXT_VALIDATION = "NEXT_VALIDATION"

EDGE_TYPES: frozenset[str] = frozenset({
    EDGE_HAS_ENDPOINT,
    EDGE_HAS_PARAM,
    EDGE_PRODUCED_FINDING,
    EDGE_SUPPORTS_PATH,
    EDGE_DEPENDS_ON,
    EDGE_BLOCKED_BY,
    EDGE_NEXT_VALIDATION,
})


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class AttackPathNode:
    """A single node in an attack-path graph."""

    node_id: str
    """Machine-readable identifier (e.g. finding id, endpoint url)."""

    display_label: str
    """Human-readable short label for Markdown/Mermaid display."""

    node_type: str
    """One of NODE_TYPES (Target, Endpoint, Parameter, Finding, ...)."""

    evidence_state: str
    """One of EVIDENCE_STATES (confirmed, candidate, blocked, backfill)."""

    why_in_path: str = ""
    """Explanation of why this node appears in the attack path."""

    source_refs: List[str] = field(default_factory=list)
    """Traceability references (finding_id, decision_id, task_id, source_event_ids)."""

    blocked_reason: str = ""
    """If evidence_state is 'blocked', why the path cannot be confirmed."""

    next_validation_hint: str = ""
    """Suggested next validation action for this node."""

    observed_at: Optional[str] = None
    """ISO-8601 timestamp when the evidence was observed in-session."""

    inferred_after: Optional[str] = None
    """ISO-8601 timestamp when the inference was made (formatter execution time)."""

    extra: Dict[str, Any] = field(default_factory=dict)
    """Extension point for additional metadata (target_url, severity, etc.)."""


@dataclass
class AttackPathEdge:
    """A directed edge connecting two nodes in an attack-path graph."""

    edge_id: str
    """Machine-readable edge identifier."""

    source_node_id: str
    """Node id at the tail of the edge."""

    target_node_id: str
    """Node id at the head of the edge."""

    edge_type: str
    """One of EDGE_TYPES."""

    display_label: str = ""
    """Human-readable short label."""

    evidence_state: str = ""
    """Inherited evidence state (strongest of connected nodes)."""

    why_in_path: str = ""
    """Explanation of why this edge exists."""

    source_refs: List[str] = field(default_factory=list)
    """Traceability references."""

    extra: Dict[str, Any] = field(default_factory=dict)
    """Extension point."""


@dataclass
class AttackPathGraph:
    """Full attack-path graph: nodes + edges + metadata."""

    nodes: List[AttackPathNode] = field(default_factory=list)
    edges: List[AttackPathEdge] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    """Includes session_id, generated_at, config thresholds, etc."""


# ---------------------------------------------------------------------------
# Evidence state resolution
# ---------------------------------------------------------------------------

def resolve_evidence_state(
    finding: Dict[str, Any],
    *,
    confidence: Optional[float] = None,
    state: Optional[str] = None,
    source_origin: Optional[str] = None,
) -> str:
    """Map an attack-chain finding to a canonical ``evidence_state``.

    Mapping rules (from subtask plan §3.1):

    ======================================  ===================
    Condition                                evidence_state
    ======================================  ===================
    state == "confirmed" AND conf >= 0.8     ``confirmed``
    state == "confirmed" AND conf <  0.8     ``candidate``
    state in {blocked, draft}                ``blocked``
    No decision_trace (legacy ExploitChain)  ``backfill``
    source_origin == "proposal_engine"       ``backfill``
    Fallback                                 ``backfill``
    ======================================  ===================

    Args:
        finding: A finding dict (as extracted by
            :func:`~src.reporting.finding_extractor.extract_all_findings`).
        confidence: Explicit override for confidence (falls back to
            ``finding.get("confidence", 0.0)``).
        state: Explicit override for chain state (falls back to
            ``additional_info.decision_trace.final_state``).
        source_origin: Explicit override for source origin hint.

    Returns:
        One of ``EVIDENCE_STATES``.
    """
    additional_info = finding.get("additional_info")
    if not isinstance(additional_info, dict):
        additional_info = {}

    original_decision_trace = additional_info.get("decision_trace")
    decision_trace: Dict[str, Any] = (
        original_decision_trace
        if isinstance(original_decision_trace, dict)
        else {}
    )

    # Guard: no decision trace data at all (None, non-dict, or empty dict)
    #          → backfill (no session-corroborated decision)
    if original_decision_trace is None or not isinstance(original_decision_trace, dict) or not decision_trace:
        return EVIDENCE_STATE_BACKFILL

    # AI proposal engine candidates (outside session evidence)
    if source_origin == "proposal_engine":
        return EVIDENCE_STATE_BACKFILL

    # --- Resolve inputs ---
    _confidence: float = (
        confidence
        if confidence is not None
        else float(finding.get("confidence", 0.0))
    )
    _state: str = (
        state
        if state is not None
        else decision_trace.get("final_state", "draft")
    )

    # --- Mapping ---
    if _state == "confirmed":
        if _confidence >= 0.8:
            return EVIDENCE_STATE_CONFIRMED
        return EVIDENCE_STATE_CANDIDATE

    if _state in ("blocked", "draft"):
        return EVIDENCE_STATE_BLOCKED

    # actionable / unknown → treat as backfill (no session-corroborated state)
    return EVIDENCE_STATE_BACKFILL
