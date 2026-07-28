"""
DecisionTreeFormatter: session JSON -> decision tree (Markdown + Mermaid).

Builds a chronological decision tree from run_ledger events, decision_traces,
task_execution_records, and checkpoint metadata.  Produces Mermaid ``graph TD``
diagrams with appended Markdown summary and degrade summary.

SGK-2026-0334 (P1b): decision-tree visualisation + shigoku-ops CLI.

Data-source priority:
  run_ledger           — canonical chronological index (primary)
  decision_traces      — judgment detail (secondary)
  task_execution_records — execution supplement (tertiary)
  checkpoint metadata  — resume/rerun hints (advisory)

Limits (defaults) for large sessions:
  max_nodes             =  80
  max_edges             = 120
  max_depth             =  10
  max_children_per_node =   8

Exceeding any limit sets ``status=degraded`` and emits ``reason_codes``.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

# ── Default limits (plan §5.1 SRE-1) ────────────────────────────────────────
DEFAULT_MAX_NODES = 80
DEFAULT_MAX_EDGES = 120
DEFAULT_MAX_DEPTH = 10
DEFAULT_MAX_CHILDREN_PER_NODE = 8

# ── Event-type → short label (for Mermaid / Markdown) ──────────────────────
_EVENT_LABEL: Dict[str, str] = {
    "decision_made": "decision",
    "swarm_dispatched": "dispatch",
    "swarm_completed": "completed",
    "swarm_failed": "failed",
    "swarm_merged": "merged",
    "swarm_skipped": "skipped",
    "tool_executed": "tool",
    "error_occurred": "error",
    "finding_created": "finding",
    "hitl_requested": "HITL",
    "hitl_resolved": "HITL-ok",
    "llm_called": "LLM",
    "llm_retry": "LLM-retry",
    "llm_failed": "LLM-fail",
    "llm_cache_hit": "LLM-cache",
    "provider_fallback": "provider-fb",
}

# ── Decorative icons for important node types ──────────────────────────────
_FAILURE_EVENT_TYPES = frozenset({"swarm_failed", "llm_failed", "error_occurred"})
_RETRY_EVENT_TYPES = frozenset({"llm_retry"})
_DECISION_EVENT_TYPES = frozenset({"decision_made"})
_DISPATCH_EVENT_TYPES = frozenset({"swarm_dispatched"})

# ── Redaction: sensitive-looking tokens ────────────────────────────────────
_SECRET_PATTERNS = [
    re.compile(r, re.IGNORECASE)
    for r in (
        r"\b[A-Za-z0-9+/=]{20,}\b",  # base64-like
        r"\b[0-9a-f]{32,}\b",          # hex hash / api-key
        r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b",  # JWT
        r"\bBearer\s+\S+",             # auth header
        r"\bAuthorization:\s*\S+",     # auth header
        r"(?:api[_-]?key|apikey|secret|token|password|passwd)\s*[:=]\s*\S+",
    )
]

# ── Mermaid / Markdown unsafe characters ───────────────────────────────────
_MERMAID_UNSAFE_RE = re.compile(r'[\[\]{}()<>"#&;|]')
_MARKDOWN_UNSAFE_RE = re.compile(r'([\\*_{}\[\]()#+\-.!|<>`~])')


# ============================================================================
# Internal contracts (plan §4 step 2)
# ============================================================================


@dataclass
class DecisionTreeNode:
    """A decision / event node in the tree."""
    node_id: str                          # stable id: event_id / decision_id / task_id
    label: str                            # display label
    event_type: str = ""
    phase: str = ""
    actor: str = ""
    timestamp: str = ""
    event_id: str = ""
    decision_id: str = ""
    task_id: str = ""
    source_refs: List[str] = field(default_factory=list)
    action: str = ""
    result: str = ""
    error: str = ""
    depth: int = 0
    link_status: str = ""                 # linked | estimated | unlinked
    missing_fields: List[str] = field(default_factory=list)


@dataclass
class DecisionTreeEdge:
    """A parent -> child edge."""
    parent_id: str
    child_id: str
    relation: str = ""                    # parent_event | decision_link | task_link


@dataclass
class DecisionTreeSummary:
    """Overall tree summary for the degrade / status report."""
    total_nodes: int = 0
    total_edges: int = 0
    max_depth_reached: int = 0
    linked_nodes: int = 0
    estimated_nodes: int = 0
    unlinked_nodes: int = 0
    failure_nodes: int = 0
    degraded_nodes: int = 0
    degraded: bool = False
    degrade_reasons: List[str] = field(default_factory=list)
    reason_codes: List[str] = field(default_factory=list)


# ============================================================================
# Formatter
# ============================================================================


class DecisionTreeFormatter:
    """Builds a decision tree from session data and renders Mermaid + Markdown."""

    def __init__(
        self,
        max_nodes: int = DEFAULT_MAX_NODES,
        max_edges: int = DEFAULT_MAX_EDGES,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_children_per_node: int = DEFAULT_MAX_CHILDREN_PER_NODE,
    ) -> None:
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self.max_depth = max_depth
        self.max_children_per_node = max_children_per_node

    # ── Public API ────────────────────────────────────────────────────────

    def format(
        self,
        session_data: dict,
        *,
        phase: str = "",
        actor: str = "",
        only_failures: bool = False,
    ) -> str:
        """Build decision tree Markdown string (Mermaid + summary).

        Args:
            session_data: Parsed session JSON dict.
            phase: Optional phase filter (e.g. ``attack``).
            actor: Optional actor filter (e.g. ``MasterConductor``).
            only_failures: If True, show only failed/error nodes.

        Returns:
            Markdown string with ``graph TD`` Mermaid block and summary tables.
        """
        sd: Dict[str, Any] = session_data if isinstance(session_data, dict) else {}
        nodes, edges, summary = self._build_tree(
            sd, phase=phase, actor=actor, only_failures=only_failures,
        )
        return self._render(nodes, edges, summary, session_data=sd)

    def format_json(
        self,
        session_data: dict,
        *,
        phase: str = "",
        actor: str = "",
        only_failures: bool = False,
    ) -> dict:
        """Return structured tree data as a JSON-serialisable dict.

        Useful for ``--json`` / ``--json-envelope`` CLI output.
        """
        sd: Dict[str, Any] = session_data if isinstance(session_data, dict) else {}
        nodes, edges, summary = self._build_tree(
            sd, phase=phase, actor=actor, only_failures=only_failures,
        )
        markdown = self._render(nodes, edges, summary, session_data=sd)
        return {
            "status": "degraded" if summary.degraded else "ok",
            "reason_codes": sorted(set(summary.reason_codes)),
            "summary": {
                "total_nodes": summary.total_nodes,
                "total_edges": summary.total_edges,
                "max_depth_reached": summary.max_depth_reached,
                "linked_nodes": summary.linked_nodes,
                "estimated_nodes": summary.estimated_nodes,
                "unlinked_nodes": summary.unlinked_nodes,
                "degraded_nodes": summary.degraded_nodes,
                "failure_nodes": summary.failure_nodes,
                "degraded": summary.degraded,
                "degrade_reasons": summary.degrade_reasons,
            },
            "markdown": markdown,
            "output": "stdout",
        }

    # ── Tree construction (plan §4 step 3-4) ──────────────────────────────

    def _build_tree(
        self,
        sd: Dict[str, Any],
        phase: str,
        actor: str,
        only_failures: bool,
    ) -> Tuple[List[DecisionTreeNode], List[DecisionTreeEdge], DecisionTreeSummary]:
        """Build node list, edge list, and summary from session data."""
        summary = DecisionTreeSummary()
        reason_codes: List[str] = []

        # 1. Gather raw events from run_ledger (primary)
        ledger_events: List[Dict[str, Any]] = self._load_run_ledger_events(sd)

        # 2. Filter by phase / actor / only_failures
        filtered = self._filter_events(ledger_events, phase, actor, only_failures)

        # 3. Stable sort: timestamp -> event_id
        filtered.sort(key=lambda e: (e.get("timestamp", ""), e.get("event_id", "")))

        # 4. Build nodes
        nodes: List[DecisionTreeNode] = []
        node_map: Dict[str, DecisionTreeNode] = {}
        depth_map: Dict[str, int] = {}

        for evt in filtered:
            if len(nodes) >= self.max_nodes:
                reason_codes.append("degraded_max_nodes")
                summary.degraded = True
                break

            node = self._event_to_node(evt)
            nodes.append(node)
            node_map[node.node_id] = node
            depth_map[node.node_id] = 0

        summary.total_nodes = len(nodes)

        # 5. Build edges from parent_event_id (primary), decision_id, task_id
        edges: List[DecisionTreeEdge] = []
        edge_set: Set[Tuple[str, str]] = set()
        child_count: Dict[str, int] = {}
        linked_ids: Set[str] = set()

        for node in nodes:
            evt = self._find_event_by_node_id(filtered, node.node_id)
            if not evt:
                node.link_status = "unlinked"
                summary.unlinked_nodes += 1
                node.missing_fields.append("event_data")
                continue

            parent_event_id = str(evt.get("parent_event_id", "") or "").strip()
            if parent_event_id and parent_event_id in node_map:
                if len(edges) >= self.max_edges:
                    reason_codes.append("degraded_max_edges")
                    summary.degraded = True
                    break
                child_count[parent_event_id] = child_count.get(parent_event_id, 0) + 1
                if child_count[parent_event_id] > self.max_children_per_node:
                    continue
                key = (parent_event_id, node.node_id)
                if key not in edge_set:
                    edge_set.add(key)
                    edges.append(DecisionTreeEdge(
                        parent_id=parent_event_id,
                        child_id=node.node_id,
                        relation="parent_event",
                    ))
                    linked_ids.add(node.node_id)
                    linked_ids.add(parent_event_id)
                    # Propagate depth
                    depth_map[node.node_id] = max(
                        depth_map.get(parent_event_id, 0) + 1,
                        depth_map.get(node.node_id, 0),
                    )

        summary.total_edges = len(edges)

        # 6. Compute depth after edges
        for node in nodes:
            depth = depth_map.get(node.node_id, 0)
            node.depth = depth
            if depth > self.max_depth:
                reason_codes.append("degraded_max_depth")
                summary.degraded = True
                node.link_status = "degraded" if not node.link_status else node.link_status
            if depth > summary.max_depth_reached:
                summary.max_depth_reached = depth

        # 7. Classify node link status (first pass)
        for node in nodes:
            if node.node_id not in linked_ids:
                node.link_status = "unlinked"
                summary.unlinked_nodes += 1
            elif node.link_status not in ("degraded", "estimated"):
                node.link_status = "linked"
                summary.linked_nodes += 1

            if node.event_type in _FAILURE_EVENT_TYPES:
                summary.failure_nodes += 1

        # 8. Attach decision_traces / task_execution_records for supplement
        self._attach_supplemental(nodes, sd)

        # 9. Second-pass auxiliary linking: decision_id / task_id chains
        #    (plan §4 step 3: decision_id/task_id as auxiliary keys when
        #     parent_event_id is absent — supports legacy sessions)
        self._attach_auxiliary_edges(
            nodes, edges, edge_set, child_count, linked_ids, depth_map, node_map,
            reason_codes, summary,
        )

        # 10. Re-count link status after supplemental + auxiliary edge attachment
        #     (step 7 counts may be stale after _attach_supplemental sets
        #      estimated, and auxiliary edges add new linked nodes)
        summary.linked_nodes = 0
        summary.unlinked_nodes = 0
        summary.estimated_nodes = 0
        summary.degraded_nodes = 0
        for node in nodes:
            if node.link_status == "degraded":
                summary.degraded_nodes += 1
                summary.degraded = True
            elif node.link_status == "estimated":
                summary.estimated_nodes += 1
            elif node.node_id in linked_ids:
                node.link_status = "linked"
                summary.linked_nodes += 1
            else:
                node.link_status = "unlinked"
                summary.unlinked_nodes += 1

        # Ensure node counts add up: every node must be counted once
        _counted = (summary.linked_nodes + summary.unlinked_nodes +
                    summary.estimated_nodes + summary.degraded_nodes)
        if _counted != summary.total_nodes:
            summary.unlinked_nodes += (summary.total_nodes - _counted)

        # Build degrade_reasons from reason_codes (limit violations) and
        # node-level degraded statuses.  Deduplicate.
        _seen_reasons: set[str] = set()
        for rc in reason_codes:
            if rc.startswith("degraded_"):
                if rc not in _seen_reasons:
                    _seen_reasons.add(rc)
                    summary.degrade_reasons.append(rc)
        for node in nodes:
            if node.link_status == "degraded":
                reason = f"node_{node.node_id}_depth_exceeded"
                if reason not in _seen_reasons:
                    _seen_reasons.add(reason)
                    summary.degrade_reasons.append(reason)

        summary.reason_codes = sorted(set(reason_codes))
        if summary.degraded and "degraded" not in summary.reason_codes:
            summary.reason_codes.insert(0, "degraded")

        return nodes, edges, summary

    # ── Event loading ─────────────────────────────────────────────────────

    @staticmethod
    def _load_run_ledger_events(sd: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract run_ledger event list from session data."""
        ledger = sd.get("run_ledger")
        if isinstance(ledger, list):
            return [{**e} for e in ledger if isinstance(e, dict)]
        # Fallback: older sessions may have decision_traces only
        dt = sd.get("decision_traces")
        if isinstance(dt, list):
            adapted: List[Dict[str, Any]] = []
            for i, d in enumerate(dt):
                if not isinstance(d, dict):
                    continue
                adapted.append({
                    "event_id": d.get("trace_id") or d.get("id") or f"dt_{i}",
                    "event_type": "decision_made",
                    "timestamp": d.get("timestamp", ""),
                    "phase": d.get("phase", ""),
                    "actor_type": d.get("actor", ""),
                    "actor_name": d.get("actor_name", ""),
                    "decision_id": d.get("decision_id", ""),
                    "action": d.get("action", ""),
                    "result": d.get("result", ""),
                    "error": d.get("error", ""),
                    "source_refs": d.get("source_refs"),
                    "parent_event_id": "",
                })
            return adapted
        return []

    def _filter_events(
        self,
        events: List[Dict[str, Any]],
        phase: str,
        actor: str,
        only_failures: bool,
    ) -> List[Dict[str, Any]]:
        """Apply CLI filters to raw event list."""
        filtered: List[Dict[str, Any]] = []
        _phase = str(phase or "").strip().lower()
        _actor = str(actor or "").strip().lower()
        for evt in events:
            if _phase and str(evt.get("phase", "")).strip().lower() != _phase:
                continue
            if _actor:
                at = str(evt.get("actor_type", "")).strip().lower()
                an = str(evt.get("actor_name", "")).strip().lower()
                if _actor not in (at, an):
                    continue
            if only_failures:
                etype = str(evt.get("event_type", "")).strip().lower()
                if etype not in _FAILURE_EVENT_TYPES:
                    continue
            filtered.append(evt)
        return filtered

    def _event_to_node(self, evt: Dict[str, Any]) -> DecisionTreeNode:
        """Convert a run_ledger event dict to a DecisionTreeNode."""
        event_id = str(evt.get("event_id", "") or "").strip()
        decision_id = str(evt.get("decision_id", "") or "").strip()
        task_id = str(evt.get("task_id", "") or "").strip()
        event_type = str(evt.get("event_type", "") or "").strip().lower()

        # Node id: prefer event_id, then decision_id, then task_id
        node_id = event_id or decision_id or task_id or f"node_{hash(str(evt)) % 100000}"

        short_label = _EVENT_LABEL.get(event_type, event_type[:12])
        label = f"{short_label}"

        phase = str(evt.get("phase", "") or "")
        actor_raw = str(evt.get("actor_type", "") or str(evt.get("actor_name", "")) or "")

        sr = evt.get("source_refs")
        if isinstance(sr, dict):
            source_refs = [f"{k}={v}" for k, v in sr.items()]
        elif isinstance(sr, list):
            source_refs = [str(x) for x in sr if x]
        else:
            source_refs = [str(sr)] if sr else []

        return DecisionTreeNode(
            node_id=node_id,
            label=label,
            event_type=event_type,
            phase=phase,
            actor=actor_raw,
            timestamp=str(evt.get("timestamp", "") or ""),
            event_id=event_id,
            decision_id=decision_id,
            task_id=task_id,
            source_refs=source_refs,
            action=str(evt.get("action", "") or ""),
            result=str(evt.get("result", "") or ""),
            error=str(evt.get("error", "") or ""),
        )

    @staticmethod
    def _find_event_by_node_id(
        events: List[Dict[str, Any]], node_id: str
    ) -> Optional[Dict[str, Any]]:
        for evt in events:
            eid = str(evt.get("event_id", "") or "")
            did = str(evt.get("decision_id", "") or "")
            tid = str(evt.get("task_id", "") or "")
            if node_id in (eid, did, tid):
                return evt
        return None

    def _attach_supplemental(
        self,
        nodes: List[DecisionTreeNode],
        sd: Dict[str, Any],
    ) -> None:
        """Attach supplemental info from decision_traces and task_execution_records."""
        dt = sd.get("decision_traces")
        ter = sd.get("task_execution_records")
        ter_list: List[Dict[str, Any]] = (
            [{**r} for r in ter if isinstance(r, dict)]
            if isinstance(ter, list) else []
        )
        dt_list: List[Dict[str, Any]] = (
            [{**d} for d in dt if isinstance(d, dict)]
            if isinstance(dt, list) else []
        )

        for node in nodes:
            if node.decision_id:
                for d in dt_list:
                    if d.get("decision_id") == node.decision_id:
                        if not node.action:
                            node.action = str(d.get("action", "") or "")
                        break
            if node.task_id:
                for r in ter_list:
                    if r.get("task_id") == node.task_id:
                        if not node.result:
                            node.result = str(r.get("result", "") or "")
                        break

        # Checkpoint metadata: attach resume/rerun hints
        ctx = sd.get("context", {})
        if isinstance(ctx, dict):
            target_info = ctx.get("target_info", {})
            if isinstance(target_info, dict):
                for node in nodes:
                    self._attach_checkpoint_meta(node, target_info)

    @staticmethod
    def _attach_checkpoint_meta(
        node: DecisionTreeNode,
        target_info: Dict[str, Any],
    ) -> None:
        """Attach checkpoint / resume hints to a node (plan §4 step 4)."""
        artifact_refs = target_info.get("artifact_refs")
        rerun_required = target_info.get("rerun_required")
        provenance = target_info.get("provenance")

        if isinstance(artifact_refs, dict) and artifact_refs.get(node.task_id):
            node.source_refs.append(f"artifact_ref:{node.task_id}")

        if rerun_required:
            # Allow upgrading "unlinked" → "estimated" for checkpoint hints
            if not node.link_status or node.link_status == "unlinked":
                node.link_status = "estimated"
            node.missing_fields.append("rerun_required")

        if isinstance(provenance, dict) and provenance.get(node.task_id, "") != "":
            # provenance exists but no specific action needed unless mismatch
            pass

    # ── Auxiliary edge attachment (plan §4 step 3) ────────────────────────

    def _attach_auxiliary_edges(
        self,
        nodes: List[DecisionTreeNode],
        edges: List[DecisionTreeEdge],
        edge_set: Set[Tuple[str, str]],
        child_count: Dict[str, int],
        linked_ids: Set[str],
        depth_map: Dict[str, int],
        node_map: Dict[str, DecisionTreeNode],
        reason_codes: List[str],
        summary: DecisionTreeSummary,
    ) -> None:
        """Second-pass linking: use decision_id / task_id as auxiliary keys.

        When parent_event_id is absent (legacy sessions or cross-phase links),
        this rebuilds chains using decision_id and task_id so orphan nodes
        can be reconnected.  Edges are marked ``relation=decision_link``
        or ``relation=task_link`` to distinguish from primary parent_event
        edges.
        """
        # Build lookup: decision_id → node_id
        decision_owners: Dict[str, str] = {}
        task_owners: Dict[str, str] = {}
        for node in nodes:
            if node.decision_id and node.decision_id not in decision_owners:
                decision_owners[node.decision_id] = node.node_id
            if node.task_id and node.task_id not in task_owners:
                task_owners[node.task_id] = node.node_id

        for node in nodes:
            # Skip already-linked nodes
            if node.node_id in linked_ids:
                continue

            # Try decision_id link: find the decision owner for this node's decision_id
            if node.decision_id and node.decision_id in decision_owners:
                owner_id = decision_owners[node.decision_id]
                if owner_id != node.node_id and owner_id in node_map:
                    if len(edges) >= self.max_edges:
                        reason_codes.append("degraded_max_edges")
                        summary.degraded = True
                        break
                    child_count[owner_id] = child_count.get(owner_id, 0) + 1
                    if child_count[owner_id] > self.max_children_per_node:
                        continue
                    key = (owner_id, node.node_id)
                    if key not in edge_set:
                        edge_set.add(key)
                        edges.append(DecisionTreeEdge(
                            parent_id=owner_id,
                            child_id=node.node_id,
                            relation="decision_link",
                        ))
                        linked_ids.add(node.node_id)
                        linked_ids.add(owner_id)
                        depth_map[node.node_id] = max(
                            depth_map.get(owner_id, 0) + 1,
                            depth_map.get(node.node_id, 0),
                        )
                        continue

            # Try task_id link
            if node.task_id and node.task_id in task_owners:
                owner_id = task_owners[node.task_id]
                if owner_id != node.node_id and owner_id in node_map:
                    if len(edges) >= self.max_edges:
                        reason_codes.append("degraded_max_edges")
                        summary.degraded = True
                        break
                    child_count[owner_id] = child_count.get(owner_id, 0) + 1
                    if child_count[owner_id] > self.max_children_per_node:
                        continue
                    key = (owner_id, node.node_id)
                    if key not in edge_set:
                        edge_set.add(key)
                        edges.append(DecisionTreeEdge(
                            parent_id=owner_id,
                            child_id=node.node_id,
                            relation="task_link",
                        ))
                        linked_ids.add(node.node_id)
                        linked_ids.add(owner_id)
                        depth_map[node.node_id] = max(
                            depth_map.get(owner_id, 0) + 1,
                            depth_map.get(node.node_id, 0),
                        )

        summary.total_edges = len(edges)

    # ── Rendering (plan §4 step 5) ────────────────────────────────────────

    def _render(
        self,
        nodes: List[DecisionTreeNode],
        edges: List[DecisionTreeEdge],
        summary: DecisionTreeSummary,
        session_data: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Render Mermaid + Markdown summary + degrade summary."""
        sections: List[str] = []

        # ─ Header ─
        sections.append("# Decision Tree (判断ツリー)")
        sections.append("")

        # ─ Mermaid ─
        sections.append("## Mermaid Diagram")
        sections.append("")
        sections.append("```mermaid")
        sections.append("graph TD")
        for node in nodes:
            safe_id = self._mermaid_id(node.node_id)
            safe_label = self._mermaid_escape(self._node_display_label(node))
            sections.append(f"  {safe_id}[\"{safe_label}\"]")
        for edge in edges:
            safe_parent = self._mermaid_id(edge.parent_id)
            safe_child = self._mermaid_id(edge.child_id)
            sections.append(f"  {safe_parent} --> {safe_child}")
        sections.append("```")
        sections.append("")

        # ─ Node summary table ─
        sections.append("## Node Summary")
        sections.append("")
        sections.append("| # | Label | Type | Phase | Actor | Status | Evidence |")
        sections.append("|---|-------|------|-------|-------|--------|----------|")
        for i, node in enumerate(nodes, 1):
            lbl = self._md_escape(node.label)
            etype = node.event_type
            phase = node.phase or "-"
            actor = node.actor or "-"
            status = node.link_status or "linked"
            evidence_parts: List[str] = []
            if node.event_id:
                evidence_parts.append(f"evt:{node.event_id[:12]}")
            if node.decision_id:
                evidence_parts.append(f"dec:{node.decision_id[:12]}")
            if node.task_id:
                evidence_parts.append(f"task:{node.task_id[:12]}")
            if node.source_refs:
                evidence_parts.append(f"refs:{len(node.source_refs)}")
            evidence = ", ".join(evidence_parts) if evidence_parts else "-"

            # Redact before rendering
            etype = self._redact(etype)
            phase = self._redact(phase)
            actor = self._redact(actor)
            status = self._redact(status)
            evidence = self._redact(evidence)

            sections.append(f"| {i} | {lbl} | {etype} | {phase} | {actor} | {status} | {evidence} |")
        sections.append("")

        # ─ Degrade / status summary ─
        sections.append("## Tree Status")
        sections.append("")
        sections.append(f"- **Total nodes**: {summary.total_nodes}")
        sections.append(f"- **Total edges**: {summary.total_edges}")
        sections.append(f"- **Max depth**: {summary.max_depth_reached}")
        sections.append(f"- **Linked**: {summary.linked_nodes}  "
                        f"**Estimated**: {summary.estimated_nodes}  "
                        f"**Unlinked**: {summary.unlinked_nodes}  "
                        f"**Degraded**: {summary.degraded_nodes}")
        sections.append(f"- **Failure nodes**: {summary.failure_nodes}")
        sections.append(f"- **Degraded**: {summary.degraded}")
        if summary.degrade_reasons:
            for reason in summary.degrade_reasons:
                sections.append(f"  - {self._redact(reason)}")
        if summary.reason_codes:
            codes = ", ".join(f"`{c}`" for c in summary.reason_codes)
            sections.append(f"- **Reason codes**: {codes}")

        if summary.degraded:
            sections.append("")
            sections.append("### Degrade Summary (縮約情報)")
            sections.append("")
            sections.append("このツリーは制限超過により縮約されています。")
            sections.append("以下の reason codes が出力されました:")
            for rc in summary.reason_codes:
                sections.append(f"- `{rc}`")

        sections.append("")
        return "\n".join(sections)

    # ── Display helpers ───────────────────────────────────────────────────

    @classmethod
    def _node_display_label(cls, node: DecisionTreeNode) -> str:
        """Short label for Mermaid node display (redacted)."""
        parts = [node.label]
        if node.phase:
            parts.append(node.phase)
        if node.actor:
            parts.append(node.actor[:20])
        if node.error:
            err_short = node.error[:40].replace("\n", " ")
            err_safe = cls._redact_string(err_short)
            parts.append(f"ERR:{err_safe}")
        return " / ".join(parts)

    @staticmethod
    def _mermaid_id(raw_id: str) -> str:
        """Sanitise a raw id into a safe Mermaid node identifier."""
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", raw_id)
        return f"n_{safe}" if safe else "n_unknown"

    @staticmethod
    def _mermaid_escape(text: str) -> str:
        """Escape text for Mermaid labels."""
        # Mermaid labels in double-quotes: escape double-quotes and backslashes
        escaped = text.replace("\\", "\\\\").replace('"', '\\"')
        # Also remove any embedded newlines
        escaped = escaped.replace("\n", " ").replace("\r", "")
        return escaped

    @classmethod
    def _md_escape(cls, text: str) -> str:
        """Escape characters that could break Markdown table cells."""
        # Replace pipe and newline — minimal escape for table cells
        escaped = str(text).replace("|", "\\|").replace("\n", " ")
        escaped = _MARKDOWN_UNSAFE_RE.sub(r"\\\1", escaped)
        return escaped

    # ── Redaction (plan §5.1 SEC-1) ───────────────────────────────────────

    @classmethod
    def _redact(cls, value: Any) -> str:
        """Recursively redact secrets from any value, returning a safe string."""
        if isinstance(value, dict):
            parts = []
            for k, v in value.items():
                safe_v = cls._redact(v)
                parts.append(f"{k}={safe_v}")
            return ", ".join(parts)
        if isinstance(value, list):
            return ", ".join(cls._redact(item) for item in value)
        text = str(value)
        return cls._redact_string(text)

    @classmethod
    def _redact_string(cls, text: str) -> str:
        """Apply secret patterns to a plain string, returning a redacted copy."""
        result = text
        for pattern in _SECRET_PATTERNS:
            result = pattern.sub("[REDACTED]", result)
        return result

    # ── JSON export ───────────────────────────────────────────────────────

    def export_json(self, session_data: dict, output_path: Any) -> None:
        """Write structured tree data to a JSON file."""
        data = self.format_json(session_data)
        path = output_path if hasattr(output_path, "write_text") else __import__("pathlib").Path(str(output_path))
        path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
