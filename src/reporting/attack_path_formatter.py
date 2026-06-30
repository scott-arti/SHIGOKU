"""
AttackPathFormatter: セッション JSON データから attack_paths.md を生成する。

攻撃パスを Markdown + Mermaid で可視化し、成立済み/候補/未検証の状態を
evidence_state による単一語彙で明確に区別する。
機械可読な JSON 出力 (Neo4j export contract) もサポートする。

Chapter order (mandated by subtask plan §3.1):
  Executive Summary → Top Paths → Candidate/Blocked Paths →
  Mermaid Graph → Blockers → Next Validation
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from src.reporting.finding_extractor import extract_all_findings
from src.core.knowledge.models import (
    AttackPathGraph,
    AttackPathNode,
    AttackPathEdge,
    resolve_evidence_state,
    EVIDENCE_STATE_CONFIRMED,
    EVIDENCE_STATE_CANDIDATE,
    EVIDENCE_STATE_BLOCKED,
    EVIDENCE_STATE_BACKFILL,
    NODE_TYPE_ATTACK_PATH,
    NODE_TYPE_FINDING,
    NODE_TYPE_ENDPOINT,
    NODE_TYPE_PARAMETER,
    NODE_TYPE_TARGET,
    EDGE_HAS_ENDPOINT,
    EDGE_PRODUCED_FINDING,
    EDGE_SUPPORTS_PATH,
    EDGE_BLOCKED_BY,
    EDGE_NEXT_VALIDATION,
)

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default thresholds (overridable via config/shigoku.yaml reporting.attack_paths)
# ---------------------------------------------------------------------------

DEFAULT_MAX_MERMAID_NODES = 25
DEFAULT_MAX_MERMAID_EDGES = 40
DEFAULT_MAX_TOP_PATHS = 5

# Evidence state → Mermaid style class
_EVIDENCE_STYLE: Dict[str, str] = {
    EVIDENCE_STATE_CONFIRMED: "confirmed",
    EVIDENCE_STATE_CANDIDATE: "candidate",
    EVIDENCE_STATE_BLOCKED: "blocked",
    EVIDENCE_STATE_BACKFILL: "backfill",
}

# Evidence state → display badge
_EVIDENCE_BADGE: Dict[str, str] = {
    EVIDENCE_STATE_CONFIRMED: "`[confirmed]`",
    EVIDENCE_STATE_CANDIDATE: "`[candidate]`",
    EVIDENCE_STATE_BLOCKED: "`[blocked]`",
    EVIDENCE_STATE_BACKFILL: "`[backfill]`",
}

# Evidence state → severity ordering (for Top Paths ranking)
_EVIDENCE_PRIORITY: Dict[str, int] = {
    EVIDENCE_STATE_CONFIRMED: 0,
    EVIDENCE_STATE_CANDIDATE: 1,
    EVIDENCE_STATE_BLOCKED: 2,
    EVIDENCE_STATE_BACKFILL: 3,
}

_SEVERITY_PRIORITY: Dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


# ---------------------------------------------------------------------------
# Formatter
# ---------------------------------------------------------------------------

class AttackPathFormatter:
    """Generate attack_paths.md Markdown + Mermaid from session data."""

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        cfg = config or {}
        self.max_mermaid_nodes: int = int(
            cfg.get("max_mermaid_nodes", DEFAULT_MAX_MERMAID_NODES)
        )
        self.max_mermaid_edges: int = int(
            cfg.get("max_mermaid_edges", DEFAULT_MAX_MERMAID_EDGES)
        )
        self.max_top_paths: int = int(
            cfg.get("max_top_paths", DEFAULT_MAX_TOP_PATHS)
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def format(self, session_data: Any) -> str:
        """Generate the complete attack_paths.md Markdown string.

        Args:
            session_data: Raw session dict (or None for graceful degradation).

        Returns:
            Markdown string.  Never raises.
        """
        sd = session_data if isinstance(session_data, dict) else {}
        sections: List[str] = []

        sections.append(self._section_header(sd))
        sections.append(self._section_executive_summary(sd))
        sections.append(self._section_top_paths(sd))
        sections.append(self._section_candidate_blocked_paths(sd))
        sections.append(self._section_mermaid_graph(sd))
        sections.append(self._section_blockers(sd))
        sections.append(self._section_next_validation(sd))
        sections.append(self._section_legend(sd))
        sections.append(self._section_footer(sd))

        return "\n\n".join(s for s in sections if s)

    def export_json(self, session_data: Any, output_path: Path) -> None:
        """Export the attack-path graph as machine-readable JSON (Neo4j contract).

        Args:
            session_data: Raw session dict.
            output_path: Path to write ``attack_paths.json``.
        """
        graph = self._build_attack_path_graph(session_data)
        payload = {
            "nodes": [self._node_to_dict(n) for n in graph.nodes],
            "edges": [self._edge_to_dict(e) for e in graph.edges],
            "metadata": graph.metadata,
        }
        output_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # Graph building (for JSON export and internal use)
    # ------------------------------------------------------------------

    def _build_attack_path_graph(self, session_data: Any) -> AttackPathGraph:
        """Build the full AttackPathGraph from session findings."""
        sd = session_data if isinstance(session_data, dict) else {}
        session_id = str(sd.get("session_id", "unknown"))
        findings = extract_all_findings(sd)
        target_info = self._safe_dict(
            self._safe_dict(sd.get("context")).get("target_info")
        )

        # Filter to chain findings
        chain_findings = [
            f
            for f in findings
            if self._safe_dict(f.get("additional_info")).get("is_attack_chain")
        ]

        nodes: List[AttackPathNode] = []
        edges: List[AttackPathEdge] = []

        # Only build graph if there are chain findings
        if not chain_findings:
            return AttackPathGraph(
                nodes=[], edges=[],
                metadata={
                    "session_id": session_id,
                    "generated_at": self._now_iso(),
                    "total_chains": 0,
                },
            )

        # Add target node
        target_url = target_info.get("url", "unknown")
        target_domain = target_info.get("domain", "")
        target_node = AttackPathNode(
            node_id=f"target:{target_domain or target_url}",
            display_label=target_domain or target_url or "Unknown Target",
            node_type=NODE_TYPE_TARGET,
            evidence_state=EVIDENCE_STATE_CONFIRMED,
            why_in_path="Root target of the assessment",
            source_refs=[session_id],
            observed_at=self._timestamp_from_epoch(sd.get("start_time")),
        )
        nodes.append(target_node)

        for finding in chain_findings:
            finding_id = str(finding.get("id", ""))
            additional = self._safe_dict(finding.get("additional_info"))
            decision_trace = self._safe_dict(additional.get("decision_trace"))
            evidence_state = resolve_evidence_state(finding)

            # --- AttackPath node (the chain itself) ---
            chain_node = AttackPathNode(
                node_id=f"attack_path:{finding_id}",
                display_label=self._safe_str(finding.get("title"), "Untitled Chain"),
                node_type=NODE_TYPE_ATTACK_PATH,
                evidence_state=evidence_state,
                why_in_path=additional.get("business_impact_sentence", ""),
                source_refs=[
                    finding_id,
                    decision_trace.get("selected_rule_id", ""),
                ],
                blocked_reason=", ".join(
                    self._safe_list(decision_trace.get("excluded_reasons"))
                ),
                next_validation_hint=self._derive_validation_hint(
                    evidence_state, decision_trace
                ),
                observed_at=self._safe_str(finding.get("discovered_at")),
                inferred_after=self._now_iso(),
            )
            nodes.append(chain_node)

            # Target → AttackPath edge
            edges.append(
                AttackPathEdge(
                    edge_id=f"edge:target_to_path:{finding_id}",
                    source_node_id=target_node.node_id,
                    target_node_id=chain_node.node_id,
                    edge_type=EDGE_SUPPORTS_PATH,
                    display_label="target hosts attack path",
                    evidence_state=evidence_state,
                    why_in_path="Target is the assessment scope for this chain",
                    source_refs=[session_id, finding_id],
                )
            )

            # --- Endpoint node ---
            target_url_val = self._safe_str(
                finding.get("target_url") or finding.get("url"), ""
            )
            if target_url_val and target_url_val.lower() not in ("multiple", ""):
                endpoint_node = AttackPathNode(
                    node_id=f"endpoint:{self._sanitise_id(target_url_val)}",
                    display_label=self._shorten_url(target_url_val),
                    node_type=NODE_TYPE_ENDPOINT,
                    evidence_state=evidence_state,
                    why_in_path=f"Affected endpoint for chain {finding_id}",
                    source_refs=[finding_id],
                )
                nodes.append(endpoint_node)

                edges.append(
                    AttackPathEdge(
                        edge_id=f"edge:path_to_endpoint:{finding_id}",
                        source_node_id=chain_node.node_id,
                        target_node_id=endpoint_node.node_id,
                        edge_type=EDGE_HAS_ENDPOINT,
                        display_label="affects",
                        evidence_state=evidence_state,
                        source_refs=[finding_id],
                    )
                )

            # --- Finding node for each component ---
            component_titles = self._safe_list(additional.get("component_titles"))
            for i, comp_title in enumerate(component_titles):
                comp_id = f"finding:comp:{finding_id}:{i}"
                comp_node = AttackPathNode(
                    node_id=comp_id,
                    display_label=self._safe_str(comp_title, f"Component {i}"),
                    node_type=NODE_TYPE_FINDING,
                    evidence_state=evidence_state,
                    why_in_path=f"Component finding of chain {finding_id}",
                    source_refs=[finding_id],
                )
                nodes.append(comp_node)

                edges.append(
                    AttackPathEdge(
                        edge_id=f"edge:chain_to_component:{finding_id}:{i}",
                        source_node_id=chain_node.node_id,
                        target_node_id=comp_id,
                        edge_type=EDGE_PRODUCED_FINDING,
                        display_label="composed of",
                        evidence_state=evidence_state,
                        source_refs=[finding_id],
                    )
                )

        now_iso = self._now_iso()
        metadata = {
            "session_id": session_id,
            "generated_at": now_iso,
            "total_chains": len(chain_findings),
            "confirmed_chains": sum(
                1
                for f in chain_findings
                if resolve_evidence_state(f) == EVIDENCE_STATE_CONFIRMED
            ),
            "candidate_chains": sum(
                1
                for f in chain_findings
                if resolve_evidence_state(f) == EVIDENCE_STATE_CANDIDATE
            ),
            "blocked_chains": sum(
                1
                for f in chain_findings
                if resolve_evidence_state(f) == EVIDENCE_STATE_BLOCKED
            ),
            "backfill_chains": sum(
                1
                for f in chain_findings
                if resolve_evidence_state(f) == EVIDENCE_STATE_BACKFILL
            ),
        }

        return AttackPathGraph(nodes=nodes, edges=edges, metadata=metadata)

    # ------------------------------------------------------------------
    # Section generators
    # ------------------------------------------------------------------

    def _section_header(self, sd: Dict[str, Any]) -> str:
        session_id = sd.get("session_id", "unknown")
        lines = [
            "# Attack Paths Report",
            "",
            f"**Session ID:** `{session_id}`",
            f"**Generated:** {self._now_iso()}",
            "",
            "---",
        ]
        return "\n".join(lines)

    def _section_executive_summary(self, sd: Dict[str, Any]) -> str:
        """Executive Summary — top 3 paths, blocked count, next validation priority."""
        chain_findings, graph = self._extract_chain_data(sd)

        lines = ["## Executive Summary", ""]

        if not chain_findings:
            lines.append(
                "> No attack chain findings in source session. "
                "No data in source session."
            )
            return "\n".join(lines)

        # Count by evidence state
        confirmed = [
            f
            for f in chain_findings
            if resolve_evidence_state(f) == EVIDENCE_STATE_CONFIRMED
        ]
        candidate = [
            f
            for f in chain_findings
            if resolve_evidence_state(f) == EVIDENCE_STATE_CANDIDATE
        ]
        blocked = [
            f
            for f in chain_findings
            if resolve_evidence_state(f) == EVIDENCE_STATE_BLOCKED
        ]
        backfill = [
            f
            for f in chain_findings
            if resolve_evidence_state(f) == EVIDENCE_STATE_BACKFILL
        ]

        lines.append(f"- **Total attack paths:** {len(chain_findings)}")
        lines.append(f"- **Confirmed:** {len(confirmed)}")
        lines.append(f"- **Candidate:** {len(candidate)}")
        lines.append(f"- **Blocked:** {len(blocked)}")
        lines.append(f"- **Backfill (AI/inferred):** {len(backfill)}")
        lines.append("")

        # Top 3 paths
        ranked = self._rank_paths(chain_findings)
        top3 = ranked[:3]
        if top3:
            lines.append("### Top 3 Paths (Immediate Attention)")
            lines.append("")
            lines.append(
                "| # | Path | Severity | Evidence | Confidence |"
            )
            lines.append("|---|---|---|---|---|")
            for i, (finding, _score) in enumerate(top3, 1):
                title = self._safe_str(finding.get("title"), "")
                severity = self._safe_str(finding.get("severity"), "")
                evidence = resolve_evidence_state(finding)
                confidence = finding.get("confidence", 0.0)
                lines.append(
                    f"| {i} | {title} | `{severity}` | "
                    f"{_EVIDENCE_BADGE.get(evidence, evidence)} | "
                    f"{confidence:.0%} |"
                )
            lines.append("")

        # Blocked summary
        if blocked:
            lines.append(f"**⚠️  {len(blocked)} path(s) blocked** — see Blockers section below.")
            lines.append("")

        return "\n".join(lines)

    def _section_top_paths(self, sd: Dict[str, Any]) -> str:
        """Top Paths — highest-priority confirmed + candidate paths."""
        chain_findings, _graph = self._extract_chain_data(sd)
        lines = ["## Top Paths", ""]

        if not chain_findings:
            lines.append("No attack chain findings in source session.")
            return "\n".join(lines)

        ranked = self._rank_paths(chain_findings)
        top = ranked[: self.max_top_paths]

        for i, (finding, score) in enumerate(top, 1):
            lines.extend(self._format_path_detail(finding, i, score))
            lines.append("")

        if len(ranked) > self.max_top_paths:
            lines.append(
                f"*({len(ranked) - self.max_top_paths} additional paths in "
                f"Candidate/Blocked section and Mermaid graph)*"
            )

        return "\n".join(lines)

    def _section_candidate_blocked_paths(self, sd: Dict[str, Any]) -> str:
        """Candidate and Blocked paths — the ones reviewers must NOT treat as confirmed."""
        chain_findings, _graph = self._extract_chain_data(sd)
        lines = ["## Candidate & Blocked Paths", ""]

        if not chain_findings:
            lines.append("No attack chain findings in source session.")
            return "\n".join(lines)

        candidate_findings = [
            f
            for f in chain_findings
            if resolve_evidence_state(f)
            in (EVIDENCE_STATE_CANDIDATE, EVIDENCE_STATE_BACKFILL, EVIDENCE_STATE_BLOCKED)
        ]

        if not candidate_findings:
            lines.append("All paths are confirmed. No candidate or blocked paths.")
            return "\n".join(lines)

        lines.append(
            "> ⚠️  **These paths are NOT confirmed.** "
            "They require additional evidence before you can treat them as actionable vulnerabilities."
        )
        lines.append("")

        for finding in candidate_findings:
            evidence_state = resolve_evidence_state(finding)
            title = self._safe_str(finding.get("title"), "Untitled")
            finding_id = self._safe_str(finding.get("id"), "")
            severity = self._safe_str(finding.get("severity"), "")
            confidence = finding.get("confidence", 0.0)
            additional = self._safe_dict(finding.get("additional_info"))
            decision_trace = self._safe_dict(additional.get("decision_trace"))
            excluded = ", ".join(
                self._safe_list(decision_trace.get("excluded_reasons"))
            )

            lines.append(f"### {title}")
            lines.append("")
            lines.append(
                f"| Property | Value |\n"
                f"|---|---|\n"
                f"| **Evidence State** | {_EVIDENCE_BADGE.get(evidence_state, evidence_state)} |\n"
                f"| **Finding ID** | `{finding_id}` |\n"
                f"| **Severity** | `{severity}` |\n"
                f"| **Confidence** | {confidence:.0%} |\n"
                f"| **Why Not Confirmed** | {excluded or 'Insufficient evidence or low confidence'} |"
            )
            lines.append("")

            if evidence_state == EVIDENCE_STATE_BLOCKED and excluded:
                lines.append(f"**Blocker:** {excluded}")
                lines.append("")

        return "\n".join(lines)

    def _section_mermaid_graph(self, sd: Dict[str, Any]) -> str:
        """Mermaid graph — visual attack path diagram with evidence state styling."""
        chain_findings, graph = self._extract_chain_data(sd)
        lines = ["## Attack Path Graph", ""]

        if not graph.nodes:
            lines.append("No attack path graph data to render.")
            return "\n".join(lines)

        lines.append(
            "> Node shapes and line styles distinguish evidence states:\n"
            "> - **Solid border** = confirmed, **Dashed** = candidate,\n"
            "> - **Dotted** = blocked, **Thin** = backfill"
        )
        lines.append("")

        mermaid = self._build_mermaid(graph)
        lines.append(mermaid)

        return "\n".join(lines)

    def _section_blockers(self, sd: Dict[str, Any]) -> str:
        """Blockers — what is preventing paths from being confirmed."""
        chain_findings, _graph = self._extract_chain_data(sd)
        lines = ["## Blockers", ""]

        if not chain_findings:
            lines.append("No attack chain findings in source session.")
            return "\n".join(lines)

        blocked_findings = [
            f
            for f in chain_findings
            if resolve_evidence_state(f) == EVIDENCE_STATE_BLOCKED
        ]

        if not blocked_findings:
            lines.append("No blocked paths. All paths are either confirmed or candidate.")
            return "\n".join(lines)

        lines.append(
            "The following blockers prevent attack paths from being confirmed:"
        )
        lines.append("")

        for finding in blocked_findings:
            title = self._safe_str(finding.get("title"), "Untitled")
            additional = self._safe_dict(finding.get("additional_info"))
            decision_trace = self._safe_dict(additional.get("decision_trace"))
            excluded = self._safe_list(decision_trace.get("excluded_reasons"))
            finding_id = self._safe_str(finding.get("id"), "")

            lines.append(f"### {title}")
            lines.append("")
            lines.append(f"- **Finding:** `{finding_id}`")
            for reason in excluded:
                lines.append(f"- **Reason:** {reason}")
            lines.append("")

        return "\n".join(lines)

    def _section_next_validation(self, sd: Dict[str, Any]) -> str:
        """Next Validation — the highest-ROI next steps to unblock or verify paths."""
        chain_findings, _graph = self._extract_chain_data(sd)
        lines = ["## Next Validation Steps", ""]

        if not chain_findings:
            lines.append("No attack chain findings in source session.")
            return "\n".join(lines)

        lines.append("Prioritised next actions to verify or unblock attack paths:")
        lines.append("")

        steps = self._derive_validation_steps(chain_findings, sd)
        for i, step in enumerate(steps, 1):
            lines.append(f"### Step {i}: {step['action']}")
            lines.append("")
            lines.append(f"- **Path:** {step['path_title']}")
            lines.append(f"- **Expected Information Gain:** {step['gain']}")
            lines.append(f"- **Unblocks Blocker:** {step['unblocks']}")
            lines.append("")

        if not steps:
            lines.append(
                "All paths are confirmed. No pending validation steps required."
            )
            lines.append("")

        return "\n".join(lines)

    def _section_legend(self, sd: Dict[str, Any]) -> str:
        """Legend — evidence state badge definitions."""
        chain_findings, _graph = self._extract_chain_data(sd)
        if not chain_findings:
            return ""

        lines = [
            "## Legend",
            "",
            "| Badge | Meaning |",
            "|---|---|",
            f"| `[confirmed]` | Chain state is confirmed with confidence ≥ 0.8 — ready to escalate |",
            f"| `[candidate]` | Chain state is confirmed but confidence < 0.8 — needs more evidence before escalation |",
            f"| `[blocked]` | Chain is blocked or in draft — missing preconditions or evidence |",
            f"| `[backfill]` | AI/proposal-engine inference without session corroboration — treat as hypothesis only |",
            "",
            "**Evidence states are never upranked by visual styling alone.**",
        ]
        return "\n".join(lines)

    def _section_footer(self, sd: Dict[str, Any]) -> str:
        """Report footer with generation metadata."""
        session_id = sd.get("session_id", "unknown")
        lines = [
            "---",
            "",
            f"*Report generated at {self._now_iso()}*",
            f"*Source session: `{session_id}`*",
            f"*Inference level: based on session findings + chain builder analysis*",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Mermaid generation
    # ------------------------------------------------------------------

    def _build_mermaid(self, graph: AttackPathGraph) -> str:
        """Build a Mermaid ``graph TD`` string from an AttackPathGraph."""
        lines = ["```mermaid", "graph TD", ""]

        # Style definitions
        lines.append("    classDef confirmed fill:#d4edda,stroke:#28a745,stroke-width:2px")
        lines.append("    classDef candidate fill:#fff3cd,stroke:#ffc107,stroke-width:2px,stroke-dasharray:5")
        lines.append("    classDef blocked fill:#f8d7da,stroke:#dc3545,stroke-width:2px,stroke-dasharray:3")
        lines.append("    classDef backfill fill:#e2e3e5,stroke:#6c757d,stroke-width:1px,stroke-dasharray:2")
        lines.append("")

        # Build node ID map
        node_ids: Dict[str, int] = {}
        for i, node in enumerate(graph.nodes):
            safe_id = self._mermaid_node_id(node.node_id, i)
            node_ids[node.node_id] = i
            style_class = _EVIDENCE_STYLE.get(node.evidence_state, "backfill")
            label = self._mermaid_label(node.display_label)
            lines.append(f"    {safe_id}[{label}]:::{style_class}")

        lines.append("")

        # Build edges (respect thresholds)
        edge_count = 0
        for edge in graph.edges:
            if edge_count >= self.max_mermaid_edges:
                lines.append(f"    %% {len(graph.edges) - edge_count} edges truncated (max_edges={self.max_mermaid_edges})")
                break
            src_idx = node_ids.get(edge.source_node_id)
            tgt_idx = node_ids.get(edge.target_node_id)
            if src_idx is not None and tgt_idx is not None:
                src_id = self._mermaid_node_id(edge.source_node_id, src_idx)
                tgt_id = self._mermaid_node_id(edge.target_node_id, tgt_idx)
                edge_label = edge.display_label or edge.edge_type
                style = _EVIDENCE_STYLE.get(edge.evidence_state, "backfill")
                link_style = "==>" if style == "confirmed" else "-->" if style == "candidate" else "-.->"
                lines.append(f"    {src_id} {link_style}|{edge_label}| {tgt_id}")
                edge_count += 1

        lines.append("```")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_chain_data(
        self, sd: Dict[str, Any]
    ) -> Tuple[List[Dict[str, Any]], AttackPathGraph]:
        """Extract chain findings and build graph from session data."""
        graph = self._build_attack_path_graph(sd)
        findings = extract_all_findings(sd)
        chain_findings = [
            f
            for f in findings
            if self._safe_dict(f.get("additional_info")).get("is_attack_chain")
        ]
        return chain_findings, graph

    def _rank_paths(
        self, chain_findings: List[Dict[str, Any]]
    ) -> List[Tuple[Dict[str, Any], float]]:
        """Rank chain findings by priority (evidence state, severity, confidence).

        Uses 5-axis scoring as specified in §3.1:
        evidence_state priority + severity + confidence + (future: asset_criticality, blast_radius)
        """
        scored: List[Tuple[Dict[str, Any], float]] = []
        for f in chain_findings:
            evidence = resolve_evidence_state(f)
            evidence_score = _EVIDENCE_PRIORITY.get(evidence, 3)
            severity = self._safe_str(f.get("severity"), "info").lower()
            severity_score = _SEVERITY_PRIORITY.get(severity, 4)
            confidence = float(f.get("confidence", 0.0))

            # Lower score = higher priority
            # confirmed(0) > candidate(1) > blocked(2) > backfill(3)
            # critical(0) > high(1) > medium(2) > low(3) > info(4)
            combined = evidence_score * 10 + severity_score - confidence
            scored.append((f, combined))

        scored.sort(key=lambda x: x[1])
        return scored

    def _format_path_detail(
        self, finding: Dict[str, Any], index: int, score: float
    ) -> List[str]:
        """Format a single attack path as a detail block."""
        lines: List[str] = []
        title = self._safe_str(finding.get("title"), "Untitled Path")
        finding_id = self._safe_str(finding.get("id"), "")
        severity = self._safe_str(finding.get("severity"), "")
        evidence_state = resolve_evidence_state(finding)
        confidence = finding.get("confidence", 0.0)
        additional = self._safe_dict(finding.get("additional_info"))
        decision_trace = self._safe_dict(additional.get("decision_trace"))
        business_impact = additional.get("business_impact_sentence", "")
        chain_details = additional.get("chain_details", "")
        matched_signals = self._safe_list(additional.get("matched_signals"))
        component_titles = self._safe_list(additional.get("component_titles"))
        excluded = ", ".join(
            self._safe_list(decision_trace.get("excluded_reasons"))
        )
        target_url = self._safe_str(
            finding.get("target_url") or finding.get("url"), ""
        )

        lines.append(f"### {index}. {title} {_EVIDENCE_BADGE.get(evidence_state, '')}")
        lines.append("")
        lines.append(
            f"| Property | Value |\n"
            f"|---|---|\n"
            f"| **Finding ID** | `{finding_id}` |\n"
            f"| **Evidence State** | {_EVIDENCE_BADGE.get(evidence_state, evidence_state)} |\n"
            f"| **Severity** | `{severity}` |\n"
            f"| **Confidence** | {confidence:.0%} |\n"
            f"| **Target URL** | `{target_url or 'N/A'}` |"
        )
        lines.append("")

        if business_impact:
            lines.append(f"**Business Impact:** {business_impact}")
            lines.append("")

        if matched_signals:
            lines.append(f"**Matched Signals:** {', '.join(matched_signals)}")
            lines.append("")

        if component_titles:
            lines.append("**Component Findings:**")
            for ct in component_titles:
                lines.append(f"- {ct}")
            lines.append("")

        if chain_details:
            lines.append(f"**Details:** {chain_details}")
            lines.append("")

        if excluded:
            lines.append(f"**Blocked Reason:** {excluded}")
            lines.append("")

        return lines

    def _derive_validation_hint(
        self, evidence_state: str, decision_trace: Dict[str, Any]
    ) -> str:
        """Derive a next-validation hint from evidence state and decision trace."""
        if evidence_state == EVIDENCE_STATE_CONFIRMED:
            return "Path confirmed — escalate to program owner"
        if evidence_state == EVIDENCE_STATE_BLOCKED:
            excluded = self._safe_list(decision_trace.get("excluded_reasons"))
            if excluded:
                return f"Unblock by addressing: {', '.join(excluded)}"
            return "Investigate why path is blocked"
        if evidence_state == EVIDENCE_STATE_CANDIDATE:
            return "Gather additional evidence to raise confidence above 0.8"
        return "Corroborate with session evidence before escalating"

    def _derive_validation_steps(
        self, chain_findings: List[Dict[str, Any]], sd: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """Derive prioritised next validation steps from chain findings."""
        steps: List[Dict[str, str]] = []

        for finding in chain_findings:
            evidence_state = resolve_evidence_state(finding)
            if evidence_state == EVIDENCE_STATE_CONFIRMED:
                continue  # Already confirmed, no validation needed

            additional = self._safe_dict(finding.get("additional_info"))
            decision_trace = self._safe_dict(additional.get("decision_trace"))
            excluded = self._safe_list(decision_trace.get("excluded_reasons"))

            title = self._safe_str(finding.get("title"), "Untitled")

            if evidence_state == EVIDENCE_STATE_BLOCKED:
                steps.append(
                    {
                        "action": f"Resolve blockers for chain",
                        "path_title": title,
                        "gain": "Unblocks a potentially critical attack path",
                        "unblocks": ", ".join(excluded) if excluded else "Unknown blocker",
                    }
                )
            elif evidence_state == EVIDENCE_STATE_CANDIDATE:
                steps.append(
                    {
                        "action": f"Gather additional evidence for chain",
                        "path_title": title,
                        "gain": "Raises confidence to confirm or falsify the path",
                        "unblocks": "Confidence below 0.8 threshold",
                    }
                )
            elif evidence_state == EVIDENCE_STATE_BACKFILL:
                steps.append(
                    {
                        "action": f"Verify AI-inferred chain with session corroboration",
                        "path_title": title,
                        "gain": "Confirms or rejects AI-generated hypothesis",
                        "unblocks": "AI inference without session evidence",
                    }
                )

        # Prioritise: blocked first (they gate other work), then candidate, then backfill
        state_order = {
            EVIDENCE_STATE_BLOCKED: 0,
            EVIDENCE_STATE_CANDIDATE: 1,
            EVIDENCE_STATE_BACKFILL: 2,
        }

        def _step_key(step: Dict[str, str]) -> int:
            # Infer state from action text
            if "blocker" in step["action"].lower() or "Resolve blocker" in step["action"]:
                return 0
            if "Gather additional evidence" in step["action"]:
                return 1
            return 2

        steps.sort(key=_step_key)
        return steps[: self.max_top_paths]

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _node_to_dict(node: AttackPathNode) -> Dict[str, Any]:
        return {
            "node_id": node.node_id,
            "display_label": node.display_label,
            "node_type": node.node_type,
            "evidence_state": node.evidence_state,
            "why_in_path": node.why_in_path,
            "source_refs": node.source_refs,
            "blocked_reason": node.blocked_reason,
            "next_validation_hint": node.next_validation_hint,
            "observed_at": node.observed_at,
            "inferred_after": node.inferred_after,
        }

    @staticmethod
    def _edge_to_dict(edge: AttackPathEdge) -> Dict[str, Any]:
        return {
            "edge_id": edge.edge_id,
            "source_node_id": edge.source_node_id,
            "target_node_id": edge.target_node_id,
            "edge_type": edge.edge_type,
            "display_label": edge.display_label,
            "evidence_state": edge.evidence_state,
            "why_in_path": edge.why_in_path,
            "source_refs": edge.source_refs,
        }

    # ------------------------------------------------------------------
    # General utilities (same pattern as other formatters)
    # ------------------------------------------------------------------

    @staticmethod
    def _now_iso() -> str:
        """Return current time as ISO 8601 string."""
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _now_jst() -> datetime:
        if ZoneInfo is not None:
            try:
                return datetime.now(ZoneInfo("Asia/Tokyo"))
            except Exception:
                pass
        return datetime.now(timezone(timedelta(hours=9)))

    @staticmethod
    def _timestamp_from_epoch(epoch: Any) -> Optional[str]:
        """Convert epoch float to ISO 8601, or None."""
        if epoch is None:
            return None
        try:
            return datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat()
        except (TypeError, ValueError, OSError):
            return None

    @staticmethod
    def _safe_get(d: Any, *keys: str, default: Any = None) -> Any:
        current = d
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key, default)
            else:
                return default
        return current

    @staticmethod
    def _safe_list(value: Any) -> List[Any]:
        if isinstance(value, list):
            return value
        return []

    @staticmethod
    def _safe_dict(value: Any) -> Dict[str, Any]:
        if isinstance(value, dict):
            return value
        return {}

    @staticmethod
    def _safe_str(value: Any, default: str = "") -> str:
        if value is None:
            return default
        return str(value)

    @staticmethod
    def _sanitise_id(raw: str) -> str:
        """Sanitise a string for use as a Mermaid node ID."""
        return (
            raw.replace("://", "_")
            .replace(":", "_")
            .replace("/", "_")
            .replace(".", "_")
            .replace("-", "_")
            .replace(" ", "_")
            .strip("_")
        )

    @staticmethod
    def _shorten_url(url: str) -> str:
        """Shorten a URL for display (strip query, keep path)."""
        if not url:
            return ""
        try:
            parsed = urlsplit(url)
            return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
        except Exception:
            return url

    @staticmethod
    def _mermaid_node_id(node_id: str, index: int) -> str:
        """Generate a safe Mermaid node identifier."""
        return f"n{index}"

    @staticmethod
    def _mermaid_label(text: str) -> str:
        """Escape a label for Mermaid (wrap in quotes, escape inner quotes)."""
        safe = text.replace('"', "'").replace("\n", " ").strip()
        if len(safe) > 60:
            safe = safe[:57] + "..."
        return f'"{safe}"'
