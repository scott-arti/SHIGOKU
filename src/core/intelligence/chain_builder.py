from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
import hashlib
import json
import logging
import time

from src.config import settings
from src.core.intelligence.chain_proposal import (
    ChainProposalEngine,
    LLMChainProposalEngine,
    NullChainProposalEngine,
)
from src.core.models.finding import Finding, Severity, VulnType


logger = logging.getLogger(__name__)
_DEFAULT_CHAIN_BUILDER: Optional["AttackChainBuilder"] = None


SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


@dataclass
class AttackChainRule:
    rule_id: str
    name: str
    description: str
    severity: str
    required_signals: list[str] = field(default_factory=list)
    min_components: int = 2
    same_target_only: bool = False
    recommended_followup: str = "escalate"
    preconditions: list[dict[str, Any]] = field(default_factory=list)
    required_evidence: list[str] = field(default_factory=list)
    falsification: list[str] = field(default_factory=list)
    dsl_version: int = 0
    industry: str = ""
    auth_model: str = ""
    surface: str = ""


@dataclass
class AttackChain:
    rule_id: str
    name: str
    description: str
    severity: str
    confidence: float
    component_findings: list[Finding] = field(default_factory=list)
    matched_signals: list[str] = field(default_factory=list)
    recommended_followup: str = "escalate"
    state: str = "confirmed"
    excluded_reasons: list[str] = field(default_factory=list)
    actor_path: list[str] = field(default_factory=list)
    business_impact_sentence: str = ""

    @property
    def chain_key(self) -> str:
        fingerprints = sorted(_finding_fingerprint(f) for f in self.component_findings)
        base = f"{self.rule_id}:{'|'.join(fingerprints)}"
        return hashlib.md5(base.encode("utf-8")).hexdigest()[:12]

    def to_finding(self) -> Finding:
        severity_enum = _to_severity(self.severity)
        primary = self.component_findings[0] if self.component_findings else None

        component_lines = []
        for f in self.component_findings:
            component_lines.append(
                f"- {f.title} ({getattr(getattr(f, 'severity', None), 'value', 'unknown')})"
            )

        details = (
            f"Attack chain inferred by rule '{self.rule_id}'.\n"
            f"Matched signals: {', '.join(self.matched_signals)}\n"
            f"Confidence: {self.confidence:.2f}\n\n"
            "Component findings:\n"
            + "\n".join(component_lines)
        )

        return Finding(
            vuln_type=VulnType.OTHER,
            severity=severity_enum,
            title=f"Attack Chain: {self.name}",
            description=self.description,
            target_url=primary.target_url if primary else "multiple",
            source_agent="chain_builder",
            confidence=self.confidence,
            recommended_followup=self.recommended_followup,
            tags=["attack_chain", self.rule_id],
            related_findings=[getattr(f, "id", "") for f in self.component_findings if getattr(f, "id", "")],
            additional_info={
                "is_attack_chain": True,
                "chain_key": self.chain_key,
                "chain_rule_id": self.rule_id,
                "matched_signals": self.matched_signals,
                "component_titles": [f.title for f in self.component_findings],
                "chain_details": details,
                "business_impact_sentence": self.business_impact_sentence or _build_business_impact_sentence(self),
                "decision_trace": {
                    "selected_rule_id": self.rule_id,
                    "final_state": self.state,
                    "excluded_reasons": list(self.excluded_reasons),
                    "actor_path": list(self.actor_path),
                },
            },
        )


class AttackChainBuilder:
    """
    Rule-based attack chain inference.

    - Loads rules from `data/attack_chain_rules.json`
    - Falls back to safe defaults when DB is missing/corrupted
    - Produces deterministic chain keys for deduplication
    """

    def __init__(
        self,
        rules_path: str = "data/attack_chain_rules.json",
        enforce_data_contract: Optional[bool] = None,
        program_memory_path: Optional[str] = None,
        program_memory_max_entries: int = 256,
        program_memory_ttl_seconds: int = 86400,
        proposal_engine: Optional[ChainProposalEngine] = None,
    ) -> None:
        self.rules_path = Path(rules_path)
        if enforce_data_contract is None:
            self.enforce_data_contract = False
        else:
            self.enforce_data_contract = enforce_data_contract
        self._rules_payload: dict[str, Any] = {}
        self._workflow_templates: dict[str, dict[str, Any]] = {}
        self._program_overrides: dict[str, dict[str, Any]] = {}
        self.rules = self._load_rules()
        self._negative_chain_memory: dict[tuple[str, str], dict[str, Any]] = {}
        self._program_memory_path = Path(program_memory_path) if program_memory_path else None
        self._program_memory_max_entries = max(1, int(program_memory_max_entries or 1))
        self._program_memory_ttl_seconds = max(1, int(program_memory_ttl_seconds or 1))
        self._program_memory_loaded = False
        self._program_memory_store: dict[str, dict[str, Any]] = {}
        self.proposal_engine: ChainProposalEngine = proposal_engine or NullChainProposalEngine()

    def analyze(self, findings: list[Finding]) -> list[AttackChain]:
        if not findings:
            return []

        # Exclude already-chained synthetic findings from rule matching input.
        base_findings = [f for f in findings if not _is_attack_chain_finding(f)]
        if self.enforce_data_contract:
            base_findings = [f for f in base_findings if self._validate_chain_contract(f)]
        if len(base_findings) < 2:
            return []

        chains: list[AttackChain] = []
        seen_keys: set[str] = set()

        for rule in self.rules:
            chain = self._build_chain_for_rule(rule, base_findings)
            if chain is None:
                continue
            if chain.chain_key in seen_keys:
                continue
            seen_keys.add(chain.chain_key)
            chains.append(chain)

        chains.sort(
            key=lambda c: (SEVERITY_RANK.get(c.severity, 0), c.confidence),
            reverse=True,
        )
        return chains

    def analyze_with_context(
        self,
        findings: list[Finding],
        runtime_context: Optional[dict[str, Any]] = None,
    ) -> list[Finding]:
        runtime_context = runtime_context or {}
        program_profile = self._normalize_program_profile(runtime_context.get("program_profile"))
        chains = self._select_contextual_chains(
            self.analyze(findings),
            program_profile=program_profile,
        )
        if not chains:
            return []

        actor_path = self._resolve_actor_path(runtime_context.get("actor_model"))
        resolved_workflow_template = self._resolve_workflow_template(program_profile)
        resolved_tactical_policy = self._resolve_tactical_policy(program_profile)
        results: list[Finding] = []
        for chain in chains:
            chain.actor_path = actor_path
            finding = chain.to_finding()
            info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
            finding.additional_info = info
            decision_trace = info.get("decision_trace")
            if not isinstance(decision_trace, dict):
                decision_trace = {}
                info["decision_trace"] = decision_trace
            decision_trace["program_profile"] = dict(program_profile)
            info["resolved_workflow_template"] = dict(resolved_workflow_template)
            info["resolved_tactical_policy"] = dict(resolved_tactical_policy)
            results.append(finding)
        return results

    def analyze_hybrid(
        self,
        findings: list[Finding],
        runtime_context: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        runtime_context = runtime_context or {}
        belief_state = self.update_belief_state(
            findings,
            previous_state=runtime_context.get("belief_state"),
        )
        heuristic_chains = self.analyze(findings)
        draft_candidates = [
            self._apply_feasibility_to_candidate(
                self._normalize_heuristic_chain(chain),
                findings,
                runtime_context=runtime_context,
            )
            for chain in heuristic_chains
        ]
        ai_candidates = self._normalize_ai_candidates(
            self.proposal_engine.propose(findings, runtime_context),
            findings,
        )
        ai_candidates = [
            self._apply_feasibility_to_candidate(candidate, findings, runtime_context=runtime_context)
            for candidate in ai_candidates
        ]
        seen_chain_keys = {candidate["chain_key"] for candidate in draft_candidates}
        for candidate in ai_candidates:
            if candidate["chain_key"] in seen_chain_keys:
                continue
            seen_chain_keys.add(candidate["chain_key"])
            draft_candidates.append(candidate)
        draft_candidates.sort(key=lambda item: float(item.get("priority_score", 0.0) or 0.0), reverse=True)
        proposal_skip_reason = getattr(self.proposal_engine, "last_skip_reason", None)
        return {
            "heuristic_chains": heuristic_chains,
            "draft_candidates": draft_candidates,
            "ai_candidates": ai_candidates,
            "proposal_skip_reason": proposal_skip_reason,
            "belief_state": belief_state,
        }

    def analyze_with_budget(
        self,
        findings: list[Finding],
        top_k: int = 5,
        timeout_ms: int = 100,
    ) -> dict[str, Any]:
        started_at = time.monotonic()
        complexity_score = max(1, len(findings)) * max(1, len(self.rules)) * 5
        should_fallback = timeout_ms <= complexity_score
        chains = self.analyze(findings)
        latency_ms = max(0.0, (time.monotonic() - started_at) * 1000.0)
        metrics = {
            "used_fallback_count": 1 if should_fallback else 0,
            "solver_timeout_count": 1 if should_fallback else 0,
            "avg_solver_latency_ms": round(latency_ms, 4),
            "p95_solver_latency_ms": round(latency_ms, 4),
        }
        if should_fallback:
            return {
                "chains": chains[: max(1, top_k)],
                "used_fallback": True,
                "timeouts": 1,
                "fallback_reason": "solver_timeout_budget_exceeded",
                "metrics": metrics,
            }
        return {
            "chains": chains[: max(1, top_k)],
            "used_fallback": False,
            "timeouts": 0,
            "fallback_reason": "",
            "metrics": metrics,
        }

    def evaluate_feasibility(
        self,
        candidate: dict[str, Any],
        findings: list[Finding],
        constraints: Optional[dict[str, Any]] = None,
        *,
        mode: str = "enforce",
    ) -> dict[str, Any]:
        candidate_copy = dict(candidate)
        selected_findings = self._resolve_candidate_findings(candidate_copy, findings)
        active_constraints = dict(constraints or {})
        failed_constraints: list[dict[str, Any]] = []
        excluded_reasons = list(candidate_copy.get("excluded_reasons", []))
        canonical_material = self._build_feasibility_canonical_material(candidate_copy, selected_findings)

        verdict = "pass"
        fallback_reason = ""
        used_fallback = False

        unsupported_reason = self._unsupported_constraint_reason(active_constraints)
        if unsupported_reason is not None:
            verdict = "draft"
            excluded_reasons.append(unsupported_reason)
            candidate_copy["state"] = "draft"
        else:
            for constraint_name, spec in active_constraints.items():
                issue = self._evaluate_single_constraint(
                    constraint_name,
                    dict(spec or {}),
                    selected_findings,
                )
                if issue is None:
                    continue
                if issue["reason"] not in excluded_reasons:
                    excluded_reasons.append(issue["reason"])
                failed_constraints.append(issue["detail"])
                issue_verdict = str(issue.get("verdict", "") or "")
                issue_state = str(issue.get("state", "") or "")
                if issue_verdict:
                    verdict = issue_verdict
                elif issue["reason"] == "feasibility:constraint_data_missing":
                    verdict = "blocked"
                else:
                    verdict = "blocked"
                candidate_copy["state"] = issue_state or ("blocked" if verdict == "blocked" else str(candidate_copy.get("state", "draft") or "draft"))
                if verdict in {"blocked", "draft"}:
                    break

        if mode == "shadow":
            candidate_copy["state"] = str(candidate.get("state", "draft") or "draft")

        trace = {
            "selected_rule_id": str(candidate_copy.get("rule_id", "")).strip(),
            "mode": str(mode or "enforce").strip().lower() or "enforce",
            "verdict": verdict,
            "failed_constraints": failed_constraints,
            "evidence_source": [detail["evidence_source"] for detail in failed_constraints],
            "used_fallback": used_fallback,
            "fallback_reason": fallback_reason,
            "canonical_material": canonical_material,
            "constraint_schema_version": "2026-06-02",
            "decision_trace_version": "2026-06-02",
        }

        candidate_copy["excluded_reasons"] = excluded_reasons
        decision_trace = dict(candidate_copy.get("decision_trace", {}) or {})
        decision_trace["feasibility"] = trace
        candidate_copy["decision_trace"] = decision_trace
        candidate_copy["failed_constraints"] = failed_constraints
        candidate_copy["verdict"] = verdict
        return candidate_copy

    def score_chain(self, chain: dict[str, Any]) -> dict[str, Any]:
        scored = dict(chain)
        matched_signals = _normalize_string_list(scored.get("matched_signals", []))
        exploitability_evidence = _normalize_string_list(scored.get("exploitability_evidence", []))
        reliability = _bounded_float(scored.get("foothold_reliability", 0.5), default=0.5)
        expected_attempts = max(1.0, _bounded_float(scored.get("expected_attempts_to_success", 1.0), default=1.0, upper=100.0))
        account_impact = _bounded_float(scored.get("account_impact", 0.5), default=0.5)
        asset_criticality = _bounded_float(scored.get("asset_criticality", 0.5), default=0.5)
        blast_radius = _bounded_float(scored.get("blast_radius", 0.5), default=0.5)
        assumption_penalty = self._assumption_penalty_for(scored)
        program_prior = _bounded_float(scored.get("program_prior", 0.0), default=0.0)
        goal_state_bonus = _bounded_float(scored.get("goal_state_bonus", 0.0), default=0.0, upper=1.0)

        confidence = min(
            0.99,
            0.35
            + (0.08 * len(set(matched_signals)))
            + (0.12 * len(set(exploitability_evidence)))
            + (0.25 * reliability),
        )
        impact_score = min(1.0, 0.25 + (0.3 * account_impact) + (0.25 * asset_criticality) + (0.2 * blast_radius))
        bounty_score = min(1.0, 0.2 + (0.3 * impact_score) + (0.2 * reliability) + (0.15 * len(set(exploitability_evidence))))
        attempt_penalty = min(0.6, (expected_attempts - 1.0) * 0.08)
        priority_score = max(
            0.0,
            (0.35 * confidence)
            + (0.30 * impact_score)
            + (0.20 * bounty_score)
            + (0.20 * reliability)
            + program_prior
            + goal_state_bonus
            - attempt_penalty
            - assumption_penalty,
        )

        scored.update(
            {
                "confidence": round(confidence, 4),
                "impact_score": round(impact_score, 4),
                "bounty_score": round(bounty_score, 4),
                "priority_score": round(priority_score, 4),
                "assumption_penalty": round(assumption_penalty, 4),
                "goal_state_bonus": round(goal_state_bonus, 4),
            }
        )
        return scored

    def rank_chains(self, chains: list[dict[str, Any]]) -> list[dict[str, Any]]:
        scored = [self.score_chain(chain) for chain in chains]
        return sorted(scored, key=lambda chain: chain.get("priority_score", 0.0), reverse=True)

    def evaluate_counterfactual(self, chain: dict[str, Any]) -> dict[str, Any]:
        path = [str(step).strip().lower() for step in chain.get("path", []) if str(step).strip()]
        if len(path) < 2:
            return {
                "critical_edge_identification": [],
                "counterfactual_penalty": 0.0,
            }

        critical_edge = (path[-2], path[-1])
        penalty = round(1.0 / max(1, len(path) - 1), 4)
        result = dict(chain)
        result.update(
            {
                "critical_edge_identification": [critical_edge],
                "counterfactual_penalty": penalty,
            }
        )
        return result

    def record_negative_chain(self, record: dict[str, Any]) -> None:
        rule_id = str(record.get("rule_id", "")).strip()
        fingerprint = str(record.get("component_fingerprint", "")).strip()
        if not rule_id or not fingerprint:
            return
        key = (rule_id, fingerprint)
        memory = self._negative_chain_memory.setdefault(
            key,
            {"failures": 0, "failure_reasons": set()},
        )
        memory["failures"] += 1
        reason = str(record.get("failure_reason", "")).strip()
        if reason:
            memory["failure_reasons"].add(reason)

    def remember_chain_outcome(self, program: str, rule_id: str, outcome: str) -> None:
        program_key = str(program).strip()
        rule_key = str(rule_id).strip()
        outcome_key = str(outcome).strip().lower()
        if not program_key or not rule_key or not outcome_key:
            return
        self._load_program_memory_if_needed()
        entry_key = self._program_memory_entry_key(program_key, rule_key)
        record = self._program_memory_store.setdefault(
            entry_key,
            {"success": 0, "failure": 0, "updated_at": 0, "key_hash": entry_key},
        )
        if outcome_key not in {"success", "failure"}:
            return
        record[outcome_key] += 1
        record["updated_at"] = time.time_ns()
        self._prune_program_memory()
        self._flush_program_memory()

    def rank_for_program(self, program: str, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        program_key = str(program).strip()
        self._load_program_memory_if_needed()
        self._prune_program_memory()
        enriched: list[dict[str, Any]] = []
        for candidate in candidates:
            item = dict(candidate)
            entry_key = self._program_memory_entry_key(program_key, str(item.get("rule_id", "")).strip())
            memory = self._program_memory_store.get(entry_key, {})
            successes = int(memory.get("success", 0))
            failures = int(memory.get("failure", 0))
            item["program_prior"] = max(-0.2, min(0.2, (successes - failures) * 0.1))
            enriched.append(item)
        return self.rank_chains(enriched)

    def _load_program_memory_if_needed(self) -> None:
        if self._program_memory_loaded:
            return
        self._program_memory_loaded = True
        if self._program_memory_path is None or not self._program_memory_path.exists():
            return
        try:
            raw = json.loads(self._program_memory_path.read_text(encoding="utf-8"))
        except Exception:
            logger.warning("Failed to load program memory store: %s", self._program_memory_path)
            return
        entries = raw.get("entries", []) if isinstance(raw, dict) else []
        if not isinstance(entries, list):
            return
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            key_hash = str(entry.get("key_hash", "")).strip()
            if not key_hash:
                continue
            self._program_memory_store[key_hash] = {
                "key_hash": key_hash,
                "success": int(entry.get("success", 0) or 0),
                "failure": int(entry.get("failure", 0) or 0),
                "updated_at": int(entry.get("updated_at", 0) or 0),
            }
        self._prune_program_memory()

    def _flush_program_memory(self) -> None:
        if self._program_memory_path is None:
            return
        self._program_memory_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "entries": sorted(
                self._program_memory_store.values(),
                key=lambda item: int(item.get("updated_at", 0) or 0),
                reverse=True,
            )[: self._program_memory_max_entries]
        }
        self._program_memory_path.write_text(
            json.dumps(payload, ensure_ascii=True, sort_keys=True),
            encoding="utf-8",
        )

    def _prune_program_memory(self) -> None:
        now = time.time_ns()
        ttl_cutoff = now - (self._program_memory_ttl_seconds * 1_000_000_000)
        active_items = [
            item
            for item in self._program_memory_store.values()
            if int(item.get("updated_at", 0) or 0) >= ttl_cutoff
        ]
        active_items.sort(key=lambda item: int(item.get("updated_at", 0) or 0), reverse=True)
        self._program_memory_store = {
            str(item.get("key_hash", "")): item
            for item in active_items[: self._program_memory_max_entries]
            if str(item.get("key_hash", "")).strip()
        }

    @staticmethod
    def _program_memory_entry_key(program: str, rule_id: str) -> str:
        normalized_program = str(program).strip().lower()
        normalized_rule = str(rule_id).strip().lower()
        material = f"{normalized_program}|{normalized_rule}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def promote_chain(self, chain: dict[str, Any]) -> dict[str, Any]:
        promoted = dict(chain)
        excluded_reasons = list(promoted.get("excluded_reasons", []))
        falsification_checks = _normalize_string_list(promoted.get("falsification_checks", []))

        if not falsification_checks:
            excluded_reasons.append("falsification_checks_missing")
            excluded_reasons.append("promotion:falsification_checks_missing")
        if not promoted.get("replay_evidence"):
            excluded_reasons.append("replay_evidence_missing")
            excluded_reasons.append("promotion:replay_evidence_missing")

        promoted["excluded_reasons"] = list(dict.fromkeys(excluded_reasons))
        promoted["state"] = "actionable" if not excluded_reasons else str(promoted.get("state", "confirmed") or "confirmed")
        return promoted

    def generate_falsification_checks(self, chain: dict[str, Any]) -> list[str]:
        path = [str(step).strip().lower() for step in chain.get("path", []) if str(step).strip()]
        assertions = dict(chain.get("goal_state_assertions", {}) or {})

        checks: list[str] = [
            "Re-login and repeat the terminal action to rule out stale-session artifacts.",
        ]
        if "csrf" in path:
            checks.append("Invalidate CSRF tokens and clear cache before replaying the state-changing request.")
        if assertions.get("privilege_changed"):
            checks.append("Verify the privilege change persists after re-login and is not UI-only state.")
        if assertions.get("cross_user_data_access"):
            checks.append("Repeat the flow against a second victim context to confirm cross-user boundary crossing.")
        if assertions.get("persistent_control"):
            checks.append("Expire the original session and confirm control persists with a fresh login.")
        return checks

    def build_canonical_report_payload(self, chain: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "title": str(chain.get("title", "")).strip(),
            "severity": str(chain.get("severity", "medium")).strip().lower() or "medium",
            "target_url": str(chain.get("target_url", "")).strip(),
            "business_impact_sentence": str(chain.get("business_impact_sentence", "")).strip(),
            "reproduction_steps": [
                str(step).strip() for step in chain.get("reproduction_steps", []) if str(step).strip()
            ],
            "boundary_cross_proof": str(chain.get("boundary_cross_proof", "")).strip(),
            "victim_impact": str(chain.get("victim_impact", "")).strip(),
            "remediation": str(chain.get("remediation", "")).strip(),
            "falsification_result": str(chain.get("falsification_result", "")).strip(),
            "goal_state_assertions": dict(chain.get("goal_state_assertions", {}) or {}),
            "minimal_success_runbook": [
                str(step).strip() for step in chain.get("minimal_success_runbook", []) if str(step).strip()
            ],
        }
        return payload

    def create_benchmark_manifest(self, contract: dict[str, Any]) -> dict[str, Any]:
        corpus = [str(item).strip() for item in contract.get("corpus", []) if str(item).strip()]
        headers = {
            str(key): str(value)
            for key, value in dict(contract.get("headers", {}) or {}).items()
            if str(key).strip()
        }
        manifest = {
            "corpus": corpus,
            "seed": int(contract.get("seed", 0) or 0),
            "headers": headers,
            "session_policy": str(contract.get("session_policy", "")).strip(),
            "label_snapshot": str(contract.get("label_snapshot", "")).strip(),
            "comparison_period": str(contract.get("comparison_period", "")).strip(),
        }
        material = json.dumps(manifest, ensure_ascii=True, sort_keys=True)
        manifest["manifest_id"] = f"bm-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:12]}"
        return manifest

    def evaluate_phase2_kpis(
        self,
        *,
        manifest: dict[str, Any],
        baseline_manifest: dict[str, Any],
        current_metrics: dict[str, Any],
        baseline_metrics: dict[str, Any],
    ) -> dict[str, Any]:
        manifest_id = str(manifest.get("manifest_id", "")).strip()
        baseline_id = str(baseline_manifest.get("manifest_id", "")).strip()
        if not manifest_id or not baseline_id or manifest_id != baseline_id:
            raise ValueError("manifest mismatch for KPI evaluation")

        current_valid_submission = _bounded_float(current_metrics.get("valid_submission_rate"), default=0.0)
        baseline_valid_submission = _bounded_float(baseline_metrics.get("valid_submission_rate"), default=0.0)
        current_bounty = float(current_metrics.get("expected_bounty_at_5", 0) or 0)
        baseline_bounty = float(baseline_metrics.get("expected_bounty_at_5", 0) or 0)
        current_cost = float(current_metrics.get("cost_per_actionable_chain", 0) or 0)
        baseline_cost = float(baseline_metrics.get("cost_per_actionable_chain", 0) or 0)

        go_no_go = {
            "valid_submission_rate": self._build_threshold_verdict(
                current=current_valid_submission,
                baseline=baseline_valid_submission,
                target_delta=0.20,
                direction="increase",
            ),
            "expected_bounty_at_5": self._build_threshold_verdict(
                current=current_bounty,
                baseline=baseline_bounty,
                target_delta=0.25,
                direction="increase",
            ),
            "cost_per_actionable_chain": self._build_threshold_verdict(
                current=current_cost,
                baseline=baseline_cost,
                target_delta=0.15,
                direction="decrease",
            ),
        }
        diagnostic = {
            key: {
                "current": float(current_metrics.get(key, 0) or 0),
                "baseline": float(baseline_metrics.get(key, 0) or 0),
                "delta": float(current_metrics.get(key, 0) or 0) - float(baseline_metrics.get(key, 0) or 0),
            }
            for key in sorted(set(current_metrics) | set(baseline_metrics))
            if key not in go_no_go
        }
        return {
            "manifest_id": manifest_id,
            "baseline_id": baseline_id,
            "go_no_go": go_no_go,
            "diagnostic": diagnostic,
        }

    def aggregate_phase2_metrics(self, samples: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        grouped: dict[str, list[float]] = {}
        for sample in samples:
            metric = str(sample.get("metric", "")).strip()
            if not metric:
                continue
            grouped.setdefault(metric, []).append(float(sample.get("value", 0.0) or 0.0))
        result: dict[str, dict[str, Any]] = {}
        for metric, values in grouped.items():
            result[metric] = {
                "count": len(values),
                "avg": round(sum(values) / len(values), 6),
                "min": round(min(values), 6),
                "max": round(max(values), 6),
            }
        return result

    @staticmethod
    def _build_threshold_verdict(
        *,
        current: float,
        baseline: float,
        target_delta: float,
        direction: str,
    ) -> dict[str, Any]:
        delta = current - baseline
        if direction == "increase":
            threshold_value = baseline * (1.0 + target_delta)
            passed = current >= threshold_value
        else:
            threshold_value = baseline * (1.0 - target_delta)
            passed = current <= threshold_value
        return {
            "current": round(current, 6),
            "baseline": round(baseline, 6),
            "delta": round(delta, 6),
            "target_delta": target_delta,
            "passed": passed,
        }

    def to_haddix_finding_dict(self, payload: dict[str, Any]) -> dict[str, Any]:
        canonical = self.build_canonical_report_payload(payload)
        description_parts = [
            canonical["business_impact_sentence"],
            canonical["boundary_cross_proof"],
            canonical["falsification_result"],
        ]
        return {
            "title": canonical["title"],
            "severity": canonical["severity"],
            "target_url": canonical["target_url"],
            "description": "\n\n".join(part for part in description_parts if part),
            "impact": canonical["victim_impact"],
            "steps_to_reproduce": canonical["reproduction_steps"],
            "recommendation": canonical["remediation"],
            "additional_info": {
                "business_impact_sentence": canonical["business_impact_sentence"],
                "boundary_cross_proof": canonical["boundary_cross_proof"],
                "falsification_result": canonical["falsification_result"],
                "goal_state_assertions": canonical["goal_state_assertions"],
                "minimal_success_runbook": canonical["minimal_success_runbook"],
            },
        }

    def validate_report_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        missing_fields: list[str] = []
        required_string_fields = [
            "title",
            "business_impact_sentence",
            "boundary_cross_proof",
            "victim_impact",
            "remediation",
            "falsification_result",
        ]
        for field_name in required_string_fields:
            value = str(payload.get(field_name, "")).strip()
            if not value:
                missing_fields.append(field_name)

        reproduction_steps = payload.get("reproduction_steps", [])
        if not isinstance(reproduction_steps, list) or not any(str(step).strip() for step in reproduction_steps):
            missing_fields.append("reproduction_steps")

        goal_state_assertions = payload.get("goal_state_assertions")
        if goal_state_assertions is not None and (
            not isinstance(goal_state_assertions, dict)
            or not any(bool(value) for value in goal_state_assertions.values())
        ):
            missing_fields.append("goal_state_assertions")

        return {
            "accepted": not missing_fields,
            "missing_fields": missing_fields,
        }

    def finalize_actionable_chain(
        self,
        findings: list[Finding],
        objective: str,
    ) -> dict[str, Any]:
        objective_key = str(objective).strip().lower()
        signals = {signal for finding in findings for signal in self._extract_signals(finding)}
        info_values = [
            getattr(finding, "additional_info", {}) or {}
            for finding in findings
            if isinstance(getattr(finding, "additional_info", {}), dict)
        ]
        primitives = {str(info.get("primitive", "")).strip().lower() for info in info_values if info.get("primitive")}

        goal_state_assertions = {
            "privilege_changed": objective_key in {"account_takeover", "privilege_escalation"} or "write" in primitives,
            "cross_user_data_access": "idor" in signals or any(info.get("tenant_boundary") for info in info_values),
            "persistent_control": bool(
                {"session_fixation", "jwt_alg_none", "secret_leak"} & signals
                or "pivot" in primitives
            ),
        }
        business_impact_sentence = self._build_objective_impact_sentence(objective_key, goal_state_assertions)

        runbook = [
            f"1. Confirm the {objective_key or 'chain'} path with the minimum evidence set.",
            "2. Re-run the final state-changing step and capture the resulting proof.",
            "3. Record falsification results and attach the business impact summary.",
        ]

        return {
            "objective": objective_key,
            "goal_state_assertions": goal_state_assertions,
            "minimal_success_runbook": runbook,
            "business_impact_sentence": business_impact_sentence,
        }

    def update_belief_state(
        self,
        findings: list[Finding],
        previous_state: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        base_findings = [f for f in findings if not _is_attack_chain_finding(f)]
        if self.enforce_data_contract:
            base_findings = [f for f in base_findings if self._validate_chain_contract(f)]

        observed_signals: set[str] = set()
        for finding in base_findings:
            observed_signals.update(self._extract_signals(finding))

        prior_candidates = {
            str(item.get("rule_id", "")).strip(): item
            for item in ((previous_state or {}).get("candidate_rules", []) or [])
            if isinstance(item, dict) and str(item.get("rule_id", "")).strip()
        }
        candidate_rules: list[dict[str, Any]] = []
        for rule in self.rules:
            required = [signal for signal in rule.required_signals if signal]
            if not required:
                continue
            observed = [signal for signal in required if signal in observed_signals]
            if not observed:
                continue
            missing = [signal for signal in required if signal not in observed_signals]
            if not missing:
                continue
            coverage = len(observed) / float(len(required))
            prior_confidence = _bounded_float(
                prior_candidates.get(rule.rule_id, {}).get("confidence", 0.0),
                default=0.0,
            )
            confidence = max(coverage, round((coverage * 0.7) + (prior_confidence * 0.3), 3))
            candidate_rules.append(
                {
                    "rule_id": rule.rule_id,
                    "state": "partial_observation",
                    "observed_signals": observed,
                    "missing_signals": missing,
                    "confidence": round(confidence, 3),
                    "next_best_probe": self._probe_for_missing_signal(missing[0]),
                }
            )

        candidate_rules.sort(key=lambda item: float(item.get("confidence", 0.0) or 0.0), reverse=True)
        previous_version = 0
        if isinstance(previous_state, dict):
            try:
                previous_version = int(previous_state.get("state_version", 0) or 0)
            except (TypeError, ValueError):
                previous_version = 0
        return {
            "state_version": previous_version + 1,
            "observed_signal_count": len(observed_signals),
            "candidate_rules": candidate_rules,
        }

    def select_chain_paths_with_mcts(
        self,
        candidates: list[dict[str, Any]],
        *,
        iterations: int = 32,
    ) -> list[dict[str, Any]]:
        total_iterations = max(1, int(iterations or 1))
        ranked: list[dict[str, Any]] = []
        candidate_count = max(1, len(candidates))
        for candidate in candidates:
            item = dict(candidate)
            success_probability = _bounded_float(item.get("success_probability", item.get("confidence", 0.5)), default=0.5)
            impact_score = _bounded_float(item.get("impact_score", 0.5), default=0.5)
            trial_cost = max(0.1, float(item.get("trial_cost", 1.0) or 1.0))
            visits = max(1, total_iterations // candidate_count)
            exploitation = (success_probability * impact_score) / trial_cost
            exploration = ((2.0 * _safe_log(total_iterations + 1)) / visits) ** 0.5
            item["mcts_score"] = round(exploitation + (0.05 * exploration), 6)
            item["visits"] = visits
            ranked.append(item)
        return sorted(ranked, key=lambda item: item.get("mcts_score", 0.0), reverse=True)

    def evaluate_preconditions(
        self,
        chain: dict[str, Any],
        *,
        threshold: float = 0.6,
    ) -> dict[str, Any]:
        preconditions = dict(chain.get("preconditions", {}) or {})
        verify_only: list[str] = []
        accepted: list[str] = []
        for name, probability in preconditions.items():
            bounded = _bounded_float(probability, default=0.0)
            if bounded < threshold:
                verify_only.append(str(name))
            else:
                accepted.append(str(name))
        return {
            "rule_id": str(chain.get("rule_id", "")).strip(),
            "verify_only": verify_only,
            "accepted": accepted,
            "threshold": threshold,
        }

    def run_step_ablation(self, chain: dict[str, Any]) -> dict[str, Any]:
        path = [str(step).strip().lower() for step in chain.get("path", []) if str(step).strip()]
        contributions = {
            str(step).strip().lower(): _bounded_float(value, default=0.0)
            for step, value in dict(chain.get("step_contributions", {}) or {}).items()
            if str(step).strip()
        }
        required_steps: list[str] = []
        ablation_table: list[dict[str, Any]] = []
        for index, step in enumerate(path):
            contribution = contributions.get(step, 0.0)
            removal_failure = contribution >= 0.5 or index == len(path) - 1
            if removal_failure:
                required_steps.append(step)
            ablation_table.append(
                {
                    "step": step,
                    "contribution": contribution,
                    "removal_breaks_chain": removal_failure,
                }
            )
        return {
            "required_steps": required_steps,
            "ablation_table": ablation_table,
            "ablation_passed": bool(required_steps),
        }

    def assess_fallback_independence(
        self,
        *,
        primary_path: list[str],
        fallback_paths: list[list[str]],
        failure_history: Optional[dict[str, int]] = None,
    ) -> dict[str, Any]:
        primary = {str(step).strip().lower() for step in primary_path if str(step).strip()}
        history = {str(key).strip().lower(): int(value or 0) for key, value in dict(failure_history or {}).items()}
        path_reports: list[dict[str, Any]] = []
        independent_fallbacks: list[list[str]] = []
        for fallback in fallback_paths:
            normalized = [str(step).strip().lower() for step in fallback if str(step).strip()]
            shared = primary & set(normalized)
            overlap_ratio = len(shared) / float(max(1, len(set(normalized))))
            history_penalty = sum(history.get(step, 0) for step in shared)
            independence_score = max(0.0, 1.0 - overlap_ratio - min(0.5, history_penalty * 0.1))
            report = {
                "path": normalized,
                "shared_steps": sorted(shared),
                "independence_score": round(independence_score, 4),
            }
            path_reports.append(report)
            if independence_score >= 0.5:
                independent_fallbacks.append(normalized)
        overall = round(
            sum(report["independence_score"] for report in path_reports) / max(1, len(path_reports)),
            4,
        )
        return {
            "fallback_reports": path_reports,
            "independent_fallbacks": independent_fallbacks,
            "independence_score": overall,
        }

    def optimize_race_execution(self, observations: list[dict[str, Any]]) -> dict[str, Any]:
        ranked: list[dict[str, Any]] = []
        for observation in observations:
            profile = dict(observation.get("profile", {}) or {})
            success_rate = _bounded_float(observation.get("success_rate", 0.0), default=0.0)
            latency_ms = max(1.0, float(observation.get("latency_ms", 1.0) or 1.0))
            burst = max(1.0, float(profile.get("burst", 1) or 1))
            score = success_rate + (burst * 0.05) - min(0.4, latency_ms / 1000.0)
            ranked.append(
                {
                    "profile": profile,
                    "success_rate": success_rate,
                    "latency_ms": latency_ms,
                    "score": round(score, 4),
                }
            )
        ranked.sort(key=lambda item: item["score"], reverse=True)
        selected = ranked[0]["profile"] if ranked else {}
        return {
            "selected_profile": selected,
            "ranked_profiles": ranked,
            "orchestrator_state": "optimized" if ranked else "empty",
        }

    def adapt_mutation_strategy(
        self,
        *,
        waf_signal: dict[str, Any],
        previous_results: list[dict[str, Any]],
        available_mutations: list[str],
    ) -> dict[str, Any]:
        status_code = int(waf_signal.get("status_code", 0) or 0)
        reaction = str(waf_signal.get("reaction", "")).strip().lower()
        previous_failures = {
            str(item.get("mutation_type", "")).strip().lower()
            for item in previous_results
            if not bool(item.get("success", False))
        }
        preferred: list[str] = []
        if status_code == 403 and reaction == "header_block":
            preferred = ["url_encode", "alt_path", "header_case"]
        elif status_code >= 500:
            preferred = ["alt_path", "url_encode", "header_case"]
        else:
            preferred = [str(item).strip().lower() for item in available_mutations if str(item).strip()]

        available = [str(item).strip().lower() for item in available_mutations if str(item).strip()]
        selected = [item for item in preferred if item in available and item not in previous_failures]
        selected.extend([item for item in available if item not in selected and item not in previous_failures])
        if not selected:
            selected = [item for item in available if item in previous_failures] or available
        return {
            "selected_mutations": selected,
            "strategy_state": "adaptive" if selected else "empty",
            "blocked_mutations": sorted(previous_failures),
        }

    def score_goal_state_strength(self, chain: dict[str, Any]) -> dict[str, Any]:
        assertions = dict(chain.get("goal_state_assertions", {}) or {})
        if assertions.get("persistent_control"):
            strength = "persistent_control"
            bonus = 0.35
        elif assertions.get("privilege_changed"):
            strength = "write"
            bonus = 0.22
        elif assertions.get("cross_user_data_access"):
            strength = "read_only"
            bonus = 0.12
        else:
            strength = "none"
            bonus = 0.0
        result = dict(chain)
        result.update(
            {
                "goal_state_strength": strength,
                "goal_state_bonus": round(bonus, 4),
            }
        )
        return result

    def transfer_program_memory_prior(
        self,
        *,
        program: str,
        program_profile: dict[str, Any],
        candidates: list[dict[str, Any]],
        neighbor_memories: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        profile = {
            "industry": str(program_profile.get("industry", "")).strip().lower(),
            "auth_model": str(program_profile.get("auth_model", "")).strip().lower(),
            "surface": str(program_profile.get("surface", "")).strip().lower(),
        }
        enriched: list[dict[str, Any]] = []
        for candidate in candidates:
            item = dict(candidate)
            rule_id = str(item.get("rule_id", "")).strip()
            prior = 0.0
            for memory in neighbor_memories:
                if str(memory.get("rule_id", "")).strip() != rule_id:
                    continue
                memory_profile = dict(memory.get("profile", {}) or {})
                matches = 0
                total = 0
                for key, value in profile.items():
                    if not value:
                        continue
                    total += 1
                    if str(memory_profile.get(key, "")).strip().lower() == value:
                        matches += 1
                similarity = (matches / float(total)) if total else 0.0
                successes = int(memory.get("success", 0) or 0)
                failures = int(memory.get("failure", 0) or 0)
                prior += similarity * ((successes - failures) * 0.1)
            item["program_prior"] = round(prior, 4)
            enriched.append(item)
        return self.rank_chains(enriched)

    def calibrate_success_probabilities(self, observations: list[dict[str, Any]]) -> dict[str, Any]:
        if not observations:
            return {"ece": 0.0, "calibrated_points": []}
        buckets = {
            "low": [],
            "high": [],
        }
        for observation in observations:
            predicted = _bounded_float(observation.get("predicted", 0.0), default=0.0)
            actual = 1.0 if bool(observation.get("actual", 0)) else 0.0
            bucket = "high" if predicted >= 0.5 else "low"
            buckets[bucket].append({"predicted": predicted, "actual": actual})

        calibrated_points: list[dict[str, Any]] = []
        ece = 0.0
        total = float(len(observations))
        for bucket_items in buckets.values():
            if not bucket_items:
                continue
            avg_pred = sum(item["predicted"] for item in bucket_items) / len(bucket_items)
            avg_actual = sum(item["actual"] for item in bucket_items) / len(bucket_items)
            ece += (len(bucket_items) / total) * abs(avg_pred - avg_actual)
            for item in bucket_items:
                calibrated_points.append(
                    {
                        "predicted": round(item["predicted"], 4),
                        "actual": int(item["actual"]),
                        "calibrated": round(avg_actual, 4),
                    }
                )
        calibrated_points.sort(key=lambda item: item["predicted"])
        return {
            "ece": round(ece, 6),
            "calibrated_points": calibrated_points,
        }

    def _normalize_heuristic_chain(self, chain: AttackChain) -> dict[str, Any]:
        candidate = {
            "rule_id": chain.rule_id,
            "chain_key": chain.chain_key,
            "matched_signals": list(chain.matched_signals),
            "exploitability_evidence": list(chain.matched_signals),
            "foothold_reliability": getattr(chain, "confidence", 0.0),
            "expected_attempts_to_success": 1,
            "account_impact": 0.5,
            "asset_criticality": 0.5,
            "blast_radius": 0.5,
            "origin": "heuristic",
            "state": "draft",
            "business_impact_sentence": chain.business_impact_sentence or _build_business_impact_sentence(chain),
            "component_findings": [getattr(finding, "id", "") for finding in chain.component_findings],
            "required_findings": [getattr(finding, "id", "") for finding in chain.component_findings],
            "recommended_probe": "",
            "missing_evidence": [],
        }
        scored = self.score_chain(candidate)
        scored["chain_key"] = chain.chain_key
        return scored

    def _apply_feasibility_to_candidate(
        self,
        candidate: dict[str, Any],
        findings: list[Finding],
        *,
        runtime_context: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        context = runtime_context or {}
        constraints = dict(context.get("feasibility_constraints", {}) or {})
        mode = str(
            context.get("feasibility_mode", context.get("mode", "enforce"))
        ).strip().lower() or "enforce"
        return self.evaluate_feasibility(candidate, findings, constraints, mode=mode)

    def _normalize_ai_candidates(
        self,
        candidates: list[dict[str, Any]],
        findings: list[Finding],
    ) -> list[dict[str, Any]]:
        indexed_findings = {getattr(finding, "id", ""): finding for finding in findings}
        normalized: list[dict[str, Any]] = []
        for candidate in candidates:
            required_finding_ids = [item for item in candidate.get("required_findings", []) if item in indexed_findings]
            selected_findings = [indexed_findings[item] for item in required_finding_ids]
            if not selected_findings:
                continue
            chain_key = self._ai_candidate_chain_key(
                objective=str(candidate.get("objective", "")).strip().lower(),
                path=[str(item).strip().lower() for item in candidate.get("path", []) if str(item).strip()],
                findings=selected_findings,
            )
            chain_data = {
                "rule_id": f"llm_proposal:{str(candidate.get('objective', '')).strip().lower() or 'unknown'}",
                "chain_key": chain_key,
                "matched_signals": [str(item).strip().lower() for item in candidate.get("path", []) if str(item).strip()],
                "exploitability_evidence": list(candidate.get("exploitability_evidence", [])),
                "foothold_reliability": candidate.get("foothold_reliability", 0.0),
                "expected_attempts_to_success": candidate.get("expected_attempts_to_success", 1),
                "account_impact": 0.5,
                "asset_criticality": 0.5,
                "blast_radius": 0.5,
                "origin": "ai_proposal",
                "state": "draft",
                "business_impact_sentence": str(candidate.get("business_impact_hypothesis", "")).strip(),
                "component_findings": [finding.id for finding in selected_findings],
                "required_findings": required_finding_ids,
                "recommended_probe": str(candidate.get("recommended_probe", "")).strip(),
                "missing_evidence": list(candidate.get("missing_evidence", [])),
                "reasoning_summary": str(candidate.get("reasoning_summary", "")).strip(),
            }
            scored = self.score_chain(chain_data)
            scored["chain_key"] = chain_key
            normalized.append(scored)
        return normalized

    def _ai_candidate_chain_key(
        self,
        *,
        objective: str,
        path: list[str],
        findings: list[Finding],
    ) -> str:
        fingerprints = sorted(_finding_fingerprint(finding) for finding in findings)
        material = json.dumps(
            {
                "objective": objective,
                "path": path,
                "fingerprints": fingerprints,
            },
            ensure_ascii=True,
            sort_keys=True,
        )
        return hashlib.md5(material.encode("utf-8")).hexdigest()[:12]

    def _probe_for_missing_signal(self, signal: str) -> str:
        mapping = {
            "open_redirect": "verify redirect replay or export handoff",
            "csrf": "verify state-changing cross-origin request path",
            "xss": "verify script execution sink on authenticated surface",
            "mass_assignment": "verify writable privileged fields in update flow",
            "os_command_injection": "verify command execution sink behind upload flow",
            "secret_leak": "verify internal token or config disclosure path",
            "ssrf": "verify internal fetch or callback primitive",
        }
        normalized = str(signal or "").strip().lower()
        return mapping.get(normalized, f"verify evidence for {normalized}")

    def _resolve_candidate_findings(
        self,
        candidate: dict[str, Any],
        findings: list[Finding],
    ) -> list[Finding]:
        indexed_findings = {getattr(finding, "id", ""): finding for finding in findings}
        selected_ids = [
            item
            for item in candidate.get("required_findings", candidate.get("component_findings", []))
            if item in indexed_findings
        ]
        if selected_ids:
            return [indexed_findings[item] for item in selected_ids]
        return list(findings)

    def _build_feasibility_canonical_material(
        self,
        candidate: dict[str, Any],
        findings: list[Finding],
    ) -> dict[str, Any]:
        signal_path = [
            str(item).strip().lower()
            for item in candidate.get("matched_signals", candidate.get("path", []))
            if str(item).strip()
        ]
        if not signal_path:
            signal_path = sorted(
                {
                    signal
                    for finding in findings
                    for signal in self._extract_signals(finding)
                    if signal
                }
            )
        return {
            "finding_fingerprints": sorted(_finding_fingerprint(finding) for finding in findings),
            "signal_path": sorted(dict.fromkeys(signal_path)),
        }

    def _unsupported_constraint_reason(self, constraints: dict[str, Any]) -> Optional[str]:
        for name, spec in constraints.items():
            normalized_name = str(name or "").strip().lower()
            normalized_spec = dict(spec or {})
            if normalized_name == "session_generation":
                supported_keys = {"requires_rotation"}
                if set(normalized_spec) - supported_keys:
                    return "feasibility:constraint_not_supported"
            elif normalized_name == "temporal_consistency":
                supported_keys = {
                    "require_matching_token_epoch",
                    "require_matching_csrf_epoch",
                    "allow_rotation_states",
                    "require_monotonic_session_generation",
                }
                if set(normalized_spec) - supported_keys:
                    return "feasibility:constraint_not_supported"
            elif normalized_name not in {"auth", "same_origin", "primitive", "asset_scope", "token_lifetime"}:
                return "feasibility:constraint_not_supported"
        return None

    def _evaluate_single_constraint(
        self,
        constraint_name: str,
        spec: dict[str, Any],
        findings: list[Finding],
    ) -> Optional[dict[str, Any]]:
        normalized_name = str(constraint_name or "").strip().lower()
        if normalized_name == "temporal_consistency":
            return self._evaluate_temporal_consistency(spec, findings)
        for finding in findings:
            info = getattr(finding, "additional_info", {}) or {}
            source_prefix = f"Finding.additional_info.{normalized_name}:{getattr(finding, 'id', '')}"
            if normalized_name == "auth":
                observed = str(info.get("auth_level", "")).strip().lower()
                if observed not in {"unauth", "user", "admin"}:
                    return self._constraint_issue(
                        normalized_name,
                        "feasibility:constraint_data_missing",
                        observed or None,
                        spec.get("required"),
                        source_prefix,
                    )
                expected = str(spec.get("required", "")).strip().lower()
                if expected and observed != expected:
                    return self._constraint_issue(normalized_name, "feasibility:constraint_failed", observed, expected, source_prefix)
            elif normalized_name == "same_origin":
                observed = info.get("same_origin")
                if not isinstance(observed, bool):
                    return self._constraint_issue(
                        normalized_name,
                        "feasibility:constraint_data_missing",
                        observed,
                        spec.get("required"),
                        source_prefix,
                    )
                expected = bool(spec.get("required"))
                if observed is not expected:
                    return self._constraint_issue(normalized_name, "feasibility:constraint_failed", observed, expected, source_prefix)
            elif normalized_name == "primitive":
                observed = str(info.get("primitive", "")).strip().lower()
                if observed not in {"read", "write", "exec", "pivot"}:
                    return self._constraint_issue(
                        normalized_name,
                        "feasibility:constraint_data_missing",
                        observed or None,
                        spec.get("required"),
                        source_prefix,
                    )
                expected = str(spec.get("required", "")).strip().lower()
                if expected and observed != expected:
                    return self._constraint_issue(normalized_name, "feasibility:constraint_failed", observed, expected, source_prefix)
            elif normalized_name == "asset_scope":
                observed = str(info.get("asset_scope", "")).strip().lower()
                if observed != "in_scope":
                    return self._constraint_issue(
                        normalized_name,
                        "feasibility:constraint_data_missing",
                        observed or None,
                        spec.get("required", "in_scope"),
                        source_prefix,
                    )
            elif normalized_name == "token_lifetime":
                observed = info.get("token_lifetime")
                if observed is None:
                    return self._constraint_issue(
                        normalized_name,
                        "feasibility:constraint_data_missing",
                        observed,
                        spec.get("max_seconds"),
                        source_prefix,
                    )
                try:
                    observed_seconds = float(observed)
                except (TypeError, ValueError):
                    return self._constraint_issue(
                        normalized_name,
                        "feasibility:constraint_data_missing",
                        observed,
                        spec.get("max_seconds"),
                        source_prefix,
                    )
                expected = float(spec.get("max_seconds", observed_seconds))
                if observed_seconds > expected:
                    return self._constraint_issue(normalized_name, "feasibility:constraint_failed", observed_seconds, expected, source_prefix)
            elif normalized_name == "session_generation":
                observed = info.get("session_generation")
                if observed is None:
                    return self._constraint_issue(
                        normalized_name,
                        "feasibility:constraint_data_missing",
                        observed,
                        spec.get("requires_rotation"),
                        source_prefix,
                    )
                expected = bool(spec.get("requires_rotation"))
                if bool(observed) is not expected:
                    return self._constraint_issue(normalized_name, "feasibility:constraint_failed", bool(observed), expected, source_prefix)
        return None

    def _evaluate_temporal_consistency(
        self,
        spec: dict[str, Any],
        findings: list[Finding],
    ) -> Optional[dict[str, Any]]:
        if not findings:
            return None

        normalized_spec = dict(spec or {})
        require_token_epoch = bool(normalized_spec.get("require_matching_token_epoch"))
        require_csrf_epoch = bool(normalized_spec.get("require_matching_csrf_epoch"))
        require_monotonic_generation = bool(normalized_spec.get("require_monotonic_session_generation"))
        allowed_rotation_states = {
            str(item).strip().lower()
            for item in normalized_spec.get("allow_rotation_states", [])
            if str(item).strip()
        }

        def info_of(finding: Finding) -> dict[str, Any]:
            info = getattr(finding, "additional_info", {}) or {}
            return info if isinstance(info, dict) else {}

        if require_token_epoch:
            token_epochs = [
                (finding, info_of(finding).get("token_epoch"))
                for finding in findings
            ]
            missing = [finding for finding, value in token_epochs if value in {None, ""}]
            if missing:
                finding = missing[0]
                return self._constraint_issue(
                    "temporal_consistency",
                    "temporal:metadata_missing",
                    None,
                    "token_epoch",
                    f"Finding.additional_info.token_epoch:{getattr(finding, 'id', '')}",
                    verdict="draft",
                    state="draft",
                )
            normalized_values = {str(value).strip() for _, value in token_epochs}
            if len(normalized_values) > 1:
                finding = token_epochs[0][0]
                return self._constraint_issue(
                    "temporal_consistency",
                    "temporal:epoch_mismatch",
                    sorted(normalized_values),
                    "all token_epoch values must match",
                    f"Finding.additional_info.token_epoch:{getattr(finding, 'id', '')}",
                    verdict="blocked",
                    state="blocked",
                )

        if require_csrf_epoch:
            csrf_epochs = [
                (finding, info_of(finding).get("csrf_epoch"))
                for finding in findings
            ]
            missing = [finding for finding, value in csrf_epochs if value in {None, ""}]
            if missing:
                finding = missing[0]
                return self._constraint_issue(
                    "temporal_consistency",
                    "temporal:metadata_missing",
                    None,
                    "csrf_epoch",
                    f"Finding.additional_info.csrf_epoch:{getattr(finding, 'id', '')}",
                    verdict="draft",
                    state="draft",
                )
            normalized_values = {str(value).strip() for _, value in csrf_epochs}
            if len(normalized_values) > 1:
                finding = csrf_epochs[0][0]
                return self._constraint_issue(
                    "temporal_consistency",
                    "temporal:epoch_mismatch",
                    sorted(normalized_values),
                    "all csrf_epoch values must match",
                    f"Finding.additional_info.csrf_epoch:{getattr(finding, 'id', '')}",
                    verdict="blocked",
                    state="blocked",
                )

        if allowed_rotation_states:
            for finding in findings:
                observed = str(info_of(finding).get("session_rotation_state", "")).strip().lower()
                if not observed:
                    return self._constraint_issue(
                        "temporal_consistency",
                        "temporal:metadata_missing",
                        None,
                        "session_rotation_state",
                        f"Finding.additional_info.session_rotation_state:{getattr(finding, 'id', '')}",
                        verdict="draft",
                        state="draft",
                    )
                if observed == "rotating":
                    return self._constraint_issue(
                        "temporal_consistency",
                        "temporal:rotation_in_progress",
                        observed,
                        sorted(allowed_rotation_states),
                        f"Finding.additional_info.session_rotation_state:{getattr(finding, 'id', '')}",
                        verdict="draft",
                        state="draft",
                    )
                if observed not in allowed_rotation_states:
                    return self._constraint_issue(
                        "temporal_consistency",
                        "temporal:rotation_state_conflict",
                        observed,
                        sorted(allowed_rotation_states),
                        f"Finding.additional_info.session_rotation_state:{getattr(finding, 'id', '')}",
                        verdict="blocked",
                        state="blocked",
                    )

        if require_monotonic_generation:
            generations: list[tuple[Finding, int]] = []
            for finding in findings:
                observed = info_of(finding).get("session_generation")
                if observed is None:
                    return self._constraint_issue(
                        "temporal_consistency",
                        "temporal:metadata_missing",
                        None,
                        "session_generation",
                        f"Finding.additional_info.session_generation:{getattr(finding, 'id', '')}",
                        verdict="draft",
                        state="draft",
                    )
                try:
                    generations.append((finding, int(observed)))
                except (TypeError, ValueError):
                    return self._constraint_issue(
                        "temporal_consistency",
                        "temporal:metadata_missing",
                        observed,
                        "session_generation(int)",
                        f"Finding.additional_info.session_generation:{getattr(finding, 'id', '')}",
                        verdict="draft",
                        state="draft",
                    )

            previous = generations[0][1]
            for finding, current in generations[1:]:
                if current < previous:
                    return self._constraint_issue(
                        "temporal_consistency",
                        "temporal:session_generation_rollback",
                        current,
                        f">= {previous}",
                        f"Finding.additional_info.session_generation:{getattr(finding, 'id', '')}",
                        verdict="blocked",
                        state="blocked",
                    )
                previous = current
        return None

    @staticmethod
    def _constraint_issue(
        constraint: str,
        reason: str,
        observed_value: Any,
        expected_value: Any,
        evidence_source: str,
        *,
        verdict: str = "blocked",
        state: str = "blocked",
    ) -> dict[str, Any]:
        detail = {
            "constraint": constraint,
            "observed_value": observed_value,
            "expected_value": expected_value,
            "evidence_source": evidence_source,
        }
        return {
            "reason": reason,
            "detail": detail,
            "verdict": verdict,
            "state": state,
        }

    def _build_chain_for_rule(self, rule: AttackChainRule, findings: list[Finding]) -> Optional[AttackChain]:
        if not rule.required_signals:
            return None

        scored = [(f, self._extract_signals(f)) for f in findings]
        selected: list[Finding] = []
        matched: list[str] = []

        for required in rule.required_signals:
            req = required.lower()
            match = next((f for f, signals in scored if req in signals), None)
            if match is None:
                return None
            matched.append(req)
            if match not in selected:
                selected.append(match)

        if len(selected) < max(2, int(rule.min_components)):
            return None

        if rule.same_target_only and not _same_target(selected):
            return None

        confidence = min(0.98, 0.5 + 0.1 * len(set(matched)) + 0.05 * len(selected))
        return AttackChain(
            rule_id=rule.rule_id,
            name=rule.name,
            description=rule.description,
            severity=rule.severity,
            confidence=round(confidence, 3),
            component_findings=selected,
            matched_signals=sorted(set(matched)),
            recommended_followup=rule.recommended_followup,
            business_impact_sentence=self._build_rule_impact_sentence(rule, selected),
        )

    def _normalize_program_profile(self, program_profile: Optional[dict[str, Any]]) -> dict[str, str]:
        profile = program_profile if isinstance(program_profile, dict) else {}
        return {
            "industry": str(profile.get("industry", "") or "").strip().lower(),
            "auth_model": str(profile.get("auth_model", "") or "").strip().lower(),
            "surface": str(profile.get("surface", "") or "").strip().lower(),
        }

    def _match_rule_to_program_profile(
        self,
        rule: AttackChainRule,
        program_profile: dict[str, str],
    ) -> int:
        constraints = {
            "industry": str(getattr(rule, "industry", "") or "").strip().lower(),
            "auth_model": str(getattr(rule, "auth_model", "") or "").strip().lower(),
            "surface": str(getattr(rule, "surface", "") or "").strip().lower(),
        }
        score = 0
        has_constraint = False
        for key, expected in constraints.items():
            if not expected:
                continue
            has_constraint = True
            if program_profile.get(key, "") != expected:
                return -1
            score += 1
        if has_constraint:
            return score
        return 0

    def _select_contextual_chains(
        self,
        chains: list[AttackChain],
        *,
        program_profile: dict[str, str],
    ) -> list[AttackChain]:
        if not chains:
            return []
        scored: list[tuple[int, AttackChain]] = []
        for chain in chains:
            rule = next((item for item in self.rules if item.rule_id == chain.rule_id), None)
            if rule is None:
                continue
            score = self._match_rule_to_program_profile(rule, program_profile)
            if score < 0:
                continue
            scored.append((score, chain))
        if not scored:
            return []
        max_score = max(score for score, _ in scored)
        selected = [chain for score, chain in scored if score == max_score]
        selected.sort(
            key=lambda c: (SEVERITY_RANK.get(c.severity, 0), c.confidence, c.rule_id),
            reverse=True,
        )
        return selected

    def _resolve_workflow_template(self, program_profile: dict[str, str]) -> dict[str, Any]:
        templates = self._workflow_templates if isinstance(self._workflow_templates, dict) else {}
        selected: dict[str, Any] = {}
        industry = program_profile.get("industry", "")
        if industry and isinstance(templates.get(industry), dict):
            selected = dict(templates.get(industry, {}))
            selected.setdefault("source", industry)
        elif isinstance(templates.get("common"), dict):
            selected = dict(templates.get("common", {}))
            selected.setdefault("source", "common")
        return {
            "template_id": str(selected.get("template_id", "") or ""),
            "steps": [str(step) for step in selected.get("steps", []) if str(step).strip()],
            "source": str(selected.get("source", "") or ""),
        }

    def _resolve_tactical_policy(self, program_profile: dict[str, str]) -> dict[str, Any]:
        overrides = self._program_overrides if isinstance(self._program_overrides, dict) else {}
        selected: dict[str, Any] = {}
        source = "config_default"
        industry = program_profile.get("industry", "")
        if industry and isinstance(overrides.get(industry), dict):
            selected = dict(overrides.get(industry, {}))
            source = "program_override"
        return {
            "allow": [str(item) for item in selected.get("allow", []) if str(item).strip()],
            "deny": [str(item) for item in selected.get("deny", []) if str(item).strip()],
            "per_asset_qps_cap": int(selected.get("per_asset_qps_cap", 0) or 0),
            "global_probe_budget": int(selected.get("global_probe_budget", 0) or 0),
            "source": source,
        }

    def _extract_signals(self, finding: Finding) -> set[str]:
        signals: set[str] = set()

        try:
            vt = finding.vuln_type.value if hasattr(finding.vuln_type, "value") else str(finding.vuln_type)
            signals.add(str(vt).lower())
        except Exception:
            pass

        text = " ".join(
            [
                str(getattr(finding, "title", "")),
                str(getattr(finding, "description", "")),
                str(getattr(finding, "impact", "")),
            ]
        ).lower()

        tags = [str(t).lower() for t in (getattr(finding, "tags", []) or [])]
        signals.update(tags)

        keyword_map = {
            "csrf": ["csrf", "cross-site request forgery", "cross site request forgery"],
            "xss": ["xss", "cross-site scripting", "cross site scripting"],
            "idor": ["idor", "insecure direct object reference", "broken access control"],
            "open_redirect": ["open redirect", "redirect uri", "redirect_uri"],
            "mass_assignment": ["mass assignment", "mass-assignment"],
            "file_upload": ["file upload", "unrestricted upload"],
            "os_command_injection": ["os command injection", "command injection", "remote code execution", "rce"],
            "ssrf": ["ssrf", "server-side request forgery", "server side request forgery"],
            "secret_leak": ["secret", "api key", "credential", "token leak"],
            "debug_enabled": ["debug", "stack trace", "traceback"],
        }
        for signal, keywords in keyword_map.items():
            if any(k in text for k in keywords):
                signals.add(signal)

        # Normalize enum aliases.
        if "sqli" in signals or "sql_injection" in signals:
            signals.add("sqli")
        if (
            "command_injection" in signals
            or "os_cmd_injection" in signals
            or "cmd_injection" in signals
        ):
            signals.add("os_command_injection")
        if "jwt_alg_none" in signals or "jwt_none_alg" in signals:
            signals.add("jwt_alg_none")

        return signals

    def _load_rules(self) -> list[AttackChainRule]:
        default_rules = _default_rules()
        path = self.rules_path
        self._rules_payload = {}
        self._workflow_templates = {}
        self._program_overrides = {}
        if not path.exists():
            return default_rules

        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._rules_payload = raw
                workflow_templates = raw.get("workflow_templates", {})
                if isinstance(workflow_templates, dict):
                    self._workflow_templates = {
                        str(key).strip().lower(): dict(value)
                        for key, value in workflow_templates.items()
                        if isinstance(value, dict)
                    }
                program_overrides = raw.get("program_overrides", {})
                if isinstance(program_overrides, dict):
                    self._program_overrides = {
                        str(key).strip().lower(): dict(value)
                        for key, value in program_overrides.items()
                        if isinstance(value, dict)
                    }
            records = raw.get("rules", raw)
            if not isinstance(records, list):
                return default_rules

            parsed: list[AttackChainRule] = []
            invalid_records = 0
            for r in records:
                if not isinstance(r, dict):
                    invalid_records += 1
                    continue
                required_signals = [str(s).lower() for s in r.get("required_signals", []) if s]
                if not required_signals:
                    required_signals = _derive_required_signals_from_dsl_rule(r)
                if not required_signals:
                    invalid_records += 1
                    continue
                parsed.append(
                    AttackChainRule(
                        rule_id=str(r.get("id", "")).strip() or "unnamed_rule",
                        name=str(r.get("name", "Unnamed Chain Rule")),
                        description=str(r.get("description", "")),
                        severity=str(r.get("severity", "high")).lower(),
                        required_signals=required_signals,
                        min_components=int(r.get("min_components", 2) or 2),
                        same_target_only=bool(r.get("same_target_only", False)),
                        recommended_followup=str(r.get("recommended_followup", "escalate")),
                        preconditions=_normalize_preconditions(r.get("preconditions", [])),
                        required_evidence=_normalize_string_list(r.get("required_evidence", [])),
                        falsification=_normalize_string_list(r.get("falsification", [])),
                        dsl_version=int(raw.get("dsl_version", 0) or 0),
                        industry=str(r.get("industry", "") or "").strip().lower(),
                        auth_model=str(r.get("auth_model", "") or "").strip().lower(),
                        surface=str(r.get("surface", "") or "").strip().lower(),
                    )
                )
            if not parsed and invalid_records:
                return default_rules
            return parsed or default_rules
        except (OSError, TypeError, ValueError) as exc:
            logger.warning("Attack chain rules load failed (%s): %s", path, exc)
            return default_rules

    def _validate_chain_contract(self, finding: Finding) -> bool:
        info = getattr(finding, "additional_info", {}) or {}
        if not isinstance(info, dict):
            return False

        auth_level = str(info.get("auth_level", "")).lower()
        user_interaction = str(info.get("user_interaction", "")).lower()
        primitive = str(info.get("primitive", "")).lower()
        asset_scope = str(info.get("asset_scope", "")).lower()
        same_origin = info.get("same_origin")

        if auth_level not in {"unauth", "user", "admin"}:
            return False
        if user_interaction not in {"none", "click", "social"}:
            return False
        if primitive not in {"read", "write", "exec", "pivot"}:
            return False
        if asset_scope != "in_scope":
            return False
        if not isinstance(same_origin, bool):
            return False
        return True

    def _assumption_penalty_for(self, chain: dict[str, Any]) -> float:
        rule_id = str(chain.get("rule_id", "")).strip()
        fingerprint = str(chain.get("component_fingerprint", "")).strip()
        if not rule_id or not fingerprint:
            return 0.0
        memory = self._negative_chain_memory.get((rule_id, fingerprint))
        if not memory:
            return 0.0
        failures = int(memory.get("failures", 0))
        return min(0.4, failures * 0.12)

    def _resolve_actor_path(self, actor_model: Any) -> list[str]:
        if not isinstance(actor_model, dict):
            return []
        actors = {str(actor).strip() for actor in actor_model.get("actors", []) if str(actor).strip()}
        transitions = actor_model.get("transitions", [])
        if not isinstance(transitions, list):
            return []

        actor_path: list[str] = []
        for transition in transitions:
            if not isinstance(transition, (list, tuple)) or len(transition) != 2:
                continue
            src = str(transition[0]).strip()
            dst = str(transition[1]).strip()
            if src not in actors or dst not in actors:
                continue
            if not actor_path:
                actor_path.append(src)
            if actor_path[-1] != src:
                actor_path.append(src)
            actor_path.append(dst)
        return actor_path

    def _build_rule_impact_sentence(self, rule: AttackChainRule, findings: list[Finding]) -> str:
        targets = sorted({str(getattr(finding, "target_url", "")).strip() for finding in findings if getattr(finding, "target_url", "")})
        target_label = targets[0] if len(targets) == 1 else "multiple in-scope targets"
        return (
            f"This chain can turn {', '.join(rule.required_signals)} into a reproducible {rule.name.lower()} "
            f"impact against {target_label}."
        )

    def _build_objective_impact_sentence(
        self,
        objective: str,
        goal_state_assertions: dict[str, bool],
    ) -> str:
        outcomes = [name for name, enabled in goal_state_assertions.items() if enabled]
        outcome_text = ", ".join(outcomes) if outcomes else "verified security impact"
        return f"The {objective or 'attack chain'} objective is actionable because it demonstrates {outcome_text}."


def get_chain_builder(
    rules_path: str = "data/attack_chain_rules.json",
    *,
    enforce_data_contract: Optional[bool] = None,
    proposal_engine: Optional[ChainProposalEngine] = None,
    llm_client: Any = None,
) -> AttackChainBuilder:
    global _DEFAULT_CHAIN_BUILDER
    if _DEFAULT_CHAIN_BUILDER is None:
        if enforce_data_contract is None:
            enforce_data_contract = bool(
                getattr(settings, "chain_builder_enforce_data_contract", True)
            )
        resolved_proposal_engine = proposal_engine
        if resolved_proposal_engine is None:
            chain_llm_enabled = bool(getattr(settings, "chain_llm_enabled", False))
            if chain_llm_enabled and llm_client is not None:
                model_name = str(getattr(settings, "chain_llm_model", "")).strip()
                if model_name:
                    resolved_proposal_engine = LLMChainProposalEngine.from_llm_client(
                        llm_client=llm_client,
                        model_name=model_name,
                        timeout_ms=int(getattr(settings, "chain_llm_timeout_ms", 1500) or 1500),
                        max_candidates=int(getattr(settings, "chain_llm_max_candidates", 3) or 3),
                        session_budget=int(getattr(settings, "chain_llm_budget_per_session", 5) or 5),
                    )
        if resolved_proposal_engine is None:
            resolved_proposal_engine = NullChainProposalEngine()
        _DEFAULT_CHAIN_BUILDER = AttackChainBuilder(
            rules_path=rules_path,
            enforce_data_contract=enforce_data_contract,
            program_memory_path=str(
                getattr(settings, "chain_builder_program_memory_path", "workspace/runtime/chain_program_memory.json")
                or "workspace/runtime/chain_program_memory.json"
            ),
            program_memory_max_entries=int(
                getattr(settings, "chain_builder_program_memory_max_entries", 256) or 256
            ),
            program_memory_ttl_seconds=int(
                getattr(settings, "chain_builder_program_memory_ttl_seconds", 86400) or 86400
            ),
            proposal_engine=resolved_proposal_engine,
        )
    return _DEFAULT_CHAIN_BUILDER


def _is_attack_chain_finding(finding: Finding) -> bool:
    try:
        tags = {str(t).lower() for t in (finding.tags or [])}
        if "attack_chain" in tags:
            return True
    except Exception:
        pass
    return bool(getattr(finding, "additional_info", {}).get("is_attack_chain", False))


def _finding_fingerprint(finding: Finding) -> str:
    vuln = str(getattr(getattr(finding, "vuln_type", ""), "value", "")).lower()
    target = str(getattr(finding, "target_url", "")).lower().rstrip("/")
    source = str(getattr(finding, "source_agent", "")).lower()
    return f"{vuln}|{target}|{source}"


def _safe_log(value: float) -> float:
    import math

    return math.log(max(1.0, float(value)))


def _bounded_float(value: Any, *, default: float, upper: float = 1.0) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(upper, numeric))


def _build_business_impact_sentence(chain: AttackChain) -> str:
    signals = ", ".join(chain.matched_signals) if chain.matched_signals else chain.rule_id
    return f"This attack chain is actionable because {signals} can be combined into a reproducible cross-boundary security impact."


def _derive_required_signals_from_dsl_rule(rule: dict[str, Any]) -> list[str]:
    transitions = rule.get("transitions", [])
    if not isinstance(transitions, list):
        return []

    required: set[str] = set()
    for transition in transitions:
        if not isinstance(transition, dict):
            continue
        src = str(transition.get("from", "")).strip().lower()
        dst = str(transition.get("to", "")).strip().lower()
        if src:
            required.add(src)
        if dst:
            required.add(dst)
    return sorted(required)


def _normalize_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v).strip() for v in value if str(v).strip()]


def _normalize_preconditions(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    for item in value:
        if isinstance(item, dict):
            result.append({str(k): v for k, v in item.items()})
    return result


def _same_target(findings: list[Finding]) -> bool:
    targets = {str(getattr(f, "target_url", "")).strip() for f in findings if getattr(f, "target_url", "")}
    return len(targets) <= 1


def _to_severity(value: str) -> Severity:
    normalized = str(value).strip().lower()
    if normalized == "critical":
        return Severity.CRITICAL
    if normalized == "high":
        return Severity.HIGH
    if normalized == "medium":
        return Severity.MEDIUM
    if normalized == "low":
        return Severity.LOW
    return Severity.INFO


def _default_rules() -> list[AttackChainRule]:
    return [
        AttackChainRule(
            rule_id="account_takeover_xss_csrf",
            name="Account Takeover via XSS + CSRF",
            description="XSS enables credential/session action triggering while CSRF protection gaps allow unauthorized state-changing requests.",
            severity="critical",
            required_signals=["xss", "csrf"],
            recommended_followup="report",
        ),
        AttackChainRule(
            rule_id="data_exfil_idor_redirect",
            name="Data Exfiltration via IDOR + Open Redirect",
            description="IDOR disclosure can be amplified via redirect-based flow confusion, enabling wider data exfiltration paths.",
            severity="high",
            required_signals=["idor", "open_redirect"],
            recommended_followup="escalate",
        ),
        AttackChainRule(
            rule_id="priv_esc_mass_assignment_csrf",
            name="Privilege Escalation via Mass Assignment + CSRF",
            description="Mass assignment combined with CSRF exposure can silently elevate user privileges.",
            severity="critical",
            required_signals=["mass_assignment", "csrf"],
            recommended_followup="report",
        ),
        AttackChainRule(
            rule_id="upload_to_rce",
            name="Remote Code Execution via File Upload + Command Injection",
            description="Weak upload validation plus command execution surface indicates probable RCE chain.",
            severity="critical",
            required_signals=["file_upload", "os_command_injection"],
            recommended_followup="report",
        ),
        AttackChainRule(
            rule_id="ssrf_to_secret_leak",
            name="Internal Secret Exposure via SSRF + Secret Leak",
            description="SSRF foothold combined with sensitive token disclosure can expose internal assets.",
            severity="high",
            required_signals=["ssrf", "secret_leak"],
            recommended_followup="escalate",
        ),
    ]
