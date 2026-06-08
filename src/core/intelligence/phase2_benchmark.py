from __future__ import annotations

from typing import Any

from src.core.models.finding import Finding, Severity, VulnType


_SEVERITY_BOUNTY = {
    "critical": 2500.0,
    "high": 1500.0,
    "medium": 500.0,
    "low": 100.0,
    "info": 0.0,
}


def build_phase2_benchmark_scenarios() -> list[dict[str, Any]]:
    return [
        {
            "corpus_id": "verify_chaining_flow:idor",
            "objective": "data_exfiltration",
            "platform": "hackerone",
            "boundary_cross_proof": "Object reference tampering returned another tenant's profile record with stable identifiers.",
            "victim_impact": "An attacker can read other users' records without authorization.",
            "remediation": "Enforce object-level authorization checks on the referenced resource before returning data.",
            "findings": [
                _make_contract_finding(
                    vuln_type=VulnType.IDOR,
                    severity=Severity.HIGH,
                    title="IDOR on user profile endpoint",
                    description="Insecure direct object reference allows cross-user data access.",
                    target_url="https://example.com/api/users/124",
                    primitive="read",
                ),
                _make_contract_finding(
                    vuln_type=VulnType.OPEN_REDIRECT,
                    severity=Severity.MEDIUM,
                    title="Open redirect in download handoff",
                    description="Redirect flow can be steered to attacker-controlled destinations after object lookup.",
                    target_url="https://example.com/download?next=/export",
                    primitive="pivot",
                ),
            ],
        },
        {
            "corpus_id": "verify_chaining_flow:secret_leak",
            "objective": "internal_pivot",
            "platform": "bugcrowd",
            "boundary_cross_proof": "The SSRF sink reached an internal metadata endpoint and exposed a bearer token from an in-scope secret.",
            "victim_impact": "An attacker can pivot to internal assets and extract secrets intended for backend services only.",
            "remediation": "Restrict server-side fetch destinations and rotate leaked credentials while removing the disclosure source.",
            "findings": [
                _make_contract_finding(
                    vuln_type=VulnType.SSRF,
                    severity=Severity.HIGH,
                    title="SSRF in webhook preview",
                    description="Server-side request forgery reaches internal network destinations.",
                    target_url="https://example.com/api/webhook/preview",
                    primitive="pivot",
                ),
                _make_contract_finding(
                    vuln_type=VulnType.SECRET_LEAK,
                    severity=Severity.CRITICAL,
                    title="Internal token leak in debug artifact",
                    description="A secret leak exposes a backend bearer token in an in-scope artifact.",
                    target_url="https://example.com/.well-known/debug/token.txt",
                    primitive="read",
                ),
            ],
        },
    ]


def build_current_submission_candidate(builder: Any, scenario: dict[str, Any], chain: Any) -> dict[str, Any]:
    findings = list(getattr(chain, "component_findings", []) or scenario.get("findings", []))
    finalized = builder.finalize_actionable_chain(findings, scenario.get("objective", "attack_chain"))
    falsification_checks = builder.generate_falsification_checks(
        {
            "path": list(getattr(chain, "matched_signals", []) or []),
            "goal_state_assertions": finalized["goal_state_assertions"],
        }
    )
    payload = builder.build_canonical_report_payload(
        {
            "title": f"Attack Chain: {getattr(chain, 'name', scenario['corpus_id'])}",
            "severity": getattr(chain, "severity", "high"),
            "target_url": getattr(findings[0], "target_url", "") if findings else "",
            "business_impact_sentence": finalized["business_impact_sentence"],
            "reproduction_steps": [
                f"1. Replay the {scenario['corpus_id']} foothold and confirm the initial primitive.",
                "2. Execute the minimal chain path and capture the cross-boundary proof.",
                "3. Re-run the terminal step after session refresh to confirm reproducibility.",
            ],
            "boundary_cross_proof": scenario["boundary_cross_proof"],
            "victim_impact": scenario["victim_impact"],
            "remediation": scenario["remediation"],
            "falsification_result": f"Executed {len(falsification_checks)} falsification checks without invalidating the chain.",
            "goal_state_assertions": finalized["goal_state_assertions"],
            "minimal_success_runbook": finalized["minimal_success_runbook"],
        }
    )
    return payload


def build_legacy_submission_candidate(scenario: dict[str, Any], finding: Finding) -> dict[str, Any]:
    return {
        "title": finding.title,
        "severity": getattr(getattr(finding, "severity", None), "value", "medium"),
        "target_url": getattr(finding, "target_url", ""),
        "description": getattr(finding, "description", ""),
        "reproduction_steps": list(getattr(finding, "reproduction_steps", []) or []),
        "impact": getattr(finding, "description", ""),
        "corpus_id": scenario["corpus_id"],
    }


def estimate_report_ready_bounty(payload: dict[str, Any], *, accepted: bool, confidence: float = 0.0) -> float:
    if not accepted:
        return 0.0
    severity = str(payload.get("severity", "medium")).strip().lower() or "medium"
    base = _SEVERITY_BOUNTY.get(severity, 500.0)
    bounded_confidence = max(0.0, min(1.0, float(confidence or 0.0)))
    return round(base * max(0.5, bounded_confidence), 2)


def manual_fix_units_from_validation(validation: dict[str, Any]) -> float:
    if validation.get("accepted"):
        return 1.0
    reason = str(validation.get("reason", "")).strip()
    if reason == "canonical_payload_required":
        return 5.0
    missing_fields = validation.get("missing_fields", [])
    if isinstance(missing_fields, list):
        return float(len(missing_fields))
    return 3.0


def summarize_phase2_profile_metrics(records: list[dict[str, Any]]) -> dict[str, float]:
    count = max(1, len(records))
    accepted = sum(1 for record in records if bool(record.get("accepted")))
    bounty_values = sorted(
        [float(record.get("estimated_bounty", 0.0) or 0.0) for record in records if float(record.get("estimated_bounty", 0.0) or 0.0) > 0],
        reverse=True,
    )
    top5_bounty = round(sum(bounty_values[:5]), 6)
    total_fix_units = sum(float(record.get("manual_fix_units", 0.0) or 0.0) for record in records)
    total_elapsed = sum(float(record.get("elapsed_seconds", 0.0) or 0.0) for record in records)
    audit_score = sum(float(record.get("audit_reproducible", 0.0) or 0.0) for record in records)
    return {
        "valid_submission_rate": round(accepted / count, 6),
        "expected_bounty_at_5": top5_bounty,
        "cost_per_actionable_chain": round(total_fix_units / count, 6),
        "precision_at_5": round(accepted / min(5, count), 6),
        "cpu_time_per_confirmed_chain": round(total_elapsed / count, 6),
        "audit_log_reproducibility": round(audit_score / count, 6),
    }


def evaluate_feasibility_solver_profiles(builder: Any) -> dict[str, Any]:
    feasible_scenario = build_phase2_benchmark_scenarios()[0]
    feasible_findings = feasible_scenario["findings"]
    feasible_candidate = {
        "rule_id": "data_exfil_idor_redirect",
        "chain_key": "feasible-candidate",
        "matched_signals": ["idor", "open_redirect"],
        "component_findings": [finding.id for finding in feasible_findings],
        "required_findings": [finding.id for finding in feasible_findings],
        "origin": "heuristic",
        "state": "draft",
        "excluded_reasons": [],
    }
    feasible_result = builder.evaluate_feasibility(
        feasible_candidate,
        feasible_findings,
        constraints={"same_origin": {"required": True}},
        mode="enforce",
    )

    budget_result = builder.analyze_with_budget(feasible_findings, top_k=3, timeout_ms=1)

    infeasible_findings = build_phase2_benchmark_scenarios()[1]["findings"]
    infeasible_findings[0].additional_info["same_origin"] = False
    infeasible_candidate = {
        "rule_id": "internal_pivot_secret_leak",
        "chain_key": "infeasible-candidate",
        "matched_signals": ["secret_leak", "ssrf"],
        "component_findings": [finding.id for finding in infeasible_findings],
        "required_findings": [finding.id for finding in infeasible_findings],
        "origin": "heuristic",
        "state": "draft",
        "excluded_reasons": [],
    }
    infeasible_result = builder.evaluate_feasibility(
        infeasible_candidate,
        infeasible_findings,
        constraints={"same_origin": {"required": True}},
        mode="enforce",
    )

    records = [
        {
            "scenario_id": "normal_feasible",
            "verdict": feasible_result["verdict"],
            "used_fallback": False,
            "latency_ms": 0.0,
        },
        {
            "scenario_id": "budget_fallback",
            "verdict": "pass" if budget_result["chains"] else "empty",
            "used_fallback": bool(budget_result["used_fallback"]),
            "latency_ms": float(budget_result["metrics"]["avg_solver_latency_ms"]),
        },
        {
            "scenario_id": "infeasible_constraints",
            "verdict": infeasible_result["verdict"],
            "used_fallback": False,
            "latency_ms": 0.0,
        },
    ]
    metrics = {
        "used_fallback_count": int(budget_result["metrics"]["used_fallback_count"]),
        "solver_timeout_count": int(budget_result["metrics"]["solver_timeout_count"]),
        "blocked_infeasible_count": 1 if infeasible_result["verdict"] == "blocked" else 0,
        "avg_solver_latency_ms": float(budget_result["metrics"]["avg_solver_latency_ms"]),
        "p95_solver_latency_ms": float(budget_result["metrics"]["p95_solver_latency_ms"]),
    }
    return {
        "records": records,
        "metrics": metrics,
    }


def _make_contract_finding(
    *,
    vuln_type: VulnType,
    severity: Severity,
    title: str,
    description: str,
    target_url: str,
    primitive: str,
) -> Finding:
    return Finding(
        vuln_type=vuln_type,
        severity=severity,
        title=title,
        description=description,
        target_url=target_url,
        source_agent="phase2_benchmark",
        confidence=0.85,
        tags=[vuln_type.value],
        additional_info={
            "auth_level": "user",
            "user_interaction": "none",
            "same_origin": True,
            "asset_scope": "in_scope",
            "primitive": primitive,
        },
    )
