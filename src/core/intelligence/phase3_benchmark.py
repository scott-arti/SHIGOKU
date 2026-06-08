from __future__ import annotations

from typing import Any

from src.core.intelligence.chain_builder import AttackChainBuilder
from src.core.models.finding import Finding, Severity, VulnType


def build_phase3_benchmark_scenarios() -> list[dict[str, Any]]:
    return [
        {
            "scenario_id": "belief_state_partial",
            "type": "belief_state",
            "findings": [
                _make_finding(
                    vuln_type=VulnType.IDOR,
                    severity=Severity.HIGH,
                    title="Cross-user invoice IDOR",
                    description="Cross-user invoice read is possible.",
                    target_url="https://example.com/api/invoices/42",
                    primitive="read",
                )
            ],
            "expected_rule_id": "data_exfil_idor_redirect",
        },
        {
            "scenario_id": "mcts_branching",
            "type": "mcts",
            "candidates": [
                {
                    "rule_id": "chain_fast_high",
                    "success_probability": 0.78,
                    "impact_score": 0.91,
                    "trial_cost": 1.2,
                    "matched_signals": ["idor", "open_redirect"],
                    "exploitability_evidence": ["cross_user_impact"],
                    "foothold_reliability": 0.62,
                    "expected_attempts_to_success": 2.2,
                    "goal_state_assertions": {"cross_user_data_access": True},
                    "fallback_paths": [["idor", "token_reuse"], ["cache_poison", "idor"]],
                },
                {
                    "rule_id": "chain_slow_medium",
                    "success_probability": 0.66,
                    "impact_score": 0.72,
                    "trial_cost": 3.1,
                    "matched_signals": ["xss", "csrf", "oauth_redirect"],
                    "exploitability_evidence": ["state_change_success", "credential_reset"],
                    "foothold_reliability": 0.94,
                    "expected_attempts_to_success": 1.0,
                    "goal_state_assertions": {"privilege_changed": True},
                    "fallback_paths": [["xss", "oauth_redirect"]],
                },
            ],
            "expected_rule_id": "chain_fast_high",
        },
        {
            "scenario_id": "precondition_filter",
            "type": "preconditions",
            "chain": {
                "rule_id": "tenant_chain",
                "preconditions": {
                    "csrf_token_reusable": 0.42,
                    "victim_session_present": 0.88,
                    "redirect_followed": 0.35,
                },
            },
            "threshold": 0.6,
        },
        {
            "scenario_id": "causal_ablation",
            "type": "ablation",
            "chain": {
                "path": ["xss", "csrf", "password_change"],
                "step_contributions": {
                    "xss": 0.25,
                    "csrf": 0.55,
                    "password_change": 0.90,
                },
            },
        },
        {
            "scenario_id": "fallback_independence",
            "type": "fallback",
            "primary_path": ["idor", "redirect"],
            "fallback_paths": [["tenant_header", "token_reuse"], ["redirect", "cache_poison"]],
            "failure_history": {"redirect": 2},
        },
        {
            "scenario_id": "goal_state_strength",
            "type": "goal_state",
            "chain": {
                "goal_state_assertions": {
                    "cross_user_data_access": True,
                    "privilege_changed": True,
                    "persistent_control": True,
                }
            },
        },
        {
            "scenario_id": "similarity_transfer",
            "type": "similarity",
            "program": "target-program",
            "program_profile": {
                "industry": "fintech",
                "auth_model": "oauth",
                "surface": "graphql",
            },
            "candidates": [
                {"rule_id": "tenant_idor_chain"},
                {"rule_id": "generic_xss_chain"},
            ],
            "neighbor_memories": [
                {
                    "rule_id": "tenant_idor_chain",
                    "success": 3,
                    "failure": 0,
                    "profile": {
                        "industry": "fintech",
                        "auth_model": "oauth",
                        "surface": "rest",
                    },
                },
                {
                    "rule_id": "generic_xss_chain",
                    "success": 1,
                    "failure": 1,
                    "profile": {
                        "industry": "media",
                        "auth_model": "session",
                        "surface": "web",
                    },
                },
            ],
            "expected_rule_id": "tenant_idor_chain",
        },
        {
            "scenario_id": "probability_calibration",
            "type": "calibration",
            "observations": [
                {"predicted": 0.92, "actual": 1},
                {"predicted": 0.98, "actual": 1},
                {"predicted": 0.05, "actual": 0},
                {"predicted": 0.10, "actual": 0},
                {"predicted": 0.15, "actual": 0},
            ],
        },
    ]


def build_phase3_benchmark_manifest(builder: AttackChainBuilder) -> dict[str, Any]:
    return builder.create_benchmark_manifest(
        {
            "corpus": [item["scenario_id"] for item in build_phase3_benchmark_scenarios()],
            "seed": 20260602,
            "headers": {"X-Benchmark-Mode": "phase3-attack-chaining"},
            "session_policy": "phase3-shadow-compare",
            "label_snapshot": "sgk-2026-0251-phase3-current",
            "comparison_period": "2026-06-02-phase3-current",
        }
    )


def evaluate_phase3_profiles(builder: AttackChainBuilder) -> dict[str, Any]:
    scenarios = build_phase3_benchmark_scenarios()
    records: list[dict[str, Any]] = []

    belief_hits = 0
    belief_total = 0
    mcts_hits = 0
    heuristic_hits = 0
    mcts_total = 0
    low_confidence_reduction = 0.0
    causal_hits = 0
    causal_total = 0
    fallback_score_total = 0.0
    fallback_total = 0
    persistent_hits = 0
    persistent_total = 0
    similarity_hits = 0
    similarity_total = 0
    calibration_ece = 1.0

    for scenario in scenarios:
        stype = scenario["type"]
        if stype == "belief_state":
            state = builder.update_belief_state(scenario["findings"])
            candidate_rules = state.get("candidate_rules", [])
            top = candidate_rules[0] if candidate_rules else {}
            hit = top.get("rule_id") == scenario["expected_rule_id"]
            belief_total += 1
            if hit:
                belief_hits += 1
            records.append(
                {
                    "scenario_id": scenario["scenario_id"],
                    "baseline": 0.0,
                    "current": 1.0 if hit else 0.0,
                }
            )
        elif stype == "mcts":
            ranked = builder.select_chain_paths_with_mcts(scenario["candidates"], iterations=24)
            heuristic_ranked = builder.rank_chains(scenario["candidates"])
            mcts_hit = bool(ranked) and ranked[0].get("rule_id") == scenario["expected_rule_id"]
            heuristic_hit = bool(heuristic_ranked) and heuristic_ranked[0].get("rule_id") == scenario["expected_rule_id"]
            mcts_total += 1
            if mcts_hit:
                mcts_hits += 1
            if heuristic_hit:
                heuristic_hits += 1
            records.append(
                {
                    "scenario_id": scenario["scenario_id"],
                    "baseline": 1.0 if heuristic_hit else 0.0,
                    "current": 1.0 if mcts_hit else 0.0,
                }
            )
        elif stype == "preconditions":
            result = builder.evaluate_preconditions(scenario["chain"], threshold=scenario["threshold"])
            total = max(1, len(scenario["chain"]["preconditions"]))
            low_confidence_reduction = 1.0 - (len(result["verify_only"]) / float(total))
            records.append(
                {
                    "scenario_id": scenario["scenario_id"],
                    "baseline": 0.0,
                    "current": low_confidence_reduction,
                }
            )
        elif stype == "ablation":
            result = builder.run_step_ablation(scenario["chain"])
            causal_total += 1
            passed = bool(result.get("ablation_passed"))
            if passed:
                causal_hits += 1
            records.append(
                {
                    "scenario_id": scenario["scenario_id"],
                    "baseline": 0.0,
                    "current": 1.0 if passed else 0.0,
                }
            )
        elif stype == "fallback":
            result = builder.assess_fallback_independence(
                primary_path=scenario["primary_path"],
                fallback_paths=scenario["fallback_paths"],
                failure_history=scenario["failure_history"],
            )
            fallback_total += 1
            score = float(result.get("independence_score", 0.0) or 0.0)
            fallback_score_total += score
            records.append(
                {
                    "scenario_id": scenario["scenario_id"],
                    "baseline": 0.25,
                    "current": score,
                }
            )
        elif stype == "goal_state":
            result = builder.score_goal_state_strength(scenario["chain"])
            persistent_total += 1
            hit = result.get("goal_state_strength") == "persistent_control"
            if hit:
                persistent_hits += 1
            records.append(
                {
                    "scenario_id": scenario["scenario_id"],
                    "baseline": 0.0,
                    "current": 1.0 if hit else 0.0,
                }
            )
        elif stype == "similarity":
            ranked = builder.transfer_program_memory_prior(
                program=scenario["program"],
                program_profile=scenario["program_profile"],
                candidates=scenario["candidates"],
                neighbor_memories=scenario["neighbor_memories"],
            )
            similarity_total += 1
            hit = bool(ranked) and ranked[0].get("rule_id") == scenario["expected_rule_id"]
            if hit:
                similarity_hits += 1
            records.append(
                {
                    "scenario_id": scenario["scenario_id"],
                    "baseline": 0.0,
                    "current": 1.0 if hit else 0.0,
                }
            )
        elif stype == "calibration":
            result = builder.calibrate_success_probabilities(scenario["observations"])
            calibration_ece = float(result.get("ece", 1.0) or 1.0)
            records.append(
                {
                    "scenario_id": scenario["scenario_id"],
                    "baseline": 1.0,
                    "current": calibration_ece,
                }
            )

    baseline_metrics = {
        "belief_state_accuracy": 0.0,
        "mcts_success_rate": round(heuristic_hits / max(1, mcts_total), 6),
        "low_confidence_verification_reduction": 0.0,
        "causal_intervention_validity": 0.0,
        "fallback_independence_score": 0.25,
        "persistent_control_rate": 0.0,
        "similarity_transfer_success_rate": 0.0,
        "ece": 1.0,
    }
    current_metrics = {
        "belief_state_accuracy": round(belief_hits / max(1, belief_total), 6),
        "mcts_success_rate": round(mcts_hits / max(1, mcts_total), 6),
        "heuristic_success_rate": round(heuristic_hits / max(1, mcts_total), 6),
        "low_confidence_verification_reduction": round(low_confidence_reduction, 6),
        "causal_intervention_validity": round(causal_hits / max(1, causal_total), 6),
        "fallback_independence_score": round(fallback_score_total / max(1, fallback_total), 6),
        "persistent_control_rate": round(persistent_hits / max(1, persistent_total), 6),
        "similarity_transfer_success_rate": round(similarity_hits / max(1, similarity_total), 6),
        "ece": round(calibration_ece, 6),
    }
    return {
        "baseline_metrics": baseline_metrics,
        "current_metrics": current_metrics,
        "records": records,
    }


def summarize_phase3_gate_metrics(
    *,
    baseline_metrics: dict[str, Any],
    current_metrics: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    mcts_delta = float(current_metrics.get("mcts_success_rate", 0.0) or 0.0) - float(
        baseline_metrics.get("mcts_success_rate", 0.0) or 0.0
    )
    fallback_delta = float(current_metrics.get("fallback_independence_score", 0.0) or 0.0) - float(
        baseline_metrics.get("fallback_independence_score", 0.0) or 0.0
    )
    causal_current = float(current_metrics.get("causal_intervention_validity", 0.0) or 0.0)
    ece_current = float(current_metrics.get("ece", 1.0) or 1.0)
    return {
        "mcts_success_rate_improvement": {
            "current": round(float(current_metrics.get("mcts_success_rate", 0.0) or 0.0), 6),
            "baseline": round(float(baseline_metrics.get("mcts_success_rate", 0.0) or 0.0), 6),
            "delta": round(mcts_delta, 6),
            "passed": mcts_delta >= 0.15,
        },
        "ece": {
            "current": round(ece_current, 6),
            "threshold": 0.08,
            "passed": ece_current <= 0.08,
        },
        "causal_intervention_validity": {
            "current": round(causal_current, 6),
            "threshold": 0.85,
            "passed": causal_current >= 0.85,
        },
        "fallback_independence_gain": {
            "current": round(float(current_metrics.get("fallback_independence_score", 0.0) or 0.0), 6),
            "baseline": round(float(baseline_metrics.get("fallback_independence_score", 0.0) or 0.0), 6),
            "delta": round(fallback_delta, 6),
            "passed": fallback_delta >= 0.20,
        },
    }


def _make_finding(
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
        source_agent="phase3_benchmark",
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
