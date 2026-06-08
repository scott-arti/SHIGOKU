from __future__ import annotations

import json
from pathlib import Path

from src.core.intelligence.chain_builder import AttackChainBuilder
from src.core.intelligence.phase3_benchmark import (
    build_phase3_benchmark_manifest,
    evaluate_phase3_profiles,
    summarize_phase3_gate_metrics,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_DIR = REPO_ROOT / "workspace" / "runtime"
MANIFEST_PATH = RUNTIME_DIR / "sgk-2026-0251_phase3_benchmark_manifest_current.json"
EVIDENCE_PATH = RUNTIME_DIR / "sgk-2026-0251_phase3_benchmark_evidence.json"


def main() -> int:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    builder = AttackChainBuilder(enforce_data_contract=True)
    manifest = build_phase3_benchmark_manifest(builder)
    evaluation = evaluate_phase3_profiles(builder)
    gate = summarize_phase3_gate_metrics(
        baseline_metrics=evaluation["baseline_metrics"],
        current_metrics=evaluation["current_metrics"],
    )

    MANIFEST_PATH.write_text(
        json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    evidence = {
        "manifest": manifest,
        "baseline_metrics": evaluation["baseline_metrics"],
        "current_metrics": evaluation["current_metrics"],
        "gate_result": gate,
        "records": evaluation["records"],
        "metric_notes": {
            "belief_state_accuracy": "top partial rule matches expected chain under observation loss",
            "mcts_success_rate": "selected branch matches expected best chain under success*impact/cost objective",
            "low_confidence_verification_reduction": "fraction of preconditions not re-verified because they already exceed threshold",
            "causal_intervention_validity": "ablation correctly identifies chain-breaking required steps",
            "fallback_independence_score": "average independence after penalizing overlap and shared failure history",
            "persistent_control_rate": "goal-state strength reaches persistent-control tier",
            "similarity_transfer_success_rate": "nearest-program memory transfer ranks expected rule first",
            "ece": "expected calibration error from calibrated probability buckets",
        },
    }
    EVIDENCE_PATH.write_text(
        json.dumps(evidence, ensure_ascii=True, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "manifest_id": manifest["manifest_id"],
                "baseline_metrics": evaluation["baseline_metrics"],
                "current_metrics": evaluation["current_metrics"],
                "gate_result": gate,
            },
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
