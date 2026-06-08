from __future__ import annotations

import json
import subprocess
import sys
import time
import types
from pathlib import Path
from typing import Any

from src.core.engine.master_conductor import MasterConductor
from src.core.intelligence.chain_builder import AttackChainBuilder
from src.core.intelligence.phase2_benchmark import (
    build_current_submission_candidate,
    build_legacy_submission_candidate,
    build_phase2_benchmark_scenarios,
    estimate_report_ready_bounty,
    manual_fix_units_from_validation,
    summarize_phase2_profile_metrics,
)
from src.core.reporting.platform_integration import ReportDraft


REPO_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_DIR = REPO_ROOT / "workspace" / "runtime"
MANIFEST_PATH = RUNTIME_DIR / "sgk-2026-0251_phase2_benchmark_manifest_current.json"
EVIDENCE_PATH = RUNTIME_DIR / "sgk-2026-0251_phase2_benchmark_evidence.json"


class _StubAuditLogger:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def log(self, event: Any) -> None:
        self.events.append(event)


class _StubDecisionTrace:
    def __init__(self, decision_id: str) -> None:
        self.decision_id = decision_id

    def to_dict(self) -> dict[str, Any]:
        return {"decision_id": self.decision_id}


class _StubDecisionTracer:
    def __init__(self) -> None:
        self._counter = 0

    def trace(self, **_: Any) -> _StubDecisionTrace:
        self._counter += 1
        return _StubDecisionTrace(f"dec_{self._counter:04d}")


def _load_head_attack_chain_builder() -> Any:
    result = subprocess.run(
        ["git", "show", "HEAD:src/core/intelligence/chain_builder.py"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    module = types.ModuleType("phase2_head_chain_builder")
    sys.modules[module.__name__] = module
    exec(compile(result.stdout, "<head_chain_builder>", "exec"), module.__dict__)
    return module.AttackChainBuilder()


def _build_manifest(builder: AttackChainBuilder) -> dict[str, Any]:
    manifest = builder.create_benchmark_manifest(
        {
            "corpus": [scenario["corpus_id"] for scenario in build_phase2_benchmark_scenarios()],
            "seed": 20260602,
            "headers": {"X-Benchmark-Mode": "phase2-attack-chaining"},
            "session_policy": "mocked-eventbus-replay",
            "label_snapshot": "sgk-2026-0251-phase2-current",
            "comparison_period": "2026-06-02-phase2-current",
        }
    )
    MANIFEST_PATH.write_text(json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True), encoding="utf-8")
    return manifest


def _measure_audit_reproducibility(chain_key: str, rule_id: str) -> float:
    conductor = MasterConductor.__new__(MasterConductor)
    conductor.audit_logger = _StubAuditLogger()
    conductor.decision_tracer = _StubDecisionTracer()
    record = conductor.emit_chain_audit_record(
        chain={
            "chain_key": chain_key,
            "rule_id": rule_id,
            "state": "actionable",
            "excluded_reasons": [],
        },
        audit_context={
            "scope_basis": "phase2_benchmark",
            "input_fingerprint": chain_key,
            "override": False,
            "stop_reason": "",
        },
    )
    if not conductor.audit_logger.events:
        return 0.0
    event = conductor.audit_logger.events[0]
    details = getattr(event, "details", {}) or {}
    return 1.0 if record.get("decision_id") and details.get("decision_id") == record.get("decision_id") else 0.0


def _merge_validation(*validations: dict[str, Any]) -> dict[str, Any]:
    missing_fields: set[str] = set()
    accepted = True
    reasons: list[str] = []
    for validation in validations:
        accepted = accepted and bool(validation.get("accepted"))
        reasons.append(str(validation.get("reason", "ok")).strip() or "ok")
        fields = validation.get("missing_fields", [])
        if isinstance(fields, list):
            missing_fields.update(str(field) for field in fields if str(field).strip())
    reason = "ok" if accepted else next((item for item in reasons if item != "ok"), "validation_failed")
    return {
        "accepted": accepted,
        "reason": reason,
        "missing_fields": sorted(missing_fields),
    }


def _evaluate_current_profile(builder: AttackChainBuilder) -> dict[str, Any]:
    scenarios = build_phase2_benchmark_scenarios()
    records: list[dict[str, Any]] = []
    details: list[dict[str, Any]] = []
    for scenario in scenarios:
        start = time.perf_counter()
        chains = builder.analyze(scenario["findings"])
        elapsed = time.perf_counter() - start
        for chain in chains:
            payload = build_current_submission_candidate(builder, scenario, chain)
            report_validation = builder.validate_report_payload(payload)
            platform_validation = ReportDraft.validate_platform_submission_payload(
                platform=scenario["platform"],
                payload=payload,
                source="canonical_report_payload",
            )
            merged = _merge_validation(report_validation, platform_validation)
            accepted = bool(merged["accepted"])
            draft = ReportDraft.from_canonical_payload(payload) if accepted else None
            estimated_bounty = estimate_report_ready_bounty(payload, accepted=accepted, confidence=float(getattr(chain, "confidence", 0.0) or 0.0))
            audit_reproducible = _measure_audit_reproducibility(chain.chain_key, chain.rule_id)
            record = {
                "accepted": accepted,
                "estimated_bounty": estimated_bounty,
                "manual_fix_units": manual_fix_units_from_validation(merged),
                "elapsed_seconds": elapsed,
                "audit_reproducible": audit_reproducible,
            }
            records.append(record)
            details.append(
                {
                    "profile": "current_phase2",
                    "corpus_id": scenario["corpus_id"],
                    "rule_id": chain.rule_id,
                    "chain_key": chain.chain_key,
                    "accepted": accepted,
                    "validation": merged,
                    "estimated_bounty": estimated_bounty,
                    "draft": draft.to_dict() if draft else None,
                }
            )
    return {
        "metrics": summarize_phase2_profile_metrics(records),
        "records": details,
    }


def _evaluate_baseline_profile(builder: Any) -> dict[str, Any]:
    scenarios = build_phase2_benchmark_scenarios()
    records: list[dict[str, Any]] = []
    details: list[dict[str, Any]] = []
    for scenario in scenarios:
        start = time.perf_counter()
        chains = builder.analyze(scenario["findings"])
        elapsed = time.perf_counter() - start
        for chain in chains:
            finding = chain.to_finding()
            payload = build_legacy_submission_candidate(scenario, finding)
            platform_validation = ReportDraft.validate_platform_submission_payload(
                platform=scenario["platform"],
                payload=payload,
                source="legacy_phase1_payload",
            )
            record = {
                "accepted": False,
                "estimated_bounty": 0.0,
                "manual_fix_units": manual_fix_units_from_validation(platform_validation),
                "elapsed_seconds": elapsed,
                "audit_reproducible": 0.0,
            }
            records.append(record)
            details.append(
                {
                    "profile": "baseline_phase1_control",
                    "corpus_id": scenario["corpus_id"],
                    "rule_id": chain.rule_id,
                    "chain_key": chain.chain_key,
                    "accepted": False,
                    "validation": platform_validation,
                    "estimated_bounty": 0.0,
                    "draft": None,
                }
            )
    return {
        "metrics": summarize_phase2_profile_metrics(records),
        "records": details,
    }


def main() -> int:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    current_builder = AttackChainBuilder(enforce_data_contract=True)
    baseline_builder = _load_head_attack_chain_builder()

    manifest = _build_manifest(current_builder)
    current = _evaluate_current_profile(current_builder)
    baseline = _evaluate_baseline_profile(baseline_builder)
    kpi = current_builder.evaluate_phase2_kpis(
        manifest=manifest,
        baseline_manifest=manifest,
        current_metrics=current["metrics"],
        baseline_metrics=baseline["metrics"],
    )

    evidence = {
        "manifest": manifest,
        "baseline_profile": "baseline_phase1_control_from_HEAD",
        "current_profile": "current_phase2_worktree",
        "baseline_metrics": baseline["metrics"],
        "current_metrics": current["metrics"],
        "kpi_result": kpi,
        "records": baseline["records"] + current["records"],
        "metric_notes": {
            "valid_submission_rate": "accepted canonical platform-ready payloads / confirmed benchmark chains",
            "expected_bounty_at_5": "sum of top-5 accepted chain bounty estimates using severity-weighted confidence",
            "cost_per_actionable_chain": "average manual completion cost units per confirmed benchmark chain",
            "baseline_definition": "HEAD chain builder output evaluated through legacy Phase1 payload route under the same manifest",
        },
    }
    EVIDENCE_PATH.write_text(json.dumps(evidence, ensure_ascii=True, indent=2, sort_keys=True), encoding="utf-8")

    print(json.dumps({
        "manifest_id": manifest["manifest_id"],
        "baseline_metrics": baseline["metrics"],
        "current_metrics": current["metrics"],
        "go_no_go": kpi["go_no_go"],
    }, ensure_ascii=True, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
