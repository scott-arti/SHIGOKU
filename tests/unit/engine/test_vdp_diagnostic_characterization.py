"""
SGK-2026-0425 M0: characterization tests — freeze EXISTING VDP outputs.

Contract (§8 M0): with the diagnostics feature flag OFF, existing
session / report / decision-trace outputs must stay BIT-IDENTICAL to the
pre-feature behavior. These tests capture the current behavior as frozen
content hashes computed over canonical JSON (sort_keys, ensure_ascii=False).

- test_..._hash_frozen: asserts the exact current bytes (golden hash).
- test_..._deterministic_across_runs: asserts stability across independent
  runs (same inputs, no wall-clock/UUID dependence).

The same tests MUST stay green after the M1 telemetry hooks are added with
diagnostics.enabled=false — any change to these bytes is a regression.
"""
from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

from src.core.engine.master_conductor_session_service import (
    build_async_session_payload,
    inject_vdp_section_to_session_payload,
)
from src.core.engine.vdp_hypothesis_generator import generate_hypotheses
from src.core.engine.vdp_observation_adapter import ObservationAdapter
from src.core.models.vdp_contract import ExecutionBudgetV1, ScopeRevalidationResult
from src.reporting.vdp_canonical import build_vdp_canonical_index, extract_vdp_canonical
from src.reporting.vdp_report_projection import (
    embed_vdp_canonical_index,
    format_vdp_funnel_markdown,
)

# --- frozen golden hashes (computed from current behavior at M0 freeze) ---
FROZEN_HASH_VDP_CONTRACT_SECTION = "a4ddbb9bcdf2d5a1140be1226d52154d5131783aa614afb1c9bd8d9d97ccbfc3"
FROZEN_HASH_FULL_SESSION_PAYLOAD = "cc905c632e939ee78ae76c6108e722e9cffafc34228a925b5552e9a6596f60bb"
FROZEN_HASH_DECISION_TRACES = "3f4a5f1ae9885f15b274f01d29bcf1c0aa44523309287fb3e6d0cdfb3f798f87"
FROZEN_HASH_REPORT_PROJECTION = "2abe44b001bb87081b3ac750f5a71f42accbaa5ff8fe44dc5493bce7cd31a08e"


def _canonical_sha(value) -> str:
    if isinstance(value, (list, tuple)):
        value = list(value)
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _signal_bundle() -> dict:
    """Fixed product-free signal bundle (no known products/URLs/payloads)."""
    return {
        "_endpoint_signals": [
            {
                "signal_id": "sig-1",
                "entity_type": "endpoint",
                "url": "https://example.com/api/users",
                "method": "GET",
                "primary_label": "users",
                "candidate_labels": ["api", "auth"],
                "auth_context": {"authorization": "Bearer secret-token-abc", "cookie": "PHPSESSID=xyz"},
                "params": [{"name": "id", "location": "query"}, {"name": "token", "location": "query"}],
            },
            {
                "signal_id": "sig-2",
                "entity_type": "form",
                "url": "https://example.com/login",
                "method": "POST",
                "primary_label": "login",
                "candidate_labels": ["form"],
                "params": [{"name": "username", "location": "form"}, {"name": "password", "location": "form"}],
            },
            {
                # structurally invalid -> adapter skip record
                "signal_id": "sig-3",
                "entity_type": "endpoint",
                "url": 12345,
                "method": "GET",
            },
            {
                # duplicate of sig-1 -> same canonical observation (dedup path)
                "signal_id": "sig-4",
                "entity_type": "endpoint",
                "url": "https://example.com/api/users",
                "method": "GET",
                "primary_label": "users",
                "candidate_labels": ["api", "auth"],
                "auth_context": {"authorization": "Bearer secret-token-abc", "cookie": "PHPSESSID=xyz"},
                "params": [{"name": "id", "location": "query"}, {"name": "token", "location": "query"}],
            },
        ]
    }


def _run_vdp_flow():
    """Deterministic adapter -> generator pipeline (no timestamps/UUIDs)."""
    adapter = ObservationAdapter()
    adapted = adapter.adapt_signal_bundle(_signal_bundle())
    generated = generate_hypotheses(
        observations=adapted.observations,
        scope_verdict_provider=lambda url: ScopeRevalidationResult.allow(),
        budget_model=ExecutionBudgetV1(),
        leakage_denylist=None,
    )
    return adapted, generated


def _vdp_state(generated) -> dict:
    return {
        "vdp_active": True,
        "vdp_contract_version": 1,
        "hypotheses": [h.to_dict() for h in generated.hypotheses],
        "attempts": [],
        "evidence_records": [],
        "verdicts": [],
        "next_actions": [],
        "budget_snapshot": {},
        "run_health": {},
    }


def _context() -> SimpleNamespace:
    return SimpleNamespace(
        _total_attempts=0,
        _successful_attempts=0,
        bypass_methods=[],
        discovered_assets=[],
        target_info={"start_time": 1000.0},
    )


_FIXED_DECISION_TRACES = [
    {
        "decision_type": "vdp_hypothesis_generation",
        "selected_option": "record_only",
        "related_task_id": None,
        "related_target": "https://example.com/api/users",
    },
    {
        "decision_type": "vdp_queue_injection",
        "selected_option": "none",
        "related_task_id": None,
        "related_target": "https://example.com/login",
    },
]


def _base_payload(decision_traces=None) -> dict:
    return build_async_session_payload(
        task_queue=[],
        completed_tasks=[],
        context=_context(),
        pending_hitl=[],
        coverage_gate={},
        scenario_coverage={},
        timestamp=1000.0,
        default_start_time=1000.0,
        decision_traces=decision_traces,
        session_id="char-session",
        run_id="char-run",
    )


def _vdp_session_payload() -> dict:
    _, generated = _run_vdp_flow()
    return inject_vdp_section_to_session_payload(
        _base_payload(), _vdp_state(generated)
    )


class TestCharacterizationSessionPayload:
    def test_vdp_contract_section_hash_frozen(self):
        payload = _vdp_session_payload()
        assert (
            _canonical_sha(payload["vdp_contract"]) == FROZEN_HASH_VDP_CONTRACT_SECTION
        )

    def test_vdp_contract_section_deterministic_across_runs(self):
        first = _canonical_sha(_vdp_session_payload()["vdp_contract"])
        second = _canonical_sha(_vdp_session_payload()["vdp_contract"])
        assert first == second

    def test_full_session_payload_hash_frozen(self):
        payload = _vdp_session_payload()
        assert _canonical_sha(payload) == FROZEN_HASH_FULL_SESSION_PAYLOAD

    def test_session_payload_deterministic_across_runs(self):
        assert _canonical_sha(_vdp_session_payload()) == _canonical_sha(
            _vdp_session_payload()
        )


class TestCharacterizationDecisionTraces:
    def test_decision_traces_hash_frozen(self):
        payload = _base_payload(decision_traces=_FIXED_DECISION_TRACES)
        assert _canonical_sha(payload["decision_traces"]) == FROZEN_HASH_DECISION_TRACES

    def test_decision_traces_deterministic_across_runs(self):
        a = _canonical_sha(_base_payload(decision_traces=_FIXED_DECISION_TRACES)["decision_traces"])
        b = _canonical_sha(_base_payload(decision_traces=_FIXED_DECISION_TRACES)["decision_traces"])
        assert a == b

    def test_decision_traces_absent_when_none(self):
        # Old-reader contract: key is written only when not None.
        payload = _base_payload(decision_traces=None)
        assert "decision_traces" not in payload


class TestCharacterizationReportProjection:
    def test_report_projection_hash_frozen(self):
        payload = _vdp_session_payload()
        summary = extract_vdp_canonical(payload)
        index = build_vdp_canonical_index(summary)
        funnel_md = format_vdp_funnel_markdown(summary)
        embedded = embed_vdp_canonical_index("", summary)
        projection = {
            "index": index,
            "funnel_markdown": funnel_md,
            "embedded_markdown": embedded,
        }
        assert _canonical_sha(projection) == FROZEN_HASH_REPORT_PROJECTION

    def test_report_projection_deterministic_across_runs(self):
        def build():
            summary = extract_vdp_canonical(_vdp_session_payload())
            return _canonical_sha(
                {
                    "index": build_vdp_canonical_index(summary),
                    "funnel_markdown": format_vdp_funnel_markdown(summary),
                    "embedded_markdown": embed_vdp_canonical_index("", summary),
                }
            )

        assert build() == build()
