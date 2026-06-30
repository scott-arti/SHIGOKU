"""
TDD tests for downstream contract fixture (Step 8).

This fixture is the minimal session that S2-S4 (Markdown/Neo4j/Haddix) will read.
It defines required and optional fields for event_id, timestamp, actor_type,
event_type, result, source_refs, inference_level.
"""
import json
import hashlib
from datetime import datetime, timezone

import pytest

from src.core.models.run_ledger import (
    RunLedgerRecorder, RunLedgerEventType,
    LLMUsageRecord, UsageStatus, CacheStatus,
    get_run_ledger_recorder, reset_run_ledger_recorder,
)


# ---------------------------------------------------------------------------
# Downstream contract fixture builder
# ---------------------------------------------------------------------------

def build_downstream_contract_session() -> dict:
    """
    Build a synthetic session payload that includes decision, Swarm, tool,
    LLM cache hit, LLM measured usage, finding, HITL, and interrupt events.

    This is the minimal fixture that S2-S4 (Markdown, Neo4j, Haddix) must
    be able to read. Required fields are verified below.
    """
    reset_run_ledger_recorder()
    recorder = get_run_ledger_recorder(run_id="contract01")

    # --- Decision event ---
    dec_evt = recorder.record(
        event_type=RunLedgerEventType.DECISION_MADE,
        phase="planning",
        actor_type="MC",
        actor_name="MasterConductor",
        task_id="task-decision-1",
        decision_id="dec_0010",
        input_summary="Selected XSS probe for target example.com",
        action="select_task",
        result="selected",
        source_refs={"available_options": ["xss", "sqli", "lfi"]},
        inference_level="medium",
    )

    # --- Swarm dispatched ---
    recorder.record(
        event_type=RunLedgerEventType.SWARM_DISPATCHED,
        phase="attack",
        actor_type="SwarmDispatcher",
        actor_name="injection_swarm",
        task_id="task-swarm-1",
        parent_event_id=dec_evt.event_id,
        input_summary="Dispatch XSS probe to injection_swarm",
        action="dispatch",
        result="dispatched",
        source_refs={"swarm_id": "inj-42"},
    )

    # --- Swarm completed ---
    recorder.record(
        event_type=RunLedgerEventType.SWARM_COMPLETED,
        phase="attack",
        actor_type="SwarmDispatcher",
        actor_name="injection_swarm",
        task_id="task-swarm-1",
        parent_event_id=dec_evt.event_id,
        input_summary="XSS probe completed",
        result="completed",
        source_refs={"findings_count": 2},
    )

    # --- Swarm merged ---
    recorder.record(
        event_type=RunLedgerEventType.SWARM_MERGED,
        phase="attack",
        actor_type="SwarmDispatcher",
        actor_name="all",
        action="merge",
        result="success",
        source_refs={"statuses": ["completed"], "total_findings": 2},
    )

    # --- Tool executed ---
    recorder.record(
        event_type=RunLedgerEventType.TOOL_EXECUTED,
        phase="attack",
        actor_type="SwarmWorker",
        actor_name="xss_prober",
        task_id="task-tool-1",
        input_summary="curl request to example.com/search?q=test",
        input_fingerprint="sha256:abc123",
        action="http_request",
        result="success",
        redaction_status="none",
        redacted_fields_count=0,
    )

    # --- Finding created ---
    recorder.record(
        event_type=RunLedgerEventType.FINDING_CREATED,
        phase="attack",
        actor_type="SwarmWorker",
        actor_name="xss_prober",
        task_id="task-finding-1",
        input_summary="XSS vulnerability found in search parameter",
        result="finding_detected",
        inference_level="high",
        source_refs={"severity": "high", "vuln_type": "reflected_xss"},
    )

    # --- HITL requested ---
    recorder.record(
        event_type=RunLedgerEventType.HITL_REQUESTED,
        phase="attack",
        actor_type="MC",
        actor_name="MasterConductor",
        task_id="task-hitl-1",
        input_summary="HITL requested for destructive test",
        action="request_approval",
        result="pending",
    )

    # --- HITL resolved ---
    recorder.record(
        event_type=RunLedgerEventType.HITL_RESOLVED,
        phase="attack",
        actor_type="MC",
        actor_name="MasterConductor",
        task_id="task-hitl-1",
        input_summary="HITL approved by operator",
        action="approve",
        result="approved",
    )

    # --- LLM called with measured usage ---
    recorder.add_llm_usage(LLMUsageRecord(
        model="deepseek/deepseek-chat",
        actor="MasterConductor",
        input_tokens=1500,
        output_tokens=800,
        usage_status=UsageStatus.MEASURED,
        cache_status=CacheStatus.MISS,
    ))
    recorder.record(
        event_type=RunLedgerEventType.LLM_CALLED,
        phase="planning",
        actor_type="LLMClient",
        actor_name="MasterConductor",
        input_summary="LLM call for task prioritization",
        result="success",
        source_refs={"model": "deepseek/deepseek-chat"},
    )

    # --- LLM cache hit ---
    recorder.add_llm_usage(LLMUsageRecord(
        model="deepseek/deepseek-chat",
        actor="MasterConductor",
        input_tokens=0,
        output_tokens=0,
        usage_status=UsageStatus.UNKNOWN,
        cache_status=CacheStatus.HIT,
    ))
    recorder.record(
        event_type=RunLedgerEventType.LLM_CACHE_HIT,
        phase="planning",
        actor_type="LLMClient",
        actor_name="MasterConductor",
        input_summary="Cache hit for tool classification",
        result="cache_hit",
        source_refs={"model": "deepseek/deepseek-chat"},
    )

    # --- Error occurred ---
    recorder.record(
        event_type=RunLedgerEventType.ERROR_OCCURRED,
        phase="attack",
        actor_type="SwarmWorker",
        actor_name="sqli_prober",
        task_id="task-error-1",
        input_summary="SQL injection probe timeout",
        error="Connection timeout after 30s",
        result="error",
    )

    # --- Swarm failed ---
    recorder.record(
        event_type=RunLedgerEventType.SWARM_FAILED,
        phase="attack",
        actor_type="SwarmDispatcher",
        actor_name="sqli_swarm",
        task_id="task-swarm-fail-1",
        error="AuthenticationError: Invalid API key",
        result="failed",
    )

    # --- Provider fallback ---
    recorder.record(
        event_type=RunLedgerEventType.PROVIDER_FALLBACK,
        phase="llm",
        actor_type="LLMClient",
        actor_name="MasterConductor",
        input_summary="Provider fallback: deepseek-v4-pro -> deepseek-chat",
        result="fallback",
        source_refs={"from_model": "deepseek-v4-pro", "to_model": "deepseek-chat"},
    )

    return recorder.to_session_payload()


# ---------------------------------------------------------------------------
# Contract tests
# ---------------------------------------------------------------------------

class TestDownstreamContract:
    """S2-S4 must be able to read this contract."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        reset_run_ledger_recorder()

    def test_contract_session_has_all_required_root_keys(self) -> None:
        session = build_downstream_contract_session()
        required_root_keys = [
            "run_ledger_schema_version",
            "run_ledger",
            "llm_usage_summary",
            "spool_path",
            "spool_sha256",
            "spool_event_count",
        ]
        for key in required_root_keys:
            assert key in session, f"Missing required root key: {key}"

    def test_contract_each_event_has_required_fields(self) -> None:
        """Every event in the contract must have these required fields."""
        session = build_downstream_contract_session()
        required_event_fields = [
            "event_id",
            "event_type",
            "timestamp",
            "phase",
            "actor_type",
            "actor_name",
        ]
        for evt in session["run_ledger"]:
            for field in required_event_fields:
                assert field in evt, f"Missing required field '{field}' in event {evt.get('event_id')}"
                assert evt[field] is not None, f"Field '{field}' is None in event {evt.get('event_id')}"

    def test_contract_event_id_format(self) -> None:
        """All event_ids follow leder_evt_<run_id>_<seq> format."""
        session = build_downstream_contract_session()
        for evt in session["run_ledger"]:
            eid = evt["event_id"]
            assert eid.startswith("ledger_evt_"), f"Bad event_id: {eid}"
            parts = eid.split("_")
            assert len(parts) >= 4, f"Bad event_id format: {eid}"
            # last part should be numeric (padded)
            assert parts[-1].isdigit(), f"Event seq not numeric: {eid}"

    def test_contract_has_all_required_event_types(self) -> None:
        """Contract must demonstrate all required event types."""
        session = build_downstream_contract_session()
        event_types = {evt["event_type"] for evt in session["run_ledger"]}
        required_types = {
            "decision_made",
            "swarm_dispatched",
            "swarm_completed",
            "swarm_merged",
            "tool_executed",
            "finding_created",
            "hitl_requested",
            "hitl_resolved",
            "llm_called",
            "llm_cache_hit",
            "error_occurred",
            "swarm_failed",
            "provider_fallback",
        }
        missing = required_types - event_types
        assert not missing, f"Contract missing event types: {missing}"

    def test_contract_llm_usage_summary_has_measured_and_cache_hit(self) -> None:
        """LLM usage summary separates measured from cache hits."""
        session = build_downstream_contract_session()
        summary = session["llm_usage_summary"]
        assert summary["schema_version"] == 1
        assert summary["totals"]["input_tokens"] == 1500  # only measured, not cache
        assert summary["totals"]["output_tokens"] == 800
        assert summary["totals"]["call_count"] == 2
        assert summary["unknown_count"] == 1  # cache hit
        assert summary["estimated_count"] == 0
        assert summary["cache_hit_ratio"] > 0

    def test_contract_timestamps_are_iso_utc(self) -> None:
        """All timestamps are ISO 8601 in UTC."""
        session = build_downstream_contract_session()
        for evt in session["run_ledger"]:
            ts = evt["timestamp"]
            # ISO 8601 format check
            assert "T" in ts
            assert "+" in ts or "Z" in ts or ts.endswith("00:00")

    def test_contract_event_has_optional_fields_with_null_defaults(self) -> None:
        """Optional fields should be present as keys (even if null)."""
        session = build_downstream_contract_session()
        optional_fields = [
            "task_id",
            "decision_id",
            "parent_event_id",
            "input_summary",
            "input_fingerprint",
            "action",
            "result",
            "error",
            "source_refs",
            "inference_level",
            "redaction_status",
            "redacted_fields_count",
        ]
        for evt in session["run_ledger"]:
            for field in optional_fields:
                assert field in evt, f"Missing optional field '{field}' in event {evt.get('event_id')}"

    def test_contract_parent_event_id_chain_is_intact(self) -> None:
        """Parent-child event chain is referenced correctly."""
        session = build_downstream_contract_session()
        events_by_id = {evt["event_id"]: evt for evt in session["run_ledger"]}
        # The swarm_dispatched event should reference the decision_made event
        swarm_events = [e for e in session["run_ledger"] if e["event_type"] == "swarm_dispatched"]
        assert len(swarm_events) >= 1
        parent_id = swarm_events[0]["parent_event_id"]
        assert parent_id is not None
        assert parent_id in events_by_id, f"parent_event_id {parent_id} not found in contract"

    def test_contract_serializable_to_json(self) -> None:
        """Contract must be JSON-serializable."""
        session = build_downstream_contract_session()
        json_str = json.dumps(session)
        parsed = json.loads(json_str)
        assert parsed["run_ledger_schema_version"] == 1
        assert len(parsed["run_ledger"]) > 0

    def test_contract_spool_fields_are_null_when_no_spool(self) -> None:
        """When no spool, spool fields are null/0."""
        session = build_downstream_contract_session()
        assert session["spool_path"] is None
        assert session["spool_sha256"] is None
        assert session["spool_event_count"] == 0
