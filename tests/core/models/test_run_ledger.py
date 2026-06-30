"""
TDD tests for RunLedgerEvent, LLMUsageRecord, RunLedgerSummary models (Step 1).
"""
import json
import hashlib
from datetime import datetime

import pytest

from src.core.models.run_ledger import (
    RunLedgerEventType,
    UsageStatus,
    CacheStatus,
    CostEstimateStatus,
    LLMUsageRecord,
    RunLedgerEvent,
    LLMUsageSummary,
    RunLedgerRecorder,
    RUN_LEDGER_SCHEMA_VERSION,
    LLM_USAGE_SUMMARY_SCHEMA_VERSION,
    DEFAULT_MAX_EVENTS,
)


# ---------------------------------------------------------------------------
# LLMUsageRecord tests
# ---------------------------------------------------------------------------

class TestLLMUsageRecord:
    def test_measured_usage_record_defaults(self) -> None:
        rec = LLMUsageRecord(
            model="deepseek/deepseek-chat",
            actor="MasterConductor",
            input_tokens=1500,
            output_tokens=800,
        )
        assert rec.model == "deepseek/deepseek-chat"
        assert rec.actor == "MasterConductor"
        assert rec.input_tokens == 1500
        assert rec.output_tokens == 800
        assert rec.input_cache_tokens == 0
        assert rec.request_id is None
        assert rec.raw_provider is None
        assert rec.usage_source is None
        assert rec.usage_status == UsageStatus.MEASURED
        assert rec.cache_status == CacheStatus.UNKNOWN
        assert rec.cost_estimate_status == CostEstimateStatus.UNAVAILABLE

    def test_estimated_usage_record(self) -> None:
        rec = LLMUsageRecord(
            model="gpt-4",
            actor="SwarmWorker",
            input_tokens=1000,
            output_tokens=500,
            usage_status=UsageStatus.ESTIMATED,
            cost_estimate_status=CostEstimateStatus.ESTIMATED,
        )
        assert rec.usage_status == UsageStatus.ESTIMATED
        assert rec.cost_estimate_status == CostEstimateStatus.ESTIMATED

    def test_unknown_usage_record_with_cache_hit(self) -> None:
        rec = LLMUsageRecord(
            model="deepseek/deepseek-chat",
            actor="MasterConductor",
            input_tokens=0,
            output_tokens=0,
            usage_status=UsageStatus.UNKNOWN,
            cache_status=CacheStatus.HIT,
        )
        assert rec.usage_status == UsageStatus.UNKNOWN
        assert rec.cache_status == CacheStatus.HIT
        assert rec.input_tokens == 0
        assert rec.output_tokens == 0

    def test_usage_record_with_request_id_and_provider(self) -> None:
        rec = LLMUsageRecord(
            model="claude-3-opus",
            actor="SwarmWorker",
            input_tokens=2000,
            output_tokens=1200,
            input_cache_tokens=300,
            request_id="req-abc-123",
            raw_provider="anthropic",
            usage_source="litellm",
        )
        assert rec.request_id == "req-abc-123"
        assert rec.raw_provider == "anthropic"
        assert rec.usage_source == "litellm"
        assert rec.input_cache_tokens == 300

    def test_to_dict(self) -> None:
        rec = LLMUsageRecord(
            model="deepseek/deepseek-chat",
            actor="MasterConductor",
            input_tokens=1500,
            output_tokens=800,
            cache_status=CacheStatus.MISS,
        )
        d = rec.to_dict()
        assert d["model"] == "deepseek/deepseek-chat"
        assert d["actor"] == "MasterConductor"
        assert d["input_tokens"] == 1500
        assert d["output_tokens"] == 800
        assert d["input_cache_tokens"] == 0
        assert d["usage_status"] == "measured"
        assert d["cache_status"] == "miss"
        assert d["cost_estimate_status"] == "unavailable"


# ---------------------------------------------------------------------------
# RunLedgerEvent tests
# ---------------------------------------------------------------------------

class TestRunLedgerEvent:
    def test_minimal_event_creation(self) -> None:
        evt = RunLedgerEvent(
            event_id="ledger_evt_run001_0001",
            event_type=RunLedgerEventType.DECISION_MADE,
            phase="planning",
            actor_type="MC",
            actor_name="MasterConductor",
        )
        assert evt.event_id == "ledger_evt_run001_0001"
        assert evt.event_type == RunLedgerEventType.DECISION_MADE
        assert evt.phase == "planning"
        assert evt.actor_type == "MC"
        assert evt.actor_name == "MasterConductor"
        assert isinstance(evt.timestamp, str)
        # optional fields default
        assert evt.task_id is None
        assert evt.decision_id is None
        assert evt.parent_event_id is None
        assert evt.input_summary is None
        assert evt.input_fingerprint is None
        assert evt.action is None
        assert evt.result is None
        assert evt.error is None
        assert evt.source_refs is None
        assert evt.inference_level is None
        assert evt.redaction_status is None
        assert evt.redacted_fields_count == 0

    def test_event_with_source_refs(self) -> None:
        evt = RunLedgerEvent(
            event_id="ledger_evt_run001_0002",
            event_type=RunLedgerEventType.SWARM_DISPATCHED,
            phase="attack",
            actor_type="SwarmDispatcher",
            actor_name="injection_swarm",
            task_id="task-inj-1",
            source_refs={"swarm_id": "swarm-42", "task_count": 3},
            input_summary="Dispatched to InjectionSwarm for XSS probe",
        )
        assert evt.task_id == "task-inj-1"
        assert evt.source_refs == {"swarm_id": "swarm-42", "task_count": 3}
        assert evt.input_summary == "Dispatched to InjectionSwarm for XSS probe"

    def test_event_with_parent_event_id_chain(self) -> None:
        parent_evt = RunLedgerEvent(
            event_id="ledger_evt_run001_0003",
            event_type=RunLedgerEventType.DECISION_MADE,
            phase="planning",
            actor_type="MC",
            actor_name="MasterConductor",
        )
        child_evt = RunLedgerEvent(
            event_id="ledger_evt_run001_0004",
            event_type=RunLedgerEventType.SWARM_DISPATCHED,
            phase="attack",
            actor_type="SwarmDispatcher",
            actor_name="injection_swarm",
            parent_event_id=parent_evt.event_id,
        )
        assert child_evt.parent_event_id == "ledger_evt_run001_0003"

    def test_event_with_error_and_result(self) -> None:
        evt = RunLedgerEvent(
            event_id="ledger_evt_run001_0005",
            event_type=RunLedgerEventType.SWARM_FAILED,
            phase="attack",
            actor_type="SwarmDispatcher",
            actor_name="xss_swarm",
            error="Connection timeout",
            result="failed",
        )
        assert evt.error == "Connection timeout"
        assert evt.result == "failed"

    def test_event_with_inference_level(self) -> None:
        evt = RunLedgerEvent(
            event_id="ledger_evt_run001_0006",
            event_type=RunLedgerEventType.FINDING_CREATED,
            phase="attack",
            actor_type="SwarmWorker",
            actor_name="sql_injector",
            inference_level="high",
        )
        assert evt.inference_level == "high"

    def test_event_with_redaction_status(self) -> None:
        evt = RunLedgerEvent(
            event_id="ledger_evt_run001_0007",
            event_type=RunLedgerEventType.TOOL_EXECUTED,
            phase="attack",
            actor_type="SwarmWorker",
            actor_name="tool_runner",
            input_summary="curl request to example.com",
            redaction_status="partial",
            redacted_fields_count=2,
        )
        assert evt.redaction_status == "partial"
        assert evt.redacted_fields_count == 2

    def test_to_dict_includes_all_fields(self) -> None:
        evt = RunLedgerEvent(
            event_id="ledger_evt_run001_0010",
            event_type=RunLedgerEventType.LLM_CALLED,
            phase="planning",
            actor_type="MC",
            actor_name="MasterConductor",
            task_id="task-mc-1",
            decision_id="dec_0042",
            parent_event_id="ledger_evt_run001_0009",
            input_summary="Select next task from queue",
            input_fingerprint="sha256:abc123",
            action="prioritize",
            result="selected",
            error=None,
            source_refs={"decision_trace_id": "dec_0042"},
            inference_level="medium",
            redaction_status="none",
            redacted_fields_count=0,
        )
        d = evt.to_dict()
        assert d["event_id"] == "ledger_evt_run001_0010"
        assert d["event_type"] == "llm_called"
        assert d["phase"] == "planning"
        assert d["actor_type"] == "MC"
        assert d["actor_name"] == "MasterConductor"
        assert d["task_id"] == "task-mc-1"
        assert d["decision_id"] == "dec_0042"
        assert d["parent_event_id"] == "ledger_evt_run001_0009"
        assert d["input_summary"] == "Select next task from queue"
        assert d["input_fingerprint"] == "sha256:abc123"
        assert d["action"] == "prioritize"
        assert d["result"] == "selected"
        assert d["error"] is None
        assert d["source_refs"] == {"decision_trace_id": "dec_0042"}
        assert d["inference_level"] == "medium"
        assert d["redaction_status"] == "none"
        assert d["redacted_fields_count"] == 0


# ---------------------------------------------------------------------------
# RunLedgerEventType enum tests
# ---------------------------------------------------------------------------

class TestRunLedgerEventType:
    def test_all_required_event_types_exist(self) -> None:
        expected = {
            "decision_made",
            "swarm_dispatched", "swarm_completed", "swarm_failed",
            "swarm_merged", "swarm_skipped",
            "tool_executed", "error_occurred", "finding_created",
            "hitl_requested", "hitl_resolved",
            "llm_called", "llm_retry", "llm_failed",
            "llm_cache_hit", "provider_fallback",
        }
        actual = set(e.value for e in RunLedgerEventType)
        assert expected.issubset(actual), f"Missing event types: {expected - actual}"


# ---------------------------------------------------------------------------
# LLMUsageSummary tests
# ---------------------------------------------------------------------------

class TestLLMUsageSummary:
    def test_empty_summary(self) -> None:
        summary = LLMUsageSummary()
        assert summary.by_model == {}
        assert summary.by_actor == {}
        assert summary.totals == {}
        assert summary.cache_hit_ratio == 0.0
        assert summary.unknown_count == 0
        assert summary.estimated_count == 0

    def test_from_records_aggregates_by_model_and_actor(self) -> None:
        records = [
            LLMUsageRecord(model="deepseek/deepseek-chat", actor="MC", input_tokens=100, output_tokens=50),
            LLMUsageRecord(model="deepseek/deepseek-chat", actor="MC", input_tokens=200, output_tokens=100),
            LLMUsageRecord(model="deepseek/deepseek-chat", actor="SwarmWorker", input_tokens=300, output_tokens=150),
            LLMUsageRecord(model="gpt-4", actor="MC", input_tokens=400, output_tokens=200),
        ]
        summary = LLMUsageSummary.from_records(records)
        assert summary.by_model["deepseek/deepseek-chat"] == {
            "input_tokens": 600, "output_tokens": 300, "input_cache_tokens": 0, "call_count": 3,
        }
        assert summary.by_model["gpt-4"] == {
            "input_tokens": 400, "output_tokens": 200, "input_cache_tokens": 0, "call_count": 1,
        }
        assert summary.by_actor["MC"]["input_tokens"] == 700
        assert summary.by_actor["SwarmWorker"]["input_tokens"] == 300
        assert summary.totals["input_tokens"] == 1000
        assert summary.totals["output_tokens"] == 500
        assert summary.totals["call_count"] == 4
        assert summary.schema_version == LLM_USAGE_SUMMARY_SCHEMA_VERSION

    def test_from_records_unknown_and_estimated_separate(self) -> None:
        records = [
            LLMUsageRecord(model="deepseek/deepseek-chat", actor="MC", input_tokens=100, output_tokens=50),
            LLMUsageRecord(model="deepseek/deepseek-chat", actor="MC", input_tokens=0, output_tokens=0, usage_status=UsageStatus.UNKNOWN),
            LLMUsageRecord(model="gpt-4", actor="MC", input_tokens=200, output_tokens=100, usage_status=UsageStatus.ESTIMATED),
        ]
        summary = LLMUsageSummary.from_records(records)
        assert summary.unknown_count == 1
        assert summary.estimated_count == 1
        # estimated usage should NOT be in raw totals
        assert summary.totals["input_tokens"] == 100
        assert summary.totals["output_tokens"] == 50

    def test_from_records_cache_hit_ratio(self) -> None:
        records = [
            LLMUsageRecord(model="deepseek/deepseek-chat", actor="MC", input_tokens=100, output_tokens=50, cache_status=CacheStatus.HIT, usage_status=UsageStatus.UNKNOWN),
            LLMUsageRecord(model="deepseek/deepseek-chat", actor="MC", input_tokens=100, output_tokens=50, cache_status=CacheStatus.MISS),
            LLMUsageRecord(model="deepseek/deepseek-chat", actor="MC", input_tokens=100, output_tokens=50, cache_status=CacheStatus.HIT, usage_status=UsageStatus.UNKNOWN),
        ]
        summary = LLMUsageSummary.from_records(records)
        assert summary.cache_hit_ratio == pytest.approx(2.0 / 3.0)

    def test_to_dict(self) -> None:
        records = [
            LLMUsageRecord(model="deepseek/deepseek-chat", actor="MC", input_tokens=100, output_tokens=50),
        ]
        summary = LLMUsageSummary.from_records(records)
        d = summary.to_dict()
        assert d["schema_version"] == LLM_USAGE_SUMMARY_SCHEMA_VERSION
        assert d["totals"]["input_tokens"] == 100
        assert d["by_model"]["deepseek/deepseek-chat"]["input_tokens"] == 100
        assert d["by_actor"]["MC"]["input_tokens"] == 100


# ---------------------------------------------------------------------------
# RunLedgerRecorder tests (Step 1: event_id generator, recording)
# ---------------------------------------------------------------------------

class TestRunLedgerRecorderEventId:
    def test_event_id_format(self) -> None:
        recorder = RunLedgerRecorder(run_id="run001")
        eid = recorder._next_event_id()
        assert eid == "ledger_evt_run001_0001"

    def test_event_id_monotonically_increasing(self) -> None:
        recorder = RunLedgerRecorder(run_id="run001")
        ids = [recorder._next_event_id() for _ in range(5)]
        assert ids == [
            "ledger_evt_run001_0001",
            "ledger_evt_run001_0002",
            "ledger_evt_run001_0003",
            "ledger_evt_run001_0004",
            "ledger_evt_run001_0005",
        ]

    def test_event_id_no_collision_across_recordings(self) -> None:
        recorder = RunLedgerRecorder(run_id="run001")
        eids = set()
        for _ in range(100):
            eids.add(recorder._next_event_id())
        assert len(eids) == 100

    def test_event_id_different_run_ids(self) -> None:
        r1 = RunLedgerRecorder(run_id="runA")
        r2 = RunLedgerRecorder(run_id="runB")
        assert r1._next_event_id() == "ledger_evt_runA_0001"
        assert r2._next_event_id() == "ledger_evt_runB_0001"


class TestRunLedgerRecorderRecording:
    def test_record_decision_event(self) -> None:
        recorder = RunLedgerRecorder(run_id="run001")
        evt = recorder.record(
            event_type=RunLedgerEventType.DECISION_MADE,
            phase="planning",
            actor_type="MC",
            actor_name="MasterConductor",
            task_id="task-1",
            decision_id="dec_0001",
            input_summary="Choose XSS probe",
            action="select_task",
            result="selected",
        )
        assert evt.event_id == "ledger_evt_run001_0001"
        assert recorder.event_count == 1
        assert len(recorder.get_events()) == 1
        assert recorder.get_events()[0] is evt

    def test_record_chain_with_parent_event_id(self) -> None:
        recorder = RunLedgerRecorder(run_id="run001")
        parent = recorder.record(
            event_type=RunLedgerEventType.DECISION_MADE,
            phase="planning",
            actor_type="MC",
            actor_name="MasterConductor",
        )
        child = recorder.record(
            event_type=RunLedgerEventType.SWARM_DISPATCHED,
            phase="attack",
            actor_type="SwarmDispatcher",
            actor_name="xss_swarm",
            parent_event_id=parent.event_id,
        )
        assert child.parent_event_id == parent.event_id
        assert child.event_id == "ledger_evt_run001_0002"

    def test_record_enforces_max_events(self) -> None:
        recorder = RunLedgerRecorder(run_id="run001", max_events=3)
        for i in range(5):
            recorder.record(
                event_type=RunLedgerEventType.TOOL_EXECUTED,
                phase="attack",
                actor_type="SwarmWorker",
                actor_name=f"worker_{i}",
            )
        assert recorder.event_count == 5  # total count tracks all
        events = recorder.get_events()
        assert len(events) == 3  # only last 3 kept
        assert events[0].actor_name == "worker_2"
        assert events[-1].actor_name == "worker_4"

    def test_clear_resets_recorder(self) -> None:
        recorder = RunLedgerRecorder(run_id="run001")
        recorder.record(
            event_type=RunLedgerEventType.DECISION_MADE,
            phase="planning",
            actor_type="MC",
            actor_name="MasterConductor",
        )
        assert recorder.event_count == 1
        recorder.clear()
        assert recorder.event_count == 0
        assert recorder.get_events() == []

    def test_summary(self) -> None:
        recorder = RunLedgerRecorder(run_id="run001")
        recorder.record(
            event_type=RunLedgerEventType.DECISION_MADE,
            phase="planning", actor_type="MC", actor_name="MasterConductor",
        )
        recorder.record(
            event_type=RunLedgerEventType.SWARM_DISPATCHED,
            phase="attack", actor_type="SwarmDispatcher", actor_name="xss_swarm",
        )
        recorder.record(
            event_type=RunLedgerEventType.SWARM_FAILED,
            phase="attack", actor_type="SwarmDispatcher", actor_name="xss_swarm",
            error="timeout",
        )
        summary = recorder.summary()
        assert summary["total_events"] == 3
        assert summary["by_type"]["decision_made"] == 1
        assert summary["by_type"]["swarm_dispatched"] == 1
        assert summary["by_type"]["swarm_failed"] == 1
        assert summary["schema_version"] == RUN_LEDGER_SCHEMA_VERSION


# ---------------------------------------------------------------------------
# Schema version constants
# ---------------------------------------------------------------------------

def test_run_ledger_schema_version() -> None:
    assert RUN_LEDGER_SCHEMA_VERSION == 1


def test_llm_usage_summary_schema_version() -> None:
    assert LLM_USAGE_SUMMARY_SCHEMA_VERSION == 1


# ---------------------------------------------------------------------------
# Session payload helpers (Step 1 partial)
# ---------------------------------------------------------------------------

class TestRunLedgerRecorderToSessionPayload:
    def test_to_session_payload_empty(self) -> None:
        recorder = RunLedgerRecorder(run_id="run001")
        payload = recorder.to_session_payload()
        assert payload["run_ledger_schema_version"] == RUN_LEDGER_SCHEMA_VERSION
        assert payload["run_ledger"] == []
        assert payload["llm_usage_summary"]["schema_version"] == LLM_USAGE_SUMMARY_SCHEMA_VERSION
        assert payload["llm_usage_summary"]["by_model"] == {}
        assert payload["llm_usage_summary"]["by_actor"] == {}
        assert payload["llm_usage_summary"]["totals"]["call_count"] == 0
        assert payload["llm_usage_summary"]["cache_hit_ratio"] == 0.0
        assert payload["llm_usage_summary"]["unknown_count"] == 0
        assert payload["llm_usage_summary"]["estimated_count"] == 0
        assert payload["spool_path"] is None
        assert payload["spool_sha256"] is None
        assert payload["spool_event_count"] == 0

    def test_to_session_payload_with_events(self) -> None:
        recorder = RunLedgerRecorder(run_id="run001")
        recorder.record(
            event_type=RunLedgerEventType.DECISION_MADE,
            phase="planning", actor_type="MC", actor_name="MasterConductor",
        )
        recorder.add_llm_usage(LLMUsageRecord(
            model="deepseek/deepseek-chat", actor="MC",
            input_tokens=100, output_tokens=50,
        ))
        payload = recorder.to_session_payload()
        assert len(payload["run_ledger"]) == 1
        assert payload["run_ledger"][0]["event_type"] == "decision_made"
        assert payload["llm_usage_summary"]["totals"]["input_tokens"] == 100
        assert payload["llm_usage_summary"]["totals"]["output_tokens"] == 50


# ---------------------------------------------------------------------------
# Spool metadata (Step 2 preview)
# ---------------------------------------------------------------------------

class TestRunLedgerRecorderSpool:
    def test_spool_metadata_is_none_by_default(self) -> None:
        recorder = RunLedgerRecorder(run_id="run001")
        assert recorder.spool_path is None
        assert recorder.spool_sha256 is None
        assert recorder.spool_event_count == 0

    def test_set_spool_metadata(self) -> None:
        recorder = RunLedgerRecorder(run_id="run001")
        recorder.set_spool_metadata(
            spool_path="/tmp/spool.jsonl",
            spool_sha256="sha256:abc123",
            spool_event_count=5000,
        )
        payload = recorder.to_session_payload()
        assert payload["spool_path"] == "/tmp/spool.jsonl"
        assert payload["spool_sha256"] == "sha256:abc123"
        assert payload["spool_event_count"] == 5000


# ---------------------------------------------------------------------------
# Step 2: JSONL spool flush (session overflow protection)
# ---------------------------------------------------------------------------

class TestJsonlSpoolFlush:
    def test_flush_no_spool_when_below_threshold(self, tmp_path) -> None:
        """spool threshold以下ではspoolを作成せず、全イベントがin-memoryに残る"""
        from src.core.models.run_ledger import SPOOL_EVENT_THRESHOLD
        recorder = RunLedgerRecorder(run_id="run001", max_events=SPOOL_EVENT_THRESHOLD)
        for i in range(3):
            recorder.record(
                event_type=RunLedgerEventType.LLM_CALLED,
                phase="planning",
                actor_type="MC",
                actor_name="MasterConductor",
                action=f"call_{i}",
            )
        spool_dir = tmp_path / "spool"
        spool_dir.mkdir()
        result = recorder.flush_to_spool(str(spool_dir))
        # flush_to_spool returns None when threshold not exceeded
        assert result is None
        assert recorder.spool_path is None
        assert recorder.spool_sha256 is None
        assert recorder.spool_event_count == 0
        # all 3 events still in memory
        assert len(recorder.get_events()) == 3

    def test_flush_creates_spool_when_above_threshold(self, tmp_path) -> None:
        """spool threshold超過時にJSONL spoolを作成し、spoolメタデータを設定する"""
        from src.core.models.run_ledger import SPOOL_EVENT_THRESHOLD
        import json
        recorder = RunLedgerRecorder(run_id="run001", max_events=SPOOL_EVENT_THRESHOLD)
        # Record more than threshold events
        total = 10
        for i in range(total):
            recorder.record(
                event_type=RunLedgerEventType.LLM_CALLED,
                phase="planning",
                actor_type="MC",
                actor_name="MasterConductor",
                action=f"call_{i}",
            )
        assert recorder.event_count == total
        spool_dir = tmp_path / "spool"
        spool_dir.mkdir()
        result = recorder.flush_to_spool(str(spool_dir))
        # flush_to_spool returns the spool path when successful
        assert result is not None
        assert recorder.spool_path == str(result)
        assert recorder.spool_sha256 is not None
        assert recorder.spool_event_count == total
        # spool file exists
        assert result.exists()
        # verify spool content: JSONL, one event per line
        lines = result.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == total
        for line in lines:
            evt = json.loads(line)
            assert evt["event_type"] == "llm_called"
            assert evt["phase"] == "planning"
            assert "event_id" in evt
        # verify SHA256
        content = result.read_bytes()
        expected_sha = "sha256:" + hashlib.sha256(content).hexdigest()
        assert recorder.spool_sha256 == expected_sha

    def test_flush_clears_in_memory_events_after_spool(self, tmp_path) -> None:
        """spool作成後、in-memoryイベントはクリアされる"""
        from src.core.models.run_ledger import SPOOL_EVENT_THRESHOLD
        recorder = RunLedgerRecorder(run_id="run001", max_events=SPOOL_EVENT_THRESHOLD)
        for i in range(10):
            recorder.record(
                event_type=RunLedgerEventType.TOOL_EXECUTED,
                phase="attack",
                actor_type="SwarmWorker",
                actor_name=f"worker_{i}",
            )
        spool_dir = tmp_path / "spool"
        spool_dir.mkdir()
        recorder.flush_to_spool(str(spool_dir))
        # in-memory events are cleared after spool
        assert len(recorder.get_events()) == 0
        # but total count is preserved
        assert recorder.event_count == 10

    def test_flush_spool_preserves_event_count_after_new_events(self, tmp_path) -> None:
        """spool flush後、新規イベントの記録が正常に動作する"""
        from src.core.models.run_ledger import SPOOL_EVENT_THRESHOLD
        recorder = RunLedgerRecorder(run_id="run001", max_events=SPOOL_EVENT_THRESHOLD)
        # First batch: spill to spool
        for i in range(10):
            recorder.record(
                event_type=RunLedgerEventType.LLM_CALLED,
                phase="planning",
                actor_type="MC",
                actor_name="MasterConductor",
                action=f"batch1_call_{i}",
            )
        spool_dir = tmp_path / "spool"
        spool_dir.mkdir()
        recorder.flush_to_spool(str(spool_dir))
        assert recorder.event_count == 10
        assert recorder.spool_event_count == 10
        # Second batch: new events stay in memory
        for i in range(3):
            recorder.record(
                event_type=RunLedgerEventType.SWARM_DISPATCHED,
                phase="attack",
                actor_type="SwarmDispatcher",
                actor_name="xss_swarm",
                action=f"batch2_call_{i}",
            )
        assert recorder.event_count == 13  # total includes both batches
        assert recorder.spool_event_count == 10  # spool count unchanged
        in_mem = recorder.get_events()
        assert len(in_mem) == 3
        assert in_mem[0].event_type == RunLedgerEventType.SWARM_DISPATCHED

    def test_flush_handles_spool_dir_creation(self, tmp_path) -> None:
        """存在しないspoolディレクトリを自動生成する"""
        from src.core.models.run_ledger import SPOOL_EVENT_THRESHOLD
        recorder = RunLedgerRecorder(run_id="run001", max_events=SPOOL_EVENT_THRESHOLD)
        for i in range(10):
            recorder.record(
                event_type=RunLedgerEventType.LLM_CALLED,
                phase="planning",
                actor_type="MC",
                actor_name="MasterConductor",
            )
        spool_dir = tmp_path / "nonexistent_spool"
        # spool_dir does not exist yet
        result = recorder.flush_to_spool(str(spool_dir))
        assert result is not None
        assert result.exists()
        assert result.parent == spool_dir

    def test_to_session_payload_includes_spool_metadata_after_flush(self, tmp_path) -> None:
        """spool flush後、session payloadにspoolメタデータが含まれる"""
        from src.core.models.run_ledger import SPOOL_EVENT_THRESHOLD
        recorder = RunLedgerRecorder(run_id="run001", max_events=SPOOL_EVENT_THRESHOLD)
        for i in range(10):
            recorder.record(
                event_type=RunLedgerEventType.LLM_CALLED,
                phase="planning",
                actor_type="MC",
                actor_name="MasterConductor",
            )
        spool_dir = tmp_path / "spool"
        spool_dir.mkdir()
        recorder.flush_to_spool(str(spool_dir))
        payload = recorder.to_session_payload()
        assert payload["spool_path"] is not None
        assert payload["spool_sha256"] is not None
        assert payload["spool_event_count"] == 10
        assert payload["run_ledger"] == []  # in-memory events cleared

    def test_flush_noop_when_no_events(self, tmp_path) -> None:
        """イベントがない場合はspoolを作成しない"""
        recorder = RunLedgerRecorder(run_id="run001")
        spool_dir = tmp_path / "spool"
        spool_dir.mkdir()
        result = recorder.flush_to_spool(str(spool_dir))
        assert result is None
        files = list(spool_dir.glob("*.jsonl"))
        assert len(files) == 0
