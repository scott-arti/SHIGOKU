from types import SimpleNamespace

from src.core.domain.model.task import Task, TaskState
from src.core.engine.master_conductor_session_service import build_async_session_payload


def test_build_async_session_payload_serializes_queue_completed_context_and_adjacency() -> None:
    queue_task = Task(
        id="queue-1",
        name="Queue Task",
        agent_type="InjectionSwarm",
        action="scan",
        phase="attack",
        params={"target": "https://example.test"},
        priority=42,
        parent_id="parent-1",
        replan_depth=1,
    )
    queue_task.state = TaskState.PENDING

    completed_task = Task(
        id="done-1",
        name="Done Task",
        agent_type="AuthSwarm",
        action="analyze",
        phase="attack",
        params={"category": "auth"},
        state=TaskState.FAILED,
        error="boom",
        result={"ok": False},
        priority=77,
    )
    completed_task.failure_phase = "dispatch_result"
    completed_task.failure_reason = "phase2_timeout"
    completed_task.failure_reason_code = "TIMEOUT_PHASE2"
    completed_task.timeout_retry_count = 2

    context = SimpleNamespace(
        _total_attempts=7,
        _successful_attempts=5,
        bypass_methods=["jwt_bypass"],
        discovered_assets=["api.example.test"],
        target_info={"target": "https://example.test", "start_time": 123.0},
    )
    pending_hitl = [{"ticket_id": "ticket-1", "task": {"id": "task-1"}}]
    coverage_gate = {"gate_passed": True}
    scenario_coverage = {"covered_count": 3}

    payload = build_async_session_payload(
        task_queue=[queue_task],
        completed_tasks=[completed_task],
        context=context,
        pending_hitl=pending_hitl,
        coverage_gate=coverage_gate,
        scenario_coverage=scenario_coverage,
        timestamp=456.0,
        default_start_time=999.0,
    )

    assert payload["task_queue"] == [
        {
            "id": "queue-1",
            "name": "Queue Task",
            "agent_type": "InjectionSwarm",
            "action": "scan",
            "phase": "attack",
            "params": {"target": "https://example.test"},
            "state": "pending",
            "priority": 42,
            "parent_id": "parent-1",
            "replan_depth": 1,
            "metadata": {},
        }
    ]
    assert payload["completed_tasks"] == [
        {
            "id": "done-1",
            "name": "Done Task",
            "agent_type": "AuthSwarm",
            "action": "analyze",
            "phase": "attack",
            "params": {"category": "auth"},
            "state": "failed",
            "error": "boom",
            "result": {"ok": False},
            "priority": 77,
            "failure_phase": "dispatch_result",
            "failure_reason": "phase2_timeout",
            "failure_reason_code": "TIMEOUT_PHASE2",
            "timeout_retry_count": 2,
            "metadata": {},
        }
    ]
    assert payload["context"]["total_attempts"] == 7
    assert payload["context"]["successful_attempts"] == 5
    assert payload["context"]["bypass_methods"] == ["jwt_bypass"]
    assert payload["context"]["discovered_assets"] == ["api.example.test"]
    assert payload["context"]["target_info"] == {"target": "https://example.test", "start_time": 123.0}
    assert payload["context"]["pending_hitl"] == [{"ticket_id": "ticket-1", "task": {"id": "task-1"}}]
    assert payload["coverage_gate"] == {"gate_passed": True}
    assert payload["scenario_coverage"] == {"covered_count": 3}
    assert payload["pending_hitl"] == [{"ticket_id": "ticket-1", "task": {"id": "task-1"}}]
    assert payload["start_time"] == 123.0
    assert payload["timestamp"] == 456.0
    assert payload["adjacency_list"] == {"parent-1": ["queue-1"]}


def test_build_async_session_payload_deep_copies_pending_hitl() -> None:
    context = SimpleNamespace(
        _total_attempts=0,
        _successful_attempts=0,
        bypass_methods=[],
        discovered_assets=[],
        target_info={},
    )
    pending_hitl = [{"ticket_id": "ticket-1", "task": {"params": {"nested": {"value": 1}}}}]

    payload = build_async_session_payload(
        task_queue=[],
        completed_tasks=[],
        context=context,
        pending_hitl=pending_hitl,
        coverage_gate={},
        scenario_coverage={},
        timestamp=1.0,
        default_start_time=2.0,
    )

    pending_hitl[0]["task"]["params"]["nested"]["value"] = 99

    assert payload["pending_hitl"][0]["task"]["params"]["nested"]["value"] == 1
    assert payload["context"]["pending_hitl"][0]["task"]["params"]["nested"]["value"] == 1


# ---------------------------------------------------------------------------
# Step 4: Run Ledger backward-compatible session payload tests
# ---------------------------------------------------------------------------

class TestBuildAsyncSessionPayloadRunLedgerBackwardCompat:
    def test_no_new_fields_preserves_existing_payload(self) -> None:
        """Old callers without new params produce same payload as before"""
        context = SimpleNamespace(
            _total_attempts=0, _successful_attempts=0,
            bypass_methods=[], discovered_assets=[], target_info={},
        )
        payload = build_async_session_payload(
            task_queue=[],
            completed_tasks=[],
            context=context,
            pending_hitl=[],
            coverage_gate={},
            scenario_coverage={},
            timestamp=123.0,
            default_start_time=456.0,
        )
        # Old fields still present
        assert "task_queue" in payload
        assert "completed_tasks" in payload
        assert "context" in payload
        # New fields NOT present (backward compat)
        assert "decision_traces" not in payload
        assert "task_execution_records" not in payload
        assert "run_ledger" not in payload
        assert "llm_usage_summary" not in payload

    def test_new_fields_appear_when_provided(self) -> None:
        """When new params are passed, they appear in payload"""
        from src.core.models.run_ledger import RunLedgerRecorder, RunLedgerEventType
        recorder = RunLedgerRecorder(run_id="r001")
        recorder.record(
            event_type=RunLedgerEventType.DECISION_MADE,
            phase="planning", actor_type="MC", actor_name="MasterConductor",
        )
        context = SimpleNamespace(
            _total_attempts=0, _successful_attempts=0,
            bypass_methods=[], discovered_assets=[], target_info={},
        )
        payload = build_async_session_payload(
            task_queue=[],
            completed_tasks=[],
            context=context,
            pending_hitl=[],
            coverage_gate={},
            scenario_coverage={},
            timestamp=123.0,
            default_start_time=456.0,
            decision_traces=[],
            task_execution_records=[],
            run_ledger_payload=recorder.to_session_payload(),
        )
        assert "decision_traces" in payload
        assert payload["decision_traces"] == []
        assert "task_execution_records" in payload
        assert payload["task_execution_records"] == []
        assert payload["run_ledger_schema_version"] == 1
        assert "run_ledger" in payload
        assert len(payload["run_ledger"]) == 1
        assert "llm_usage_summary" in payload
        assert payload["spool_path"] is None
        assert payload["spool_sha256"] is None
        assert payload["spool_event_count"] == 0

    def test_empty_ledger_is_valid(self) -> None:
        """Empty run_ledger payload (no events) is valid"""
        from src.core.models.run_ledger import RunLedgerRecorder
        recorder = RunLedgerRecorder(run_id="r001")
        context = SimpleNamespace(
            _total_attempts=0, _successful_attempts=0,
            bypass_methods=[], discovered_assets=[], target_info={},
        )
        payload = build_async_session_payload(
            task_queue=[],
            completed_tasks=[],
            context=context,
            pending_hitl=[],
            coverage_gate={},
            scenario_coverage={},
            timestamp=123.0,
            default_start_time=456.0,
            decision_traces=[],
            task_execution_records=[],
            run_ledger_payload=recorder.to_session_payload(),
        )
        assert payload["run_ledger"] == []
        assert payload["run_ledger_schema_version"] == 1
        assert payload["llm_usage_summary"]["totals"]["call_count"] == 0
        assert payload["spool_event_count"] == 0

    def test_session_with_spool_metadata(self) -> None:
        """Session payload includes spool metadata when set"""
        from src.core.models.run_ledger import RunLedgerRecorder
        recorder = RunLedgerRecorder(run_id="r001")
        recorder.set_spool_metadata("/tmp/spool.jsonl", "sha256:abc123", 42)
        context = SimpleNamespace(
            _total_attempts=0, _successful_attempts=0,
            bypass_methods=[], discovered_assets=[], target_info={},
        )
        payload = build_async_session_payload(
            task_queue=[],
            completed_tasks=[],
            context=context,
            pending_hitl=[],
            coverage_gate={},
            scenario_coverage={},
            timestamp=123.0,
            default_start_time=456.0,
            run_ledger_payload=recorder.to_session_payload(),
        )
        assert payload["spool_path"] == "/tmp/spool.jsonl"
        assert payload["spool_sha256"] == "sha256:abc123"
        assert payload["spool_event_count"] == 42

    def test_partial_new_fields_some_none(self) -> None:
        """Only some new fields provided, others absent"""
        from src.core.models.run_ledger import RunLedgerRecorder
        recorder = RunLedgerRecorder(run_id="r001")
        context = SimpleNamespace(
            _total_attempts=0, _successful_attempts=0,
            bypass_methods=[], discovered_assets=[], target_info={},
        )
        payload = build_async_session_payload(
            task_queue=[],
            completed_tasks=[],
            context=context,
            pending_hitl=[],
            coverage_gate={},
            scenario_coverage={},
            timestamp=123.0,
            default_start_time=456.0,
            decision_traces=[{"decision_id": "dec_0001"}],
            run_ledger_payload=recorder.to_session_payload(),
            # task_execution_records NOT provided
        )
        assert "decision_traces" in payload
        assert "task_execution_records" not in payload  # not provided
        assert "run_ledger" in payload  # provided via run_ledger_payload
        assert payload["run_ledger"] == []

    def test_deep_copy_new_fields_isolated(self) -> None:
        """New fields are deep-copied, mutations don't leak"""
        from src.core.models.run_ledger import RunLedgerRecorder, RunLedgerEventType
        recorder = RunLedgerRecorder(run_id="r001")
        recorder.record(
            event_type=RunLedgerEventType.DECISION_MADE,
            phase="planning", actor_type="MC", actor_name="MasterConductor",
        )
        run_ledger = recorder.to_session_payload()
        context = SimpleNamespace(
            _total_attempts=0, _successful_attempts=0,
            bypass_methods=[], discovered_assets=[], target_info={},
        )
        traces = [{"decision_id": "dec_0001"}]
        records = [{"task_id": "task-1"}]
        payload = build_async_session_payload(
            task_queue=[],
            completed_tasks=[],
            context=context,
            pending_hitl=[],
            coverage_gate={},
            scenario_coverage={},
            timestamp=123.0,
            default_start_time=456.0,
            decision_traces=traces,
            task_execution_records=records,
            run_ledger_payload=run_ledger,
        )
        # Mutate originals
        traces.append({"extra": "should not appear"})
        records[0]["extra"] = "should not appear"
        run_ledger["run_ledger"].append({"bad": "also should not appear"})
        # Payload unchanged
        assert len(payload["decision_traces"]) == 1
        assert len(payload["task_execution_records"]) == 1
        assert len(payload["run_ledger"]) == 1


# ---------------------------------------------------------------------------
# Phase 1 (SGK-2026-0310): execution contract metadata in session payload
# ---------------------------------------------------------------------------

class TestBuildAsyncSessionPayloadMetadata:
    """build_async_session_payload must preserve Task metadata across boundaries."""

    def test_metadata_present_in_task_queue(self) -> None:
        task = Task(
            id="meta-queue",
            name="Meta Queue Task",
            agent_type="Recon",
            action="scan",
            params={"target": "https://example.test"},
            metadata={
                "target_key": "https://example.test",
                "origin_key": "recon://scenario-1",
                "schema_version": 1,
                "lifecycle_status": "admitted",
            },
        )

        context = SimpleNamespace(
            _total_attempts=0, _successful_attempts=0,
            bypass_methods=[], discovered_assets=[], target_info={},
        )

        payload = build_async_session_payload(
            task_queue=[task],
            completed_tasks=[],
            context=context,
            pending_hitl=[],
            coverage_gate={},
            scenario_coverage={},
            timestamp=1.0,
            default_start_time=2.0,
        )

        assert len(payload["task_queue"]) == 1
        qt = payload["task_queue"][0]
        assert "metadata" in qt
        assert qt["metadata"]["target_key"] == "https://example.test"
        assert qt["metadata"]["origin_key"] == "recon://scenario-1"
        assert qt["metadata"]["lifecycle_status"] == "admitted"

    def test_metadata_present_in_completed_tasks(self) -> None:
        task = Task(
            id="meta-done",
            name="Meta Done Task",
            agent_type="Auth",
            action="verify",
            state=TaskState.SUCCESS,
            metadata={
                "target_key": "https://example.test",
                "correlation_id": "corr-abc",
            },
        )

        context = SimpleNamespace(
            _total_attempts=0, _successful_attempts=0,
            bypass_methods=[], discovered_assets=[], target_info={},
        )

        payload = build_async_session_payload(
            task_queue=[],
            completed_tasks=[task],
            context=context,
            pending_hitl=[],
            coverage_gate={},
            scenario_coverage={},
            timestamp=1.0,
            default_start_time=2.0,
        )

        assert len(payload["completed_tasks"]) == 1
        ct = payload["completed_tasks"][0]
        assert "metadata" in ct
        assert ct["metadata"]["target_key"] == "https://example.test"
        assert ct["metadata"]["correlation_id"] == "corr-abc"

    def test_metadata_absent_task_produces_empty_metadata(self) -> None:
        """Task without metadata must still have empty metadata in payload."""
        task = Task(id="no-meta", name="No Meta Task", agent_type="Recon", action="scan")

        context = SimpleNamespace(
            _total_attempts=0, _successful_attempts=0,
            bypass_methods=[], discovered_assets=[], target_info={},
        )

        payload = build_async_session_payload(
            task_queue=[task],
            completed_tasks=[],
            context=context,
            pending_hitl=[],
            coverage_gate={},
            scenario_coverage={},
            timestamp=1.0,
            default_start_time=2.0,
        )

        assert payload["task_queue"][0]["metadata"] == {}

    def test_existing_payload_without_metadata_still_works(self) -> None:
        """Existing tests (non-metadata tasks) must still produce correct payloads."""
        queue_task = Task(
            id="queue-1",
            name="Queue Task",
            agent_type="InjectionSwarm",
            action="scan",
            params={"target": "https://example.test"},
            priority=42,
            parent_id="parent-1",
            replan_depth=1,
        )
        queue_task.state = TaskState.PENDING

        context = SimpleNamespace(
            _total_attempts=7,
            _successful_attempts=5,
            bypass_methods=["jwt_bypass"],
            discovered_assets=["api.example.test"],
            target_info={"target": "https://example.test", "start_time": 123.0},
        )

        payload = build_async_session_payload(
            task_queue=[queue_task],
            completed_tasks=[],
            context=context,
            pending_hitl=[],
            coverage_gate={},
            scenario_coverage={},
            timestamp=456.0,
            default_start_time=999.0,
        )

        # Legacy fields must still be present
        assert payload["task_queue"][0]["id"] == "queue-1"
        assert payload["task_queue"][0]["name"] == "Queue Task"
        assert payload["task_queue"][0]["state"] == "pending"
        assert payload["task_queue"][0]["priority"] == 42
        # Phase 1: metadata is always present (empty for non-metadata tasks)
        assert payload["task_queue"][0]["metadata"] == {}

    def test_metadata_secret_redaction_in_payload(self) -> None:
        """Metadata containing secrets must be redacted in session payload (F-1)."""
        task = Task(
            id="meta-secret",
            name="Secret Meta Task",
            agent_type="Recon",
            action="scan",
            params={"target": "https://example.test"},
            metadata={
                "target_key": "https://example.test",
                "origin_key": "recon://scenario-1",
                "cookie": "session=abc123secret",
                "token": "Bearer xyz789",
                "Authorization": "Bearer secret-auth",
            },
        )

        context = SimpleNamespace(
            _total_attempts=0, _successful_attempts=0,
            bypass_methods=[], discovered_assets=[], target_info={},
        )

        payload = build_async_session_payload(
            task_queue=[task],
            completed_tasks=[],
            context=context,
            pending_hitl=[],
            coverage_gate={},
            scenario_coverage={},
            timestamp=1.0,
            default_start_time=2.0,
        )

        md = payload["task_queue"][0]["metadata"]
        assert md["target_key"] == "https://example.test"
        assert md["origin_key"] == "recon://scenario-1"
        assert md["cookie"] == "[REDACTED]"
        assert md["token"] == "[REDACTED]"
        assert md["Authorization"] == "[REDACTED]"

    def test_metadata_schema_version_injected_in_payload(self) -> None:
        """Metadata without schema_version must get auto-injected in payload (F-2)."""
        task = Task(
            id="meta-no-version",
            name="No Version Task",
            agent_type="Recon",
            action="scan",
            params={"target": "https://example.test"},
            metadata={"target_key": "https://example.test"},
        )

        context = SimpleNamespace(
            _total_attempts=0, _successful_attempts=0,
            bypass_methods=[], discovered_assets=[], target_info={},
        )

        payload = build_async_session_payload(
            task_queue=[task],
            completed_tasks=[],
            context=context,
            pending_hitl=[],
            coverage_gate={},
            scenario_coverage={},
            timestamp=1.0,
            default_start_time=2.0,
        )

        md = payload["task_queue"][0]["metadata"]
        assert md["target_key"] == "https://example.test"
        assert md["schema_version"] == 1
