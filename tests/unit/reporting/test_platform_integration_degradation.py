from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.core.reporting.platform_integration import PlatformAPI, PlatformIntegrationManager, ReportDraft


class _StubPlatformAPI(PlatformAPI):
    def __init__(self) -> None:
        self.create_calls = 0

    async def create_draft(self, draft: ReportDraft) -> str:
        self.create_calls += 1
        return "https://example.test/draft/1"

    async def get_programs(self):
        return []

    async def get_program_scope(self, program_id: str):
        return {}


class _FailingPlatformAPI(PlatformAPI):
    async def create_draft(self, draft: ReportDraft) -> str:
        raise RuntimeError("platform create failed")

    async def get_programs(self):
        return []

    async def get_program_scope(self, program_id: str):
        return {}


@pytest.mark.asyncio
async def test_create_draft_on_platform_blocks_submit_when_report_adapter_is_degraded(monkeypatch) -> None:
    manager = PlatformIntegrationManager()
    api = _StubPlatformAPI()
    manager.register_platform("hackerone", api)

    captured: dict[str, object] = {}

    def _fake_emit(*, component_status, degradation_result, audit_context):
        captured["component_status"] = component_status
        captured["degradation_result"] = degradation_result
        captured["audit_context"] = audit_context
        return {
            "audit_event_id": "audit-123",
            "decision_id": "dec_123",
            "final_state": degradation_result["state"],
            "submit_blocked": degradation_result["submit_blocked"],
        }

    monkeypatch.setattr(
        "src.core.reporting.platform_integration.emit_report_adapter_degradation_audit",
        _fake_emit,
    )

    draft = ReportDraft(
        title="ATO chain",
        summary="summary",
        description="description",
        severity="high",
        evidence={},
        reproduction_steps=["1. replay"],
    )
    canonical_payload = {
        "title": "ATO chain",
        "severity": "high",
        "business_impact_sentence": "impact",
        "boundary_cross_proof": "proof",
        "victim_impact": "victim",
        "remediation": "fix",
        "falsification_result": "stable",
        "reproduction_steps": ["1. replay"],
        "goal_state_assertions": {"cross_user_data_access": True},
        "minimal_success_runbook": ["step1"],
    }
    replay_queue_path = Path("tmp/test-report-adapter-replay-queue.jsonl")
    if replay_queue_path.exists():
        replay_queue_path.unlink()

    with pytest.raises(RuntimeError, match="report_adapter_degraded"):
        await manager.create_draft_on_platform(
            "hackerone",
            draft,
            degradation_result={
                "state": "continue",
                "reason": "report_adapter_degraded",
                "submit_blocked": True,
                "replay_verdict": "required",
                "fallbacks": {"report_adapter": "canonical_payload_only"},
                "recovery_actions": {"report_adapter": "replay_canonical_payload"},
            },
            component_status={"report_adapter": "degraded"},
            audit_context={"correlation_id": "corr-123", "policy_version": "phase2_degrade_v1"},
            canonical_payload=canonical_payload,
            replay_queue_path=replay_queue_path,
        )

    assert api.create_calls == 0
    assert captured["component_status"] == {"report_adapter": "degraded"}
    assert captured["degradation_result"]["submit_blocked"] is True
    assert captured["audit_context"]["correlation_id"] == "corr-123"
    rows = replay_queue_path.read_text(encoding="utf-8").splitlines()
    assert len(rows) == 1
    record = json.loads(rows[0])
    assert record["platform"] == "hackerone"
    assert record["reason"] == "report_adapter_degraded"
    assert record["replay_status"] == "pending"
    assert record["canonical_report_payload"]["title"] == "ATO chain"
    assert record["correlation_id"] == "corr-123"
    replay_queue_path.unlink()


@pytest.mark.asyncio
async def test_create_draft_on_platform_calls_api_when_report_adapter_is_healthy(monkeypatch) -> None:
    manager = PlatformIntegrationManager()
    api = _StubPlatformAPI()
    manager.register_platform("hackerone", api)

    emitted = {"called": False}

    def _fake_emit(*, component_status, degradation_result, audit_context):
        emitted["called"] = True
        return {}

    monkeypatch.setattr(
        "src.core.reporting.platform_integration.emit_report_adapter_degradation_audit",
        _fake_emit,
    )

    draft = ReportDraft(
        title="ATO chain",
        summary="summary",
        description="description",
        severity="high",
        evidence={},
        reproduction_steps=["1. replay"],
    )

    url = await manager.create_draft_on_platform(
        "hackerone",
        draft,
        degradation_result={
            "state": "continue",
            "reason": "nominal",
            "submit_blocked": False,
            "replay_verdict": "not_required",
            "fallbacks": {},
            "recovery_actions": {},
        },
        component_status={"report_adapter": "healthy"},
        audit_context={"correlation_id": "corr-healthy", "policy_version": "phase2_degrade_v1"},
    )

    assert url == "https://example.test/draft/1"
    assert api.create_calls == 1
    assert emitted["called"] is False


@pytest.mark.asyncio
async def test_create_draft_on_platform_requires_canonical_payload_to_enqueue_replay() -> None:
    manager = PlatformIntegrationManager()
    api = _StubPlatformAPI()
    manager.register_platform("hackerone", api)

    draft = ReportDraft(
        title="ATO chain",
        summary="summary",
        description="description",
        severity="high",
        evidence={},
        reproduction_steps=["1. replay"],
    )

    with pytest.raises(ValueError, match="canonical_payload required"):
        await manager.create_draft_on_platform(
            "hackerone",
            draft,
            degradation_result={
                "state": "continue",
                "reason": "report_adapter_degraded",
                "submit_blocked": True,
                "replay_verdict": "required",
                "fallbacks": {"report_adapter": "canonical_payload_only"},
                "recovery_actions": {"report_adapter": "replay_canonical_payload"},
            },
            component_status={"report_adapter": "degraded"},
            audit_context={"correlation_id": "corr-123", "policy_version": "phase2_degrade_v1"},
        )

    assert api.create_calls == 0


@pytest.mark.asyncio
async def test_replay_pending_submissions_replays_pending_entry(tmp_path: Path) -> None:
    manager = PlatformIntegrationManager()
    api = _StubPlatformAPI()
    manager.register_platform("hackerone", api)
    replay_queue_path = tmp_path / "report_adapter_replay_queue.jsonl"
    replay_queue_path.write_text(
        json.dumps(
            {
                "queue_id": "replay-123",
                "created_at": "2026-06-03T00:00:00Z",
                "platform": "hackerone",
                "canonical_report_payload": {
                    "title": "ATO chain",
                    "severity": "high",
                    "business_impact_sentence": "impact",
                    "boundary_cross_proof": "proof",
                    "victim_impact": "victim",
                    "remediation": "fix",
                    "falsification_result": "stable",
                    "reproduction_steps": ["1. replay"],
                    "goal_state_assertions": {"cross_user_data_access": True},
                    "minimal_success_runbook": ["step1"],
                },
                "reason": "report_adapter_degraded",
                "replay_status": "pending",
                "correlation_id": "corr-123",
                "policy_version": "phase2_degrade_v1",
                "degradation_state": "continue",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = await manager.replay_pending_submissions(
        "hackerone",
        component_status={"report_adapter": "healthy"},
        replay_queue_path=replay_queue_path,
    )

    assert result["replayed"] == 1
    assert result["failed"] == 0
    assert api.create_calls == 1
    record = json.loads(replay_queue_path.read_text(encoding="utf-8").splitlines()[0])
    assert record["replay_status"] == "completed"
    assert record["replay_url"] == "https://example.test/draft/1"
    assert record["replayed_at"]


@pytest.mark.asyncio
async def test_replay_pending_submissions_marks_failure_when_platform_submit_fails(tmp_path: Path) -> None:
    manager = PlatformIntegrationManager()
    manager.register_platform("hackerone", _FailingPlatformAPI())
    replay_queue_path = tmp_path / "report_adapter_replay_queue.jsonl"
    replay_queue_path.write_text(
        json.dumps(
            {
                "queue_id": "replay-123",
                "created_at": "2026-06-03T00:00:00Z",
                "platform": "hackerone",
                "canonical_report_payload": {
                    "title": "ATO chain",
                    "severity": "high",
                    "business_impact_sentence": "impact",
                    "boundary_cross_proof": "proof",
                    "victim_impact": "victim",
                    "remediation": "fix",
                    "falsification_result": "stable",
                    "reproduction_steps": ["1. replay"],
                    "goal_state_assertions": {"cross_user_data_access": True},
                    "minimal_success_runbook": ["step1"],
                },
                "reason": "report_adapter_degraded",
                "replay_status": "pending",
                "correlation_id": "corr-123",
                "policy_version": "phase2_degrade_v1",
                "degradation_state": "continue",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = await manager.replay_pending_submissions(
        "hackerone",
        component_status={"report_adapter": "healthy"},
        replay_queue_path=replay_queue_path,
    )

    assert result["replayed"] == 0
    assert result["failed"] == 1
    record = json.loads(replay_queue_path.read_text(encoding="utf-8").splitlines()[0])
    assert record["replay_status"] == "failed"
    assert "platform create failed" in record["replay_error"]


@pytest.mark.asyncio
async def test_create_draft_on_platform_auto_replays_pending_queue_on_recovery(monkeypatch, tmp_path: Path) -> None:
    manager = PlatformIntegrationManager()
    api = _StubPlatformAPI()
    manager.register_platform("hackerone", api)
    replay_queue_path = tmp_path / "report_adapter_replay_queue.jsonl"
    replay_queue_path.write_text(
        json.dumps(
            {
                "queue_id": "replay-123",
                "created_at": "2026-06-03T00:00:00Z",
                "platform": "hackerone",
                "canonical_report_payload": {
                    "title": "Old ATO chain",
                    "severity": "high",
                    "business_impact_sentence": "impact",
                    "boundary_cross_proof": "proof",
                    "victim_impact": "victim",
                    "remediation": "fix",
                    "falsification_result": "stable",
                    "reproduction_steps": ["1. replay"],
                    "goal_state_assertions": {"cross_user_data_access": True},
                    "minimal_success_runbook": ["step1"],
                },
                "reason": "report_adapter_degraded",
                "replay_status": "pending",
                "correlation_id": "corr-123",
                "policy_version": "phase2_degrade_v1",
                "degradation_state": "continue",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    draft = ReportDraft(
        title="Fresh chain",
        summary="summary",
        description="description",
        severity="high",
        evidence={},
        reproduction_steps=["1. replay"],
    )

    url = await manager.create_draft_on_platform(
        "hackerone",
        draft,
        degradation_result={
            "state": "continue",
            "reason": "nominal",
            "submit_blocked": False,
            "replay_verdict": "not_required",
            "fallbacks": {},
            "recovery_actions": {},
        },
        component_status={"report_adapter": "healthy"},
        audit_context={"correlation_id": "corr-healthy", "policy_version": "phase2_degrade_v1"},
        replay_queue_path=replay_queue_path,
    )

    assert url == "https://example.test/draft/1"
    assert api.create_calls == 2
    record = json.loads(replay_queue_path.read_text(encoding="utf-8").splitlines()[0])
    assert record["replay_status"] == "completed"


def test_retry_failed_submissions_resets_failed_records(tmp_path: Path) -> None:
    from src.core.reporting.platform_integration import retry_failed_report_adapter_replay

    replay_queue_path = tmp_path / "report_adapter_replay_queue.jsonl"
    replay_queue_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "queue_id": "replay-1",
                        "platform": "hackerone",
                        "replay_status": "failed",
                        "replay_error": "platform create failed",
                    }
                ),
                json.dumps(
                    {
                        "queue_id": "replay-2",
                        "platform": "hackerone",
                        "replay_status": "completed",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = retry_failed_report_adapter_replay(
        platform="hackerone",
        replay_queue_path=replay_queue_path,
    )

    assert result["reset"] == 1
    assert result["skipped"] == 1
    records = [json.loads(line) for line in replay_queue_path.read_text(encoding="utf-8").splitlines()]
    assert records[0]["replay_status"] == "pending"
    assert "replay_error" not in records[0]
    assert records[0]["retry_requested_at"]


def test_retry_failed_submissions_filters_by_queue_id(tmp_path: Path) -> None:
    from src.core.reporting.platform_integration import retry_failed_report_adapter_replay

    replay_queue_path = tmp_path / "report_adapter_replay_queue.jsonl"
    replay_queue_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "queue_id": "replay-1",
                        "platform": "hackerone",
                        "replay_status": "failed",
                        "replay_error": "boom-1",
                    }
                ),
                json.dumps(
                    {
                        "queue_id": "replay-2",
                        "platform": "hackerone",
                        "replay_status": "failed",
                        "replay_error": "boom-2",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = retry_failed_report_adapter_replay(
        platform="hackerone",
        replay_queue_path=replay_queue_path,
        queue_id="replay-2",
    )

    assert result["reset"] == 1
    records = [json.loads(line) for line in replay_queue_path.read_text(encoding="utf-8").splitlines()]
    assert records[0]["replay_status"] == "failed"
    assert records[1]["replay_status"] == "pending"


def test_list_report_adapter_replay_queue_filters_by_platform_and_queue_id(tmp_path: Path) -> None:
    from src.core.reporting.platform_integration import list_report_adapter_replay_queue

    replay_queue_path = tmp_path / "report_adapter_replay_queue.jsonl"
    replay_queue_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "queue_id": "replay-1",
                        "platform": "hackerone",
                        "replay_status": "failed",
                    }
                ),
                json.dumps(
                    {
                        "queue_id": "replay-2",
                        "platform": "bugcrowd",
                        "replay_status": "pending",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = list_report_adapter_replay_queue(
        replay_queue_path=replay_queue_path,
        platform="hackerone",
        queue_id="replay-1",
    )

    assert result["count"] == 1
    assert result["records"][0]["queue_id"] == "replay-1"


def test_list_report_adapter_replay_queue_filters_by_status(tmp_path: Path) -> None:
    from src.core.reporting.platform_integration import list_report_adapter_replay_queue

    replay_queue_path = tmp_path / "report_adapter_replay_queue.jsonl"
    replay_queue_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "queue_id": "replay-1",
                        "platform": "hackerone",
                        "replay_status": "failed",
                    }
                ),
                json.dumps(
                    {
                        "queue_id": "replay-2",
                        "platform": "hackerone",
                        "replay_status": "pending",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = list_report_adapter_replay_queue(
        replay_queue_path=replay_queue_path,
        platform="hackerone",
        status="pending",
    )

    assert result["count"] == 1
    assert result["records"][0]["queue_id"] == "replay-2"
