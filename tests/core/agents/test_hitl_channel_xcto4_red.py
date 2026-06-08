"""
XCTO-4 HITL通知チャネル Red テスト。

目的:
- 計画書 5.3/5.4 で定義した懸念点対策を、実装前に失敗するテストで固定する。
- 本ファイルは「まだ未実装の仕様」を先にテスト化するため、現状は失敗が正しい。
"""

from __future__ import annotations

import pytest

from src.core.agents.swarm.injection.stored_xss_detector import (
    FormRiskLevel,
    HITLGate,
    ParsedForm,
)


@pytest.mark.asyncio
async def test_hitl_gate_supports_approval_callback_for_external_control():
    """
    XCTO-4 要件:
    - approval_callback 注入で外部承認制御可能
    """

    async def approval_callback(_request):
        return True

    gate = HITLGate(auto_approve_low_risk=False, approval_callback=approval_callback)
    form = ParsedForm("/create", "POST", {"name": "x"}, FormRiskLevel.MEDIUM)

    approved = await gate.request_approval(form, {"name": "payload"}, "payload injection")
    assert approved is True


@pytest.mark.asyncio
async def test_hitl_gate_persists_request_in_store():
    """
    XCTO-4 要件:
    - pending をメモリだけでなく永続ストアへ保存
    """
    from src.core.agents.swarm.injection.stored_xss_detector import HITLRequestStore

    store = HITLRequestStore(":memory:")
    gate = HITLGate(auto_approve_low_risk=False, request_store=store)
    form = ParsedForm("/create", "POST", {"name": "x"}, FormRiskLevel.MEDIUM)

    await gate.request_approval(form, {"name": "payload"}, "payload injection")
    saved = store.list_pending()
    assert len(saved) == 1
    assert saved[0]["form_action"] == "/create"


@pytest.mark.asyncio
async def test_hitl_gate_retries_notification_channel_with_backoff():
    """
    XCTO-4 要件:
    - timeout/retry/backoff/max_attempts が実装される
    """
    calls = {"count": 0}

    class DummyChannel:
        async def send(self, _request):
            calls["count"] += 1
            if calls["count"] < 3:
                raise TimeoutError("channel timeout")
            return "ticket-1"

    gate = HITLGate(
        auto_approve_low_risk=False,
        notification_channel=DummyChannel(),
        notification_retry=3,
        notification_backoff_seconds=[0.01, 0.02, 0.03],
    )
    form = ParsedForm("/create", "POST", {"name": "x"}, FormRiskLevel.MEDIUM)

    await gate.request_approval(form, {"name": "payload"}, "payload injection")
    assert calls["count"] == 3


@pytest.mark.asyncio
async def test_hitl_gate_fail_closed_when_notification_channel_down():
    """
    XCTO-4 要件:
    - チャネル障害時に fail-closed
    - error_code を記録
    """

    class FailingChannel:
        async def send(self, _request):
            raise ConnectionError("channel down")

    gate = HITLGate(
        auto_approve_low_risk=False,
        notification_channel=FailingChannel(),
        notification_retry=1,
    )
    form = ParsedForm("/create", "POST", {"name": "x"}, FormRiskLevel.MEDIUM)

    approved = await gate.request_approval(form, {"name": "payload"}, "payload injection")
    assert approved is False

    pending = gate.get_pending_requests()
    assert len(pending) == 1
    assert getattr(pending[0], "error_code") == "notification_failed"


@pytest.mark.asyncio
async def test_hitl_request_has_ticket_metadata_for_observability():
    """
    XCTO-4 要件:
    - ticket_id/risk_level/channel/status/error_code/timestamp を記録
    """
    gate = HITLGate(auto_approve_low_risk=False)
    form = ParsedForm("/create", "POST", {"name": "x"}, FormRiskLevel.MEDIUM)

    await gate.request_approval(form, {"name": "payload"}, "payload injection")
    req = gate.get_pending_requests()[0]

    assert hasattr(req, "ticket_id")
    assert hasattr(req, "status")
    assert hasattr(req, "channel")
    assert hasattr(req, "error_code")
    assert hasattr(req, "timestamp")


@pytest.mark.asyncio
async def test_hitl_state_transition_is_single_direction_with_cas():
    """
    XCTO-4 要件:
    - PENDING -> APPROVED/REJECTED/EXPIRED 単方向
    - 失効後承認などを拒否
    """
    gate = HITLGate(auto_approve_low_risk=False)
    form = ParsedForm("/create", "POST", {"name": "x"}, FormRiskLevel.MEDIUM)

    await gate.request_approval(form, {"name": "payload"}, "payload injection")
    req = gate.get_pending_requests()[0]

    # first transition
    changed = gate.transition_request(req.ticket_id, from_status="PENDING", to_status="EXPIRED")
    assert changed is True

    # invalid transition after EXPIRED
    changed_again = gate.transition_request(req.ticket_id, from_status="EXPIRED", to_status="APPROVED")
    assert changed_again is False


@pytest.mark.asyncio
async def test_hitl_gate_exposes_operational_kpis():
    """
    XCTO-4 要件:
    - 通知到達率/承認取得率/平均承認時間/失効率/fail-closed率
    """
    gate = HITLGate(auto_approve_low_risk=False)
    metrics = gate.get_metrics()

    expected_keys = {
        "notification_delivery_rate",
        "approval_rate",
        "avg_approval_latency_seconds",
        "expiration_rate",
        "fail_closed_rate",
    }
    assert expected_keys.issubset(metrics.keys())

