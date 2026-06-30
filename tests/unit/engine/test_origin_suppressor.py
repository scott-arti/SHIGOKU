"""
Phase 7 Task 2: Origin Suppressor standalone tests (SGK-2026-0316).

Focused tests for the OriginSuppressor class.
"""
from src.core.engine.origin_suppressor import OriginSuppressor


def test_aggressive_origin_suppresses_other_lanes_until_released():
    suppressor = OriginSuppressor()
    suppressor.enter("https://example.com", lane="aggressive_exclusive", owner_task_id="aggr-1")

    decision = suppressor.check("https://example.com", lane="read_only", task_id="read-1")

    assert decision.allowed is False
    assert decision.reason_code == "origin_suppressed_by_aggressive"
    assert decision.owner_task_id == "aggr-1"

    suppressor.release("https://example.com", owner_task_id="aggr-1")
    assert suppressor.check("https://example.com", lane="read_only", task_id="read-1").allowed is True


def test_aggressive_does_not_suppress_same_lane_on_same_origin():
    suppressor = OriginSuppressor()
    suppressor.enter("https://example.com", lane="aggressive_exclusive", owner_task_id="aggr-1")

    decision = suppressor.check("https://example.com", lane="aggressive_exclusive", task_id="aggr-2")

    assert decision.allowed is True


def test_different_origin_not_affected():
    suppressor = OriginSuppressor()
    suppressor.enter("https://a.example.com", lane="aggressive_exclusive", owner_task_id="aggr-1")

    decision = suppressor.check("https://b.example.com", lane="read_only", task_id="read-1")

    assert decision.allowed is True


def test_suppressor_allows_stateful_read_on_different_origin():
    suppressor = OriginSuppressor()
    suppressor.enter("https://a.example.com", lane="aggressive_exclusive", owner_task_id="aggr-1")

    decision = suppressor.check("https://a.example.com", lane="stateful_read", task_id="sr-1")

    assert decision.allowed is False
    assert decision.reason_code == "origin_suppressed_by_aggressive"


def test_empty_origin_key_always_allows():
    suppressor = OriginSuppressor()
    suppressor.enter("https://example.com", lane="aggressive_exclusive", owner_task_id="aggr-1")

    decision = suppressor.check("", lane="read_only", task_id="read-1")

    assert decision.allowed is True


def test_release_wrong_owner_does_not_release():
    suppressor = OriginSuppressor()
    suppressor.enter("https://example.com", lane="aggressive_exclusive", owner_task_id="aggr-1")

    suppressor.release("https://example.com", owner_task_id="wrong-owner")

    decision = suppressor.check("https://example.com", lane="read_only", task_id="read-1")
    assert decision.allowed is False


def test_enter_non_aggressive_lane_does_nothing():
    suppressor = OriginSuppressor()
    suppressor.enter("https://example.com", lane="read_only", owner_task_id="ro-1")

    decision = suppressor.check("https://example.com", lane="read_only", task_id="ro-2")

    assert decision.allowed is True


def test_multiple_aggressive_owners_last_wins():
    suppressor = OriginSuppressor()
    suppressor.enter("https://example.com", lane="aggressive_exclusive", owner_task_id="aggr-1")
    suppressor.enter("https://example.com", lane="aggressive_exclusive", owner_task_id="aggr-2")

    decision = suppressor.check("https://example.com", lane="read_only", task_id="read-1")
    assert decision.allowed is False
    assert decision.owner_task_id == "aggr-2"


def test_release_then_enter_new_owner():
    suppressor = OriginSuppressor()
    suppressor.enter("https://example.com", lane="aggressive_exclusive", owner_task_id="aggr-1")
    suppressor.release("https://example.com", owner_task_id="aggr-1")
    # Origin should be clear
    assert suppressor.check("https://example.com", lane="read_only", task_id="read-1").allowed is True
    # New owner can enter
    suppressor.enter("https://example.com", lane="aggressive_exclusive", owner_task_id="aggr-3")
    assert suppressor.check("https://example.com", lane="read_only", task_id="read-2").allowed is False
