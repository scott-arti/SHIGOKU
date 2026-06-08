from pathlib import Path

from src.main import _extract_hitl_tickets_from_session_data
from src.main import _session_order_key
from src.main import _select_hitl_session


def test_extract_hitl_tickets_supports_context_fallback() -> None:
    data = {"context": {"pending_hitl": [{"ticket_id": "t1", "status": "pending"}]}}
    tickets = _extract_hitl_tickets_from_session_data(data)
    assert len(tickets) == 1
    assert tickets[0]["ticket_id"] == "t1"


def test_select_hitl_session_prefers_actionable_ticket_session() -> None:
    parsed_sessions = [
        (Path("session_new_done.json"), {"pending_hitl": [{"ticket_id": "done1", "status": "done"}]}),
        (Path("session_old_pending.json"), {"pending_hitl": [{"ticket_id": "p1", "status": "pending"}]}),
    ]

    selected, reason = _select_hitl_session(parsed_sessions)
    assert selected == Path("session_old_pending.json")
    assert reason == "latest session with actionable HITL tickets"


def test_select_hitl_session_prefers_requested_ticket_id() -> None:
    parsed_sessions = [
        (Path("session_new_pending.json"), {"pending_hitl": [{"ticket_id": "p1", "status": "pending"}]}),
        (Path("session_old_target.json"), {"pending_hitl": [{"ticket_id": "target", "status": "done"}]}),
    ]

    selected, reason = _select_hitl_session(parsed_sessions, requested_ticket_ids={"target"})
    assert selected == Path("session_old_target.json")
    assert reason == "session containing specified HITL ticket(s)"


def test_select_hitl_session_falls_back_to_hitl_history_when_no_actionable() -> None:
    parsed_sessions = [
        (Path("session_new_done.json"), {"pending_hitl": [{"ticket_id": "done1", "status": "done"}]}),
        (Path("session_old_valid.json"), {"completed_tasks": []}),
    ]

    selected, reason = _select_hitl_session(parsed_sessions)
    assert selected == Path("session_new_done.json")
    assert reason == "latest session with HITL ticket history"


def test_select_hitl_session_ignores_stale_pending_when_newer_ticket_is_done() -> None:
    parsed_sessions = [
        (Path("session_new_done.json"), {"pending_hitl": [{"ticket_id": "t1", "status": "done"}]}),
        (Path("session_old_pending.json"), {"pending_hitl": [{"ticket_id": "t1", "status": "pending"}]}),
    ]

    selected, reason = _select_hitl_session(parsed_sessions)
    assert selected == Path("session_new_done.json")
    assert reason == "latest session with HITL ticket history"


def test_session_order_key_prefers_filename_sequence_over_mtime() -> None:
    old = Path("session_20260409_010000.json")
    new = Path("session_20260409_020000.json")

    # mtimeに依存しない比較（filename時刻を優先）
    assert _session_order_key(new)[0] > _session_order_key(old)[0]
