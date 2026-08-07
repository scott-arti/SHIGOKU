"""
SGK-2026-0423 Lane J-2 — state-change write-ahead journal (TDD).

Crash-safe no-auto-resend for M3b state-changing sends: the journal records
the attempt lifecycle DURABLY before any network activity, so a process
crash between send and checkpoint save cannot lose the sent fact.

Lifecycle::

    begin(attempt_id)  -> "in_flight"   (durable, BEFORE the send)
    mark_sent(...)     -> "sent"        (after a successful send)
    mark_failed(...)   -> "not_sent"    (any other outcome)

Recovery treats "in_flight" as outcome-unknown -> Hold, never auto-resend.
Every write is atomic (temp file + os.replace); an unreadable or malformed
journal fails CLOSED (recovery must not guess). Entries contain IDs only —
never secrets or spec payloads.
"""
from __future__ import annotations

import json

import pytest

from src.core.engine.vdp_state_change_journal import (
    StateChangeJournal,
    StateChangeJournalError,
)


class TestJournalBegin:
    def test_begin_writes_durable_entry(self, tmp_path):
        """begin() persists an in_flight entry; a NEW journal object on the
        same path (process restart) sees it."""
        path = tmp_path / "ck.json.wal.json"
        journal = StateChangeJournal(path)
        entry = journal.begin(
            "att-1",
            next_action_id="nxt-1",
            hypothesis_id="hyp-1",
            task_id="task-1",
        )
        assert entry["attempt_id"] == "att-1"
        assert entry["state"] == "in_flight"
        assert entry["next_action_id"] == "nxt-1"

        reloaded = StateChangeJournal(path)
        assert reloaded.state("att-1") == "in_flight"
        entries = reloaded.load()
        assert len(entries) == 1
        assert entries[0]["attempt_id"] == "att-1"
        assert entries[0]["state"] == "in_flight"

    def test_begin_conflict_second_begin_raises(self, tmp_path):
        """A second begin() for the SAME attempt fails closed (journal
        conflict) — an in_flight/sent entry means the attempt already has a
        lifecycle and must not be re-begun."""
        journal = StateChangeJournal(tmp_path / "ck.json.wal.json")
        journal.begin("att-1")
        with pytest.raises(StateChangeJournalError, match="journal_conflict"):
            journal.begin("att-1")
        with pytest.raises(StateChangeJournalError, match="journal_conflict"):
            journal.begin("att-1", next_action_id="nxt-other")

    def test_begin_requires_attempt_id(self, tmp_path):
        journal = StateChangeJournal(tmp_path / "ck.json.wal.json")
        with pytest.raises(StateChangeJournalError, match="attempt_id_required"):
            journal.begin("")


class TestJournalTransitions:
    def test_mark_sent_transition_and_reload(self, tmp_path):
        path = tmp_path / "ck.json.wal.json"
        journal = StateChangeJournal(path)
        journal.begin("att-2")
        journal.mark_sent("att-2")
        assert journal.state("att-2") == "sent"
        reloaded = StateChangeJournal(path)
        assert reloaded.state("att-2") == "sent"
        assert [e["attempt_id"] for e in reloaded.load()] == ["att-2"]

    def test_mark_failed_transition(self, tmp_path):
        path = tmp_path / "ck.json.wal.json"
        journal = StateChangeJournal(path)
        journal.begin("att-3")
        journal.mark_failed("att-3")
        assert journal.state("att-3") == "not_sent"
        assert StateChangeJournal(path).state("att-3") == "not_sent"

    def test_mark_sent_without_begin_raises(self, tmp_path):
        """A sent fact without a begin is journal corruption — raise."""
        journal = StateChangeJournal(tmp_path / "ck.json.wal.json")
        with pytest.raises(StateChangeJournalError, match="sent_without_begin"):
            journal.mark_sent("att-never-begun")

    def test_mark_failed_without_begin_raises(self, tmp_path):
        journal = StateChangeJournal(tmp_path / "ck.json.wal.json")
        with pytest.raises(StateChangeJournalError):
            journal.mark_failed("att-never-begun")

    def test_begin_after_not_sent_allowed(self, tmp_path):
        """A failed (not_sent) attempt never transmitted — re-beginning is
        safe (the in-memory idempotency guard, not the journal, is what
        blocks a same-process retry)."""
        path = tmp_path / "ck.json.wal.json"
        journal = StateChangeJournal(path)
        journal.begin("att-4")
        journal.mark_failed("att-4")
        journal.begin("att-4")
        assert journal.state("att-4") == "in_flight"


class TestJournalQueries:
    def test_in_flight_lists_only_in_flight(self, tmp_path):
        path = tmp_path / "ck.json.wal.json"
        journal = StateChangeJournal(path)
        journal.begin("att-a")
        journal.begin("att-b")
        journal.begin("att-c")
        journal.mark_sent("att-b")
        journal.mark_failed("att-c")
        assert sorted(journal.in_flight()) == ["att-a"]

    def test_state_unknown_attempt_is_none(self, tmp_path):
        journal = StateChangeJournal(tmp_path / "ck.json.wal.json")
        assert journal.state("att-unknown") is None


class TestJournalFailClosed:
    def test_corrupt_journal_file_raises(self, tmp_path):
        """Malformed JSON fails CLOSED — recovery must not guess."""
        path = tmp_path / "ck.json.wal.json"
        path.write_text("{not json", encoding="utf-8")
        journal = StateChangeJournal(path)
        with pytest.raises(StateChangeJournalError):
            journal.state("att-1")
        with pytest.raises(StateChangeJournalError):
            journal.load()

    def test_malformed_entry_shape_raises(self, tmp_path):
        path = tmp_path / "ck.json.wal.json"
        path.write_text(json.dumps([{"attempt_id": "att-1", "state": "flying"}]), encoding="utf-8")
        with pytest.raises(StateChangeJournalError):
            StateChangeJournal(path).load()

    def test_missing_journal_file_is_empty(self, tmp_path):
        """A missing journal (no state change ever begun) is NOT an error."""
        journal = StateChangeJournal(tmp_path / "missing.json.wal.json")
        assert journal.load() == []
        assert journal.state("att-1") is None


class TestJournalConvention:
    def test_for_checkpoint_path_convention(self, tmp_path):
        """for_checkpoint derives a sibling ``<checkpoint>.wal.json``."""
        journal = StateChangeJournal.for_checkpoint(tmp_path / "sessions" / "vdp_checkpoint_x.json")
        assert str(journal.path) == str(
            tmp_path / "sessions" / "vdp_checkpoint_x.json.wal.json"
        )

    def test_entries_never_carry_spec_payload(self, tmp_path):
        """Entries contain IDs only — a spec-like payload must never leak."""
        path = tmp_path / "ck.json.wal.json"
        journal = StateChangeJournal(path)
        journal.begin("att-secret", next_action_id="nxt-1", hypothesis_id="hyp-1", task_id="task-1")
        raw = path.read_text(encoding="utf-8")
        assert "vdp_follow_up_spec" not in raw
        assert "url" not in raw
        assert "Authorization" not in raw
        assert "token" not in raw
