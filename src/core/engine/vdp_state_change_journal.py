"""
SGK-2026-0423 Lane J-2 — state-change write-ahead journal (durability).

The M3b state-changing send boundary must survive a process crash: the
in-memory ``StateChangeGuard.mark_sent`` is only durable once the checkpoint
save lands, and a crash between send and save would otherwise let another
process resend the mutation. This journal durably records the attempt
lifecycle BEFORE any network activity::

    begin(attempt_id)   -> "in_flight"   (durable, written BEFORE the send)
    mark_sent(...)      -> "sent"        (after a successful send)
    mark_failed(...)    -> "not_sent"    (any other outcome)

Invariant: a state-changing send happens ONLY after a durable ``begin``.
Recovery treats "in_flight" as outcome-unknown -> Hold, never auto-resend
(the send may or may not have happened — guessing would risk a double state
change).

Safety properties:
- Every write is atomic (temp file in the same directory + ``os.replace``).
- An unreadable or malformed journal raises ``StateChangeJournalError``
  (fail-closed — recovery must not guess).
- A ``begin`` for an attempt already ``in_flight`` or ``sent`` is a journal
  conflict (fail-closed); ``not_sent`` may be re-begun (nothing was sent).
- ``mark_sent``/``mark_failed`` without a prior ``begin`` is corruption.
- Entries contain IDs ONLY — never secrets or spec payloads.

Convention: ``StateChangeJournal.for_checkpoint(checkpoint_path)`` derives
the journal path as the checkpoint path + ``.wal.json`` (a sibling file), so
the journal travels with the checkpoint it protects.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class StateChangeJournalError(Exception):
    """Journal unreadable, malformed, or lifecycle-contract violation."""


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


class StateChangeJournal:
    """Durable write-ahead journal for M3b state-changing attempts.

    Path points at the journal FILE (not a directory). All reads re-parse
    the file from disk so a journal object is safe to share across
    "process" boundaries in tests and across calls in production.
    """

    _VALID_STATES = ("in_flight", "sent", "not_sent")

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def for_checkpoint(cls, checkpoint_path) -> "StateChangeJournal":
        """Journal path convention: ``<checkpoint_path>.wal.json`` — a
        sibling of the checkpoint it protects (documented convention)."""
        return cls(Path(str(checkpoint_path) + ".wal.json"))

    # ------------------------------------------------------------------
    # Lifecycle writes
    # ------------------------------------------------------------------

    def begin(
        self,
        attempt_id: str,
        *,
        next_action_id: str = "",
        hypothesis_id: str = "",
        task_id: str = "",
    ) -> dict:
        """Durably record the attempt as ``in_flight`` BEFORE the send.

        Raises ``StateChangeJournalError`` when the attempt_id is missing or
        an existing entry is ``in_flight``/``sent`` (journal conflict —
        fail-closed: a lifecycle already in progress must not be re-begun).
        A ``not_sent`` entry may be re-begun (nothing was transmitted).
        """
        attempt_id = str(attempt_id or "")
        if not attempt_id:
            raise StateChangeJournalError("attempt_id_required")
        entries = self.load()
        for index, entry in enumerate(entries):
            if entry.get("attempt_id") == attempt_id:
                if entry.get("state") in ("in_flight", "sent"):
                    raise StateChangeJournalError(
                        f"journal_conflict:{attempt_id}"
                    )
                entry.update(
                    {
                        "state": "in_flight",
                        "next_action_id": str(next_action_id or ""),
                        "hypothesis_id": str(hypothesis_id or ""),
                        "task_id": str(task_id or ""),
                        "began_at": _now_iso(),
                    }
                )
                self._write(entries)
                return dict(entries[index])
        entry = {
            "attempt_id": attempt_id,
            "state": "in_flight",
            "next_action_id": str(next_action_id or ""),
            "hypothesis_id": str(hypothesis_id or ""),
            "task_id": str(task_id or ""),
            "began_at": _now_iso(),
        }
        entries.append(entry)
        self._write(entries)
        return dict(entry)

    def mark_sent(self, attempt_id: str) -> None:
        """Transition ``in_flight`` -> ``sent`` (atomic rewrite).

        Raises ``StateChangeJournalError`` when the entry is absent (a sent
        fact without a begin is journal corruption). Already-``sent`` is
        idempotent.
        """
        self._transition(attempt_id, "sent")

    def mark_failed(self, attempt_id: str) -> None:
        """Transition ``in_flight`` -> ``not_sent`` (atomic rewrite)."""
        self._transition(attempt_id, "not_sent")

    def _transition(self, attempt_id: str, target: str) -> None:
        attempt_id = str(attempt_id or "")
        entries = self.load()
        for entry in entries:
            if entry.get("attempt_id") != attempt_id:
                continue
            current = entry.get("state")
            if current == target:
                return  # idempotent
            if current != "in_flight":
                raise StateChangeJournalError(
                    f"journal_corruption:{attempt_id}:{current}"
                )
            entry["state"] = target
            self._write(entries)
            return
        if target == "sent":
            raise StateChangeJournalError(f"sent_without_begin:{attempt_id}")
        raise StateChangeJournalError(f"failed_without_begin:{attempt_id}")

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def state(self, attempt_id: str) -> Optional[str]:
        """Current journal state of the attempt, or None when unknown."""
        attempt_id = str(attempt_id or "")
        for entry in self.load():
            if entry.get("attempt_id") == attempt_id:
                return str(entry.get("state") or "")
        return None

    def load(self) -> List[dict]:
        """All journal entries (deep-copied).

        A missing file is an empty journal (no state change ever begun);
        an unreadable or malformed file raises ``StateChangeJournalError``
        (fail-closed — recovery must not guess).
        """
        if not self.path.exists():
            return []
        try:
            raw = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            raise StateChangeJournalError("journal_unreadable") from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise StateChangeJournalError("journal_malformed_json") from exc
        if not isinstance(data, list):
            raise StateChangeJournalError("journal_malformed")
        entries: List[dict] = []
        for item in data:
            if not isinstance(item, dict):
                raise StateChangeJournalError("journal_malformed")
            if (
                not str(item.get("attempt_id") or "")
                or str(item.get("state") or "") not in self._VALID_STATES
            ):
                raise StateChangeJournalError("journal_malformed")
            entries.append(dict(item))
        return entries

    def in_flight(self) -> List[str]:
        """Attempt IDs currently in the outcome-unknown state."""
        return [
            str(entry.get("attempt_id") or "")
            for entry in self.load()
            if entry.get("state") == "in_flight"
        ]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _write(self, entries: List[Dict[str, Any]]) -> None:
        """Atomic rewrite of the whole journal (temp file + os.replace)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            dir=str(self.path.parent),
            prefix=f".{self.path.name}.",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(entries, handle, indent=2, sort_keys=True)
            os.replace(tmp_name, self.path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
