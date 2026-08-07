"""
SGK-2026-0426 W3 — fail-open fix verification flow (FO-1..FO-3) on the
VDP follow-up enqueue failure path.

FO-1 (pre-fix baseline): the 0427 instrumented run crashed at the follow-up
enqueue (attempts=0, verdicts=6) yet still produced a normal report and a
``consistent`` report/session pair — the fail-open defect. The historical
session shape is asserted from the real artifact; the pre-fix replay (session
without run_outcome + report without marker) still passes consistency,
pinning what the defect looked like.

FO-2: the fix (deferred injection buffer + main-thread drain) records
``run_outcome=follow_up_stage_failed`` + ``verdicts_finalized=false`` + the
S05 failed event with the W1 mechanism reason code (implemented in
``_record_vdp_follow_up_enqueue_failure``).

FO-3 (post-fix): (a) fault-injected enqueue failure is fail-closed at the
drain level; (b) report/consistency surface the failure (covered by
test_report_session_consistency.py W3 tests); (c) the healthy path stays
unchanged; (d) deterministic matrix {enqueue ok -> normal} x {enqueue fail
-> fail-closed}.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from src.core.engine.master_conductor import MasterConductor
from src.core.security.ethics_guard import ScopeDefinition

from tests.unit.engine.test_vdp_followup_thread_confinement import (
    _minimal_mc,
    _StubObservation,
)

SESSION_0427 = Path(
    "workspace/projects/localhost:3000/sessions/session_20260806_105634.json"
)


def _scope():
    return ScopeDefinition(
        program_name="vdp-follow-up",
        in_scope_domains=["opaque-target.test"],
        out_of_scope_domains=[],
        max_requests_per_minute=60,
    )


def _enqueue(mc, *, fail: bool):
    """Run the follow-up enqueue from a worker thread (production topology)
    and then drain on the main thread. ``fail`` injects an enqueue crash."""
    if fail:
        def _boom(tasks, source="vdp_follow_up"):
            raise AssertionError(
                "PCR-P1: task_queue mutation must be on main thread"
            )
        mc._add_tasks = _boom

    worker_error: list[BaseException] = []

    def _run():
        try:
            mc._queue_vdp_follow_ups(
                scope_definition=_scope(),
                checkpoint_path=None,
                observations=[_StubObservation()],
            )
        except BaseException as exc:  # noqa: BLE001 — capture
            worker_error.append(exc)

    worker = threading.Thread(target=_run)
    worker.start()
    worker.join(timeout=30)
    assert not worker.is_alive()
    assert worker_error == []
    return mc._drain_vdp_pending_follow_up_injections()


class TestFO1PreFixFailOpenBaseline:
    def test_historical_0427_session_shape(self):
        """FO-1: the real pre-fix session carries the fail-open signature:
        attempts=0, verdicts=6, and NO fail-closed run_outcome marker."""
        session = json.loads(SESSION_0427.read_text(encoding="utf-8"))
        vc = session.get("vdp_contract") or {}
        assert len(vc.get("attempts") or []) == 0
        assert len(vc.get("verdicts") or []) == 6
        assert vc.get("run_outcome") is None
        assert vc.get("verdicts_finalized") is None


class TestFO3PostFixFailClosed:
    def test_enqueue_failure_is_fail_closed(self):
        """FO-3(a): fault-injected enqueue failure at the drain sets the
        fail-closed markers (run_outcome, non-finalized verdicts) and emits
        the S05 failed event with the W1 mechanism reason code."""
        mc, _ = _minimal_mc(pytest.MonkeyPatch())
        mc._vdp_diagnostic_emit = _RecordingEmitter()
        drained = _enqueue(mc, fail=True)
        assert drained == 0
        assert mc._vdp_state.get("run_outcome") == "follow_up_stage_failed"
        assert mc._vdp_state.get("verdicts_finalized") is False
        s05 = [e for e in mc._vdp_diagnostic_emit.events if e["stage_id"] == "S05"]
        assert s05 and s05[0]["outcome"] == "failed"
        assert "queue_mutation_off_main_thread" in s05[0]["reason_codes"]

    def test_healthy_enqueue_stays_normal(self):
        """FO-3(c): the healthy path is unchanged — tasks queued, no
        fail-closed markers."""
        mc, _ = _minimal_mc(pytest.MonkeyPatch())
        mc._vdp_diagnostic_emit = _RecordingEmitter()
        drained = _enqueue(mc, fail=False)
        assert drained == 1
        assert mc._vdp_state.get("run_outcome") is None
        s05 = [e for e in mc._vdp_diagnostic_emit.events if e["stage_id"] == "S05"]
        assert s05 and s05[0]["outcome"] == "reached"

    @pytest.mark.parametrize(
        "fail,expected_outcome,expected_drained",
        [
            (False, None, 1),
            (True, "follow_up_stage_failed", 0),
        ],
    )
    def test_deterministic_matrix(
        self, fail, expected_outcome, expected_drained
    ):
        """FO-3(d): {enqueue ok -> normal complete} x {enqueue fail ->
        fail-closed} in one table test."""
        mc, _ = _minimal_mc(pytest.MonkeyPatch())
        drained = _enqueue(mc, fail=fail)
        assert drained == expected_drained
        assert mc._vdp_state.get("run_outcome") == expected_outcome


class _RecordingEmitter:
    """Records diagnostic events (replaces the MagicMock emitter)."""

    def __init__(self):
        self.events: list[dict] = []

    def __call__(self, **kwargs):
        self.events.append(dict(kwargs))
        return f"evt-{len(self.events)}"
