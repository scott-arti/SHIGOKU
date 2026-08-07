"""
Task queue main-thread enforcement — SGK-2026-0421 (C23 fix).

PCR-P1 asserts must be real executable code (previously they lived inside
docstrings and never ran). Every mutation entry point must reject
non-main-thread callers with AssertionError.
"""
from __future__ import annotations

import threading

import pytest

from src.core.engine.task_queue import DynamicTaskQueue
from src.core.domain.model.task import Task


def _task(tid: str) -> Task:
    return Task(id=tid, name=f"task-{tid}", agent_type="universal")


def _run_in_thread(fn, *args):
    errors: list = []

    def target():
        try:
            fn(*args)
        except BaseException as exc:  # noqa: BLE001 - captured for assertion
            errors.append(exc)

    t = threading.Thread(target=target)
    t.start()
    t.join(timeout=10)
    assert not t.is_alive(), "worker thread hung"
    return errors


class TestMainThreadEnforcement:
    def test_add_rejects_non_main_thread(self):
        q = DynamicTaskQueue()
        errors = _run_in_thread(q.add, _task("t1"))
        assert len(errors) == 1
        assert isinstance(errors[0], AssertionError)
        assert "main thread" in str(errors[0])

    def test_add_batch_rejects_non_main_thread(self):
        q = DynamicTaskQueue()
        errors = _run_in_thread(q.add_batch, [_task("t1"), _task("t2")], "test")
        assert len(errors) == 1
        assert isinstance(errors[0], AssertionError)

    def test_remove_by_id_rejects_non_main_thread(self):
        q = DynamicTaskQueue()
        q.add(_task("t1"))
        errors = _run_in_thread(q.remove_by_id, "t1")
        assert len(errors) == 1
        assert isinstance(errors[0], AssertionError)

    def test_inject_context_rejects_non_main_thread(self):
        from src.core.engine.task_queue import TaskContext

        q = DynamicTaskQueue()
        q.add(_task("t1"))
        ctx = TaskContext()
        errors = _run_in_thread(q.inject_context, ctx)
        assert len(errors) == 1
        assert isinstance(errors[0], AssertionError)

    def test_boost_priority_rejects_non_main_thread(self):
        q = DynamicTaskQueue()
        q.add(_task("t1"))
        errors = _run_in_thread(q.boost_priority, lambda t: True, 5)
        assert len(errors) == 1
        assert isinstance(errors[0], AssertionError)

    def test_main_thread_mutation_still_works(self):
        q = DynamicTaskQueue()
        q.add(_task("t1"))
        q.add_batch([_task("t2")], "test")
        assert q.get_by_id("t1") is not None
        assert q.get_by_id("t2") is not None
        assert q.remove_by_id("t1") is True

    def test_get_by_id_allowed_from_any_thread(self):
        q = DynamicTaskQueue()
        q.add(_task("t1"))
        result = []

        def read():
            result.append(q.get_by_id("t1"))

        t = threading.Thread(target=read)
        t.start()
        t.join(timeout=10)
        assert result == [q.get_by_id("t1")]
