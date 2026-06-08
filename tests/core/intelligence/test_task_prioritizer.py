import json
from pathlib import Path

from src.core.domain.model.task import Task
from src.core.intelligence.task_prioritizer import TaskPrioritizer


class TestTaskPrioritizer:
    def test_select_task_returns_from_candidates(self, tmp_path: Path):
        db_path = tmp_path / "roi.json"
        prioritizer = TaskPrioritizer(
            db_path=str(db_path),
            exploration_rate=0.0,
            static_priority_weight=1.0,
        )

        tasks = [
            Task(id="t1", name="low", agent_type="recon", priority=10),
            Task(id="t2", name="high", agent_type="injection", priority=90),
        ]

        selected = prioritizer.select_task(tasks)

        assert selected is not None
        assert selected.id == "t2"

    def test_record_outcome_persists_roi_db(self, tmp_path: Path):
        db_path = tmp_path / "roi.json"
        prioritizer = TaskPrioritizer(db_path=str(db_path), exploration_rate=0.0)
        task = Task(id="t1", name="sqli", agent_type="injection", params={"vuln_type": "sqli"})

        prioritizer.record_outcome(task, {"success": True, "findings": [{"title": "x"}]})

        assert db_path.exists()
        payload = json.loads(db_path.read_text(encoding="utf-8"))
        assert "arms" in payload
        assert "injection::sqli" in payload["arms"]
        assert payload["arms"]["injection::sqli"]["pulls"] == 1

    def test_record_outcome_updates_success_failure_counters(self, tmp_path: Path):
        db_path = tmp_path / "roi.json"
        prioritizer = TaskPrioritizer(db_path=str(db_path), exploration_rate=0.0)
        task = Task(id="t1", name="task", agent_type="auth", params={})

        prioritizer.record_outcome(task, {"success": True, "findings": []})
        prioritizer.record_outcome(task, {"success": False, "error": "boom"})

        stats = prioritizer.get_stats()["auth::generic"]
        assert stats["pulls"] == 2
        assert stats["successes"] == 1
        assert stats["failures"] == 1

    def test_selection_trace_exploit_mode(self, tmp_path: Path):
        db_path = tmp_path / "roi.json"
        prioritizer = TaskPrioritizer(
            db_path=str(db_path),
            exploration_rate=0.0,
            static_priority_weight=1.0,
        )
        tasks = [
            Task(id="t1", name="low", agent_type="recon", priority=10),
            Task(id="t2", name="high", agent_type="injection", priority=90),
        ]

        selected = prioritizer.select_task(tasks)
        trace = prioritizer.get_last_selection_trace()

        assert selected is not None
        assert trace["mode"] == "exploit"
        assert trace["selected_task_id"] == "t2"
        assert trace["selected_arm"] == "injection::generic"
        assert trace["candidates"] == 2
        assert isinstance(trace["score"], float)

    def test_selection_trace_explore_mode(self, tmp_path: Path):
        db_path = tmp_path / "roi.json"
        prioritizer = TaskPrioritizer(
            db_path=str(db_path),
            exploration_rate=1.0,
            static_priority_weight=1.0,
        )
        tasks = [
            Task(id="t1", name="low", agent_type="recon", priority=10),
            Task(id="t2", name="high", agent_type="injection", priority=90),
        ]

        selected = prioritizer.select_task(tasks)
        trace = prioritizer.get_last_selection_trace()

        assert selected is not None
        assert trace["mode"] == "explore"
        assert trace["selected_task_id"] in {"t1", "t2"}
        assert trace["selected_arm"] in {"recon::generic", "injection::generic"}
        assert trace["candidates"] == 2
        assert trace["score"] is None

    def test_record_outcome_safe_fallback_on_missing_result(self, tmp_path: Path):
        db_path = tmp_path / "roi.json"
        prioritizer = TaskPrioritizer(db_path=str(db_path), exploration_rate=0.0)
        task = Task(id="t1", name="task", agent_type="recon", params={})

        prioritizer.record_outcome(task, None)

        stats = prioritizer.get_stats()["recon::generic"]
        assert stats["pulls"] == 1
        assert stats["failures"] == 1
        assert db_path.exists()

    def test_invalid_db_is_ignored_and_runtime_continues(self, tmp_path: Path):
        db_path = tmp_path / "roi.json"
        db_path.write_text("{invalid json", encoding="utf-8")

        prioritizer = TaskPrioritizer(db_path=str(db_path), exploration_rate=0.0)
        task = Task(id="t1", name="task", agent_type="scanner", params={})
        prioritizer.record_outcome(task, {"success": True, "findings": []})

        stats = prioritizer.get_stats()["scanner::generic"]
        assert stats["pulls"] == 1
        assert stats["successes"] == 1
