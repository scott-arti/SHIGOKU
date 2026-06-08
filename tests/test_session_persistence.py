"""セッション永続化機能の回帰テスト。"""

import json

from src.core.engine.master_conductor import MasterConductor, Task


def test_save_and_load_session(tmp_path):
    """保存ペイロードと復元後キューが現行APIで一致すること。"""
    session_file = tmp_path / "test_session.json"

    mc = MasterConductor()
    mc.task_queue.add(
        Task(
            id="test_001",
            name="Test Task 1",
            agent_type="test_agent",
            action="test",
            phase="recon",
            params={"target": "example.com"},
            priority=100,
        )
    )
    mc.task_queue.add(
        Task(
            id="test_002",
            name="Test Task 2",
            agent_type="test_agent",
            action="test",
            phase="attack",
            params={"target": "example.com"},
            priority=90,
        )
    )
    mc.context.discovered_assets = ["example.com", "api.example.com"]
    mc.context._total_attempts = 5
    mc.context._successful_attempts = 3

    mc.save_session(str(session_file))

    assert session_file.exists()

    session_data = json.loads(session_file.read_text(encoding="utf-8"))
    assert [task["id"] for task in session_data["task_queue"]] == ["test_001", "test_002"]
    assert session_data["context"]["total_attempts"] == 5
    assert session_data["context"]["successful_attempts"] == 3
    assert session_data["context"]["discovered_assets"] == ["example.com", "api.example.com"]

    mc2 = MasterConductor()
    assert len(mc2.task_queue) == 0

    assert mc2.load_session(str(session_file)) is True

    restored_tasks = list(mc2.task_queue)
    assert [task.id for task in restored_tasks] == ["test_001", "test_002"]
    assert restored_tasks[0].name == "Test Task 1"
    assert restored_tasks[0].phase == "recon"
    assert restored_tasks[1].phase == "attack"
    assert mc2.context.total_attempts == 5
    assert mc2.context.successful_attempts == 3
    assert mc2.context.discovered_assets == ["example.com", "api.example.com"]
