import pytest
import json
import os
import tempfile
from src.core.agents.swarm.base import Task
from src.core.engine.task_expander import TaskExpander
from src.core.workspace.shared_workspace import SharedWorkspace

class TestTaskExpander:

    @pytest.fixture
    def workspace(self):
        ws = MagicMock(spec=SharedWorkspace)
        ws.user_sessions = {"admin": {"Cookie": "admin=1"}, "user1": {"Cookie": "user1=1"}}
        return ws

    def test_expand_targets_file(self, workspace):
        # 一時的な targets_file を作成
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps({"url": "http://example.com/api/v1/user/100"}) + "\n")
            f.write(json.dumps({"url": "http://example.com/api/v1/user/200"}) + "\n")
            temp_path = f.name

        try:
            expander = TaskExpander(workspace)
            parent = Task(
                id="parent",
                name="IDOR Test",
                agent_type="LogicSwarm",
                priority=50,
                params={
                    "targets_file": temp_path,
                    "tags": ["idor_candidate"]
                }
            )
            
            subtasks = expander.expand(parent)
            
            assert len(subtasks) == 2
            assert subtasks[0].target == "http://example.com/api/v1/user/100"
            assert subtasks[1].target == "http://example.com/api/v1/user/200"
            
            # 優先度ブースト (+30 for idor_candidate)
            assert subtasks[0].priority == 80
            
            # セッションが引き継がれているか
            assert "admin" in subtasks[0].params["alternative_sessions"]
            
            # targets_file が削除されているか
            assert "targets_file" not in subtasks[0].params
            
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_expand_duplicate_urls(self, workspace):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps({"url": "http://example.com/api/v1/user/100"}) + "\n")
            f.write(json.dumps({"url": "http://example.com/api/v1/user/100"}) + "\n") # 重複
            temp_path = f.name

        try:
            expander = TaskExpander(workspace)
            parent = Task(
                id="parent",
                name="IDOR Test",
                agent_type="LogicSwarm",
                priority=50,
                params={"targets_file": temp_path}
            )
            subtasks = expander.expand(parent)
            assert len(subtasks) == 1
        finally:
            os.remove(temp_path)

from unittest.mock import MagicMock
