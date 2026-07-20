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

    # ------------------------------------------------------------------
    # SGK-2026-0367: evidence normalization tests
    # ------------------------------------------------------------------

    def test_subtask_evidence_per_url_only(self, workspace):
        """subtask は count=1, targets=[target], 対象URL 1件分の evidence のみ保持する"""
        url_a = "http://example.com/a"
        url_b = "http://example.com/b"

        full_forms = {
            url_a: [{"method": "GET", "inputs": [{"name": "q"}]}],
            url_b: [{"method": "POST", "inputs": [{"name": "id"}]}],
        }
        full_evidence = {
            url_a: {"method": "GET", "has_form_tag": True, "response_status": 200},
            url_b: {"method": "POST", "has_form_tag": False, "response_status": 301},
        }

        parent = Task(
            id="parent",
            name="XSS Scan",
            agent_type="InjectionSwarm",
            priority=80,
            params={
                "targets": [url_a, url_b],
                "target": url_a,
                "category": "xss_candidate",
                "tags": ["xss_candidate"],
                "_context": {
                    "forms_by_url": full_forms,
                    "url_evidence_by_url": full_evidence,
                    "scan_profile": "bbpt",
                },
                "count": 2,
                "selection_origin": "recon.tagged_xss_candidate",
            },
        )

        expander = TaskExpander(workspace)
        subtasks = expander.expand(parent)

        assert len(subtasks) == 2

        # subtask A: only url_a evidence
        sub_a = [s for s in subtasks if s.target == url_a][0]
        ctx_a = sub_a.params["_context"]
        assert ctx_a["forms_by_url"] == {url_a: full_forms[url_a]}, (
            "Subtask A should only have url_a forms"
        )
        assert ctx_a["url_evidence_by_url"] == {url_a: full_evidence[url_a]}, (
            "Subtask A should only have url_a evidence"
        )
        assert sub_a.params["target"] == url_a
        assert sub_a.params.get("count") == 1

        # subtask B: only url_b evidence
        sub_b = [s for s in subtasks if s.target == url_b][0]
        ctx_b = sub_b.params["_context"]
        assert ctx_b["forms_by_url"] == {url_b: full_forms[url_b]}, (
            "Subtask B should only have url_b forms"
        )
        assert ctx_b["url_evidence_by_url"] == {url_b: full_evidence[url_b]}, (
            "Subtask B should only have url_b evidence"
        )
        assert sub_b.params["target"] == url_b
        assert sub_b.params.get("count") == 1

    def test_subtask_handles_missing_evidence(self, workspace):
        """subtask 生成時、evidence が無い場合もエラーにならない"""
        parent = Task(
            id="parent",
            name="Scan",
            agent_type="InjectionSwarm",
            priority=80,
            params={
                "targets": ["http://example.com/page"],
                "category": "xss_candidate",
                "tags": ["xss_candidate"],
                "_context": {},
            },
        )

        expander = TaskExpander(workspace)
        subtasks = expander.expand(parent)
        assert len(subtasks) == 1
        sub = subtasks[0]
        ctx = sub.params["_context"]
        assert "forms_by_url" not in ctx, "Empty context should not inject empty forms_by_url"
        assert sub.params.get("count") == 1

    def test_subtask_preserves_selection_origin(self, workspace):
        """selection_origin が subtask に継承されること"""
        parent = Task(
            id="parent",
            name="XSS Scan",
            agent_type="InjectionSwarm",
            priority=80,
            params={
                "targets": ["http://example.com/page"],
                "category": "xss_candidate",
                "tags": ["xss_candidate"],
                "selection_origin": "recon.tagged_xss_candidate",
                "source_file": "/tmp/test.jsonl",
                "_context": {"scan_profile": "bbpt"},
            },
        )

        expander = TaskExpander(workspace)
        subtasks = expander.expand(parent)
        assert len(subtasks) == 1
        sub = subtasks[0]
        assert sub.params["selection_origin"] == "recon.tagged_xss_candidate"
        assert sub.params["source_file"] == "/tmp/test.jsonl"

from unittest.mock import MagicMock
