import os
import json
import pytest
import tempfile
from pathlib import Path
from src.core.utils.json_utils import stream_jsonl
from src.core.engine.swarm_dispatcher import SwarmDispatcher
from src.core.models.task_execution_log import TaskExecutionLog, TaskExecutionRecord, TaskResult
from src.core.models.decision_trace import DecisionTracer, DecisionType

def test_stream_jsonl():
    """stream_jsonl が正しく動作することを確認"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        data = [
            {"id": 1, "msg": "first"},
            {"id": 2, "msg": "second"},
            {"id": 3, "msg": "third"}
        ]
        for item in data:
            f.write(json.dumps(item) + "\n")
        temp_path = f.name

    try:
        results = list(stream_jsonl(temp_path))
        assert len(results) == 3
        assert results[0]["id"] == 1
        assert results[2]["msg"] == "third"
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def test_swarm_dispatcher_pooling():
    """SwarmDispatcher がインスタンスをプール（共有）していることを確認"""
    dispatcher = SwarmDispatcher()
    
    # 初回取得
    swarm1 = dispatcher._get_or_create_swarm("auth")
    # 2回目取得
    swarm2 = dispatcher._get_or_create_swarm("auth")
    
    # 同じインスタンスであることを確認
    assert swarm1 is swarm2
    assert len(dispatcher._swarm_pool) == 1
    
    # 別のSwarm
    swarm3 = dispatcher._get_or_create_swarm("injection")
    assert swarm3 is not swarm1
    assert len(dispatcher._swarm_pool) == 2

def test_task_execution_log_memory_limit():
    """TaskExecutionLog が上限を超えた時に古い記録を削除することを確認"""
    log = TaskExecutionLog(max_records=5)
    
    # 10件追加
    for i in range(10):
        record = TaskExecutionRecord(
            task_id=f"task_{i}",
            task_name=f"Test Task {i}",
            agent_type="test_agent",
            action="test_action",
            target_url="http://example.com"
        )
        log.add_record(record)
    
    # 5件に制限されていること
    records = log.get_all()
    assert len(records) == 5
    # 最新の5件が残っていること (task_5 to task_9)
    assert records[0].task_id == "task_5"
    assert records[-1].task_id == "task_9"

def test_decision_tracer_memory_limit():
    """DecisionTracer が上限を超えた時に古いトレースを削除することを確認"""
    tracer = DecisionTracer(max_traces=3)
    
    # 5件記録
    for i in range(5):
        tracer.trace(
            decision_type=DecisionType.RECON_DISPATCH,
            input_context={"i": i},
            available_options=["a", "b"],
            selected_option="a",
            reasoning=f"test {i}"
        )
    
    # 3件に制限されていること
    traces = tracer.get_all()
    assert len(traces) == 3
    # 最新の3件が残っていること
    assert traces[0].input_context["i"] == 2
    assert traces[-1].input_context["i"] == 4
