import pytest
import uuid
import os

# Set dummy env vars to bypass Pydantic validation
os.environ["SHIGOKU_NEO4J_PASSWORD"] = "dummy_password_for_tests"
os.environ["SHIGOKU_NEO4J_USER"] = "neo4j"
os.environ["SHIGOKU_NEO4J_URI"] = "bolt://localhost:7687"

from src.core.engine.master_conductor import MasterConductor, Task, TaskState

class MockTaskQueue:
    def __init__(self):
        self.tasks = []
    
    def add(self, task):
        self.tasks.append(task)
        
    def add_batch(self, tasks, source="unknown"):
        self.tasks.extend(tasks)
        return len(tasks)
    def __len__(self):
        return len(self.tasks)
    def __getitem__(self, idx):
        return self.tasks[idx]

class MockMasterConductor(MasterConductor):
    """Mock for MasterConductor to test specific methods without full init"""
    def __init__(self):
        self.task_queue = MockTaskQueue()
        self.context = type('Context', (), {'target_info': {}})()  # minimal mock

@pytest.fixture
def conductor():
    return MockMasterConductor()

def test_process_handoff_success(conductor):
    # Initial task
    initial_task = Task(
        id="task_1",
        name="Initial Task",
        agent_type="agent_a",
        action="execute",
        params={"target": "example.com"}, 
        priority=50
    )
    
    # Simulate result containing Handoff request
    # Expecting result['data']['output']['next_suggested_agent'] based on implementation
    result = {
        "success": True,
        "data": {
            "output": {
                "next_suggested_agent": "agent_b",
                "reason": "Found something interesting",
                "handoff_context": {
                    "token": "xyz123",
                    "found_at": "login_page"
                }
            }
        }
    }
    
    # Execute handoff processing
    conductor._process_handoff(initial_task, result)
    
    # Verify a new task was added to queue
    assert len(conductor.task_queue) == 1
    new_task = conductor.task_queue[0]
    
    # Verify new task properties
    assert new_task.agent_type == "agent_b"
    assert "Handoff: agent_b" in new_task.name
    assert new_task.priority > initial_task.priority  # Should be higher priority
    assert new_task.parent_id == initial_task.id
    
    # Verify context injection
    assert new_task.params["token"] == "xyz123"
    assert new_task.params["found_at"] == "login_page"
    assert new_task.params["target"] == "example.com"

def test_process_handoff_no_handoff(conductor):
    initial_task = Task(id="task_1", name="Task", agent_type="a", action="run")
    
    # Result without handoff info
    result = {
        "success": True,
        "data": {
            "output": "Just a normal string output"
        }
    }
    
    conductor._process_handoff(initial_task, result)
    
    # Queue should remain empty
    assert len(conductor.task_queue) == 0

def test_process_handoff_nested_structure(conductor):
    # Test flat structure if data = HandoffResult.to_dict (without output wrapper)
    initial_task = Task(id="task_1", name="Task", agent_type="a", action="run")
    
    result = {
        "success": True,
        "data": { # Flat structure
            "next_suggested_agent": "agent_c",
            "reason": "Direct handoff",
            "handoff_context": {"foo": "bar"}
        }
    }
    
    conductor._process_handoff(initial_task, result)
    
    assert len(conductor.task_queue) == 1
    assert conductor.task_queue[0].agent_type == "agent_c"
    assert conductor.task_queue[0].params["foo"] == "bar"
