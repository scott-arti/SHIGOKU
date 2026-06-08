import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from src.core.domain.model.task import Task, TaskState, TaskResult
from src.core.engine.task_queue import TaskContext
from src.core.swarm.worker.base import BaseWorker
from src.core.swarm.worker.procedural import ProceduralWorker
from src.core.swarm.worker.llm_worker import LLMWorker

# --- Fixtures ---

@pytest.fixture
def mock_context():
    return TaskContext()

@pytest.fixture
def mock_task():
    return Task(
        id="test_task_1",
        name="Test Task",
        agent_type="test_agent",
        action="run",
        params={"target": "example.com"}
    )

# --- BaseWorker Tests ---

class ConcreteWorker(BaseWorker):
    def execute(self, task: Task) -> TaskResult:
        return TaskResult(success=True, data={"msg": "executed"})

def test_base_worker_init(mock_context):
    worker = ConcreteWorker(mock_context)
    assert worker.context == mock_context

def test_base_worker_execute(mock_context, mock_task):
    worker = ConcreteWorker(mock_context)
    result = worker.execute(mock_task)
    assert result.success is True
    assert result.data["msg"] == "executed"

# --- ProceduralWorker Tests ---

class TestProceduralWorker(ProceduralWorker):
    def _execute_procedural(self, task: Task) -> TaskResult:
        # Simulate command execution
        output = self.run_command(["echo", "hello"], timeout=1)
        return TaskResult(success=True, data={"output": output.strip()})

@patch("subprocess.run")
def test_procedural_worker_run_command_success(mock_subprocess, mock_context, mock_task):
    # Setup mock
    mock_process = MagicMock()
    mock_process.stdout = "hello\n"
    mock_process.stderr = ""
    mock_process.returncode = 0
    mock_subprocess.return_value = mock_process

    worker = TestProceduralWorker(mock_context)
    result = worker.execute(mock_task)

    assert result.success is True
    assert result.data["output"] == "hello"
    mock_subprocess.assert_called_once()
    args, kwargs = mock_subprocess.call_args
    assert args[0] == ["echo", "hello"]
    assert kwargs["timeout"] == 1
    assert kwargs["check"] == True

@patch("subprocess.run")
def test_procedural_worker_run_command_failure(mock_subprocess, mock_context, mock_task):
    # Setup mock to raise CalledProcessError
    import subprocess
    error = subprocess.CalledProcessError(1, ["ls"], stderr="error")
    mock_subprocess.side_effect = error

    worker = TestProceduralWorker(mock_context)
    
    # ProceduralWorker.execute catches exceptions and returns success=False
    # But here we are calling _execute_procedural via execute
    # Ideally execute should catch it.
    
    # However, TestProceduralWorker._execute_procedural calls run_command
    # run_command raises RuntimeError on CalledProcessError
    # ProceduralWorker.execute catches Exception
    
    result = worker.execute(mock_task)
    assert result.success is False
    assert "Command failed with code 1" in result.error

# --- LLMWorker Tests ---

class TestLLMWorker(LLMWorker):
    def think(self, task: Task):
        return {"action": "greet"}
    
    def _act(self, plan):
        if plan["action"] == "greet":
            return {"response": "hello from llm"}
        return {}
    
    def verify(self, result):
        return "response" in result

def test_llm_worker_flow(mock_context, mock_task):
    mock_llm_client = MagicMock()
    worker = TestLLMWorker(mock_context, mock_llm_client)
    
    result = worker.execute(mock_task)
    
    assert result.success is True
    assert result.data["response"] == "hello from llm"

@pytest.mark.asyncio
async def test_llm_worker_ask_llm(mock_context):
    mock_llm_client = AsyncMock()
    # Mock agenerate response structure
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "Filtered Response"
    mock_llm_client.agenerate.return_value = mock_response

    worker = TestLLMWorker(mock_context, mock_llm_client)
    
    response = await worker.ask_llm("prompt")
    assert response == "Filtered Response"
    mock_llm_client.agenerate.assert_called_once()
