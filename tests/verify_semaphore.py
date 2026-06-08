
import asyncio
import sys
import os
from unittest.mock import MagicMock, AsyncMock

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.agents.swarm.base_manager import BaseManagerAgent
from src.core.domain.model.task import Task

async def test_semaphore_concurrency():
    # Setup
    config = {"max_concurrent_tasks": 1, "name": "SemaphoreTestAgent"}
    agent = BaseManagerAgent(config=config)
    
    # Mock LLM
    mock_llm = MagicMock()
    
    active_calls = 0
    max_active_calls = 0
    
    async def slow_generate(*args, **kwargs):
        nonlocal active_calls, max_active_calls
        active_calls += 1
        max_active_calls = max(max_active_calls, active_calls)
        print(f"  [LLM Call] active={active_calls}, max={max_active_calls}")
        await asyncio.sleep(0.1) # Simulate delay
        active_calls -= 1
        
        # Return a mock response object
        response = MagicMock()
        response.choices = [MagicMock()]
        response.choices[0].message.content = "Final Answer: Done"
        return response

    mock_llm.agenerate = AsyncMock(side_effect=slow_generate)
    agent.set_llm_client(mock_llm)
    
    # Mock workspace and other dependencies if needed
    agent.shared_workspace = MagicMock()
    
    task = Task(id="test-task-001", name="Test Task", target="http://example.com")
    
    print(f"Starting test with max_concurrent_tasks={config['max_concurrent_tasks']}")
    
    # Run twice concurrently. Since limit is 1, max_active_calls should be 1.
    await asyncio.gather(
        agent.dispatch(task),
        agent.dispatch(task)
    )
    
    print(f"Max active LLM calls: {max_active_calls}")
    if max_active_calls > config['max_concurrent_tasks']:
        print("FAIL: Semaphore did not limit concurrency.")
        sys.exit(1)
    else:
        print("PASS: Semaphore limited concurrency.")

if __name__ == "__main__":
    asyncio.run(test_semaphore_concurrency())
