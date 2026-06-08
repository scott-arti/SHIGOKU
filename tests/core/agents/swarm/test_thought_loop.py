
import pytest
import asyncio
from typing import Any, Tuple
from unittest.mock import MagicMock

from src.core.agents.swarm.thought_loop import ThoughtLoop, LoopStatus, ThoughtStep

class MockLoop(ThoughtLoop):
    """
    Concrete implementation of ThoughtLoop for testing.
    """
    def __init__(self, max_turns: int = 5):
        super().__init__(max_turns)
        self.decide_count = 0
        self.act_count = 0
        self.should_finish = False
        
    async def decide(self, turn: int) -> Tuple[str, str, Any]:
        self.decide_count += 1
        if self.should_finish:
            return "Thinking done", "finish", {}
        return f"Thinking {turn}", "mock_action", {"input": turn}
        
    async def act(self, action: str, action_input: Any) -> str:
        self.act_count += 1
        # Fix: Robustly handle input
        if isinstance(action_input, dict):
            val = action_input.get('input', 'N/A')
        else:
            val = str(action_input)
        return f"Result {val}"

@pytest.mark.asyncio
async def test_thought_loop_run():
    loop = MockLoop(max_turns=3)
    
    # Run loop
    initial_context = {"target": "http://example.com"}
    result = await loop.run_loop(initial_context)
    
    # Verify status
    assert result["status"] == LoopStatus.ABORTED.value # Max turns reached
    assert result["turns"] == 3
    assert len(loop.history) == 3
    
    step1 = loop.history[0]
    assert step1.turn == 1
    assert step1.thought == "Thinking 1"
    assert step1.action == "mock_action"
    assert step1.observation == "Result 1"

@pytest.mark.asyncio
async def test_thought_loop_finish():
    loop = MockLoop(max_turns=5)
    
    class FinishingLoop(MockLoop):
        async def decide(self, turn):
            if turn == 2:
                return "Done", "finish", {}
            return "Thinking", "action", {}
            
    loop = FinishingLoop(max_turns=5)
    result = await loop.run_loop({})
    
    assert result["status"] == LoopStatus.COMPLETED.value
    # Finish action breaks loop before Act/Observe, so history has 1 item (Turn 1)
    assert len(loop.history) == 1 
    assert result["turns"] == 1
    
