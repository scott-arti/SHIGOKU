
import logging
import asyncio
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class LoopStatus(Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"

@dataclass
class ThoughtStep:
    turn: int
    thought: str
    action: str
    action_input: Any
    observation: str

class ThoughtLoop(ABC):
    """
    Base class for loop-based reasoning agents (The "Brain").
    Implements the Observe-Think-Act cycle.
    """
    
    def __init__(self, max_turns: int = 10):
        self.max_turns = max_turns
        self.history: List[ThoughtStep] = []
        self.status = LoopStatus.RUNNING
        self.context: Dict[str, Any] = {}

    async def run_loop(self, initial_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the main reasoning loop.
        """
        self.context = initial_context
        self.history = []
        self.status = LoopStatus.RUNNING
        
        logger.info(f"Starting ThoughtLoop with context: {list(self.context.keys())}")
        
        for turn in range(1, self.max_turns + 1):
            if self.status != LoopStatus.RUNNING:
                break
                
            logger.info(f"--- Turn {turn}/{self.max_turns} ---")
            
            try:
                # 1. Decide (Think & Plan)
                # Based on history and context, decide next action
                thought, action, action_input = await self.decide(turn)
                
                # 2. Act (Execute Tool/Command)
                # Allow 'finish' to go through act/observe/should_stop
                observation = await self.act(action, action_input)
                
                # 3. Observe (Record & Analyze)
                # Save step to history
                step = ThoughtStep(
                    turn=turn,
                    thought=thought,
                    action=action,
                    action_input=action_input,
                    observation=observation
                )
                self.history.append(step)
                
                # Verify if we should stop based on observation
                if await self.should_stop(step):
                    self.status = LoopStatus.COMPLETED
                    break
                    
            except Exception as e:
                logger.error(f"Error in turn {turn}: {e}", exc_info=True)
                self.history.append(ThoughtStep(turn, "Error", "error", {}, str(e)))
                self.status = LoopStatus.FAILED
                break
                
        if self.status == LoopStatus.RUNNING:
            logger.warning("Max turns reached without completion.")
            self.status = LoopStatus.ABORTED

        return self.get_result()

    @abstractmethod
    async def decide(self, turn: int) -> tuple[str, str, Any]:
        """
        Returns: (thought, action_name, action_input)
        """
        pass

    @abstractmethod
    async def act(self, action: str, action_input: Any) -> str:
        """
        Executes the action and returns an observation string.
        """
        pass
        
    async def should_stop(self, step: ThoughtStep) -> bool:
        """
        Override to implement custom stopping logic based on observation.
        """
        return False

    def get_result(self) -> Dict[str, Any]:
        """
        Returns the final result of the loop.
        """
        return {
            "status": self.status.value,
            "turns": len(self.history),
            "history": [
                {
                    "turn": s.turn,
                    "thought": s.thought,
                    "action": s.action,
                    "input": str(s.action_input),
                    "observation": s.observation[:200] + "..." if len(s.observation) > 200 else s.observation
                }
                for s in self.history
            ]
        }
