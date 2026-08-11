
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
    # Lane B (SGK-2026-0441): additive status — 時間予算超過による早期停止
    TIME_BUDGET_EXHAUSTED = "time_budget_exhausted"

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
    
    def __init__(self, max_turns: int = 10, time_budget_seconds: Optional[float] = None):
        self.max_turns = max_turns
        # Lane B (SGK-2026-0441): 時間予算（None → legacy: チェックなし）
        self.time_budget_seconds = time_budget_seconds
        self.stop_reason: Optional[str] = None
        self._start_time: float = 0.0
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
        self.stop_reason = None
        self._start_time = asyncio.get_running_loop().time()
        
        logger.info(f"Starting ThoughtLoop with context: {list(self.context.keys())}")
        
        for turn in range(1, self.max_turns + 1):
            if self.status != LoopStatus.RUNNING:
                break

            # Lane B (SGK-2026-0441): 各ターン前に時間予算を確認（超過 → 早期停止）
            if self._time_budget_exhausted():
                self.status = LoopStatus.TIME_BUDGET_EXHAUSTED
                self.stop_reason = "time_budget_exhausted"
                logger.warning("Time budget exhausted after %d turn(s).", turn - 1)
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

                # Lane B (SGK-2026-0441): ペイアウト級 PoC 早期停止（fail-closed no-op）
                if self._payout_grade_obtained():
                    self.status = LoopStatus.COMPLETED
                    self.stop_reason = "payout_grade_obtained"
                    logger.info("Payout-grade PoC obtained; stopping loop early.")
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

    def _time_budget_exhausted(self) -> bool:
        """Lane B (SGK-2026-0441): 時間予算超過チェック。

        time_budget_seconds が None（legacy）→ 常に False。不正値・負値も no-op。
        """
        if self.time_budget_seconds is None:
            return False
        try:
            budget = float(self.time_budget_seconds)
        except (TypeError, ValueError):
            return False
        if budget < 0:
            return False
        return (asyncio.get_running_loop().time() - self._start_time) >= budget

    def _payout_grade_obtained(self) -> bool:
        """Lane B (SGK-2026-0441): ペイアウト級 PoC 早期停止チェック。

        ループ context が候補 finding（dict: `candidate_finding` / リスト:
        `candidate_findings`）を持つ場合のみ、Lane A の決定的ジャッジ
        evaluate_payout_grade(finding) に問い合わせる。
        fail-closed: ジャッジ未実装（import 失敗）・候補なし・ジャッジ例外 → False。
        ジャッジのモジュールは循環 import 回避のためメソッド内で遅延 import する。
        """
        candidate = self.context.get("candidate_finding")
        candidates: List[Any] = []
        if isinstance(candidate, dict):
            candidates.append(candidate)
        raw = self.context.get("candidate_findings")
        if isinstance(raw, list):
            candidates.extend(raw)
        if not candidates:
            return False
        try:
            from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
        except Exception as exc:  # Lane A モジュール未着など → no-op
            logger.debug("payout_grade judge unavailable: %s", exc)
            return False
        for finding in candidates:
            if not isinstance(finding, dict):
                continue
            try:
                if evaluate_payout_grade(finding).payout_grade:
                    return True
            except Exception as exc:  # ジャッジ例外も fail-closed
                logger.debug("payout_grade judge error: %s", exc)
        return False

    def get_result(self) -> Dict[str, Any]:
        """
        Returns the final result of the loop.
        """
        return {
            "status": self.status.value,
            "turns": len(self.history),
            # Lane B (SGK-2026-0441): additive フィールド（早期停止理由）
            "stop_reason": self.stop_reason,
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
