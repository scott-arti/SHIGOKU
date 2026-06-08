from abc import abstractmethod
from typing import Any, Dict, List, Optional
import logging

from src.core.domain.model.task import Task, TaskResult
from src.core.swarm.worker.base import BaseWorker
from src.core.models.llm import LLMClient
from src.core.engine.task_queue import TaskContext

logger = logging.getLogger(__name__)

class LLMWorker(BaseWorker):
    """
    自律型 Worker
    
    LLMを使用して推論、判断、コード生成などを行う。
    """
    
    def __init__(self, context: TaskContext, llm_client: LLMClient):
        super().__init__(context)
        self.llm_client = llm_client

    def execute(self, task: Task) -> TaskResult:
        try:
            plan = self.think(task)
            result_data = self._act(plan)
            success = self.verify(result_data)
            return TaskResult(success=success, data=result_data, execution_time=0.0)
        except Exception as e:
            logger.error(f"LLMWorker execution failed: {e}")
            return TaskResult(success=False, error=str(e))

    @abstractmethod
    def think(self, task: Task) -> Any:
        pass
    
    def _act(self, plan: Any) -> Dict[str, Any]:
        return {"plan": plan, "status": "executed"}

    @abstractmethod
    def verify(self, result: Any) -> bool:
        pass
    
    async def ask_llm(self, prompt: str, system_message: str = None) -> str:
        messages = []
        if system_message:
            messages.append({"role": "system", "content": system_message})
        messages.append({"role": "user", "content": prompt})
        response = await self.llm_client.agenerate(messages)
        return response.choices[0].message.content
