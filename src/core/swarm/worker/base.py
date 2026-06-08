from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
import logging

from src.core.domain.model.task import Task, TaskResult
from src.core.engine.task_queue import TaskContext

logger = logging.getLogger(__name__)

class BaseWorker(ABC):
    """
    Worker基底クラス
    
    MasterConductor -> Swarm -> Worker という階層構造の末端。
    具体的なタスク実行ロジックを持つ。
    """
    
    def __init__(self, context: TaskContext):
        """
        Args:
            context: タスク実行コンテキスト（発見済み資産、トークンなど）
        """
        self.context = context

    @abstractmethod
    def execute(self, task: Task) -> TaskResult:
        """
        タスクを実行し、結果を返す共通インターフェース
        
        Args:
            task: 実行対象のタスク
            
        Returns:
            TaskResult: 実行結果
        """
        pass

    def log(self, message: str, level: int = logging.INFO):
        """Worker用のログ出力ヘルパー"""
        logger.log(level, f"[{self.__class__.__name__}] {message}")
