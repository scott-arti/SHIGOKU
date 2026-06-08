"""
SmartScheduler: タスクスケジューリングエンジン (Phase 1)

依存関係とDecision Dependencyを考慮した並列タスク実行を管理する。
"""

import asyncio
from dataclasses import dataclass, field
from typing import Optional, Callable, Any
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class TaskState(Enum):
    """タスクの状態"""
    PENDING = "pending"
    READY = "ready"  # 依存関係クリア済み
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ScheduledTask:
    """スケジュール対象のタスク"""
    id: str
    name: str
    agent_type: str
    action: str
    params: dict = field(default_factory=dict)
    priority: int = 0
    
    # 依存関係
    depends_on: list[str] = field(default_factory=list)  # 親タスクID
    
    # 実行状態
    state: TaskState = TaskState.PENDING
    result: Optional[dict] = None
    error: Optional[str] = None
    
    # Decision Dependency: このタスクが実行されるべきかの判定関数
    decision_check: Optional[Callable[[dict], bool]] = None


class SmartScheduler:
    """
    Smart Task Scheduler with Dependency Graph and Decision Dependencies
    
    機能:
    1. データ依存: A完了後にBを実行
    2. 意思決定依存: Aの結果によってBをスキップ (Negative Dependency)
    3. 並列実行: 依存のないタスクは同時実行
    """
    
    def __init__(self, max_workers: int = 5):
        """
        Args:
            max_workers: 同時実行タスク数の上限
        """
        self.max_workers = max_workers
        self.tasks: dict[str, ScheduledTask] = {}
        self.execution_context: dict[str, Any] = {}
        
    def add_task(self, task: ScheduledTask) -> None:
        """タスクをスケジューラに追加"""
        self.tasks[task.id] = task
        logger.debug(f"Task added: {task.id} (depends on: {task.depends_on})")
    
    def update_context(self, key: str, value: Any) -> None:
        """実行コンテキストを更新 (Decision Check用)"""
        self.execution_context[key] = value
    
    def should_skip_task(self, task: ScheduledTask) -> bool:
        """
        Decision Dependency Check: タスクをスキップすべきか判定
        
        Args:
            task: 判定対象のタスク
        
        Returns:
            スキップすべき場合True
        """
        if task.decision_check is None:
            return False
        
        try:
            # decision_checkがTrueを返す = タスクを実行すべき
            # Falseを返す = スキップ
            should_run = task.decision_check(self.execution_context)
            return not should_run
        except Exception as e:
            logger.warning(f"Decision check failed for task {task.id}: {e}")
            # エラー時はスキップしない（安全側に倒す）
            return False
    
    def get_ready_tasks(self) -> list[ScheduledTask]:
        """
        実行可能なタスクのリストを取得
        
        Returns:
            READYまたはPENDINGで依存関係がクリアされたタスク
        """
        ready = []
        
        for task in self.tasks.values():
            if task.state not in [TaskState.PENDING, TaskState.READY]:
                continue
            
            # 依存関係チェック
            all_deps_done = all(
                self.tasks.get(dep_id, ScheduledTask(id=dep_id, name="", agent_type="", action="")).state == TaskState.SUCCESS
                for dep_id in task.depends_on
            )
            
            if not all_deps_done:
                continue
            
            # Decision Dependency Check
            if self.should_skip_task(task):
                task.state = TaskState.SKIPPED
                logger.info(f"Task {task.id} skipped due to decision dependency")
                continue
            
            task.state = TaskState.READY
            ready.append(task)
        
        # 優先度でソート（高い順）
        ready.sort(key=lambda t: t.priority, reverse=True)
        return ready
    
    async def execute_task(self, task: ScheduledTask, executor: Callable) -> None:
        """
        タスクを実行
        
        Args:
            task: 実行するタスク
            executor: タスクを実行する関数 (async)
        """
        task.state = TaskState.RUNNING
        logger.info(f"Executing task: {task.id} ({task.name})")
        
        try:
            result = await executor(task)
            task.result = result
            task.state = TaskState.SUCCESS
            logger.info(f"Task {task.id} completed successfully")
        except Exception as e:
            task.error = str(e)
            task.state = TaskState.FAILED
            logger.error(f"Task {task.id} failed: {e}")
    
    async def run(self, executor: Callable) -> dict:
        """
        全タスクを並列実行
        
        Args:
            executor: タスクを実行する非同期関数
        
        Returns:
            実行結果のサマリー
        """
        pending_tasks = set(self.tasks.keys())
        running_tasks = set()
        
        while pending_tasks or running_tasks:
            # 実行可能なタスクを取得
            ready_tasks = self.get_ready_tasks()
            
            # Worker数の制限内で実行
            available_slots = self.max_workers - len(running_tasks)
            tasks_to_start = ready_tasks[:available_slots]
            
            # タスクを非同期で起動
            new_tasks = []
            for task in tasks_to_start:
                if task.id in pending_tasks:
                    new_tasks.append(asyncio.create_task(self.execute_task(task, executor)))
                    running_tasks.add(task.id)
                    pending_tasks.discard(task.id)
            
            if not new_tasks and not running_tasks:
                # Deadlock検出: 実行可能なタスクがない
                remaining = [t for t in self.tasks.values() if t.state == TaskState.PENDING]
                if remaining:
                    logger.warning(f"Deadlock detected. {len(remaining)} tasks cannot run due to unmet dependencies.")
                    for t in remaining:
                        t.state = TaskState.SKIPPED
                break
            
            # 少なくとも1つのタスクが完了するまで待機
            if running_tasks:
                await asyncio.sleep(0.1)  # 短い待機
                # 完了したタスクを検出
                for task_id in list(running_tasks):
                    task = self.tasks[task_id]
                    if task.state in [TaskState.SUCCESS, TaskState.FAILED]:
                        running_tasks.discard(task_id)
        
        # サマリー作成
        summary = {
            "total": len(self.tasks),
            "success": sum(1 for t in self.tasks.values() if t.state == TaskState.SUCCESS),
            "failed": sum(1 for t in self.tasks.values() if t.state == TaskState.FAILED),
            "skipped": sum(1 for t in self.tasks.values() if t.state == TaskState.SKIPPED),
        }
        
        logger.info(f"Execution complete: {summary}")
        return summary
