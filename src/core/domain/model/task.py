from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any, List
import uuid
import time

class TaskState(Enum):
    """タスクの状態"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    REPLANNED = "replanned"
    SKIPPED = "skipped"

@dataclass
class TaskResult:
    """タスク実行結果"""
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    findings: List[Any] = field(default_factory=list)
    execution_time: float = 0.0

@dataclass
class Task:
    """
    実行可能なタスク (Core Domain Model)
    MasterConductor, Swarm, Worker 間で共有される統一タスクオブジェクト
    """
    id: str
    name: str
    agent_type: str = "universal"
    action: str = "run"
    phase: str = "init"  # init/recon/attack/report
    params: Dict[str, Any] = field(default_factory=dict)
    target: str = ""
    
    state: TaskState = TaskState.PENDING
    result: Optional[TaskResult] = None  # Unified Result Object (or dict for legacy compat)
    error: Optional[str] = None
    priority: int = 0  # 高い = 優先
    
    parent_id: Optional[str] = None
    replan_depth: int = 0
    
    # Legacy fields compatibility (Swarm uses tags)
    tags: List[str] = field(default_factory=list)
    is_aggressive: bool = False

    def __post_init__(self):
        if not self.id:
            self.id = f"task_{uuid.uuid4().hex[:8]}"

    def to_dict(self) -> dict:
        result_data = None
        if self.result:
            if isinstance(self.result, TaskResult):
                result_data = {"success": self.result.success, "data": self.result.data, "error": self.result.error}
            else:
                result_data = self.result
                
        return {
            "id": self.id,
            "name": self.name,
            "agent_type": self.agent_type,
            "target": self.target,
            "action": self.action,
            "params": self.params,
            "state": self.state.value,
            "priority": self.priority,
            "replan_depth": self.replan_depth,
            "result": result_data,
            "error": self.error,
            "tags": self.tags,
            "is_aggressive": self.is_aggressive
        }
