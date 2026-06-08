"""Backward-compatible import surface for TaskPrioritizer.

The canonical implementation lives in `src.core.intelligence.task_prioritizer`.
"""

from src.core.intelligence.task_prioritizer import ArmStats, TaskPrioritizer, get_task_prioritizer

__all__ = ["ArmStats", "TaskPrioritizer", "get_task_prioritizer"]
