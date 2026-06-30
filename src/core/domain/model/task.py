from __future__ import annotations

import copy
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any, List


# ---------------------------------------------------------------------------
# Secret keys that must be redacted from metadata at serialization boundary
# ---------------------------------------------------------------------------
_SECRET_METADATA_KEYS: set[str] = {
    "cookie",
    "token",
    "authorization",
    "api_key",
    "secret",
    "password",
    "access_token",
    "refresh_token",
    "session_id",
    "Authorization",
    "Cookie",
    "Set-Cookie",
    "X-Api-Key",
}


def _redact_secrets(value: Any) -> Any:
    """Recursively redact secret-bearing keys from a metadata structure.

    Returns a deep copy with secret values replaced by ``[REDACTED]``.
    Does not mutate the input.
    """
    if isinstance(value, dict):
        return {
            k: "[REDACTED]" if k in _SECRET_METADATA_KEYS else _redact_secrets(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact_secrets(item) for item in value]
    return copy.deepcopy(value)


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

    # Phase 1 (SGK-2026-0310): additive execution contract metadata.
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            self.id = f"task_{uuid.uuid4().hex[:8]}"

    def to_dict(self) -> dict:
        result_data = None
        if self.result:
            if isinstance(self.result, TaskResult):
                result_data = {
                    "success": self.result.success,
                    "data": self.result.data,
                    "error": self.result.error,
                }
            else:
                result_data = self.result

        payload = {
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
            "is_aggressive": self.is_aggressive,
        }

        # Phase 1: include metadata only when it has content
        if self.metadata:
            safe = _redact_secrets(self.metadata)
            # Auto-inject schema_version when metadata is present but version is missing
            if "schema_version" not in safe:
                safe["schema_version"] = 1
            payload["metadata"] = safe
        else:
            payload["metadata"] = {}

        return payload

    @classmethod
    def from_dict(cls, d: dict) -> Task:
        raw_metadata = d.get("metadata", {})

        # Redact secrets at the deserialization boundary
        safe_metadata = _redact_secrets(raw_metadata) if raw_metadata else {}

        return cls(
            id=d.get("id", ""),
            name=d.get("name", ""),
            agent_type=d.get("agent_type", "universal"),
            action=d.get("action", "run"),
            phase=d.get("phase", "init"),
            params=d.get("params", {}),
            target=d.get("target", ""),
            state=TaskState(d.get("state", "pending")),
            priority=d.get("priority", 0),
            parent_id=d.get("parent_id"),
            replan_depth=d.get("replan_depth", 0),
            tags=d.get("tags", []),
            is_aggressive=d.get("is_aggressive", False),
            metadata=safe_metadata,
        )
