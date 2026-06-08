from __future__ import annotations

from dataclasses import dataclass
from json import JSONDecodeError
from pathlib import Path
from threading import RLock
from typing import Any, Optional
import json
import logging
import random


logger = logging.getLogger(__name__)
_DEFAULT_TASK_PRIORITIZER: dict[str, Optional["TaskPrioritizer"]] = {"instance": None}


@dataclass
class ArmStats:
    alpha: float = 1.0
    beta: float = 1.0
    pulls: int = 0
    total_reward: float = 0.0
    successes: int = 0
    failures: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "alpha": self.alpha,
            "beta": self.beta,
            "pulls": self.pulls,
            "total_reward": self.total_reward,
            "successes": self.successes,
            "failures": self.failures,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ArmStats":
        return cls(
            alpha=float(data.get("alpha", 1.0) or 1.0),
            beta=float(data.get("beta", 1.0) or 1.0),
            pulls=int(data.get("pulls", 0) or 0),
            total_reward=float(data.get("total_reward", 0.0) or 0.0),
            successes=int(data.get("successes", 0) or 0),
            failures=int(data.get("failures", 0) or 0),
        )


class TaskPrioritizer:
    def __init__(
        self,
        db_path: str = "data/vuln_roi_db.json",
        exploration_rate: float = 0.10,
        static_priority_weight: float = 0.35,
    ) -> None:
        self.db_path = Path(db_path)
        self.exploration_rate = max(0.0, min(1.0, float(exploration_rate)))
        self.static_priority_weight = max(0.0, min(1.0, float(static_priority_weight)))
        self._lock = RLock()
        self._arms: dict[str, ArmStats] = {}
        self._last_selection_trace: dict[str, Any] = {"mode": "init"}
        self._load()

    def select_task(self, tasks: list[Any]) -> Optional[Any]:
        if not tasks:
            self._last_selection_trace = {"mode": "empty", "candidates": 0}
            return None

        with self._lock:
            if random.random() < self.exploration_rate:
                selected = random.choice(tasks)
                self._last_selection_trace = {
                    "mode": "explore",
                    "candidates": len(tasks),
                    "selected_task_id": getattr(selected, "id", None),
                    "selected_arm": self._arm_key(selected),
                    "score": None,
                }
                return selected

            priorities = [int(getattr(t, "priority", 0) or 0) for t in tasks]
            min_p = min(priorities)
            max_p = max(priorities)
            span = max(1, max_p - min_p)

            best_task: Optional[Any] = None
            best_arm = "unknown"
            best_score = -1.0

            for task in tasks:
                arm_key = self._arm_key(task)
                arm = self._arms.get(arm_key)
                if arm is None:
                    arm = ArmStats()
                    self._arms[arm_key] = arm

                sampled_roi = random.betavariate(arm.alpha, arm.beta)
                static_pri = int(getattr(task, "priority", 0) or 0)
                normalized_pri = (static_pri - min_p) / span
                score = (1.0 - self.static_priority_weight) * sampled_roi + self.static_priority_weight * normalized_pri

                if score > best_score:
                    best_score = score
                    best_task = task
                    best_arm = arm_key

            self._last_selection_trace = {
                "mode": "exploit",
                "candidates": len(tasks),
                "selected_task_id": getattr(best_task, "id", None),
                "selected_arm": best_arm,
                "score": round(best_score, 6),
            }
            return best_task

    def record_outcome(self, task: Any, result: Optional[dict[str, Any]]) -> None:
        with self._lock:
            arm_key = self._arm_key(task)
            arm = self._arms.get(arm_key)
            if arm is None:
                arm = ArmStats()
                self._arms[arm_key] = arm

            reward = self._reward(result or {})
            arm.alpha += reward
            arm.beta += max(0.0, 1.0 - reward)
            arm.pulls += 1
            arm.total_reward += reward

            if reward >= 0.5:
                arm.successes += 1
            else:
                arm.failures += 1

            self._save()

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {k: v.to_dict() for k, v in self._arms.items()}

    def get_last_selection_trace(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._last_selection_trace)

    def _arm_key(self, task: Any) -> str:
        agent = str(getattr(task, "agent_type", "unknown") or "unknown").lower()
        params = getattr(task, "params", {}) or {}

        vuln_hint = "generic"
        for key in ("vuln_type", "type", "category", "attack_type"):
            if key in params and params[key]:
                vuln_hint = str(params[key]).lower()
                break

        return f"{agent}::{vuln_hint}"

    def _reward(self, result: dict[str, Any]) -> float:
        success = bool(result.get("success", False))

        findings = result.get("findings")
        if findings is None:
            findings = result.get("data", {}).get("findings", [])
        finding_count = len(findings) if isinstance(findings, list) else 0

        if finding_count > 0:
            return 1.0
        if success:
            return 0.6
        return 0.0

    def _load(self) -> None:
        if not self.db_path.exists():
            return

        try:
            raw = json.loads(self.db_path.read_text(encoding="utf-8"))
            arms = raw.get("arms", raw)
            if isinstance(arms, dict):
                for key, value in arms.items():
                    if isinstance(value, dict):
                        self._arms[key] = ArmStats.from_dict(value)
        except (OSError, JSONDecodeError, TypeError, ValueError) as exc:
            logger.warning("TaskPrioritizer DB load failed (%s): %s", self.db_path, exc)

    def _save(self) -> None:
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "version": 1,
                "arms": {k: v.to_dict() for k, v in self._arms.items()},
            }
            self.db_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except (OSError, TypeError, ValueError) as exc:
            logger.warning("TaskPrioritizer DB save failed (%s): %s", self.db_path, exc)


def get_task_prioritizer(
    db_path: str = "data/vuln_roi_db.json",
    exploration_rate: float = 0.10,
    static_priority_weight: float = 0.35,
) -> TaskPrioritizer:
    instance = _DEFAULT_TASK_PRIORITIZER["instance"]
    if instance is None:
        instance = TaskPrioritizer(
            db_path=db_path,
            exploration_rate=exploration_rate,
            static_priority_weight=static_priority_weight,
        )
        _DEFAULT_TASK_PRIORITIZER["instance"] = instance
    return instance
