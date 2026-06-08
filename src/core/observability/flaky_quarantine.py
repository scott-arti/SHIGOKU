from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FlakyQuarantinePolicy:
    window_size: int = 20
    min_failures: int = 2
    release_success_streak: int = 3


@dataclass
class FlakyQuarantineTracker:
    policy: FlakyQuarantinePolicy = field(default_factory=FlakyQuarantinePolicy)
    _history: deque[bool] = field(default_factory=deque)

    def record(self, success: bool) -> None:
        self._history.append(bool(success))
        while len(self._history) > self.policy.window_size:
            self._history.popleft()

    def evaluate(self) -> dict[str, object]:
        failures = sum(1 for item in self._history if not item)
        total = len(self._history)
        quarantine = failures >= self.policy.min_failures and total >= self.policy.window_size
        return {
            "status": "quarantine" if quarantine else "ok",
            "window_size": self.policy.window_size,
            "min_failures": self.policy.min_failures,
            "release_success_streak": self.policy.release_success_streak,
            "observed_total": total,
            "observed_failures": failures,
            "failure_rate": round((failures / total), 6) if total else 0.0,
        }


def resolve_flaky_policy_from_settings(settings_obj: Any) -> FlakyQuarantinePolicy:
    window_size = int(getattr(settings_obj, "flaky_quarantine_window_size", 20) or 20)
    min_failures = int(getattr(settings_obj, "flaky_quarantine_min_failures", 2) or 2)
    release_success_streak = int(getattr(settings_obj, "flaky_quarantine_release_success_streak", 3) or 3)
    environment = str(getattr(settings_obj, "flaky_quarantine_environment", "default") or "default").strip().lower()
    profile_json = str(getattr(settings_obj, "flaky_quarantine_env_profiles_json", "") or "").strip()
    if profile_json:
        try:
            profile_payload = json.loads(profile_json)
        except Exception:
            profile_payload = {}
        if isinstance(profile_payload, dict):
            env_profile = profile_payload.get(environment)
            if isinstance(env_profile, dict):
                window_size = int(env_profile.get("window_size", window_size) or window_size)
                min_failures = int(env_profile.get("min_failures", min_failures) or min_failures)
                release_success_streak = int(
                    env_profile.get("release_success_streak", release_success_streak) or release_success_streak
                )
    return FlakyQuarantinePolicy(
        window_size=max(1, window_size),
        min_failures=max(1, min_failures),
        release_success_streak=max(1, release_success_streak),
    )
