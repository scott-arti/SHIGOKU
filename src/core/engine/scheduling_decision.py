from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class MutationSurface(str, Enum):
    """Identifies which part of a request would be mutated by a task."""
    PATH = "path"
    QUERY = "query"
    BODY = "body"
    HEADER = "header"
    COOKIE = "cookie"
    UNKNOWN = "unknown"


@dataclass
class SchedulingDecision:
    """Safe-by-construction shadow scheduling decision. Contains NO secrets."""
    lane: str                                          # one of 5 lanes: read_only, stateful_read, mutating, aggressive_exclusive, sequential_required
    parallel_safe: bool
    rate_limited: bool
    compat_lane: str | None = None                     # Phase 2 CATEGORY_TO_LANE derived lane for disagreement comparison
    lane_disagreement: bool = False
    reason_code: str = ""                              # never empty after classification
    mutex_key: str = ""                                # hash of (origin_key + session_key + auth_context_version + mutation_surface)
    mutation_surface: str = MutationSurface.UNKNOWN.value
    would_wait: bool = False
    would_reject: bool = False
    shadow_only: bool = True                           # Phase 4 always True
    origin_key: str = ""                               # already normalized
    auth_context_version: int = 0
