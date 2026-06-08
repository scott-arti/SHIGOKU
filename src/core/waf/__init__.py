"""WAF modeling utilities (Phase 4 entrypoint)."""

from src.core.waf.detector import WAFDetectionResult, WAFDetector
from src.core.waf.bypasser import WAFBypasser

__all__ = [
    "WAFDetectionResult",
    "WAFDetector",
    "WAFBypasser",
]

