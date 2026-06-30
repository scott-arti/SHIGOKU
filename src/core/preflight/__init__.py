"""Preflight module - Strict entry gate validation before task execution.

Provides:
- EntryGate: orchestration of preflight checks
- EntryGateFacade: single entry point for all execution paths
- CaidoCheck: Caido mandatory connectivity validation
- ToolCheck: required tool existence and version verification
- AuthProbe: authenticated reachability preflight
- AIClassifier: lightweight AI fallback for ambiguous responses
"""

from src.core.preflight.models import (
    PreflightResult,
    PreflightFailure,
    PreflightStatus,
    ToolRequirement,
    ToolStatus,
    ToolCategory,
    AuthProbeResult,
    AuthClassification,
    ResponseClassificationInput,
    ResponseClassificationResult,
    PreflightContext,
    PreflightSnapshot,
    ReasonCodeNamespace,
    GatePhase,
    GatePolicy,
)

__all__ = [
    "PreflightResult",
    "PreflightFailure",
    "PreflightStatus",
    "ToolRequirement",
    "ToolStatus",
    "ToolCategory",
    "AuthProbeResult",
    "AuthClassification",
    "ResponseClassificationInput",
    "ResponseClassificationResult",
    "PreflightContext",
    "PreflightSnapshot",
    "ReasonCodeNamespace",
    "GatePhase",
    "GatePolicy",
    "EntryGate",
    "EntryGateFacade",
    "CaidoCheck",
    "ToolChecker",
    "ToolUpdatePolicy",
    "AuthProbe",
    "AIClassifier",
]


def __getattr__(name):
    """Lazy import for modules that may not exist yet."""
    if name == "EntryGate" or name == "EntryGateFacade":
        from src.core.preflight.entry_gate import EntryGate as _EntryGate, EntryGateFacade as _Facade
        if name == "EntryGate":
            return _EntryGate
        return _Facade
    if name == "CaidoCheck":
        from src.core.preflight.caido_check import CaidoCheck
        return CaidoCheck
    if name == "ToolChecker":
        from src.core.preflight.tool_check import ToolChecker
        return ToolChecker
    if name == "ToolUpdatePolicy":
        from src.core.preflight.tool_update_policy import ToolUpdatePolicy
        return ToolUpdatePolicy
    if name == "AuthProbe":
        from src.core.preflight.auth_probe import AuthProbe
        return AuthProbe
    if name == "AIClassifier":
        from src.core.preflight.ai_classifier import AIClassifier
        return AIClassifier
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
