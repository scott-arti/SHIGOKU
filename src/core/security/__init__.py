"""SHIGOKU Security Layer"""
from .ethics_guard import (
    EthicsGuard,
    ActionType,
    ActionResult,
    ScopeDefinition,
    get_ethics_guard,
    check_before_action,
)
from .enhanced_ethics_guard import (
    EnhancedEthicsGuard,
    ScopeConfig,
    ValidationResult,
    BlockReason,
    create_ethics_guard,
)
from .auth_manager import (
    AuthManager,
    AuthConfig,
    create_auth_manager,
)
from .pii_masker import (
    PIIMasker,
    PIIPattern,
    MaskResult,
    get_pii_masker,
    mask_pii,
    unmask_pii,
)
from .request_guard import (
    RequestGuard,
    get_request_guard,
    reset_request_guard,
)
from .execution_safeguard import (
    SafeguardDecision,
    PayloadRiskPolicy,
    MethodRiskPolicy,
    ExecutionSafeguardService,
    get_execution_safeguard,
    reset_execution_safeguard,
)

__all__ = [
    # 既存
    "EthicsGuard",
    "ActionType",
    "ActionResult",
    "ScopeDefinition",
    "get_ethics_guard",
    "check_before_action",
    # Phase 8
    "EnhancedEthicsGuard",
    "ScopeConfig",
    "ValidationResult",
    "BlockReason",
    "create_ethics_guard",
    "AuthManager",
    "AuthConfig",
    "create_auth_manager",
    # PII Masker
    "PIIMasker",
    "PIIPattern",
    "MaskResult",
    "get_pii_masker",
    "mask_pii",
    "unmask_pii",
    # Request Guard (HTTP/HITL adapter)
    "RequestGuard",
    "get_request_guard",
    "reset_request_guard",
    # Execution Safeguard (shared safeguard)
    "SafeguardDecision",
    "PayloadRiskPolicy",
    "MethodRiskPolicy",
    "ExecutionSafeguardService",
    "get_execution_safeguard",
    "reset_execution_safeguard",
]

