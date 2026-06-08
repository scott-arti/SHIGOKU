"""AuthNinja Swarm
Swarm agents for advanced operations.
"""

from .auth_ninja import (
    BaseAuthAgent,
    JWTInspector,
    OAuthDancer,
    MFABypasser,
    AuthBypassResult,
    create_auth_agent,
)
from .biz_logic_hunter import (
    BizLogicHunter,
    VerifyResult,
    VerifyContext,
    create_bizlogic_hunter,
)
# Context-Aware Handoff 2.0
from src.tools.builtin.handoff import (
    HandoffContext,
    HandoffResult,
    HandoffStatus,
    create_handoff_result,
    create_handoff_context,
)

__all__ = [
    "BaseAuthAgent",
    "JWTInspector",
    "OAuthDancer",
    "MFABypasser",
    "HandoffContext",
    "HandoffResult",
    "HandoffStatus",
    "AuthBypassResult",
    "create_auth_agent",
    "create_handoff_result",
    "create_handoff_context",
    "BizLogicHunter",
    "VerifyResult",
    "VerifyContext",
    "create_bizlogic_hunter",
]
