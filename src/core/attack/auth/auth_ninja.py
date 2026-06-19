"""
AuthNinja legacy shim.

Re-exports auth-ninja classes from the canonical swarm module so that
``from src.core.attack.auth import JWTInspector`` and similar imports
remain compatible after the AuthNinja split (SGK-2026-0301).
"""

from src.core.agents.swarm.auth_ninja import (  # noqa: F401
    BaseAuthAgent,
    JWTInspector,
    OAuthDancer,
    MFABypasser,
    SessionHijacker,
    AuthBypassResult,
    create_auth_agent,
)
