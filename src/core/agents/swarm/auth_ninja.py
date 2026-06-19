"""
AuthNinja Swarm: 認証特化型エージェント群

各クラスは、バイパス成功時に Context-Aware Handoff 2.0 形式で
文脈を返すインターフェースを持つ。

EthicsGuard連携: 全リクエストはスコープチェックを通過
Finding生成: 成功時にHackerOne報告書用のFindingを生成

This file is a thin facade. All class implementations are in sibling modules:
  - auth_ninja_base.py: BaseAuthAgent, AuthBypassResult, logger
  - auth_ninja_jwt.py: JWTInspector
  - auth_ninja_oauth.py: OAuthDancer
  - auth_ninja_mfa.py: MFABypasser
  - auth_ninja_session.py: SessionHijacker
"""

# Re-export base classes
from .auth_ninja_base import BaseAuthAgent, AuthBypassResult, logger  # noqa: F401

# Re-export concrete agents (eager import preserves @register_agent side-effects)
from .auth_ninja_jwt import JWTInspector  # noqa: F401
from .auth_ninja_oauth import OAuthDancer  # noqa: F401
from .auth_ninja_mfa import MFABypasser  # noqa: F401
from .auth_ninja_session import SessionHijacker  # noqa: F401


def create_auth_agent(agent_type: str) -> BaseAuthAgent:
    """AuthNinja Swarmエージェントを作成"""
    agents = {
        "jwt": JWTInspector,
        "jwt_inspector": JWTInspector,
        "oauth": OAuthDancer,
        "oauth_dancer": OAuthDancer,
        "mfa": MFABypasser,
        "mfa_bypasser": MFABypasser,
        "session": SessionHijacker,
        "session_hijacker": SessionHijacker,
    }

    agent_class = agents.get(agent_type.lower())
    if not agent_class:
        raise ValueError(f"Unknown auth agent: {agent_type}")

    return agent_class()
