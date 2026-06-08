"""
AuthSwarm Package

認証系脆弱性検査 Swarm
"""

from src.core.agents.swarm.auth.manager import AuthManagerAgent

# AuthSwarm is an alias for AuthManagerAgent
AuthSwarm = AuthManagerAgent

__all__ = [
    "AuthManagerAgent",
    "AuthSwarm",
]
