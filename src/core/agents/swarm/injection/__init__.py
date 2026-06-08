"""
InjectionSwarm Package

インジェクション系脆弱性検査 Swarm
"""

from src.core.agents.swarm.injection.manager import InjectionManagerAgent

InjectionSwarm = InjectionManagerAgent
__all__ = ["InjectionManagerAgent", "InjectionSwarm"]

# Legacy Specialists (Need to check if they still exist or should be imported from elsewhere)
# For now, we only export the Manager.

__all__ = [
    "InjectionManagerAgent",
    "InjectionSwarm",
]
