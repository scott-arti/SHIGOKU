"""エージェントレジストリ - 複数エージェントの管理"""
from typing import Dict, Optional
from src.core.agent import Agent

class AgentRegistry:
    """複数エージェントを管理するレジストリ"""
    _agents: Dict[str, Agent] = {}
    _current_agent: Optional[str] = None
    
    @classmethod
    def register(cls, agent: Agent):
        """エージェントを登録"""
        cls._agents[agent.name] = agent
        if cls._current_agent is None:
            cls._current_agent = agent.name
    
    @classmethod
    def get(cls, name: str) -> Optional[Agent]:
        """名前でエージェントを取得"""
        return cls._agents.get(name)
    
    @classmethod
    def get_current(cls) -> Optional[Agent]:
        """現在のアクティブエージェントを取得"""
        if cls._current_agent:
            return cls._agents.get(cls._current_agent)
        return None
    
    @classmethod
    def set_current(cls, name: str) -> bool:
        """現在のエージェントを切り替え"""
        if name in cls._agents:
            cls._current_agent = name
            return True
        return False
    
    @classmethod
    def list_all(cls) -> Dict[str, Agent]:
        """全エージェントを取得"""
        return cls._agents.copy()
    
    @classmethod
    def clear(cls):
        """レジストリをクリア（テスト用）"""
        cls._agents.clear()
        cls._current_agent = None
