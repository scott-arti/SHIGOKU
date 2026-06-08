import json
import sys
import os
from typing import List, Dict, Any
from src.core.utils.async_utils import safe_run_async

# プロジェクトルートパスを追加してインポート問題を解決
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.core.agent import Agent
from src.core.models.llm import LLMClient

# パス解決のための安全なインポート
try:
    from src.core.models.memory import Memory
except ImportError:
    Memory = None

class Runner:
    """
    [DEPRECATED] Phase 4でMasterConductorに統合予定。
    InteractiveBridgeまたはMasterConductorを使用してください。
    """
    def __init__(self, agent: Agent):
        self.agent = agent
        self.llm = LLMClient(model=agent.model)
        self.interrupted = False  # HITL用の割り込みフラグ
        
        # 実行グラフとメモリ管理
        from src.cli.graph import ExecutionGraph
        self.graph = ExecutionGraph()

    async def run(self, user_input: str, max_steps: int = None) -> str:
        """
        Run the agent process.
        Delegates to the agent's encapsulated process loop.
        """
        from src.core.models.memory import Memory
        
        # グラフをリセット
        self.graph.clear()
        self.graph.add_step(f"Start Task: {user_input[:30]}...")
        
        final_result = await self.agent.process(user_input)
        
        # メモリ保存（CTFのみ）
        if hasattr(self.agent, "mode") and self.agent.mode == "ctf":
             if Memory:
                try:
                    memory = Memory()
                    memory.save_session({
                        "summary": user_input,
                        "agent": self.agent.name if hasattr(self.agent, "name") else "Unknown",
                        "mode": self.agent.mode,
                        "steps": len(self.agent.messages),
                        "result": final_result
                    })
                except Exception as e:
                    print(f"Failed to save session: {e}")

        return final_result

    def run_sync(self, user_input: str, max_steps: int = 10) -> str:
        """Synchronous version."""
        return safe_run_async(self.run(user_input, max_steps))
