from typing import List, Optional, Dict, Any
from src.core.agents.base import BaseAgent, AgentConfig
from src.core.engine.agent_registry import register_agent
import asyncio

@register_agent(
    names=["agent", "general", "securitybot", "default"],
    tags=["all", "security"]
)
class Agent(BaseAgent):
    """
    General purpose agent (Standard ReAct/Tool-use).
    Refactored to use BaseAgent logic.
    """
    def __init__(
        self,
        name: str,
        instructions: str = "",
        model: Optional[str] = None,
        mode: str = "general",
        tools: List[Any] = None,
        workspace_root: Optional[str] = None,
        project_manager: Any = None,
        **kwargs,
    ):
        from src.config import settings

        resolved_model = model or getattr(settings, "model_output", None) or getattr(settings, "model", "deepseek/deepseek-chat")
        # Adapt legacy init to Config
        config = AgentConfig(
            name=name,
            description=f"Mode: {mode}",
            model=resolved_model,
            instructions=instructions,
            tools=tools or []
        )
        super().__init__(config, project_manager=project_manager, workspace_root=workspace_root, **kwargs)
        self.mode = mode
        self.image_url = None # Legacy support

    @property
    def name(self): return self.config.name
    
    @property
    def model(self): return self.config.model
    
    @property
    def tools(self): return self.config.tools

    async def process(self, input_message: str) -> str:
        """
        Process user input with ReAct loop.
        Note: The complex ReAct logic in the previous version was mostly redundant
        with the MasterConductor's orchestration. This version remains for legacy support.
        """
        from src.core.utils.tracing import Tracer
        import json
        
        # Input Guardrail
        is_safe, reason = self.check_input_guardrail(input_message)
        if not is_safe:
            return f"🛡️ Blocked: {reason}"

        self.add_message("user", input_message)
        Tracer.log_agent(self.name, "start_process")
        
        max_steps = 10
        final_response = "No response."
        
        for _ in range(max_steps):
            self._prune_messages()
            Tracer.log_llm(self.model)
            
            response = await asyncio.to_thread(
                self.llm.generate,
                messages=self.messages,
                tools=self.get_tools_schema()
            )
            
            if not response or not response.choices:
                return "Error: Empty response."
                
            msg = response.choices[0].message
            self.messages.append(msg.model_dump())
            
            if msg.tool_calls:
                for tool_call in msg.tool_calls:
                    fname = tool_call.function.name
                    args = json.loads(tool_call.function.arguments)
                    
                    # Guardrail check & execution
                    result = await self.execute_tool_with_guardrail(fname, args, self.tools)
                    
                    self.messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": str(result)
                    })
            elif msg.content:
                return msg.content
                
        return final_response
