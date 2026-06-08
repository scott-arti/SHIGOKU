from typing import Any, Dict, List, Optional
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import BaseModel, Field

class MCPToolWrapper:
    """
    Wraps an MCP tool to be compatible with the Agent's tool interface.
    """
    def __init__(self, session: ClientSession, name: str, description: str, input_schema: Dict[str, Any]):
        self.session = session
        self.name = name
        self.description = description
        self.input_schema = input_schema

    def to_schema(self) -> Dict[str, Any]:
        """Convert to OpenAI function schema."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.input_schema
            }
        }

    async def run(self, **kwargs) -> str:
        """Execute the MCP tool."""
        try:
            result = await self.session.call_tool(self.name, arguments=kwargs)
            # Format result content
            output = []
            for content in result.content:
                if content.type == "text":
                    output.append(content.text)
                elif content.type == "image":
                    output.append(f"[Image: {content.mime_type}]")
                elif content.type == "resource":
                    output.append(f"[Resource: {content.uri}]")
            
            return "\n".join(output) if output else "Tool executed successfully."
        except Exception as e:
            return f"Error executing MCP tool {self.name}: {str(e)}"

class MCPClientManager:
    """
    Manages connections to MCP servers.
    """
    def __init__(self):
        self.sessions: List[ClientSession] = []
        self._exit_stack = None

    async def connect_stdio(self, command: str, args: List[str], env: Optional[Dict[str, str]] = None) -> List[MCPToolWrapper]:
        """
        Connect to a stdio MCP server and return its tools.
        Note: This context should be managed properly (e.g., using contextlib.AsyncExitStack).
        For simplicity in this sync-ish runner, we might need a persistent connection manager.
        """
        # simplified for this implementation
        server_params = StdioServerParameters(command=command, args=args, env=env)
        
        # We need to maintain the connection. 
        # This is tricky without a global async context manager in the Runner.
        # For now, we'll return a setup function or object that manages the lifecycle.
        pass 
        # Implementation Detail: MCP requires `async with stdio_client(...)` which blocks.
        # We need to spawn it in background or manage it via a long-lived task.
        
        return []

# NOTE: Integrating MCP properly requires managing the async context of the client.
# Given the current simple architecture, we might need to structure this class to hold the context.
