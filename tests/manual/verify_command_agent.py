import sys
import asyncio
from typing import Dict, Any

# Add project root
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.core.agents.general.command import CommandAgent
from src.core.agents.base import AgentConfig

# Mock objects
class MockLLMResponse:
    class Message:
        def __init__(self):
            self.content = "Thinking..."
            self.tool_calls = [MockToolCall()]
            
        def model_dump(self):
            return {"role": "assistant", "content": self.content}

    class Choice:
        def __init__(self):
            self.message = MockLLMResponse.Message()

    def __init__(self):
        self.choices = [MockLLMResponse.Choice()]

class MockToolCall:
    def __init__(self):
        self.id = "call_123"
        self.function = self.Function()
    
    class Function:
        def __init__(self):
            self.name = "nuclei"
            self.arguments = '{"target": "http://localhost", "mode": "quick"}'

async def mock_agenerate(*args, **kwargs):
    if "tools" in kwargs:
        return MockLLMResponse()
    return None # Follow up

async def verify_fix():
    print("[*] Initializing CommandAgent...")
    config = AgentConfig(
        name="command",
        description="test",
        model="test-model",
        instructions="test"
    )
    agent = CommandAgent(config)
    
    # Mock LLM and methods to avoid real network/execution
    agent.llm.agenerate = mock_agenerate
    
    # Mock context
    agent.current_context = {"auth_headers": {"Cookie": "PHPSESSID=TEST"}}
    
    print("[*] Running process()...")
    # We expect this NOT to raise TypeError
    try:
        response = await agent.process("Scan localhost")
        print(f"[+] Process finished. Response: {response}")
    except TypeError as e:
        print(f"[-] FAILED with TypeError: {e}")
        import traceback
        traceback.print_exc()
    except Exception as e:
        print(f"[-] FAILED with Exception: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(verify_fix())
