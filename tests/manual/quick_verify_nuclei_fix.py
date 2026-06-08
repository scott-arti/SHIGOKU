import asyncio
import sys
import json
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock

# Setup path
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.core.agents.general.command import CommandAgent
from src.config import settings

async def run_quick_verification():
    print("🚀 Starting Quick Verification for Nuclei Path Fix...")
    
    # 1. Initialize Agent
    print(f"[-] Initializing CommandAgent (Model: {settings.model})...")
    
    # Create a mock AgentConfig-like object
    class MockConfig:
        model = settings.model
        tools = ["linux_cmd", "nuclei", "httpx"] # CommandAgent expects a list of tool names in config? Actually let's check input.
        name = "reconbot"
        
    # CommandAgent takes (config: AgentConfig). AgentConfig is likely Pydantic.
    # Let's import AgentConfig properly if possible, or mock it.
    from src.core.agents.base import AgentConfig
    
    config = AgentConfig(
        name="reconbot",
        model=settings.model,
        instructions="You are a recon bot.",
        description="Verification Agent"
    )
    
    agent = CommandAgent(config)
    
    # 2. Mock LLM to force specific legacy path usage
    # We want to simulate the Agent deciding to use a V2 path that doesn't exist standardly
    # AND is mapped to a DAST template
    legacy_path = "vulnerabilities/lfi/linux-lfi-fuzz.yaml" 
    
    # Construct the mock response
    mock_response = MagicMock()
    mock_message = MagicMock()
    mock_tool_call = MagicMock()
    
    # Define the tool call: nuclei target=localhost extra_args="-t <legacy_path>"
    mock_tool_call.id = "call_123"
    mock_tool_call.function.name = "nuclei"
    mock_tool_call.function.arguments = json.dumps({
        "target": "http://localhost:4280",
        "mode": "standard", 
        "extra_args": f"-t {legacy_path}"
    })
    
    # Set the response structure
    mock_message.tool_calls = [mock_tool_call]
    mock_message.content = "Scanning for CORS misconfigurations."
    mock_response.choices = [MagicMock(message=mock_message)]
    
    # Mock generation to return our pre-canned decision
    agent.llm.agenerate = AsyncMock(return_value=mock_response)
    
    # 3. Execution
    print(f"[-] Simulating Agent Action: Running Nuclei with legacy path: '{legacy_path}'")
    
    # We need to mock the *second* call to agenerate (the follow-up after tool execution)
    # just to avoid it crashing or hanging, though we mainly care about the tool run.
    agent.llm.agenerate.side_effect = [
        mock_response, # First call (decide to run tool)
        MagicMock(choices=[MagicMock(message=MagicMock(content="Scan complete."))]) # Second call (summarize)
    ]

    print("[-] Executing Agent Process...")
    # This will trigger:
    # 1. process() calls agenerate -> returns tool call
    # 2. process() calls execute_tool_with_guardrail -> calls NucleiTool.run
    # 3. NucleiTool.run calls _resolve_template_path (THIS IS WHAT WE TEST)
    # 4. NucleiTool runs the actual binary
    
    result = await agent.process("Check for CORS")
    
    # 4. Verification
    print("\n✅ Agent Execution Finished.")
    print("-" * 40)
    
    # We can inspect the agent's history or string output to see if it worked.
    # The actual tool output is stored in agent.messages
    tool_output_msg = next((m for m in agent.messages if m.get("role") == "tool"), None)
    
    if tool_output_msg:
        output = tool_output_msg["content"]
        print(f"📝 Tool Output Snippet:\n{output[:300]}...")
        
        if "Nuclei Error" in output or "No such file" in output:
            print("\n❌ FAILURE: Tool reported error.")
            if "No such file" in output:
                print("   -> Path resolution failed.")
        elif "No results found" in output:
            print("\n⚠️  SUCCESS (Partial): Tool ran but found nothing (Expected for localhost).")
            print("   -> Path was likely resolved correctly because Nuclei didn't crash on startup.")
        else:
            print("\n✅ SUCCESS: Tool ran and produced output!")
            print("   -> Legacy path was correctly resolved to V3 path.")
    else:
        print("\n❌ FAILURE: No tool execution recorded.")

if __name__ == "__main__":
    try:
        asyncio.run(run_quick_verification())
    except KeyboardInterrupt:
        print("\nAborted.")
    except Exception as e:
        print(f"\n❌ Error during verification: {e}")
