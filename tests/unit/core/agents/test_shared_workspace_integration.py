import pytest
import os
import json
from src.core.agents.base import BaseAgent, AgentConfig

class DummyAgent(BaseAgent):
    """Test agent inheriting from BaseAgent"""
    async def process(self, input_message: str) -> str:
        return "processed"

@pytest.fixture
def agent_config():
    return AgentConfig(
        name="TestAgent",
        description="Agent for testing workspace integration",
        model="test-model",
        instructions="Test instructions"
    )

@pytest.mark.asyncio
async def test_shared_workspace_initialization(agent_config, tmp_path):
    # Test initialization with workspace_root
    workspace_root = tmp_path / "workspace"
    agent = DummyAgent(agent_config, workspace_root=str(workspace_root))
    
    assert agent.workspace is not None
    assert str(agent.workspace.root) == str(workspace_root)
    assert agent.workspace_root == str(workspace_root)
    
    # Check directory creation
    assert (workspace_root / "findings").exists()
    assert (workspace_root / "intel").exists()

@pytest.mark.asyncio
async def test_save_finding_helper(agent_config, tmp_path):
    workspace_root = tmp_path / "workspace"
    agent = DummyAgent(agent_config, workspace_root=str(workspace_root))
    
    finding_data = {
        "id": "test_vuln_1",
        "title": "Test Vulnerability",
        "severity": "high",
        "target": "example.com",
        "description": "Test description",
        "reproduction_steps": [],
        "evidence_files": [],
        "timestamp": "2023-01-01T00:00:00"
    }
    
    # Save finding
    file_path = await agent.save_finding(finding_data)
    
    assert file_path
    assert os.path.exists(file_path)
    
    # Verify content
    with open(file_path, "r") as f:
        saved_data = json.load(f)
        assert saved_data["id"] == "test_vuln_1"
        assert saved_data["title"] == "Test Vulnerability"

@pytest.mark.asyncio
async def test_save_intel_helper(agent_config, tmp_path):
    workspace_root = tmp_path / "workspace"
    agent = DummyAgent(agent_config, workspace_root=str(workspace_root))
    
    intel_data = {"ip": "127.0.0.1", "ports": [80, 443]}
    
    # Save intel
    # Should use agent name "TestAgent" as type if not specified
    file_path = await agent.save_intel(data=intel_data)
    
    assert file_path
    assert os.path.exists(file_path)
    assert "TestAgent.jsonl" in file_path
    
    # Save specific type
    file_path_domain = await agent.save_intel(intel_type="domain", data={"domain": "example.com"})
    assert "domain.jsonl" in file_path_domain
