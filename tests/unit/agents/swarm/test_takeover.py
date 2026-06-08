import pytest
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch, mock_open
from src.core.agents.swarm.discovery.takeover import TakeoverSpecialist
from src.core.agents.swarm.base import Task

@pytest.mark.asyncio
async def test_takeover_specialist_execution():
    # Mock SubjackTool.run
    with patch("src.core.agents.swarm.discovery.takeover.SubjackTool") as MockTool:
        tool_instance = MockTool.return_value
        tool_instance.run = MagicMock(return_value="[GitHub] test.example.com\n")
        
        # Mock file operations for dead_subs.txt
        with patch("src.core.agents.swarm.discovery.takeover.Path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data="test.example.com\ndead.example.com")):
            
            specialist = TakeoverSpecialist(config={})
            # Mock workspace by setting the internal instance variable
            mock_ws = MagicMock()
            mock_ws.root = Path("/tmp/fake_ws")
            specialist._workspace_instance = mock_ws
            
            task = Task(id="tk-1", name="takeover", target="example.com")
            
            findings = await specialist.execute(task)
            
            assert len(findings) == 1
            assert "Subdomain Takeover: test.example.com (GitHub)" in findings[0].title

            assert findings[0].severity.value == "high"
            assert "GitHub" in findings[0].description
