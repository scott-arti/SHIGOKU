import pytest
import json
from unittest.mock import MagicMock, AsyncMock, patch
from src.core.agents.swarm.secret.sourcemap import SourceMapSpecialist
from src.core.agents.swarm.base import Task

@pytest.mark.asyncio
async def test_sourcemap_specialist_extraction():
    # Mock AsyncNetworkClient
    with patch("src.core.agents.swarm.secret.sourcemap.AsyncNetworkClient") as MockClient:
        client = MockClient.return_value
        
        # Mock .js.map response
        mock_map_resp = MagicMock()
        mock_map_resp.status = 200
        # Specialist uses resp.text then json.loads(resp.text)
        mock_map_resp.text = json.dumps({
            "version": 3,
            "sources": ["main.js"],
            "sourcesContent": [
                # Key must be 35+4 chars long
                "const API_KEY = 'AIzaSy-TEST-KEY-FOR-REGEX-VALIDATION-1234567890';",
                "console.log('hello');"
            ]
        })
        
        client.request = AsyncMock(return_value=mock_map_resp)
        
        specialist = SourceMapSpecialist(config={})
        task = Task(id="sm-1", name="sourcemap", target="https://example.com/main.js.map")
        
        findings = await specialist.execute(task)
        
        assert len(findings) >= 1
        assert "Exposed Source Map w/ Secrets" in findings[0].title
        assert "AIzaSy" in findings[0].evidence.response_body
