import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from src.core.agents.swarm.scanner.webcache import WebCacheDeceptionSpecialist
from src.core.agents.swarm.base import Task

@pytest.mark.asyncio
async def test_web_cache_deception_vulnerable():
    # Mock AsyncNetworkClient
    with patch("src.core.agents.swarm.scanner.webcache.AsyncNetworkClient") as MockClient:
        client = MockClient.return_value
        
        # Mock responses
        mock_resp_auth = MagicMock()
        mock_resp_auth.status = 200
        mock_resp_auth.text = "<html>Profile Data: SensitiveUser@example.com</html>"
        
        mock_resp_hit = MagicMock()
        mock_resp_hit.status = 200
        mock_resp_hit.headers = {"X-Cache": "HIT"}
        mock_resp_hit.text = "<html>Profile Data: SensitiveUser@example.com</html>"
        
        # Specialist calls client.request multiple times: 
        # 1. Base auth check
        # 2. Trick request (auth)
        # 3. Validation request (unauth)
        client.request = AsyncMock(side_effect=[
            mock_resp_auth, # Base
            mock_resp_auth, # Trick (.css)
            mock_resp_hit  # Validation (.css)
        ])
        
        specialist = WebCacheDeceptionSpecialist(config={})
        task = Task(
            id="wc-1", 
            name="webcache", 
            target="https://example.com/profile",
            params={"cookies": {"session": "valid"}}
        )
        
        findings = await specialist.execute(task)
        
        assert len(findings) >= 1
        assert "Web Cache Deception" in findings[0].title

