import pytest
import asyncio
import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from src.core.infra.network_client import AsyncNetworkClient

@pytest.fixture
def temp_session_file(tmp_path):
    return str(tmp_path / "session.json")

@pytest.mark.asyncio
async def test_save_and_load_session(temp_session_file):
    client = AsyncNetworkClient()
    client.initial_cookies = {"PHPSESSID": "test_cookie"}
    client.user_agent = "TestAgent"
    client.mode = "bugbounty"
    
    # Save
    await client.save_session_async(temp_session_file)
    
    assert os.path.exists(temp_session_file)
    
    # Verify content
    # Note: If orjson is used, the file might be simpler, but json.load handles it fine
    with open(temp_session_file, 'r') as f:
        data = json.load(f)
        assert data['cookies']['PHPSESSID'] == "test_cookie"
        assert data['user_agent'] == "TestAgent"
        assert data['mode'] == "bugbounty"
    
    # Load into new client
    new_client = AsyncNetworkClient()
    await new_client.load_session_async(temp_session_file)
    
    # Check if cookies are loaded into initial_cookies
    assert new_client.initial_cookies.get('PHPSESSID') == "test_cookie"
    assert new_client.user_agent == "TestAgent"
    assert new_client.mode == "bugbounty"

@pytest.mark.asyncio
async def test_load_non_existent_file():
    client = AsyncNetworkClient()
    with pytest.raises(FileNotFoundError):
        await client.load_session_async("/non/existent/path.json")
