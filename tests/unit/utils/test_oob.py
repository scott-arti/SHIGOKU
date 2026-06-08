import pytest
import asyncio
import aiohttp
from src.core.utils.oob_listener import LocalOOBListener
from src.core.agents.spec.oob_verifier import OOBVerifier

@pytest.fixture
async def oob_listener():
    # Use a random port or a specific test port to avoid conflicts
    listener = LocalOOBListener(port=13338)
    await listener.start()
    yield listener
    await listener.stop()

@pytest.mark.asyncio
async def test_oob_listener_start_stop():
    listener = LocalOOBListener(port=13339)
    await listener.start()
    assert listener._site is not None
    await listener.stop()
    assert listener._site is None

@pytest.mark.asyncio
async def test_oob_interaction_detection(oob_listener):
    # Generate payload
    url, token = oob_listener.generate_payload()
    assert token in url
    
    # Simulate external interaction using aiohttp client
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            assert response.status == 200
            text = await response.text()
            assert text == "OK"

    # Verify interaction is recorded
    interactions = oob_listener.get_interactions(token)
    assert len(interactions) == 1
    assert interactions[0].token == token
    assert interactions[0].method == "GET"

@pytest.mark.asyncio
async def test_oob_wait_for_interaction(oob_listener):
    url, token = oob_listener.generate_payload()
    
    # Task to wait for interaction
    wait_task = asyncio.create_task(oob_listener.wait_for_interaction(token, timeout=2.0))
    
    # Simulate interaction after a small delay
    await asyncio.sleep(0.5)
    async with aiohttp.ClientSession() as session:
        await session.get(url)
    
    # Should return True
    result = await wait_task
    assert result is True

@pytest.mark.asyncio
async def test_oob_wait_timeout(oob_listener):
    _, token = oob_listener.generate_payload()
    # Wait for non-existent interaction
    result = await oob_listener.wait_for_interaction(token, timeout=0.5)
    assert result is False

@pytest.mark.asyncio
async def test_oob_verifier_integration(oob_listener):
    verifier = OOBVerifier(listener=oob_listener)
    
    # Test valid interaction verification
    payload, token = verifier.generate_ssrf_payload()
    
    # Simulate interaction
    async with aiohttp.ClientSession() as session:
        await session.get(payload)
    
    assert await verifier.verify(token, timeout=1.0) is True
    
    details = verifier.get_details(token)
    assert len(details) > 0
    assert details[0]['method'] == 'GET'
