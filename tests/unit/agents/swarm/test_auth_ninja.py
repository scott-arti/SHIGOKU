import pytest
import base64
import json
from unittest.mock import AsyncMock, MagicMock

from src.core.agents.swarm.auth_ninja import JWTInspector, OAuthDancer, SessionHijacker
from src.core.security.ethics_guard import ActionResult
from src.tools.builtin.handoff import HandoffStatus, HandoffContext

@pytest.fixture
def sample_jwt():
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "123", "role": "user"}
    
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    
    return f"{h_b64}.{p_b64}.dummy_signature"

@pytest.mark.asyncio
async def test_jwt_inspector_try_alg_none(sample_jwt):
    # Setup agent
    agent = JWTInspector()
    agent.network_client = MagicMock()
    
    # Mock network client response (success case)
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.text = "welcome admin"
    agent.network_client.request = AsyncMock(return_value=mock_resp)
    
    params = {"test_endpoint": "http://example.com/api/test"}
    result = await agent._try_alg_none("http://example.com", sample_jwt, params)
    
    assert result["success"] is True
    assert "forged_token" in result
    assert result["response_status"] == 200
    assert result["details"]["alg_variant"].lower() == "none"

@pytest.mark.asyncio
async def test_oauth_dancer_try_redirect_bypass():
    agent = OAuthDancer()
    agent.network_client = MagicMock()
    
    # Mock EthicsGuard to always allow for testing
    agent._guard.check_action = MagicMock(return_value=(ActionResult.ALLOWED, ""))
    
    # Mock network client response for a successful redirect to evil domain
    mock_resp = MagicMock()
    mock_resp.status = 302
    mock_resp.headers = {"Location": "https://evil.com/callback?code=123"}
    mock_resp.text = ""
    agent.network_client.request = AsyncMock(return_value=mock_resp)
    
    params = {
        "authorize_url": "http://example.com/oauth/authorize",
        "client_id": "client123",
        "legitimate_redirect": "https://legit.com/callback",
        "evil_redirect": "https://evil.com/callback"
    }
    
    # Test execution
    result = await agent._try_redirect_bypass("http://example.com", params)
    
    assert result["success"] is True
    assert "bypass_pattern" in result
    assert "evil.com" in result["redirect_location"]

@pytest.mark.asyncio
async def test_oauth_dancer_try_pkce_downgrade():
    agent = OAuthDancer()
    agent.network_client = MagicMock()
    agent._guard.check_action = MagicMock(return_value=(ActionResult.ALLOWED, ""))
    
    # Mock requests for both with and without PKCE -> both successful (simulating vulnerability)
    mock_resp_ok = MagicMock()
    mock_resp_ok.status = 200
    mock_resp_ok.text = "Please authorize"
    
    agent.network_client.request = AsyncMock(side_effect=[mock_resp_ok, mock_resp_ok])
    
    params = {
        "authorize_url": "http://example.com/oauth/authorize",
        "client_id": "client123",
        "legitimate_redirect": "https://legit.com/callback",
    }
    
    result = await agent._try_pkce_downgrade("http://example.com", params)
    
    assert result["success"] is True
    assert result["bypass_pattern"] == "PKCE Downgrade"
    assert result["details"]["pkce_required"] is False


@pytest.mark.asyncio
async def test_session_hijacker_try_weak_session_id_sets_vuln_type():
    agent = SessionHijacker()
    agent._payloads = {"session_cookie_names": ["PHPSESSID"]}

    cookie_jar = MagicMock()
    mock_session = MagicMock()
    mock_session.cookie_jar = cookie_jar

    agent.network_client = MagicMock()
    agent.network_client._session = mock_session
    agent.network_client.request = AsyncMock(return_value=MagicMock(status=200))
    agent.network_client.get_cookies = MagicMock(
        side_effect=[
            {"PHPSESSID": "fixed"},
            {"PHPSESSID": "fixed"},
            {"PHPSESSID": "fixed"},
            {"PHPSESSID": "fixed"},
            {"PHPSESSID": "fixed"},
        ]
    )

    result = await agent._try_weak_session_id("http://example.com", {})

    assert result["success"] is True
    assert result["vuln_type"] == "session_fixation"
    assert result["details"]["vuln_type"] == "session_fixation"


@pytest.mark.asyncio
async def test_session_hijacker_execute_uses_dynamic_vuln_type_from_attack_result():
    agent = SessionHijacker()
    agent._guard.check_action = MagicMock(return_value=(ActionResult.ALLOWED, ""))

    agent._try_session_fixation = AsyncMock(return_value={"success": False})
    agent._audit_cookie_attributes = AsyncMock(return_value={"success": False})
    agent._try_weak_session_id = AsyncMock(
        return_value={
            "success": True,
            "vuln_type": "session_fixation",
            "details": {"description": "Predictable session values"},
            "reproduction_steps": ["collect samples", "confirm static token"],
            "response_status": 200,
        }
    )

    context = HandoffContext(target_url="http://example.com", metadata={"login_url": "http://example.com/login"})
    result = await agent.execute(context)

    assert result.status == HandoffStatus.SUCCESS
    assert result.findings
    assert result.findings[0]["vuln_type"] == "session_fixation"


@pytest.mark.asyncio
async def test_session_hijacker_weak_id_executes_fixation_before_idor():
    agent = SessionHijacker()
    agent._guard.check_action = MagicMock(return_value=(ActionResult.ALLOWED, ""))
    agent.save_finding = AsyncMock(return_value="")

    call_order = []

    async def _mock_fixation(_target, _params):
        call_order.append("session_fixation")
        return {
            "success": True,
            "details": {"description": "session fixed"},
            "response_status": 200,
            "reproduction_steps": ["step1"],
        }

    async def _mock_weak_id_idor(_target, _params):
        call_order.append("weak_id_idor")
        return {
            "success": True,
            "vuln_type": "broken_access_control",
            "details": {"description": "weak_id id tampering confirmed"},
            "response_status": 200,
            "reproduction_steps": ["stepA", "stepB"],
        }

    agent._try_session_fixation = AsyncMock(side_effect=_mock_fixation)
    agent._try_weak_id_idor = AsyncMock(side_effect=_mock_weak_id_idor)
    agent._audit_cookie_attributes = AsyncMock(return_value={"success": False})
    agent._try_weak_session_id = AsyncMock(return_value={"success": False})

    context = HandoffContext(
        target_url="http://localhost:4280/vulnerabilities/weak_id/",
        metadata={"login_url": "http://localhost:4280/login.php", "credentials": {"username": "admin", "password": "password"}},
    )
    result = await agent.execute(context)

    assert call_order[:2] == ["session_fixation", "weak_id_idor"]
    assert result.status == HandoffStatus.SUCCESS
    assert any(f.get("vuln_type") == "broken_access_control" for f in (result.findings or []))


@pytest.mark.asyncio
async def test_session_hijacker_weak_id_idor_uses_auth_headers():
    agent = SessionHijacker()
    agent.network_client = MagicMock()

    resp1 = MagicMock()
    resp1.status = 200
    resp1.text = "User ID: 1 First Name: Alice Surname: Smith"
    resp2 = MagicMock()
    resp2.status = 200
    resp2.text = "User ID: 2 First Name: Bob Surname: Jones"
    agent.network_client.request = AsyncMock(side_effect=[resp1, resp2])

    result = await agent._try_weak_id_idor(
        "http://localhost:4280/vulnerabilities/weak_id/",
        {"auth_headers": {"Cookie": "PHPSESSID=test123; security=low"}},
    )

    assert result["success"] is True
    assert result.get("vuln_type") == "broken_access_control"
    for call in agent.network_client.request.await_args_list:
        assert call.kwargs.get("headers", {}).get("Cookie") == "PHPSESSID=test123; security=low"


@pytest.mark.asyncio
async def test_session_hijacker_weak_id_idor_prefers_runtime_session_cookie():
    agent = SessionHijacker()
    agent.network_client = MagicMock()
    agent.network_client.get_cookies = MagicMock(return_value={"PHPSESSID": "fresh456"})

    resp1 = MagicMock()
    resp1.status = 200
    resp1.text = "User ID: 1 First Name: Alice Surname: Smith"
    resp2 = MagicMock()
    resp2.status = 200
    resp2.text = "User ID: 2 First Name: Bob Surname: Jones"
    agent.network_client.request = AsyncMock(side_effect=[resp1, resp2])

    result = await agent._try_weak_id_idor(
        "http://localhost:4280/vulnerabilities/weak_id/",
        {"auth_headers": {"Cookie": "PHPSESSID=stale999; security=low"}, "cookies": "PHPSESSID=stale999; security=low"},
    )

    assert result["success"] is True
    assert result.get("vuln_type") == "broken_access_control"
    for call in agent.network_client.request.await_args_list:
        cookie_header = call.kwargs.get("headers", {}).get("Cookie", "")
        assert "PHPSESSID=fresh456" in cookie_header
        assert "security=low" in cookie_header
