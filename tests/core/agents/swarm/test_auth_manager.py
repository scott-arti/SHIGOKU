import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from src.core.agents.swarm.auth.manager import AuthManagerAgent
from src.core.agents.swarm.auth.auth_ninja import AuthNinja
from src.core.agents.swarm.base import Task

@pytest.mark.asyncio
async def test_auth_manager_ninja_delegation():
    """
    AuthManagerAgentがAuthNinjaを正しく呼び出すかテスト
    """
    # 1. Mocking
    mock_llm_response = MagicMock()
    mock_llm_response.choices = [MagicMock()]
    mock_llm_response.choices[0].message.content = "Thought: Need check.\nAction: run_auth_ninja(token=\"a.b.c\", check_type=\"all\")"
    
    mock_llm_response_2 = MagicMock()
    mock_llm_response_2.choices = [MagicMock()]
    mock_llm_response_2.choices[0].message.content = "Thought: Done.\nFinal Answer: Weak Secret Found"

    # 2. Setup Manager
    manager = AuthManagerAgent(config={"model": "test-model"})
    mock_llm = MagicMock()
    mock_llm.agenerate = AsyncMock(side_effect=[mock_llm_response, mock_llm_response_2])
    manager.set_llm_client(mock_llm)

    # 3. Running
    with patch("src.core.agents.swarm.auth.auth_ninja.AuthNinja.run_as_tool", new_callable=AsyncMock) as mock_tool:
        mock_tool.return_value = {"vulnerable": True, "description": "Weak Secret"}
        
        task = Task(id="test-auth", name="Test Auth", target="http://example.com")
        result = await manager.dispatch(task)

        # 4. Verification
        assert result.status == "success"
        
        # Tool呼び出し確認
        mock_tool.assert_called_once()
        args, kwargs = mock_tool.call_args
        assert args[0] == "a.b.c" # Token passed in action


@pytest.mark.asyncio
async def test_auth_manager_dispatch_uses_session_bac_precheck_for_weak_id():
    manager = AuthManagerAgent(config={"model": "test-model"})

    async def _mock_precheck(target_url, _params):
        manager.current_context.setdefault("findings", []).append(
            {
                "vuln_type": "broken_access_control",
                "title": "Broken Access Control via ID Tampering",
                "target_url": target_url,
            }
        )
        return {
            "vulnerable": True,
            "vulnerability": "broken_access_control",
            "message": "Session-based BAC/IDOR signal confirmed",
        }

    manager._run_session_bac_check = AsyncMock(side_effect=_mock_precheck)

    task = Task(
        id="weak-id-precheck",
        name="Authentication Analysis",
        target="http://localhost:4280/vulnerabilities/weak_id/",
        params={"cookies": "PHPSESSID=test123; security=low"},
    )
    result = await manager.dispatch(task)

    assert result.status == "success"
    assert result.findings
    assert result.execution_log
    assert result.execution_log[0]["reason"] == "session_bac_precheck_confirmed"
    manager._run_session_bac_check.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_session_bac_check_sets_idor_bola_detection_class():
    manager = AuthManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}

    manager.network_client = MagicMock()
    manager.network_client.request = AsyncMock(
        side_effect=[
            MagicMock(status=200, body="User ID: 1 First Name: Gordon"),
            MagicMock(status=200, body="User ID: 2 First Name: Smithy"),
            MagicMock(status=200, body="User ID: 1 First Name: Gordon"),
            MagicMock(status=200, body="User ID: 2 First Name: Smithy"),
        ]
    )

    result = await manager._run_session_bac_check(
        "http://localhost:4280/vulnerabilities/weak_id/?id=1",
        {"cookies": "PHPSESSID=test123; security=low"},
    )

    assert result["vulnerable"] is True
    assert manager.current_context["findings"]
    finding = manager.current_context["findings"][0]
    assert finding.additional_info.get("detection_class") == "idor_bola"
