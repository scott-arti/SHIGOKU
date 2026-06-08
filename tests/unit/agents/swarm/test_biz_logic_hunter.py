import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch

from src.core.agents.swarm.biz_logic_hunter import BizLogicHunter, VerifyResult, VerifyContext
from src.intelligence.proxy_log_analyzer import FindingCandidate, SmellType
from src.core.models.finding import VulnType

from src.core.security.ethics_guard import ActionResult

@pytest.fixture
def biz_logic_hunter():
    hunter = BizLogicHunter(program_name="test_program")
    # EthicsGuardのモック設定
    hunter._guard.check_action = MagicMock(return_value=(ActionResult.ALLOWED, ""))
    # ネットワーククライアントのモック設定は各テスト内で行う
    hunter._make_request = AsyncMock()
    return hunter

@pytest.mark.asyncio
async def test_biz_logic_hunter_execute_race_condition(biz_logic_hunter):
    """
    executeメソッドがSmellType.PAYMENT_ENDPOINTでPOSTの場合、
    verify_race_conditionを呼び出すことを検証。
    """
    candidate = FindingCandidate(
        smell_type=SmellType.PAYMENT_ENDPOINT,
        target_url="http://example.com/api/payment",
        method="POST",
        evidence="test evidence",
        confidence=0.8,
        parameters={}
    )
    
    expected_context = VerifyContext(result=VerifyResult.SUCCESS)
    with patch.object(biz_logic_hunter, 'verify_race_condition', return_value=expected_context) as mock_race:
        result = await biz_logic_hunter.execute("http://example.com/api/payment", candidate)
        
        mock_race.assert_called_once()
        assert result == expected_context

@pytest.mark.asyncio
async def test_verify_race_condition_success(biz_logic_hunter):
    """
    verify_race_conditionで複数リクエストが200 OKになる場合、脆弱性と判定される。
    """
    candidate = FindingCandidate(
        smell_type=SmellType.PAYMENT_ENDPOINT,
        target_url="http://example.com/api/payment",
        method="POST",
        evidence="test evidence",
        confidence=0.8,
        parameters={}
    )
    
    # 全て正常（200）で返すモック
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = '{"status": "success"}'
    biz_logic_hunter._make_request.return_value = mock_response

    # 共有ワークスペースを保存しないようにモック
    with patch("src.core.workspace.shared_workspace.SharedWorkspace") as mock_workspace:
        context = await biz_logic_hunter.verify_race_condition("http://example.com/api/payment", candidate)
        
        assert context.result == VerifyResult.SUCCESS
        assert context.finding is not None
        assert context.finding.vuln_type == VulnType.RACE_CONDITION
        assert context.details["successful_requests"] == 5

@pytest.mark.asyncio
async def test_verify_race_condition_no_vuln(biz_logic_hunter):
    """
    verify_race_conditionで1回だけ成功し、それ以外がエラー(400など)になる場合、脆弱性なしと判定。
    """
    candidate = FindingCandidate(
        smell_type=SmellType.PAYMENT_ENDPOINT,
        target_url="http://example.com/api/payment",
        method="POST",
        evidence="test evidence",
        confidence=0.8,
        parameters={}
    )
    
    # 最初の1回だけ200を返し、後は400を返すようなモック
    call_counts = {"count": 0}
    async def side_effect(*args, **kwargs):
        mock_response = MagicMock()
        if call_counts["count"] == 0:
            mock_response.status_code = 200
            mock_response.text = '{"status": "success"}'
        else:
            mock_response.status_code = 400
            mock_response.text = '{"status": "already_processed"}'
        call_counts["count"] += 1
        return mock_response
        
    biz_logic_hunter._make_request.side_effect = side_effect

    context = await biz_logic_hunter.verify_race_condition("http://example.com/api/payment", candidate)
    
    assert context.result == VerifyResult.FAILED

@pytest.mark.asyncio
async def test_verify_state_machine_bypass_success():
    """
    verify_state_machine_bypassのテスト。
    KnowledgeGraphから取得したresult_pageに直接アクセス可能か検証。
    """
    hunter = BizLogicHunter(program_name="test_program")
    hunter._guard.check_action = MagicMock(return_value=(ActionResult.ALLOWED, ""))
    
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = '{"message": "order confirmed"}'
    hunter._make_request = AsyncMock(return_value=mock_response)
    
    with patch("src.core.infra.knowledge_graph.KnowledgeGraph") as mock_kg_cls:
        mock_kg = MagicMock()
        mock_kg.get_contextual_flows.return_value = [
            {
                "state_changing_endpoint": "/api/checkout",
                "result_page": "/api/order_success"
            }
        ]
        mock_kg_cls.return_value = mock_kg
        
        context = await hunter.verify_state_machine_bypass("example.com")
        
        assert context.result == VerifyResult.SUCCESS
        assert context.finding is not None
        assert "State Machine Bypass" in context.finding.title


def test_generate_cookie_mutations_includes_spec_patterns(biz_logic_hunter):
    admin_mutations = biz_logic_hunter._generate_cookie_mutations("admin", "0")
    role_mutations = biz_logic_hunter._generate_cookie_mutations("role", "user")
    user_mutations = biz_logic_hunter._generate_cookie_mutations("user", "victim")

    assert "1" in admin_mutations
    assert "true" in admin_mutations
    assert "admin" in role_mutations
    assert "attacker" in user_mutations


@pytest.mark.asyncio
async def test_verify_cookie_priv_esc_sets_authz_differential_metadata(biz_logic_hunter):
    candidate = FindingCandidate(
        smell_type=SmellType.IDOR_CANDIDATE,
        target_url="http://example.com/profile",
        method="GET",
        evidence="test evidence",
        confidence=0.8,
        parameters={},
    )

    baseline_resp = MagicMock()
    baseline_resp.status_code = 403
    baseline_resp.text = "forbidden"

    biz_logic_hunter.network_client = MagicMock()
    biz_logic_hunter.network_client.request = AsyncMock(return_value=baseline_resp)
    biz_logic_hunter.network_client.get_cookies = MagicMock(
        return_value={"admin": "0", "PHPSESSID": "abc"}
    )

    test_resp = MagicMock()
    test_resp.status_code = 200
    test_resp.text = "admin dashboard"
    biz_logic_hunter._make_request = AsyncMock(return_value=test_resp)

    context = await biz_logic_hunter.verify_cookie_priv_esc("http://example.com/profile", candidate)

    assert context.result == VerifyResult.SUCCESS
    assert context.finding is not None
    assert context.finding.additional_info["authz_differential"]["scenario"] == "cookie_privilege_escalation"
    assert "status_improved" in context.finding.additional_info["authz_differential"]["signals"]
    assert context.finding.additional_info["authz_differential"]["baseline_status"] == 403
    assert context.finding.additional_info["authz_differential"]["test_status"] == 200


@pytest.mark.asyncio
async def test_execute_admin_endpoint_falls_back_to_cookie_priv_esc(biz_logic_hunter):
    candidate = FindingCandidate(
        smell_type=SmellType.ADMIN_ENDPOINT,
        target_url="http://example.com/admin",
        method="GET",
        evidence="test evidence",
        confidence=0.8,
        parameters={},
    )

    failed_ctx = VerifyContext(result=VerifyResult.FAILED)
    success_ctx = VerifyContext(result=VerifyResult.SUCCESS)

    biz_logic_hunter.verify_admin_access = AsyncMock(return_value=failed_ctx)
    biz_logic_hunter.verify_cookie_priv_esc = AsyncMock(return_value=success_ctx)

    result = await biz_logic_hunter.execute("http://example.com/admin", candidate)

    assert result == success_ctx
    biz_logic_hunter.verify_admin_access.assert_awaited_once()
    biz_logic_hunter.verify_cookie_priv_esc.assert_awaited_once()


@pytest.mark.asyncio
async def test_verify_cookie_priv_esc_detects_identity_data_change_under_200_status(biz_logic_hunter):
    candidate = FindingCandidate(
        smell_type=SmellType.ADMIN_ENDPOINT,
        target_url="http://example.com/vulnerabilities/authbypass/get_user_data.php",
        method="GET",
        evidence="test evidence",
        confidence=0.8,
        parameters={},
    )

    baseline_resp = MagicMock()
    baseline_resp.status_code = 200
    baseline_resp.text = '{"first_name":"Gordon","last_name":"Brown","user_id":"2"}'

    biz_logic_hunter.network_client = MagicMock()
    biz_logic_hunter.network_client.request = AsyncMock(return_value=baseline_resp)
    biz_logic_hunter.network_client.get_cookies = MagicMock(
        return_value={"PHPSESSID": "abc123", "security": "low"}
    )

    test_resp = MagicMock()
    test_resp.status_code = 200
    test_resp.text = '{"first_name":"Admin","last_name":"User","user_id":"1"}'
    biz_logic_hunter._make_request = AsyncMock(return_value=test_resp)

    context = await biz_logic_hunter.verify_cookie_priv_esc(candidate.target_url, candidate)

    assert context.result == VerifyResult.SUCCESS
    assert context.finding is not None
    signals = context.finding.additional_info["authz_differential"]["signals"]
    assert "response_identity_data_changed" in signals


def test_set_session_manager_accepts_alternative_session_provider(biz_logic_hunter):
    session_manager = MagicMock()
    session_manager.get_all_alternative_sessions = MagicMock(
        return_value={"victim": {"headers": {"Cookie": "PHPSESSID=victim"}}}
    )

    biz_logic_hunter.set_session_manager(session_manager)

    assert biz_logic_hunter.is_cross_test_available() is True


@pytest.mark.asyncio
async def test_verify_idor_with_second_account_uses_alternative_headers_provider(biz_logic_hunter):
    session_manager = MagicMock()
    session_manager.get_all_alternative_sessions = MagicMock(
        return_value={"victim": {"headers": {"Cookie": "PHPSESSID=victim"}}}
    )
    biz_logic_hunter.set_session_manager(session_manager)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "victim profile data"

    biz_logic_hunter._make_request = AsyncMock(return_value=mock_resp)
    biz_logic_hunter._is_significant_idor = MagicMock(return_value=(True, "sensitive_data_exposed"))

    is_vuln, reason, resp = await biz_logic_hunter._verify_idor_with_second_account(
        "http://example.com/profile?id=2",
        "attacker profile data",
    )

    assert is_vuln is True
    assert reason == "sensitive_data_exposed"
    assert resp is mock_resp
    biz_logic_hunter._make_request.assert_awaited_once()
    _, kwargs = biz_logic_hunter._make_request.await_args
    assert kwargs["headers"]["Cookie"] == "PHPSESSID=victim"


@pytest.mark.asyncio
async def test_verify_idor_promotes_authz_probe_to_broken_access_control(biz_logic_hunter):
    candidate = FindingCandidate(
        smell_type=SmellType.IDOR_CANDIDATE,
        target_url="http://example.com/vulnerabilities/weak_id/?id=1",
        method="GET",
        evidence="test evidence",
        confidence=0.8,
        parameters={"authz_probe": "weak_id_idor"},
    )

    baseline_resp = MagicMock()
    baseline_resp.status_code = 200
    baseline_resp.text = '{"user_id":"1","username":"victim"}'

    tampered_resp = MagicMock()
    tampered_resp.status_code = 200
    tampered_resp.text = '{"user_id":"2","username":"admin"}'

    biz_logic_hunter._make_request = AsyncMock(side_effect=[baseline_resp, tampered_resp])

    with patch("src.core.workspace.shared_workspace.SharedWorkspace"):
        context = await biz_logic_hunter.verify_idor(candidate.target_url, candidate)

    assert context.result == VerifyResult.SUCCESS
    assert context.finding is not None
    assert context.finding.vuln_type == VulnType.BROKEN_ACCESS_CONTROL
    assert context.finding.additional_info.get("authz_probe") == "weak_id_idor"


@pytest.mark.asyncio
async def test_run_adds_findings_list_when_single_finding_returned(biz_logic_hunter):
    mocked_finding = MagicMock()
    mocked_finding.to_dict.return_value = {
        "id": "finding-authz-1",
        "title": "Broken Access Control via id",
        "vuln_type": "broken_access_control",
    }
    biz_logic_hunter.execute = AsyncMock(
        return_value=VerifyContext(
            result=VerifyResult.SUCCESS,
            method="idor",
            finding=mocked_finding,
        )
    )

    result = await biz_logic_hunter.run(
        {
            "target": "http://example.com/vulnerabilities/authbypass/get_user_data.php?id=2",
            "candidate": {"smell_type": "idor_candidate", "method": "GET"},
        }
    )

    assert result["success"] is True
    payload = result.get("data", {})
    assert "finding" in payload
    assert payload.get("findings") == [payload.get("finding")]
