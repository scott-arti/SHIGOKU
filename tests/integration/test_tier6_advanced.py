import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from src.core.models.finding import Finding, VulnType, Severity
from src.core.agents.swarm.auth_ninja import JWTInspector
from src.core.agents.swarm.biz_logic_hunter import BizLogicHunter
from src.core.attack.chain_builder import ChainBuilder
from src.core.security.ethics_guard import EthicsGuard, ActionType, ActionResult
from src.intelligence.proxy_log_analyzer import FindingCandidate, SmellType

@pytest.mark.asyncio
async def test_jwt_exploit_to_chain():
    """
    JWT の none アルゴリズム脆弱性から Exploitation Chain が構築されるまでの
    統合フローをテストする。
    """
    candidate = FindingCandidate(
        target_url="http://example.com/api/admin",
        method="GET",
        smell_type=SmellType.JWT_DETECTED,
        confidence=0.9,
        evidence="JWT detected",
        parameters={"jwt": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ."}
    )

    with patch("src.core.security.ethics_guard.EthicsGuard.check_action", return_value=(ActionResult.ALLOWED, "OK")):
        ninja = JWTInspector()
        
        # モックネットワーク: JWTを書き換えたリクエストが成功する(200 OK) というシナリオ
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.text = '{"status": "admin_granted"}'
        mock_client.request = AsyncMock(return_value=mock_resp)
        
        ninja.network_client = mock_client
        
        # kwargs として実行
        result = await ninja.execute(target=candidate.target_url, params={"token": candidate.parameters.get("jwt")})
        
        from src.tools.builtin.handoff import HandoffStatus
        assert result.status == HandoffStatus.SUCCESS
        assert len(result.findings) > 0
        finding_dict = result.findings[0]
        
        # Dict文字列からFindingオブジェクトを復元
        finding = Finding(
            title=finding_dict["title"],
            description=finding_dict["description"],
            vuln_type=VulnType(finding_dict["vuln_type"]),
            severity=Severity(finding_dict["severity"]),
            target_url=finding_dict["target_url"],
            is_aggressive=True
        )
        
        # 3. ChainBuilder の動作確認
        builder = ChainBuilder()
        chain = builder.build_custom_chain(
            name="Chain: Admin Takeover",
            description="Chained JWT alg None",
            severity="CRITICAL",
            findings=[finding]
        )
        
        # Admin アクセスが成功すれば Chain が構築されているはず
        assert chain.name == "Chain: Admin Takeover"
        assert chain.component_findings[0].vuln_type == VulnType.JWT_ALG_NONE


@pytest.mark.asyncio
async def test_biz_logic_race_condition_to_chain():
    """
    決済エンドポイントでの Race Condition が ChainBuilder に渡り、
    Critical な連鎖として登録されるまでのフロー。
    """
    candidate = FindingCandidate(
        target_url="http://example.com/api/checkout",
        method="POST",
        smell_type=SmellType.PAYMENT_ENDPOINT,
        confidence=0.8,
        evidence="Payment endpoint",
        parameters={"body": '{"amount": 1000}'}
    )

    hunter = BizLogicHunter()
    
    # ここではモックを使って意図的にRace ConditionのFindingを返させる
    mock_finding = Finding(
        title="Payment Race Condition",
        description="Able to use single coupon multiple times",
        vuln_type=VulnType.RACE_CONDITION,
        severity=Severity.CRITICAL,
        target_url="http://example.com/api/checkout",
        is_aggressive=True
    )
    
    with patch.object(hunter, 'execute', return_value=[mock_finding]):
        findings = await hunter.execute(candidate)
        assert len(findings) == 1
        
        # ChainBuilder に評価させる
        builder = ChainBuilder()
        chain = builder.build_custom_chain(
            name="Race Condition Double Spend",
            description="Coupons double spend",
            severity="CRITICAL",
            findings=[findings[0]]
        )
        
        assert len(chain.component_findings) == 1
        assert chain.severity == "CRITICAL"


@pytest.mark.asyncio
async def test_ethics_guard_chain_approval():
    """
    Exploitation Chain が実際の攻撃実行（EXPLOIT）に移る際に、
    EthicsGuard によって承認待ち（REQUIRES_APPROVAL）となることをテストする。
    """
    builder = ChainBuilder()
    finding = Finding(
        title="Admin Access via JWT",
        description="JWT alg:none exploit",
        vuln_type=VulnType.JWT_ALG_NONE,
        severity=Severity.CRITICAL,
        target_url="http://example.com/api",
        is_aggressive=True
    )
    chain = builder.build_custom_chain("Chain", "desc", "CRITICAL", [finding])
    
    # 攻撃実行のためのActionパラメータを作成
    params = {
        "agent_name": "MasterConductor",
        "risk_score": 9.0, # CRITICAL 相当の高さ
        "description": f"Executing exploit chain: {chain.name}",
        "requires_approval": True # EthicsGuard が ActionType.EXPLOIT なき場合に REQUIRES_APPROVAL を出すトリガー
    }
    
    guard = EthicsGuard()
    
    import os
    with patch.dict(os.environ, {"SHIGOKU_MODE": "bugbounty"}):
        action_result, reason = guard.check_action(ActionType.HTTP_REQUEST, "http://example.com/api", params)
        
        assert action_result == ActionResult.REQUIRES_APPROVAL
