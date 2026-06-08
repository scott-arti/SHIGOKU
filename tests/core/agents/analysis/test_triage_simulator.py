import pytest
from typing import Any
from src.core.agents.analysis.triage_simulator import TriageSimulator, TriageResult, create_triage_simulator
from src.core.models.finding import Finding, Evidence, VulnType, Severity

@pytest.fixture
def triage_simulator():
    return create_triage_simulator()

def test_triage_perfect_finding(triage_simulator):
    """完璧なFindingの評価テスト"""
    finding = Finding(
        vuln_type=VulnType.SQLI,
        severity=Severity.HIGH,
        title="SQL Injection in /api/users endpoint leads to RCE",
        description="A time-based SQL injection vulnerability exists in the 'id' parameter. " * 5, # > 100 chars
        target_url="http://example.com",
        reproduction_steps=["1. Go to URL", "2. Inject payload"],
        impact="Full database compromise including user credentials.",
        evidence=Evidence(
            request_url="http://example.com/api/users?id=1'",
            request_method="GET",
            response_status=500,
            response_body="SQL Syntax Error"
        )
    )
    
    result = triage_simulator.simulate(finding)
    
    assert result.score == 100
    assert result.rejection_risk == 0.0
    assert len(result.issues) == 0

def test_triage_poor_quality_finding(triage_simulator):
    """品質の低いFindingの評価テスト"""
    finding = Finding(
        vuln_type=VulnType.XSS,
        severity=Severity.LOW,
        title="XSS", # Too short
        description="Found XSS.", # Too short
        target_url="http://example.com",
        reproduction_steps=[], # Missing
        impact="", # Missing
        evidence=Evidence() # Empty
    )
    
    result = triage_simulator.simulate(finding)
    
    assert result.score < 50
    assert result.rejection_risk > 0.5
    assert any(i.category == "quality" for i in result.issues)
    assert any(i.category == "poc" for i in result.issues)

@pytest.mark.asyncio
async def test_run_as_tool_with_dict(triage_simulator):
    """run_as_toolが辞書入力で動作するかテスト"""
    finding_dict = {
        "title": "SQL Injection in /api/users endpoint leads to RCE",
        "description": "A time-based SQL injection vulnerability exists in the 'id' parameter. " * 5,
        "reproduction_steps": ["1. Go to URL"],
        "impact": "Full database compromise.",
        "evidence": {
            "request_url": "http://example.com",
            "response_status": 200
        }
    }
    
    result = await triage_simulator.run_as_tool(finding_dict)
    
    assert result["score"] == 100
    assert result["rejection_risk"] == 0.0
