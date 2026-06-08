"""
CRLF パイプライン結合テスト

以下3経路が完走することを検証する:

T1: run_crlf_hunter → current_context["findings"] に Finding が積まれる
T2: dispatch() の phase1 で vuln_type="crlf" が run_crlf_hunter を呼ぶ
T3: HaddixFormatter が crlf_injection Finding を受け取りレポート本文に出力する
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.agents.swarm.base import Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.reporting.haddix_formatter import HaddixFormatter


# ---------------------------------------------------------------------------
# helper: Finding オブジェクト（CRLF）
# ---------------------------------------------------------------------------

def _crlf_finding(url: str = "http://target.test/redirect") -> Finding:
    return Finding(
        target_url=url,
        vuln_type=VulnType.CRLF_INJECTION,
        severity=Severity.MEDIUM,
        title="CRLF Injection via parameter 'url'",
        description="Parameter 'url' reflects CRLF sequence into response headers.",
        evidence=Evidence(
            request_method="GET",
            request_url=url,
            request_headers={},
            response_status=302,
            response_headers={"X-Injected": "injected-via-crlf"},
        ),
        reproduction_steps=["1. Send payload"],
        impact="Header injection via CRLF sequence",
        source_agent="SmartCRLFHunter",
        confidence=0.90,
        tags=["crlf", "medium"],
        additional_info={
            "parameter": "url",
            "payload": "%0d%0aX-Injected:%20shigoku",
            "injected_header": "X-Injected",
            "tested_params": ["url"],
            "poc_request": "GET /redirect?url=%0d%0aX-Injected:%20shigoku HTTP/1.1\r\nHost: target.test\r\n\r\n",
            "poc_response": "HTTP/1.1 302 Found\r\nX-Injected: injected-via-crlf\r\n\r\n",
        },
    )


def _agent() -> InjectionManagerAgent:
    config = MagicMock()
    config.get.return_value = 1
    return InjectionManagerAgent(config=config)


# ---------------------------------------------------------------------------
# T1: run_crlf_hunter → current_context["findings"] に格納される
# ---------------------------------------------------------------------------

class TestRunCrlfHunterStoresFindings:

    @pytest.mark.asyncio
    async def test_findings_stored_in_current_context(self):
        """run_crlf_hunter が Finding を current_context["findings"] に extend する"""
        agent = _agent()
        agent.current_context = {"findings": [], "auth_headers": {}, "params": {}}

        mock_findings = [_crlf_finding()]
        agent.specialists["crlf"] = MagicMock()
        agent.specialists["crlf"].execute = AsyncMock(return_value=mock_findings)

        result = await agent.run_crlf_hunter(
            url="http://target.test/redirect",
            params={"url": "x"},
        )

        assert result["vulnerable"] is True
        assert result["findings_count"] == 1
        assert len(agent.current_context["findings"]) == 1
        stored = agent.current_context["findings"][0]
        assert stored.vuln_type == VulnType.CRLF_INJECTION

    @pytest.mark.asyncio
    async def test_no_findings_when_not_vulnerable(self):
        """脆弱性なし → findings は空のまま"""
        agent = _agent()
        agent.current_context = {"findings": [], "auth_headers": {}, "params": {}}

        agent.specialists["crlf"] = MagicMock()
        agent.specialists["crlf"].execute = AsyncMock(return_value=[])

        result = await agent.run_crlf_hunter(
            url="http://target.test/safe",
            params={"url": "x"},
        )

        assert result["vulnerable"] is False
        assert result["findings_count"] == 0
        assert len(agent.current_context["findings"]) == 0

    @pytest.mark.asyncio
    async def test_finding_has_correct_fields(self):
        """格納された Finding が正しいフィールドを持つ"""
        agent = _agent()
        agent.current_context = {"findings": [], "auth_headers": {}, "params": {}}

        finding = _crlf_finding()
        agent.specialists["crlf"] = MagicMock()
        agent.specialists["crlf"].execute = AsyncMock(return_value=[finding])

        await agent.run_crlf_hunter(url="http://target.test/redirect", params={"url": "x"})

        stored = agent.current_context["findings"][0]
        assert stored.severity == Severity.MEDIUM
        assert stored.source_agent == "SmartCRLFHunter"
        assert stored.confidence == pytest.approx(0.90)
        assert stored.additional_info["injected_header"] == "X-Injected"

    @pytest.mark.asyncio
    async def test_result_shape_has_required_keys(self):
        """run_crlf_hunter の戻り値が必須キーを持つ"""
        agent = _agent()
        agent.current_context = {"findings": [], "auth_headers": {}, "params": {}}

        agent.specialists["crlf"] = MagicMock()
        agent.specialists["crlf"].execute = AsyncMock(return_value=[_crlf_finding()])

        result = await agent.run_crlf_hunter(url="http://target.test/redirect", params={})

        for key in ("findings_count", "vulnerable", "tested_params", "injected_header", "payload"):
            assert key in result, f"Missing key: {key}"


# ---------------------------------------------------------------------------
# T2: dispatch() phase1 で vuln_type="crlf" → run_crlf_hunter が呼ばれる
# ---------------------------------------------------------------------------

class TestDispatchCrlfPhase1:

    @pytest.mark.asyncio
    async def test_dispatch_crlf_candidate_calls_run_crlf_hunter(self):
        """crlf_candidate カテゴリの Task を dispatch すると run_crlf_hunter が呼ばれる"""
        agent = _agent()

        called_urls = []

        async def fake_crlf_hunter(url, params=None, quick_mode=False, **_kw):
            called_urls.append(url)
            return {
                "findings_count": 1,
                "vulnerable": True,
                "tested_params": ["url"],
                "injected_header": "X-Injected",
                "payload": "%0d%0aX-Injected:%20shigoku",
                "findings": [_crlf_finding(url)],
            }

        agent.run_crlf_hunter = fake_crlf_hunter
        agent.current_context = {
            "findings": [], "auth_headers": {}, "params": {}, "url_results": [], "scan_profile": "bbpt",
        }

        task = Task(
            id="test_crlf_dispatch",
            name="CRLF Scan",
            target="http://target.test/redirect?url=x",
            params={
                "category": "crlf_candidate",
                "targets": ["http://target.test/redirect?url=x"],
            },
        )

        with patch.object(
            type(agent), "INJECTION_MANAGER_TIMEOUT", new=10
        ):
            result = await asyncio.wait_for(agent.dispatch(task), timeout=15)

        assert "http://target.test/redirect?url=x" in called_urls

    @pytest.mark.asyncio
    async def test_dispatch_stores_crlf_findings_in_context(self):
        """dispatch が run_crlf_hunter の Finding を context に格納する"""
        agent = _agent()
        target = "http://target.test/redirect?url=x"
        finding = _crlf_finding(target)

        async def fake_crlf_hunter(url, params=None, quick_mode=False, **_kw):
            agent.current_context["findings"].append(finding)
            return {
                "findings_count": 1,
                "vulnerable": True,
                "tested_params": ["url"],
                "injected_header": "X-Injected",
                "payload": "%0d%0aX-Injected:%20shigoku",
            }

        agent.run_crlf_hunter = fake_crlf_hunter

        task = Task(
            id="test_crlf_ctx",
            name="CRLF Scan",
            target=target,
            params={
                "category": "crlf_candidate",
                "targets": [target],
            },
        )

        with patch.object(type(agent), "INJECTION_MANAGER_TIMEOUT", new=10):
            await asyncio.wait_for(agent.dispatch(task), timeout=15)

        findings = agent.current_context.get("findings", [])
        crlf_findings = [f for f in findings if hasattr(f, "vuln_type") and f.vuln_type == VulnType.CRLF_INJECTION]
        assert len(crlf_findings) >= 1


# ---------------------------------------------------------------------------
# T3: HaddixFormatter が crlf_injection Finding をレポートに出力する
# ---------------------------------------------------------------------------

class TestHaddixFormatterCRLF:

    def _make_formatter(self) -> HaddixFormatter:
        fmt = HaddixFormatter()
        fmt.set_target("http://target.test", "CRLF Test")
        return fmt

    def _crlf_finding_dict(self) -> dict:
        return {
            "title": "CRLF Injection via parameter 'url'",
            "severity": "medium",
            "vuln_type": "crlf_injection",
            "target_url": "http://target.test/redirect",
            "summary": "Parameter 'url' reflects CRLF sequence into response headers.",
            "impact": "Header injection enabling session fixation and cache poisoning.",
            "source_agent": "SmartCRLFHunter",
            "confidence": 0.90,
            "tags": ["crlf", "medium"],
            "additional_info": {
                "parameter": "url",
                "payload": "%0d%0aX-Injected:%20shigoku",
                "injected_header": "X-Injected",
                "tested_params": ["url"],
                "poc_request": "GET /redirect?url=%0d%0aX-Injected:%20shigoku HTTP/1.1\r\nHost: target.test\r\n\r\n",
                "poc_response": "HTTP/1.1 302 Found\r\nX-Injected: injected-via-crlf\r\n\r\n",
            },
        }

    def test_add_finding_from_dict_accepted(self):
        """crlf_injection Finding が suppress されずに追加される"""
        fmt = self._make_formatter()
        fmt.add_finding_from_dict(self._crlf_finding_dict())
        assert len(fmt._findings) == 1
        assert fmt._findings[0].vuln_type == "crlf_injection"

    def test_crlf_finding_appears_in_markdown(self):
        """format_markdown() にタイトルが出力される"""
        fmt = self._make_formatter()
        fmt.add_finding_from_dict(self._crlf_finding_dict())
        md = fmt.format_markdown()
        assert "CRLF Injection" in md

    def test_crlf_vuln_type_in_markdown(self):
        """format_markdown() に crlf_injection または CRLF が含まれる"""
        fmt = self._make_formatter()
        fmt.add_finding_from_dict(self._crlf_finding_dict())
        md = fmt.format_markdown()
        assert "crlf" in md.lower()

    def test_crlf_cia_impact_in_markdown(self):
        """_cia_impact_assessment の CRLF ブランチ文字列が出力される"""
        fmt = self._make_formatter()
        fmt.add_finding_from_dict(self._crlf_finding_dict())
        md = fmt.format_markdown()
        assert "セッション" in md or "ヘッダー" in md or "フィッシング" in md

    def test_crlf_remediation_in_markdown(self):
        """_remediation の CRLF ブランチ文字列が出力される"""
        fmt = self._make_formatter()
        fmt.add_finding_from_dict(self._crlf_finding_dict())
        md = fmt.format_markdown()
        assert "\\r\\n" in md or "サニタイズ" in md or "ヘッダー設定" in md

    def test_low_confidence_crlf_suppressed(self):
        """confidence < 0.5 かつ verification signal なし → suppress される"""
        fmt = self._make_formatter()
        data = self._crlf_finding_dict()
        data["confidence"] = 0.3
        data["additional_info"] = {}
        fmt.add_finding_from_dict(data)
        assert len(fmt._findings) == 0
        assert len(fmt._suppressed_findings) == 1

    def test_poc_request_in_markdown(self):
        """PoC リクエストがレポートに出力される"""
        fmt = self._make_formatter()
        fmt.add_finding_from_dict(self._crlf_finding_dict())
        md = fmt.format_markdown()
        assert "X-Injected" in md or "redirect" in md.lower()
