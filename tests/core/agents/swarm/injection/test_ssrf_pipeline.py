import pytest
from unittest.mock import AsyncMock, MagicMock

from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.reporting.haddix_formatter import HaddixFormatter


def _ssrf_finding(url: str = "http://target.test/fetch?url=x") -> Finding:
    return Finding(
        target_url=url,
        vuln_type=VulnType.SSRF,
        severity=Severity.HIGH,
        title="SSRF detected",
        description="Response-based SSRF indicator matched.",
        evidence=Evidence(request_method="GET", request_url=url, response_status=200, response_body="ami-id"),
        source_agent="SmartSSRFHunter",
        confidence=0.9,
        additional_info={
            "tested_params": ["url"],
            "payload_type": "cloud_metadata",
            "payload": "http://169.254.169.254/latest/meta-data/",
            "evidence": "ami-id: i-123",
            "poc_request": "GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1",
            "poc_response": "HTTP/1.1 200 OK",
            "poc_html": "<form></form>",
        },
    )


def _agent() -> InjectionManagerAgent:
    cfg = MagicMock()
    cfg.get.return_value = 1
    return InjectionManagerAgent(config=cfg)


class TestRunSsrfHunterStoresFindings:
    @pytest.mark.asyncio
    async def test_findings_stored_in_current_context(self):
        agent = _agent()
        agent.current_context = {"findings": [], "auth_headers": {}, "params": {}}
        finding = _ssrf_finding()
        agent.specialists["ssrf"] = MagicMock()
        agent.specialists["ssrf"].execute_with_retry = AsyncMock(return_value=[finding])
        result = await agent.run_ssrf_hunter("http://target.test/fetch?url=x", {"url": "x"})
        assert result["vulnerable"] is True
        assert len(agent.current_context["findings"]) == 1


class TestHaddixFormatterSSRF:
    def test_ssrf_finding_appears_in_markdown(self):
        fmt = HaddixFormatter()
        fmt.set_target("http://target.test", "SSRF Test")
        fmt.add_finding_from_dict(
            {
                "title": "SSRF detected",
                "severity": "high",
                "vuln_type": "ssrf",
                "target_url": "http://target.test/fetch?url=x",
                "summary": "Response-based SSRF indicator matched.",
                "impact": "Internal metadata may be exposed.",
                "source_agent": "SmartSSRFHunter",
                "confidence": 0.9,
                "additional_info": {
                    "tested_params": ["url"],
                    "payload": "http://169.254.169.254/latest/meta-data/",
                    "poc_request": "GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1",
                    "poc_response": "HTTP/1.1 200 OK",
                },
            }
        )
        md = fmt.format_markdown()
        assert "SSRF detected" in md
