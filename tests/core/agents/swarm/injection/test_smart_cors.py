"""
SmartCORSHunter L1 + L2 テスト

L1: モックを使った単体テスト（ネットワーク不要）
L2: Flask ターゲットへの統合テスト（pytest-integration または手動）
"""

import socket
import time

import pytest
from unittest.mock import AsyncMock, patch

from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.smart_cors import SmartCORSHunter
from src.core.attack.cors_tester import CORSTester, CORSResult
from src.core.models.finding import Severity, VulnType


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _cors_result(**kwargs) -> CORSResult:
    base = dict(
        url="http://target.test/api",
        test_origin="https://evil.com",
        vulnerable=True,
        acao_header="https://evil.com",
        acac_header="true",
        misconfiguration="origin_reflection_with_credentials",
        severity="high",
    )
    base.update(kwargs)
    return CORSResult(**base)


# ---------------------------------------------------------------------------
# L2 integration fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def cors_server():
    from tests.helpers.cors_flask_target import start_cors_flask_server, CORS_FLASK_PORT
    start_cors_flask_server(port=CORS_FLASK_PORT)
    assert _wait_for_port("127.0.0.1", CORS_FLASK_PORT), "CORS Flask target did not start in time"
    yield f"http://127.0.0.1:{CORS_FLASK_PORT}"


# ---------------------------------------------------------------------------
# L1 unit tests
# ---------------------------------------------------------------------------

class TestCORSTesterIsVulnerable:
    """CORSTester._is_vulnerable のバグ修正確認"""

    def setup_method(self):
        self.tester = CORSTester()

    def test_wildcard_with_credentials(self):
        vuln, kind = self.tester._is_vulnerable("https://evil.com", "*", "true")
        assert vuln is True
        assert kind == "wildcard_with_credentials"

    def test_wildcard_no_credentials(self):
        vuln, kind = self.tester._is_vulnerable("https://evil.com", "*", "")
        assert vuln is True
        assert kind == "wildcard_no_credentials"

    def test_origin_reflection_with_credentials(self):
        origin = "https://attacker.com"
        vuln, kind = self.tester._is_vulnerable(origin, origin, "true")
        assert vuln is True
        assert kind == "origin_reflection_with_credentials"

    def test_origin_reflection_no_credentials(self):
        origin = "https://attacker.com"
        vuln, kind = self.tester._is_vulnerable(origin, origin, "")
        assert vuln is True
        assert kind == "origin_reflection"

    def test_null_origin_allowed(self):
        vuln, kind = self.tester._is_vulnerable("null", "null", "")
        assert vuln is True
        assert kind == "null_origin_allowed"

    def test_safe_no_reflection(self):
        vuln, kind = self.tester._is_vulnerable("https://evil.com", "https://trusted.com", "")
        assert vuln is False
        assert kind == ""

    def test_no_acao(self):
        vuln, _ = self.tester._is_vulnerable("https://evil.com", "", "")
        assert vuln is False

    def test_origin_reflection_does_not_require_evil_substring(self):
        origin = "https://legit-looking-but-attacker.com"
        vuln, kind = self.tester._is_vulnerable(origin, origin, "true")
        assert vuln is True, "evil substring 不要 — 送信Originが返れば脆弱"


class TestCORSTesterGeneratePocHtml:
    def test_contains_fetch(self):
        html = CORSTester.generate_poc_html(
            "http://target.test/api", "https://evil.com", "origin_reflection_with_credentials"
        )
        assert "fetch(" in html
        assert "credentials" in html
        assert "origin_reflection_with_credentials" in html

    def test_html_structure(self):
        html = CORSTester.generate_poc_html("http://t.test/", "null", "null_origin_allowed")
        assert "<html>" in html
        assert "<script>" in html


class TestSmartCORSHunterUnit:
    """SmartCORSHunter のモック単体テスト"""

    @pytest.mark.asyncio
    async def test_run_as_tool_vulnerable(self):
        hunter = SmartCORSHunter()
        mock_results = [_cors_result()]
        with patch.object(CORSTester, "scan_async", new=AsyncMock(return_value=mock_results)):
            result = await hunter.run_as_tool("http://target.test/api", {})
        assert result["vulnerable"] is True
        assert result["findings_count"] == 1
        assert result["results"][0]["misconfiguration"] == "origin_reflection_with_credentials"

    @pytest.mark.asyncio
    async def test_run_as_tool_safe(self):
        hunter = SmartCORSHunter()
        with patch.object(CORSTester, "scan_async", new=AsyncMock(return_value=[])):
            result = await hunter.run_as_tool("http://target.test/safe", {})
        assert result["vulnerable"] is False
        assert result["findings_count"] == 0

    @pytest.mark.asyncio
    async def test_execute_returns_findings(self):
        hunter = SmartCORSHunter()
        task = Task(id="t1", name="CORS", target="http://target.test/api", params={}, tags=["cors"])
        mock_results = [_cors_result()]
        with patch.object(CORSTester, "scan_async", new=AsyncMock(return_value=mock_results)):
            findings = await hunter.execute(task)
        assert len(findings) == 1
        assert findings[0].vuln_type == VulnType.CORS_MISCONFIGURATION
        assert findings[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_execute_uses_auth_headers(self):
        hunter = SmartCORSHunter()
        task = Task(
            id="t2", name="CORS", target="http://target.test/api",
            params={"_auth": {"auth_headers": {"Cookie": "session=abc"}, "cookies": ""}},
            tags=["cors"],
        )
        captured = {}
        original_init = CORSTester.__init__

        def patched_init(self_inner, target_domain=None, auth_headers=None):
            original_init(self_inner, target_domain=target_domain, auth_headers=auth_headers)
            captured["auth"] = self_inner.auth_headers

        async def fake_scan(self_inner, url=None, auth_headers=None):
            return []

        with patch.object(CORSTester, "__init__", patched_init), \
             patch.object(CORSTester, "scan_async", fake_scan):
            await hunter.execute(task)
        assert captured["auth"].get("Cookie") == "session=abc"


# ---------------------------------------------------------------------------
# L2 integration tests (require live Flask target)
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestSmartCORSHunterL2:
    """実 Flask ターゲットへの統合テスト"""

    @pytest.mark.asyncio
    async def test_reflect_endpoint_detected(self, cors_server):
        hunter = SmartCORSHunter()
        result = await hunter.run_as_tool(f"{cors_server}/reflect", {})
        assert result["vulnerable"] is True
        misconfigs = {r["misconfiguration"] for r in result["results"]}
        assert "origin_reflection_with_credentials" in misconfigs

    @pytest.mark.asyncio
    async def test_wildcard_endpoint_detected(self, cors_server):
        hunter = SmartCORSHunter()
        result = await hunter.run_as_tool(f"{cors_server}/wildcard", {})
        assert result["vulnerable"] is True
        misconfigs = {r["misconfiguration"] for r in result["results"]}
        assert "wildcard_no_credentials" in misconfigs

    @pytest.mark.asyncio
    async def test_null_endpoint_detected(self, cors_server):
        hunter = SmartCORSHunter()
        result = await hunter.run_as_tool(f"{cors_server}/null", {})
        assert result["vulnerable"] is True

    @pytest.mark.asyncio
    async def test_safe_endpoint_not_detected(self, cors_server):
        hunter = SmartCORSHunter()
        result = await hunter.run_as_tool(f"{cors_server}/safe", {})
        assert result["vulnerable"] is False
        assert result["findings_count"] == 0
