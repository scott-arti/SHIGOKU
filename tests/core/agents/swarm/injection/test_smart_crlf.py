"""
SmartCRLFHunter L1 + L2 テスト

L1: モックを使った単体テスト（ネットワーク不要）
L2: Flask ターゲットへの統合テスト（pytest -m integration が必要）
"""

import socket
import time

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.smart_crlf import SmartCRLFHunter, FALLBACK_PARAMS
from src.core.attack.crlf_tester import CRLFTester, CRLFResult
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


def _crlf_result(**kwargs) -> CRLFResult:
    base = dict(
        url="http://target.test/redirect",
        parameter="url",
        payload="%0d%0aX-Injected: shigoku",
        vulnerable=True,
        injected_header="X-Injected",
        severity="medium",
    )
    base.update(kwargs)
    return CRLFResult(**base)


# ---------------------------------------------------------------------------
# L2 integration fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def crlf_server():
    from tests.helpers.crlf_flask_target import start_crlf_server, FLASK_PORT
    start_crlf_server(FLASK_PORT)
    if not _wait_for_port("127.0.0.1", FLASK_PORT, timeout=5.0):
        pytest.skip("CRLF Flask target failed to start")
    yield f"http://127.0.0.1:{FLASK_PORT}"


# ---------------------------------------------------------------------------
# L1 Unit Tests
# ---------------------------------------------------------------------------

class TestSmartCRLFHunterRunAsTool:

    @pytest.mark.asyncio
    async def test_execute_returns_finding_when_vulnerable(self):
        """脆弱エンドポイント → Finding が生成される"""
        hunter = SmartCRLFHunter()
        mock_result = _crlf_result()

        with patch.object(CRLFTester, "scan_async", new=AsyncMock(return_value=[mock_result])):
            task = Task(
                id="test1", name="test", target="http://target.test/redirect",
                params={"url": "https://example.com"},
            )
            findings = await hunter.execute(task)

        assert len(findings) >= 1
        assert findings[0].vuln_type == VulnType.CRLF_INJECTION

    @pytest.mark.asyncio
    async def test_execute_returns_empty_when_safe(self):
        """安全エンドポイント → 空リスト"""
        hunter = SmartCRLFHunter()

        with patch.object(CRLFTester, "scan_async", new=AsyncMock(return_value=[])):
            task = Task(
                id="test2", name="test", target="http://target.test/safe", params={},
            )
            findings = await hunter.execute(task)

        assert findings == []

    @pytest.mark.asyncio
    async def test_finding_severity_is_medium(self):
        """CRLF は MEDIUM severity"""
        hunter = SmartCRLFHunter()
        mock_result = _crlf_result()

        with patch.object(CRLFTester, "scan_async", new=AsyncMock(return_value=[mock_result])):
            task = Task(
                id="test3", name="test", target="http://target.test/redirect",
                params={"url": "x"},
            )
            findings = await hunter.execute(task)

        assert findings[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_finding_has_injected_header_in_additional_info(self):
        """injected_header が additional_info に含まれる"""
        hunter = SmartCRLFHunter()
        mock_result = _crlf_result(injected_header="Location")

        with patch.object(CRLFTester, "scan_async", new=AsyncMock(return_value=[mock_result])):
            task = Task(
                id="test4", name="test", target="http://target.test/redirect",
                params={"url": "x"},
            )
            findings = await hunter.execute(task)

        assert findings[0].additional_info.get("injected_header") == "Location"

    @pytest.mark.asyncio
    async def test_finding_has_poc_request_and_poc_response(self):
        """poc_request と poc_response が additional_info に存在する"""
        hunter = SmartCRLFHunter()
        mock_result = _crlf_result()

        with patch.object(CRLFTester, "scan_async", new=AsyncMock(return_value=[mock_result])):
            task = Task(
                id="test5", name="test", target="http://target.test/redirect",
                params={"url": "x"},
            )
            findings = await hunter.execute(task)

        info = findings[0].additional_info
        assert "poc_request" in info
        assert "poc_response" in info

    @pytest.mark.asyncio
    async def test_tested_params_excludes_control_params(self):
        """META_KEYS が tested_params に含まれない"""
        hunter = SmartCRLFHunter()

        with patch.object(CRLFTester, "scan_async", new=AsyncMock(return_value=[])):
            result = await hunter.run_as_tool(
                "http://target.test/redirect",
                {"url": "x", "_auth": {"cookies": "c=1"}, "scan_profile": "default"},
            )

        tested = result["tested_params"]
        assert "_auth" not in tested
        assert "scan_profile" not in tested

    @pytest.mark.asyncio
    async def test_run_as_tool_empty_params_uses_fallback(self):
        """tested_params が空の場合は FALLBACK_PARAMS でスキャンされる（B4）"""
        hunter = SmartCRLFHunter()
        captured: list = []

        async def mock_scan(url, params):
            captured.extend(params)
            return []

        with patch.object(CRLFTester, "scan_async", side_effect=mock_scan):
            await hunter.run_as_tool("http://target.test/safe", {})

        for fp in FALLBACK_PARAMS:
            assert fp in captured

    @pytest.mark.asyncio
    async def test_run_as_tool_initializes_result_shape(self):
        """返却 dict のキーが全て揃っている"""
        hunter = SmartCRLFHunter()

        with patch.object(CRLFTester, "scan_async", new=AsyncMock(return_value=[])):
            result = await hunter.run_as_tool("http://target.test/safe", {})

        for key in ("vulnerable", "findings_count", "tested_params", "injected_header", "payload"):
            assert key in result

    @pytest.mark.asyncio
    async def test_auth_headers_forwarded_to_scanner(self):
        """auth_headers が CRLFTester に Cookie として渡される"""
        hunter = SmartCRLFHunter()
        created_scanners: list = []

        original_init = CRLFTester.__init__

        def capture_init(self_inner, auth_headers=None):
            original_init(self_inner, auth_headers=auth_headers)
            created_scanners.append(self_inner)

        async def mock_scan(url, params):
            return []

        with patch.object(CRLFTester, "__init__", capture_init), \
             patch.object(CRLFTester, "scan_async", side_effect=mock_scan):
            await hunter.run_as_tool(
                "http://target.test/redirect",
                {"_auth": {"cookies": "SESS=abc", "auth_headers": {}}},
            )

        assert created_scanners, "CRLFTester was not instantiated"
        assert created_scanners[0].auth_headers.get("Cookie") == "SESS=abc"

    @pytest.mark.asyncio
    async def test_evidence_object_set_on_finding(self):
        """Finding に Evidence オブジェクトが設定されている"""
        hunter = SmartCRLFHunter()
        mock_result = _crlf_result()

        with patch.object(CRLFTester, "scan_async", new=AsyncMock(return_value=[mock_result])):
            task = Task(
                id="test9", name="test", target="http://target.test/redirect",
                params={"url": "x"},
            )
            findings = await hunter.execute(task)

        assert findings[0].evidence is not None

    @pytest.mark.asyncio
    async def test_run_as_tool_error_returns_safe_default(self):
        """CRLFTester が例外を投げても安全なデフォルトを返す"""
        hunter = SmartCRLFHunter()

        with patch.object(CRLFTester, "scan_async", side_effect=Exception("timeout")):
            result = await hunter.run_as_tool("http://target.test/redirect", {"url": "x"})

        assert result["vulnerable"] is False
        assert result["findings_count"] == 0


# ---------------------------------------------------------------------------
# L2 Integration Tests
# ---------------------------------------------------------------------------

class TestSmartCRLFHunterIntegration:

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_crlf_scanner_detects_live(self, crlf_server):
        """Flask ターゲットの /redirect で検出される"""
        hunter = SmartCRLFHunter()
        result = await hunter.run_as_tool(
            f"{crlf_server}/redirect",
            {"url": "placeholder"},
        )
        assert result["vulnerable"] is True
        assert result["findings_count"] >= 1
        assert result["injected_header"] != ""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_crlf_scanner_no_false_positive_on_safe(self, crlf_server):
        """Flask ターゲットの /safe で偽陽性が出ない"""
        hunter = SmartCRLFHunter()
        result = await hunter.run_as_tool(f"{crlf_server}/safe", {})
        assert result["vulnerable"] is False
        assert result["findings_count"] == 0

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_crlf_scanner_execute_returns_findings(self, crlf_server):
        """execute() 経由でも Finding が返る"""
        hunter = SmartCRLFHunter()
        task = Task(
            id="l2_test",
            name="L2 CRLF Test",
            target=f"{crlf_server}/redirect",
            params={"url": "placeholder"},
        )
        findings = await hunter.execute(task)
        assert len(findings) >= 1
        assert findings[0].vuln_type == VulnType.CRLF_INJECTION
