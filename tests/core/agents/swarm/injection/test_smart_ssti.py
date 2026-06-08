import socket
import time

import pytest
from unittest.mock import AsyncMock, patch

from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.smart_ssti import SmartSSTIHunter
from src.core.models.finding import Severity, VulnType


# ---------------------------------------------------------------------------
# L2 integration: Flask target fixture
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


@pytest.fixture(scope="module")
def ssti_server():
    from tests.helpers.ssti_flask_target import start_server
    _, _ = start_server(port=15555)
    assert _wait_for_port("127.0.0.1", 15555), "Flask target did not start in time"
    yield "http://127.0.0.1:15555"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _vuln_result(**kwargs):
    base = {
        "vulnerable": True,
        "findings_count": 1,
        "param": "name",
        "engine": "jinja2",
        "payload": "{{7*7}}abc123",
        "confidence": 0.95,
        "evidence": "Result: 49abc123",
        "tested_params": ["name"],
        "all_results": [],
    }
    base.update(kwargs)
    return base


def _safe_result(**kwargs):
    base = {
        "vulnerable": False,
        "findings_count": 0,
        "param": None,
        "engine": "unknown",
        "payload": "",
        "confidence": 0.0,
        "evidence": "",
        "tested_params": ["name"],
        "all_results": [],
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# execute() tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_execute_returns_finding_when_vulnerable():
    hunter = SmartSSTIHunter(config={"model": "test-model"})
    hunter.run_as_tool = AsyncMock(return_value=_vuln_result())

    task = Task(
        id="ssti-vuln",
        name="ssti",
        target="http://example.com/greet?name=world",
        params={"name": "world"},
    )
    findings = await hunter.execute(task)

    assert len(findings) == 1
    assert findings[0].vuln_type == VulnType.SSTI
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].additional_info.get("engine") == "jinja2"
    assert findings[0].additional_info.get("tested_params") == ["name"]


@pytest.mark.asyncio
async def test_execute_returns_empty_when_safe():
    hunter = SmartSSTIHunter(config={"model": "test-model"})
    hunter.run_as_tool = AsyncMock(return_value=_safe_result())

    task = Task(
        id="ssti-safe",
        name="ssti",
        target="http://example.com/safe?name=world",
        params={"name": "world"},
    )
    findings = await hunter.execute(task)

    assert findings == []


@pytest.mark.asyncio
async def test_finding_severity_is_critical():
    hunter = SmartSSTIHunter(config={"model": "test-model"})
    hunter.run_as_tool = AsyncMock(return_value=_vuln_result())

    task = Task(id="ssti-sev", name="ssti", target="http://example.com/?x=1", params={})
    findings = await hunter.execute(task)

    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_finding_has_engine_in_additional_info():
    hunter = SmartSSTIHunter(config={"model": "test-model"})
    hunter.run_as_tool = AsyncMock(return_value=_vuln_result(engine="twig"))

    task = Task(id="ssti-eng", name="ssti", target="http://example.com/?x=1", params={})
    findings = await hunter.execute(task)

    assert findings[0].additional_info["engine"] == "twig"


# ---------------------------------------------------------------------------
# tested_params sanitation tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tested_params_excludes_control_params():
    hunter = SmartSSTIHunter(config={"model": "test-model"})
    hunter.run_as_tool = AsyncMock(return_value=_vuln_result(tested_params=["name"]))

    task = Task(
        id="ssti-clean",
        name="ssti",
        target="http://example.com/greet?name=world",
        params={"name": "world", "scan_profile": "ctf", "_auth": {}, "forms": []},
    )
    findings = await hunter.execute(task)

    tp = findings[0].additional_info.get("tested_params", [])
    assert "scan_profile" not in tp
    assert "_auth" not in tp
    assert "forms" not in tp


@pytest.mark.asyncio
async def test_last_tested_params_updated_after_run():
    hunter = SmartSSTIHunter(config={"model": "test-model"})

    with patch(
        "src.core.attack.ssti_scanner.SSTIScanner.scan_async",
        new_callable=AsyncMock,
        return_value=[],
    ):
        await hunter.run_as_tool(
            "http://example.com/greet?name=world",
            params={"name": "world"},
        )

    assert "name" in hunter.last_tested_params


# ---------------------------------------------------------------------------
# run_as_tool() shape tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_as_tool_initializes_result_shape():
    hunter = SmartSSTIHunter(config={"model": "test-model"})

    with patch(
        "src.core.attack.ssti_scanner.SSTIScanner.scan_async",
        new_callable=AsyncMock,
        return_value=[],
    ):
        result = await hunter.run_as_tool(
            "http://example.com/?name=x",
            params={"name": "x"},
        )

    for key in ("vulnerable", "findings_count", "tested_params", "engine"):
        assert key in result, f"Missing key: {key}"


@pytest.mark.asyncio
async def test_auth_headers_forwarded_to_scanner():
    hunter = SmartSSTIHunter(config={"model": "test-model"})

    with patch(
        "src.core.attack.ssti_scanner.SSTIScanner.scan_async",
        new_callable=AsyncMock,
        return_value=[],
    ) as mock_scan:
        await hunter.run_as_tool(
            "http://example.com/?name=x",
            params={
                "name": "x",
                "_auth": {"auth_headers": {"Cookie": "session=abc"}, "cookies": ""},
            },
        )

    mock_scan.assert_called_once()
    _, kwargs = mock_scan.call_args
    ah = kwargs.get("auth_headers", {})
    assert ah.get("Cookie") == "session=abc"


@pytest.mark.asyncio
async def test_tech_stack_triggers_fingerprint_scan():
    hunter = SmartSSTIHunter(config={"model": "test-model"})

    with patch(
        "src.core.attack.ssti_scanner.SSTIScanner.scan_with_fingerprint_async",
        new_callable=AsyncMock,
        return_value=[],
    ) as mock_fp:
        await hunter.run_as_tool(
            "http://example.com/?name=x",
            params={
                "name": "x",
                "_context": {"tech_stack": ["Django", "Python"]},
            },
        )

    mock_fp.assert_called_once()


# ---------------------------------------------------------------------------
# L2: 統合テスト（実 Flask ターゲット使用）
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_ssti_scanner_detects_jinja2_live(ssti_server):
    """実 Flask/Jinja2 エンドポイントで SSTI を検出できること"""
    from src.core.attack.ssti_scanner import SSTIScanner, TemplateEngine

    scanner = SSTIScanner(delay=0)
    results = scanner.scan(f"{ssti_server}/greet", ["name"])

    assert len(results) == 1
    assert results[0].vulnerable is True
    assert results[0].engine == TemplateEngine.JINJA2
    assert results[0].parameter == "name"


@pytest.mark.integration
def test_ssti_scanner_no_false_positive_on_safe(ssti_server):
    """安全なエンドポイントで陰性（誤検知なし）であること"""
    from src.core.attack.ssti_scanner import SSTIScanner

    scanner = SSTIScanner(delay=0)
    results = scanner.scan(f"{ssti_server}/safe", ["name"])

    assert results == []


@pytest.mark.integration
def test_ssti_scanner_detects_post_body(ssti_server):
    """POST body の name パラメータで SSTI を検出できること"""
    from src.core.attack.ssti_scanner import SSTIScanner, TemplateEngine

    scanner = SSTIScanner(delay=0)
    results = scanner.scan(f"{ssti_server}/post", ["name"], method="POST")

    assert len(results) == 1
    assert results[0].vulnerable is True
    assert results[0].engine == TemplateEngine.JINJA2
