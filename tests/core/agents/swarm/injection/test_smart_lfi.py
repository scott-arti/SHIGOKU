import pytest
from unittest.mock import MagicMock, AsyncMock
from src.core.attack.lfi_tester import LFITester
from src.core.agents.swarm.injection.smart_lfi import SmartLFIHunter
from src.core.agents.swarm.base import Task

@pytest.mark.asyncio
async def test_lfi_tester_traversal_depth():
    tester = LFITester()
    # /a/b/c/ -> 3 levels + up to 3 minimum = 3
    assert tester._calculate_traversal_depth("http://example.com/a/b/c/") == 3
    # /a/b/c/d/e/ -> 5 dirs + 1 file = 6 levels
    assert tester._calculate_traversal_depth("http://example.com/a/b/c/d/e/index.php") == 6

@pytest.mark.asyncio
async def test_lfi_tester_analysis():
    tester = LFITester()
    # Linux indicator
    is_vuln, os_p, evidence = tester._analyze_response("root:x:0:0:root:/root:/bin/bash")
    assert is_vuln is True
    assert os_p == "linux"
    
    # Windows indicator
    is_vuln, os_p, evidence = tester._analyze_response("[fonts]\nArial=arial.ttf")
    assert is_vuln is True
    assert os_p == "windows"

@pytest.mark.asyncio
async def test_smart_lfi_hunter_execute_no_vuln():
    config = {"name": "TestAgent", "description": "Test", "model": "gpt-4", "instructions": "test"}
    hunter = SmartLFIHunter(config=config)
    hunter.run_as_tool = AsyncMock(return_value={"vulnerable": False, "description": "No LFI detected."})
    task = Task(id="lfi-no-vuln", name="lfi", target="http://example.com/view.php?file=test.txt", params={"file": "test.txt"})
    
    findings = await hunter.execute(task)
    assert len(findings) == 0

@pytest.mark.asyncio
async def test_smart_lfi_hunter_execute_with_vuln():
    config = {"name": "TestAgent", "description": "Test", "model": "gpt-4", "instructions": "test"}
    hunter = SmartLFIHunter(config=config)
    hunter.run_as_tool = AsyncMock(return_value={
        "vulnerable": True,
        "param": "file",
        "evidence": "root:x:0:0:root:/root:/bin/bash",
        "description": "LFI detected.",
        "payloads_used": ["../../../../etc/passwd"],
    })
    task = Task(id="lfi-vuln", name="lfi", target="http://example.com/view.php?file=test.txt", params={"file": "test.txt"})
    
    findings = await hunter.execute(task)
    assert len(findings) > 0
    assert findings[0].vuln_type.value == "lfi"
    assert findings[0].additional_info.get("tested_params") == ["file"]
    assert findings[0].additional_info.get("payload") == "../../../../etc/passwd"


@pytest.mark.asyncio
async def test_run_as_tool_uses_url_query_params_not_manager_metadata():
    hunter = SmartLFIHunter(config={"model": "test-model"})
    hunter._run_lfi_deterministic_precheck = AsyncMock(return_value={"confirmed": False})
    hunter.run_loop = AsyncMock(return_value={"status": "completed"})

    result = await hunter.run_as_tool(
        "http://example.com/vulnerabilities/fi/?page=include.php",
        params={
            "_auth": {"auth_headers": {}, "cookies": ""},
            "method": "GET",
            "forms": [{"action": "/vulnerabilities/fi/"}],
            "url_evidence": {"method": "GET"},
            "scan_profile": "bbpt",
            "detection_mode": "phase1",
        },
    )

    assert "page" in result["tested_params"]
    assert "forms" not in result["tested_params"]
    assert "url_evidence" not in result["tested_params"]
    assert hunter.context.get("param") == "page"


@pytest.mark.asyncio
async def test_send_request_detects_lfi_indicator_beyond_snippet_window():
    hunter = SmartLFIHunter(config={"model": "test-model"})
    hunter.context = {
        "target": "http://example.com/vulnerabilities/fi/?page=include.php",
        "param": "page",
        "method": "GET",
        "params": {"page": "include.php"},
        "auth_headers": {},
    }

    long_html_prefix = "A" * 700
    hunter.smart_client.request = AsyncMock(
        return_value={
            "status": 200,
            "body": f"{long_html_prefix}\nroot:x:0:0:root:/root:/bin/bash\n",
            "error": None,
        }
    )

    obs = await hunter._send_request("../../../../etc/passwd")

    assert obs["diff"] == "lfi_found"
