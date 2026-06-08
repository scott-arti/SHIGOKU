
import pytest
import json
from unittest.mock import MagicMock, AsyncMock, patch
from urllib.parse import urlparse, parse_qs
from src.core.agents.swarm.injection.smart_xss import SmartXSSHunter
from src.core.agents.swarm.base import Task
from src.core.models.finding import VulnType

@pytest.mark.asyncio
async def test_smart_xss_probe_logic_multiple_reflections():
    """SmartXSSHunter の強化された複数反射検知ロジックをテスト"""
    hunter = SmartXSSHunter()
    
    html_content = """
    <html>
    <body>
        <h1>Hello shigoku_probe</h1>
        <input value="shigoku_probe">
        <script>var x = 'shigoku_probe';</script>
        <!-- shigoku_probe -->
    </body>
    </html>
    """
    contexts = hunter._analyze_reflection(html_content, "shigoku_probe")
    
    assert len(contexts) == 4
    assert any(c["context"] == "HTML Body" for c in contexts)
    assert any("Attribute" in c["context"] for c in contexts)
    assert any(c["context"] == "JavaScript" for c in contexts)
    assert any(c["context"] == "Comment" for c in contexts)

@pytest.mark.asyncio
async def test_smart_xss_post_body_flow():
    """SmartXSSHunter の POST ボディインジェクションフローをテスト"""
    hunter = SmartXSSHunter(config={"model": "test-model"})
    
    # 1: probe (POST), 2: finish
    mock_responses = [
        MagicMock(choices=[MagicMock(message=MagicMock(content="THOUGHT: Testing POST body.\nACTION: probe\nINPUT: probe123"))]),
        MagicMock(choices=[MagicMock(message=MagicMock(content="THOUGHT: Reflected. Found vulnerability.\nACTION: finish\nINPUT: Vulnerable"))]),
    ]
    hunter.llm.agenerate = AsyncMock(side_effect=mock_responses)
    
    hunter.smart_client.request = AsyncMock(return_value={
        "status": 200, "body": "<html>probe123</html>", "waf_suspected": False
    })
    
    # POST タスク
    task = Task(
        id="test-post-xss", 
        name="POST XSS Test", 
        target="http://example.com/api/msg",
        params={
            "method": "POST",
            "content_type": "json",
            "body": {"message": "hello"}
        }
    )
    findings = await hunter.execute(task)
    
    assert len(findings) == 1
    # リクエストが POST で行われたか確認
    hunter.smart_client.request.assert_called()
    args, kwargs = hunter.smart_client.request.call_args_list[0]
    assert args[0] == "POST"
    assert kwargs["json"] == {"message": "probe123"}

@pytest.mark.asyncio
async def test_smart_xss_stored_flow():
    """SmartXSSHunter の Stored XSS フロー (POST -> GET) をテスト"""
    hunter = SmartXSSHunter(config={"model": "test-model"})
    
    # 1: stored_probe, 2: finish
    mock_responses = [
        MagicMock(choices=[MagicMock(message=MagicMock(content="THOUGHT: Testing Stored XSS.\nACTION: stored_probe\nINPUT: stored123"))]),
        MagicMock(choices=[MagicMock(message=MagicMock(content="THOUGHT: Reflected on display page.\nACTION: finish\nINPUT: Vulnerable"))]),
    ]
    hunter.llm.agenerate = AsyncMock(side_effect=mock_responses)
    
    # リクエストのモック（1回目はPOST, 2回目はGETでの確認）
    hunter.smart_client.request = AsyncMock(side_effect=[
        {"status": 200, "body": "Stored successful", "waf_suspected": False}, # POST to target
        {"status": 200, "body": "Reflected here: stored123", "waf_suspected": False}, # GET from reflection_url
    ])
    
    task = Task(
        id="test-stored-xss", 
        name="Stored XSS Test", 
        target="http://example.com/update",
        params={
            "method": "POST",
            "body": {"name": "test"},
            "reflection_url": "http://example.com/profile"
        }
    )
    findings = await hunter.execute(task)
    
    assert len(findings) == 1
    assert hunter.smart_client.request.call_count == 2
    # 2回目の確認リクエストが reflection_url に対して行われたか
    args, kwargs = hunter.smart_client.request.call_args_list[1]
    assert args[0] == "GET"
    assert args[1] == "http://example.com/profile"


@pytest.mark.asyncio
async def test_smart_xss_run_as_tool_accepts_param_and_discovered_hints():
    hunter = SmartXSSHunter(config={"model": "test-model"})

    async def _mock_request(_method, target_url, **_kwargs):
        query = parse_qs(urlparse(target_url).query)
        reflected = ""
        if query:
            first_key = next(iter(query.keys()))
            reflected = (query.get(first_key) or [""])[0]
        return {"status": 200, "body": f"<html>{reflected}</html>", "headers": {}, "waf_suspected": False}

    hunter.smart_client.request = AsyncMock(side_effect=_mock_request)

    with patch(
        "src.core.agents.swarm.injection.smart_xss._fetch_and_parse_form",
        new=AsyncMock(return_value=[]),
    ):
        result = await hunter.run_as_tool(
            "http://example.com/chatbot/genai/state",
            params={
                "param": "test",
                "payload": "<script>alert(1)</script>",
                "discovered_params": ["state", "user_id"],
                "method": "GET",
            },
        )

    assert result["vulnerable"] is True
    assert "test" in result["tested_params"]
    assert "param" not in result["tested_params"]
    assert "payload" not in result["tested_params"]
    assert "discovered_params" not in result["tested_params"]


@pytest.mark.asyncio
async def test_playwright_validator_cookies_and_console(monkeypatch):
    """PlaywrightValidator の新規機能 (Cookie, Console監視) の統合をテスト"""
    from src.tools.browser.playwright_validator import PlaywrightValidator
    
    # Playwright 自身をモックするのは複雑なので、ロジックが呼ばれることだけを確認するか
    # 実際にインストールされている場合は動かす（CI/Environmentに依存）
    validator = PlaywrightValidator()
    if not validator.is_available:
        pytest.skip("Playwright not installed")
        
    # TODO: 実際のヘッドレスブラウザを動かすインテグレーションテストを別で書くべきだが
    # ここではインターフェースの確認に留める
