import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from src.core.agents.swarm.injection.smart_sqli import SmartSQLiHunter

@pytest.mark.asyncio
async def test_smart_sqli_hunter_post_json_support():
    """
    SmartSQLiHunter が POST/JSON リクエストを正しく処理できるか確認
    """
    mock_llm = AsyncMock()
    # Turn 1: 攻撃
    resp1 = MagicMock()
    resp1.choices = [MagicMock()]
    resp1.choices[0].message.content = "THOUGHT: Testing JSON SQLi.\nACTION: request\nINPUT: ' OR 1=1--"
    mock_llm.agenerate.return_value = resp1

    mock_client = AsyncMock()
    mock_client.request.return_value = MagicMock(status=200, text="Logged in")

    hunter = SmartSQLiHunter()
    hunter.llm = mock_llm
    # smart_client をモックに置き換え
    hunter.smart_client = mock_client

    # POST + JSON シナリオで実行
    params = {
        "user": "admin",
        "method": "POST",
        "content_type": "json",
        "body": '{"user": "admin", "pass": "secret"}'
    }
    
    # ThoughtLoop のコンテキストに手動設定して act を呼ぶか、run_loop する
    # run_as_tool を経由して実行
    with patch.object(hunter, 'run_loop', AsyncMock()):
        await hunter.run_as_tool("http://example.com/api/login", params)
        
        # コンテキストが正しく設定されているか確認
        import json
        assert hunter.context["method"] == "POST"
        assert hunter.context["content_type"] == "json"
        assert hunter.context["body"] == json.loads(params["body"])

    # act() 内部の挙動を直接テスト
    hunter.context = {
        "target": "http://example.com/api/login",
        "method": "POST",
        "param": "user",
        "content_type": "json",
        "body": {"user": "FUZZ", "pass": "secret"},
        "vulnerability_found": False
    }
    
    await hunter.act("request", "' OR 1=1--")
    
    # 検証: mock_client.request が POST かつ body 内の FUZZ が置換されているか
    mock_client.request.assert_called()
    call_args = mock_client.request.call_args[0]
    call_kwargs = mock_client.request.call_args[1]
    
    assert call_args[0] == "POST"
    actual_data = call_kwargs.get("json", call_kwargs.get("data", {}))
    assert "' OR 1=1--" in str(actual_data)
    assert "admin" not in str(actual_data) # 置換されていること
