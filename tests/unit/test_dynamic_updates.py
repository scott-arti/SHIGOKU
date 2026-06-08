
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from pathlib import Path
import json

from src.recon.pipeline import ReconPipeline

@pytest.fixture
def pipeline(tmp_path):
    """テスト用パイプライン"""
    from src.recon.pipeline import ReconPipeline
    p = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_path,
    )
    p.runner.dev_mode = True
    return p

@pytest.mark.asyncio
async def test_step3b_playwright_integration(pipeline, tmp_path):
    """Step 3b: PlaywrightCrawler が統合され、呼び出されることを確認"""
    
    pipeline.state.dead_subs = []
    
    # 既存ツールのモック
    mock_katana = MagicMock()
    mock_katana.run.return_value = ""
    mock_gau = MagicMock()
    mock_gau.run.return_value = ""
    mock_httpx = MagicMock()
    mock_httpx.run.return_value = ""
    mock_filter = MagicMock()
    mock_filter.process_file.return_value = {"playwright": 1}
    
    # PlaywrightCrawler のモック
    mock_crawler = MagicMock()
    mock_crawler.crawl = AsyncMock(return_value={
        "urls": [
            "https://www.example.com/api/xhr",
            "https://www.example.com/api/fetch",
        ]
    })
    
    with patch("src.recon.pipeline.KatanaTool", return_value=mock_katana), \
         patch("src.recon.pipeline.GAUTool", return_value=mock_gau), \
         patch("src.recon.pipeline.HttpxTool", return_value=mock_httpx), \
         patch("src.recon.pipeline.TaggingFilter", return_value=mock_filter), \
         patch("src.recon.pipeline.PlaywrightCrawler", return_value=mock_crawler):
        
        # settings.max_httpx_urls の MagicMock 問題を回避するため直接設定
        with patch("src.recon.pipeline.settings") as mock_settings:
            mock_settings.max_httpx_urls = 500
            mock_settings.get_proxy_url.return_value = None
            
            stats = await pipeline.step3b_hybrid_url_discovery(["www.example.com"])
    
    # PlaywrightCrawler が呼ばれたことを確認
    mock_crawler.crawl.assert_called()
    _, crawl_kwargs = mock_crawler.crawl.call_args
    assert crawl_kwargs.get("cookies_str") is None
    assert crawl_kwargs.get("auth_headers") in ({}, None)
    assert int(crawl_kwargs.get("max_post_login_actions_per_page", 0)) > 0
    assert int(crawl_kwargs.get("max_route_hints_per_page", 0)) > 0
    
    # TaggingFilter に渡されたデータを確認
    # pipeline._get_path は project_manager=None の場合 tmp_path 直下に保存する
    all_urls_files = list(tmp_path.glob("*_all_urls_for_tagging.json"))
    assert len(all_urls_files) > 0
    
    all_entries = json.loads(all_urls_files[0].read_text())
    
    sources = [e.get("source") for e in all_entries]
    assert "playwright_dynamic" in sources
    
    # 特定の URL が含まれているか
    urls = [e.get("url") for e in all_entries]
    assert "https://www.example.com/api/xhr" in urls
    assert "https://www.example.com/api/fetch" in urls

@pytest.mark.asyncio
async def test_base_manager_context_propagation():
    """BaseManagerAgent のコンテキスト伝播をテスト"""
    from src.core.agents.swarm.base_manager import BaseManagerAgent
    
    agent = BaseManagerAgent()
    # 実装に合わせて正しいキーを使用
    agent.current_context["params"] = {"cookies": "test-cookie=123"}
    agent.current_context["auth_headers"] = {"X-Test": "Header"}
    
    # モックツールの実行
    mock_tool = MagicMock()
    mock_tool.name = "test_tool"
    mock_tool.run = AsyncMock(return_value="success")
    
    with patch.dict(agent.available_tools, {"test_tool": {"func": mock_tool.run}}):
        result = await agent._execute_tool("test_tool", {"param1": "val1"})
    
    # 引数に cookies と auth_headers が追加されているか確認
    mock_tool.run.assert_called_once()
    
    # call_args.kwargs を確認
    call_kwargs = mock_tool.run.call_args.kwargs
    assert call_kwargs.get("cookies") == "test-cookie=123"
    assert call_kwargs.get("auth_headers") == {"X-Test": "Header"}
