"""
Test Step 3b: Hybrid URL Discovery & Tagging

Katana, GAU, Httpx を使用したURL収集とタグ付けのテスト。
"""

import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path

from src.recon.pipeline import ReconPipeline, ReconState


@pytest.fixture
def pipeline(tmp_path):
    """テスト用パイプライン"""
    p = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_path,
    )
    p.runner.dev_mode = True
    return p


@pytest.mark.asyncio
async def test_step3b_excludes_dead_subs(pipeline, tmp_path):
    """Step 3b: dead_subs を含む URL が除外される"""
    
    # State に dead_subs を設定
    pipeline.state.dead_subs = ["dead.example.com"]
    pipeline.state.live_subs = ["www.example.com", "api.example.com"]
    
    # Katana モック (空結果)
    mock_katana = MagicMock()
    mock_katana.run.return_value = ""
    
    # GAU モック (dead サブドメインを含む URL を返す)
    mock_gau = MagicMock()
    mock_gau.run.return_value = (
        "https://www.example.com/page1\n"
        "https://api.example.com/v1/users\n"
        "https://dead.example.com/admin\n"  # 除外されるべき
    )
    
    # Httpx モック
    mock_httpx = MagicMock()
    mock_httpx.run.return_value = (
        '{"url":"https://www.example.com/page1","status_code":200}\n'
        '{"url":"https://api.example.com/v1/users","status_code":200}\n'
    )
    
    # TaggingFilter モック
    mock_filter = MagicMock()
    mock_filter.process_file.return_value = {"auth": 0, "id_param": 1}
    
    with patch("src.recon.pipeline.KatanaTool", return_value=mock_katana):
        with patch("src.recon.pipeline.GAUTool", return_value=mock_gau):
            with patch("src.recon.pipeline.HttpxTool", return_value=mock_httpx):
                with patch("src.recon.pipeline.TaggingFilter", return_value=mock_filter):
                    stats = await pipeline.step3b_hybrid_url_discovery(["www.example.com", "api.example.com"])
    
    # GAU が呼ばれた
    mock_gau.run.assert_called_once()
    
    # Httpx が呼ばれた (dead サブドメイン除外後の URL に対して)
    httpx_call_args = mock_httpx.run.call_args
    input_file = httpx_call_args[0][0]
    input_content = Path(input_file).read_text()
    
    # dead.example.com の URL は含まれていないはず
    assert "dead.example.com" not in input_content
    assert "www.example.com" in input_content
    assert "api.example.com" in input_content


@pytest.mark.asyncio
async def test_step3b_excludes_katana_urls(pipeline, tmp_path):
    """Step 3b: Katana で見つかった URL は GAU 結果から除外"""
    
    pipeline.state.dead_subs = []
    
    # Katana モック (1件見つかる)
    mock_katana = MagicMock()
    mock_katana.run.return_value = (
        '{"request":{"endpoint":"https://www.example.com/page1","method":"GET"},'
        '"response":{"status_code":200}}\n'
    )
    
    # GAU モック (Katana と同じ URL + 追加 URL)
    mock_gau = MagicMock()
    mock_gau.run.return_value = (
        "https://www.example.com/page1\n"  # Katana で見つかった→除外
        "https://www.example.com/page2\n"  # 新規→含まれる
    )
    
    # Httpx モック
    mock_httpx = MagicMock()
    mock_httpx.run.return_value = '{"url":"https://www.example.com/page2","status_code":200}\n'
    
    mock_filter = MagicMock()
    mock_filter.process_file.return_value = {}
    
    with patch("src.recon.pipeline.KatanaTool", return_value=mock_katana):
        with patch("src.recon.pipeline.GAUTool", return_value=mock_gau):
            with patch("src.recon.pipeline.HttpxTool", return_value=mock_httpx):
                with patch("src.recon.pipeline.TaggingFilter", return_value=mock_filter):
                    await pipeline.step3b_hybrid_url_discovery(["www.example.com"])
    
    # Httpx 入力ファイルを確認
    httpx_call_args = mock_httpx.run.call_args
    input_file = httpx_call_args[0][0]
    input_content = Path(input_file).read_text()
    
    # page1 は除外、page2 のみ含まれる
    assert "page1" not in input_content
    assert "page2" in input_content


@pytest.mark.asyncio
async def test_step3b_uses_proxy_from_config(pipeline, tmp_path):
    """Step 3b: Proxy 設定が外部設定から取得される"""
    
    pipeline.state.dead_subs = []
    
    mock_katana = MagicMock()
    mock_katana.run.return_value = ""
    mock_gau = MagicMock()
    mock_gau.run.return_value = "https://www.example.com/test\n"
    mock_httpx = MagicMock()
    mock_httpx.run.return_value = '{"url":"https://www.example.com/test","status_code":200}\n'
    mock_filter = MagicMock()
    mock_filter.process_file.return_value = {}
    
    # get_proxy_url のモック
    with patch("src.recon.pipeline.settings") as mock_settings:
        mock_settings.max_httpx_urls = 500
        mock_settings.get_proxy_url.return_value = "http://custom-proxy:9090"
        
        with patch("src.recon.pipeline.KatanaTool", return_value=mock_katana):
            with patch("src.recon.pipeline.GAUTool", return_value=mock_gau):
                with patch("src.recon.pipeline.HttpxTool", return_value=mock_httpx):
                    with patch("src.recon.pipeline.TaggingFilter", return_value=mock_filter):
                        await pipeline.step3b_hybrid_url_discovery(["www.example.com"])
    
    # Katana に proxy が渡された
    katana_call = mock_katana.run.call_args
    assert katana_call.kwargs.get("proxy") == "http://custom-proxy:9090"
    
    # Httpx に proxy が渡された
    httpx_call = mock_httpx.run.call_args
    assert httpx_call.kwargs.get("proxy") == "http://custom-proxy:9090"


@pytest.mark.asyncio
async def test_step3b_empty_live_subs_returns_empty(pipeline):
    """Step 3b: live_subs が空の場合は空の統計を返す"""
    
    stats = await pipeline.step3b_hybrid_url_discovery([])
    
    assert stats == {}


@pytest.mark.asyncio
async def test_step3b_tagging_filter_called(pipeline, tmp_path):
    """Step 3b: TaggingFilter が正しく呼ばれる"""
    
    pipeline.state.dead_subs = []
    
    mock_katana = MagicMock()
    mock_katana.run.return_value = ""
    mock_gau = MagicMock()
    mock_gau.run.return_value = "https://www.example.com/login\n"
    mock_httpx = MagicMock()
    mock_httpx.run.return_value = '{"url":"https://www.example.com/login","status_code":200}\n'
    
    mock_filter = MagicMock()
    mock_filter.process_file.return_value = {"auth": 1, "uncategorized": 0}
    
    with patch("src.recon.pipeline.KatanaTool", return_value=mock_katana):
        with patch("src.recon.pipeline.GAUTool", return_value=mock_gau):
            with patch("src.recon.pipeline.HttpxTool", return_value=mock_httpx):
                with patch("src.recon.pipeline.TaggingFilter", return_value=mock_filter):
                    stats = await pipeline.step3b_hybrid_url_discovery(["www.example.com"])
    
    # TaggingFilter.process_file が呼ばれた
    mock_filter.process_file.assert_called_once()
    
    # 統計が返された
    assert stats == {"auth": 1, "uncategorized": 0}


@pytest.mark.asyncio
async def test_step3b_injects_playwright_fallback_seeds_when_dynamic_empty(pipeline, tmp_path):
    pipeline.state.dead_subs = []

    mock_katana = MagicMock()
    mock_katana.run.return_value = (
        '{"request":{"endpoint":"http://www.example.com/","method":"GET"},'
        '"response":{"status_code":200}}\n'
    )
    mock_gau = MagicMock()
    mock_gau.run.return_value = ""
    mock_httpx = MagicMock()
    mock_httpx.run.return_value = ""
    mock_playwright = MagicMock()
    mock_playwright.crawl = AsyncMock(return_value={"urls": [], "endpoints": [], "js_files": [], "errors": ["no browser"]})
    mock_filter = MagicMock()
    mock_filter.process_file.return_value = {}

    with patch("src.recon.pipeline.KatanaTool", return_value=mock_katana):
        with patch("src.recon.pipeline.GAUTool", return_value=mock_gau):
            with patch("src.recon.pipeline.HttpxTool", return_value=mock_httpx):
                with patch("src.recon.pipeline.PlaywrightCrawler", return_value=mock_playwright):
                    with patch("src.recon.pipeline.TaggingFilter", return_value=mock_filter):
                        await pipeline.step3b_hybrid_url_discovery(["www.example.com"])

    mock_filter.process_file.assert_called_once()
    all_urls_file = Path(mock_filter.process_file.call_args[0][0])
    all_entries = json.loads(all_urls_file.read_text(encoding="utf-8"))
    fallback_entries = [e for e in all_entries if e.get("source") == "playwright_seed_fallback"]
    assert fallback_entries, "Expected fallback seed entries when Playwright returns no dynamic URLs"
    assert any("chatbot/genai/state" in str(e.get("url", "")) for e in fallback_entries)


@pytest.mark.asyncio
async def test_step3b_fallback_reuses_recent_tagged_history_seeds(tmp_path):
    p = ReconPipeline(
        config={"scan": {"playwright_target_budget": 1}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_path,
    )
    p.runner.dev_mode = True
    p.state.dead_subs = []

    tagged_dir = tmp_path / "tagged_urls"
    tagged_dir.mkdir(parents=True, exist_ok=True)
    history_file = tagged_dir / "20260401_target_tagged_uncategorized_promoted_auth.jsonl"
    history_file.write_text(
        json.dumps(
            {
                "url": "http://www.example.com/history/replay-account",
                "method": "GET",
                "forms": [],
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    mock_katana = MagicMock()
    mock_katana.run.return_value = (
        '{"request":{"endpoint":"http://www.example.com/","method":"GET"},'
        '"response":{"status_code":200}}\n'
    )
    mock_gau = MagicMock()
    mock_gau.run.return_value = ""
    mock_httpx = MagicMock()
    mock_httpx.run.return_value = ""
    mock_playwright = MagicMock()
    mock_playwright.crawl = AsyncMock(return_value={"urls": [], "endpoints": [], "js_files": [], "errors": []})
    mock_filter = MagicMock()
    mock_filter.process_file.return_value = {}

    with patch("src.recon.pipeline.KatanaTool", return_value=mock_katana):
        with patch("src.recon.pipeline.GAUTool", return_value=mock_gau):
            with patch("src.recon.pipeline.HttpxTool", return_value=mock_httpx):
                with patch("src.recon.pipeline.PlaywrightCrawler", return_value=mock_playwright):
                    with patch("src.recon.pipeline.TaggingFilter", return_value=mock_filter):
                        await p.step3b_hybrid_url_discovery(["www.example.com"])

    all_urls_file = Path(mock_filter.process_file.call_args[0][0])
    all_entries = json.loads(all_urls_file.read_text(encoding="utf-8"))
    fallback_entries = [e for e in all_entries if e.get("source") == "playwright_seed_fallback"]
    assert fallback_entries, "Expected fallback seed entries when Playwright returns no dynamic URLs"
    assert any("/history/replay-account" in str(e.get("url", "")) for e in fallback_entries)


@pytest.mark.asyncio
async def test_step3b_passes_post_login_budgets_to_playwright(tmp_path):
    p = ReconPipeline(
        config={
            "scan": {
                "playwright_target_budget": 1,
                "playwright_max_pages_per_seed": 4,
                "playwright_max_clicks_per_page": 5,
                "playwright_max_forms_per_page": 2,
                "playwright_max_post_login_actions_per_page": 9,
                "playwright_max_route_hints_per_page": 17,
            }
        },
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_path,
    )
    p.runner.dev_mode = True
    p.state.dead_subs = []

    mock_katana = MagicMock()
    mock_katana.run.return_value = (
        '{"request":{"endpoint":"http://www.example.com/","method":"GET"},'
        '"response":{"status_code":200}}\n'
    )
    mock_gau = MagicMock()
    mock_gau.run.return_value = ""
    mock_httpx = MagicMock()
    mock_httpx.run.return_value = ""
    mock_playwright = MagicMock()
    mock_playwright.crawl = AsyncMock(return_value={"urls": [], "endpoints": [], "js_files": [], "errors": []})
    mock_filter = MagicMock()
    mock_filter.process_file.return_value = {}

    with patch("src.recon.pipeline.KatanaTool", return_value=mock_katana):
        with patch("src.recon.pipeline.GAUTool", return_value=mock_gau):
            with patch("src.recon.pipeline.HttpxTool", return_value=mock_httpx):
                with patch("src.recon.pipeline.PlaywrightCrawler", return_value=mock_playwright):
                    with patch("src.recon.pipeline.TaggingFilter", return_value=mock_filter):
                        await p.step3b_hybrid_url_discovery(["www.example.com"])

    mock_playwright.crawl.assert_called()
    _, crawl_kwargs = mock_playwright.crawl.call_args
    assert crawl_kwargs.get("max_pages") == 4
    assert crawl_kwargs.get("max_clicks_per_page") == 5
    assert crawl_kwargs.get("max_forms_per_page") == 2
    assert crawl_kwargs.get("max_post_login_actions_per_page") == 9
    assert crawl_kwargs.get("max_route_hints_per_page") == 17


def test_select_playwright_seed_targets_prioritizes_dynamic_and_excludes_static(pipeline):
    base_targets = [
        "http://www.example.com/",
        "http://api.example.com/",
    ]
    discovered_entries = [
        {"url": "http://www.example.com/static/js/app.js", "method": "GET"},
        {"url": "http://www.example.com/orders/history?query=desk", "method": "GET"},
        {"url": "http://www.example.com/profile", "method": "GET"},
        {"url": "http://external.example.net/api/v1/users", "method": "GET"},
    ]

    selected = pipeline._select_playwright_seed_targets(
        base_targets=base_targets,
        discovered_entries=discovered_entries,
        budget=3,
    )

    assert selected
    assert any("orders/history?query=desk" in url for url in selected)
    assert not any("/static/js/" in url for url in selected)
    assert not any("external.example.net" in url for url in selected)
    assert len(selected) <= 3


def test_is_low_value_playwright_seed_url_filters_root_and_static(pipeline):
    assert pipeline._is_low_value_playwright_seed_url("http://www.example.com/", allow_root=False) is True
    assert pipeline._is_low_value_playwright_seed_url("http://www.example.com/", allow_root=True) is False
    assert pipeline._is_low_value_playwright_seed_url("http://www.example.com/static/js/app.js", allow_root=True) is True
    assert pipeline._is_low_value_playwright_seed_url("http://www.example.com/search?q=desk", allow_root=False) is False


def test_is_host_in_scope_handles_target_with_port(tmp_path):
    p = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="http://127.0.0.1:8888/",
        workspace_root=tmp_path,
    )
    assert p._is_host_in_scope("127.0.0.1:8888") is True
    assert p._is_host_in_scope("127.0.0.1") is True
    assert p._is_host_in_scope("localhost:8888") is False


def test_select_playwright_seed_targets_with_ported_target_selects_local_dynamic(tmp_path):
    p = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="http://127.0.0.1:8888/",
        workspace_root=tmp_path,
    )

    selected = p._select_playwright_seed_targets(
        base_targets=["http://127.0.0.1:8888/"],
        discovered_entries=[
            {"url": "http://127.0.0.1:8888/chatbot/genai/state", "method": "GET"},
            {"url": "http://127.0.0.1:8888/static/js/app.js", "method": "GET"},
        ],
        budget=2,
    )

    assert "http://127.0.0.1:8888/chatbot/genai/state" in selected
    assert "http://127.0.0.1:8888/static/js/app.js" not in selected


def test_score_playwright_seed_url_prioritizes_auth_and_id_signals(pipeline):
    rich = pipeline._score_playwright_seed_url(
        "http://www.example.com/account/profile?user_id=1&token=abc",
        method="GET",
    )
    plain = pipeline._score_playwright_seed_url(
        "http://www.example.com/help/about",
        method="GET",
    )
    assert rich > plain


def test_collect_recent_playwright_history_seeds_includes_id_param_category(tmp_path):
    p = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_path,
    )
    tagged_dir = tmp_path / "tagged_urls"
    tagged_dir.mkdir(parents=True, exist_ok=True)
    history_file = tagged_dir / "20260409_target_tagged_id_param.jsonl"
    history_file.write_text(
        json.dumps(
            {
                "url": "http://www.example.com/api/users?id=7",
                "method": "GET",
                "forms": [],
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    seeds = p._collect_recent_playwright_history_seeds(
        tagged_dir=tagged_dir,
        target_url="http://www.example.com/",
        max_urls=5,
        max_files=5,
    )
    assert "http://www.example.com/api/users?id=7" in seeds
