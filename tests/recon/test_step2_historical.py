"""
Test Step 2: Historical Discovery
"""

import pytest
from unittest.mock import AsyncMock, patch
from pathlib import Path

from src.recon.pipeline import ReconPipeline


@pytest.mark.asyncio
async def test_step2_historical_discovery_dev_mode():
    """Step 2: DEV_MODE でモック出力を使用"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    pipeline.runner.dev_mode = True
    
    # 既存のサブドメインリスト
    existing_subs = ["www.example.com", "api.example.com"]
    
    # 実行
    subs = await pipeline.step2_historical_discovery(existing_subs)
    
    # 検証
    assert isinstance(subs, list)
    assert len(subs) >= len(existing_subs)  # 既存 + 新規
    # 既存のサブドメインは保持される
    assert "www.example.com" in subs
    assert "api.example.com" in subs


@pytest.mark.asyncio
async def test_step2_url_parsing():
    """Step 2: URL からホスト部を正しく抽出"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    pipeline.runner.dev_mode = True
    
    # gau の出力をモック
    mock_urls = (
        "https://old.example.com/page\n"
        "http://legacy.example.com:8080/api\n"
        "https://test.example.com/path?query=value\n"
    )
    
    with patch.object(pipeline.runner, 'run', new=AsyncMock(return_value=mock_urls)):
        subs = await pipeline.step2_historical_discovery([])
    
    # ホスト部が抽出される
    assert "old.example.com" in subs
    assert "legacy.example.com" in subs
    assert "test.example.com" in subs


@pytest.mark.asyncio
async def test_step2_invalid_url_handling():
    """Step 2: 不正なURLをスキップ"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    pipeline.runner.dev_mode = True
    
    # 不正なURLを含むモック出力
    mock_urls = (
        "https://valid.example.com/page\n"
        "not-a-url\n"
        "://broken.com\n"
        "https://another.example.com/path\n"
    )
    
    with patch.object(pipeline.runner, 'run', new=AsyncMock(return_value=mock_urls)):
        subs = await pipeline.step2_historical_discovery([])
    
    # 正常なURLのみ抽出
    assert "valid.example.com" in subs
    assert "another.example.com" in subs
    # 不正なURLはスキップ
    assert len(subs) == 2


@pytest.mark.asyncio
async def test_step2_deduplication():
    """Step 2: 既存リストとの重複除外"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    pipeline.runner.dev_mode = True
    
    existing_subs = ["www.example.com", "api.example.com"]
    
    # gau が既存のサブドメインを返す
    mock_urls = "https://www.example.com/page\n"
    
    with patch.object(pipeline.runner, 'run', new=AsyncMock(return_value=mock_urls)):
        subs = await pipeline.step2_historical_discovery(existing_subs)
    
    # 重複除外確認
    assert subs.count("www.example.com") == 1
    assert len(subs) == len(set(subs))


@pytest.mark.asyncio
async def test_step2_tool_check():
    """Step 2: ツール可用性チェックが呼ばれる"""
    
    pipeline = ReconPipeline(
        config={},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    
    with patch.object(pipeline.runner, 'is_tool_available', return_value=True) as mock_is_avail:
        with patch.object(pipeline.runner, 'run', new=AsyncMock(return_value="http://example.com/page1")):
            await pipeline.step2_historical_discovery([])
            
    # Verify gau or waybackurls checked
    calls = [args[0] for args, _ in mock_is_avail.call_args_list]
    assert "gau" in calls or "waybackurls" in calls


@pytest.mark.asyncio
async def test_step2_gau_urls_saved_to_file(tmp_path):
    """Step 2: gau の URL リストがファイルに保存される"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_path,
    )
    pipeline.runner.dev_mode = True
    
    # gau の出力をモック
    mock_urls = "https://old.example.com/page\nhttps://legacy.example.com/api\n"
    
    with patch.object(pipeline.runner, 'run', new=AsyncMock(return_value=mock_urls)):
        await pipeline.step2_historical_discovery([])
    
    # gau_urls.txt が保存されている (命名規則準拠)
    gau_files = list(tmp_path.glob("*_example_com_gau_urls.txt"))
    assert len(gau_files) == 1
    gau_file = gau_files[0]
    
    # 内容が正しい
    content = gau_file.read_text()
    assert "https://old.example.com/page" in content
    assert "https://legacy.example.com/api" in content

