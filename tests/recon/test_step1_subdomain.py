"""
Test Step 1: Subdomain Discovery
"""

import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path

from src.recon.pipeline import ReconPipeline


@pytest.mark.asyncio
async def test_step1_subdomain_discovery_dev_mode():
    """Step 1: DEV_MODE でモック出力を使用"""
    
    # DEV_MODE で初期化
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    pipeline.runner.dev_mode = True
    
    # 実行
    subs = await pipeline.step1_subdomain_discovery()
    
    # 検証
    assert isinstance(subs, list)
    assert len(subs) > 0
    assert all(isinstance(s, str) for s in subs)
    # モック出力には "example.com" が含まれる
    assert any("example.com" in s for s in subs)


@pytest.mark.asyncio
async def test_step1_deduplication():
    """Step 1: 重複除外の確認"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    pipeline.runner.dev_mode = True
    
    # モック出力に重複を含める
    with patch.object(pipeline.runner, 'run', new=AsyncMock(return_value="www.example.com\nwww.example.com\napi.example.com\n")):
        with patch.object(pipeline.runner, 'run_json', new=AsyncMock(return_value=[])):
            subs = await pipeline.step1_subdomain_discovery()
    
    # 重複除外確認
    assert len(subs) == len(set(subs))
    assert "www.example.com" in subs
    assert "api.example.com" in subs


@pytest.mark.asyncio
async def test_step1_empty_response():
    """Step 1: 空レスポンスの処理"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    pipeline.runner.dev_mode = True
    
    # 全ツールが空を返す
    with patch.object(pipeline.runner, 'run', new=AsyncMock(return_value="")):
        with patch.object(pipeline.runner, 'run_json', new=AsyncMock(return_value=[])):
            subs = await pipeline.step1_subdomain_discovery()
    
    # 空リストが返る
    assert subs == []


@pytest.mark.asyncio
async def test_step1_tool_check():
    """Step 1: ツール可用性チェックが呼ばれる"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    
    # check_tools is commented out in implementation to allow partial runs
    # Instead, we check if is_tool_available is called for each tool
    with patch.object(pipeline.runner, 'is_tool_available', return_value=True) as mock_is_avail:
        with patch.object(pipeline.runner, 'run', new=AsyncMock(return_value="www.example.com\n")):
            with patch.object(pipeline.runner, 'run_json', new=AsyncMock(return_value=[])):
                await pipeline.step1_subdomain_discovery()
    
    # Verify is_tool_available called for expected tools
    assert mock_is_avail.call_count >= 1
    # Check that at least some core tools were checked
    calls = [args[0] for args, _ in mock_is_avail.call_args_list]
    assert "subfinder" in calls or "amass" in calls or "bbot" in calls


@pytest.mark.asyncio
async def test_step1_file_persistence(tmp_path):
    """Step 1: 各ツールの出力が命名規則に従って保存される"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_path,
    )
    pipeline.runner.dev_mode = True
    
    # 子ツールがデータを返すようにモック
    mock_bbot = [{"type": "DNS_NAME", "data": "api.example.com"}, {"type": "STORAGE_BUCKET", "data": "mybucket"}]
    with patch.object(pipeline.runner, 'run', new=AsyncMock(return_value="www.example.com\n")):
        with patch.object(pipeline.runner, 'run_json', side_effect=[
            [{"name": "api.example.com", "tag": "asn"}], # amass
            mock_bbot # bbot
        ]):
            await pipeline.step1_subdomain_discovery()
    
    # ファイル存在確認 (命名規則準拠)
    assert len(list(tmp_path.glob("*_example_com_subfinder.txt"))) == 1
    assert len(list(tmp_path.glob("*_example_com_amass.json"))) == 1
    assert len(list(tmp_path.glob("*_example_com_asn.json"))) == 1
    assert len(list(tmp_path.glob("*_example_com_bbot.jsonl"))) == 1
    assert len(list(tmp_path.glob("*_example_com_buckets.json"))) == 1
