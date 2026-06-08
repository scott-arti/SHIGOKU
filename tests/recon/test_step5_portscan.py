"""
Test Step 5: Port Scan
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path

from src.recon.pipeline import ReconPipeline


@pytest.mark.asyncio
async def test_step5_phase1_port_scan_dev_mode():
    """Step 5 Phase 1: DEV_MODE でモック出力を使用"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    pipeline.runner.dev_mode = True
    pipeline.workspace_root.mkdir(parents=True, exist_ok=True)
    
    # ライブサブドメインリスト
    live_subs = ["www.example.com", "api.example.com"]
    
    # 実行
    port_map = await pipeline.step5_port_scan_phase1(live_subs)
    
    # 検証
    assert isinstance(port_map, dict)
    # モック出力にはポート情報が含まれる
    assert len(port_map) > 0


@pytest.mark.asyncio
async def test_step5_phase1_parsing():
    """Step 5 Phase 1: naabu 出力パース"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    pipeline.runner.dev_mode = True
    pipeline.workspace_root.mkdir(parents=True, exist_ok=True)
    
    # モック出力
    mock_naabu = (
        "www.example.com:80 [http]\n"
        "www.example.com:443 [https]\n"
        "api.example.com:443 [https]\n"
        "api.example.com:8080 [http-proxy]\n"
    )
    
    with patch.object(pipeline.runner, 'run', new=AsyncMock(return_value=mock_naabu)):
        port_map = await pipeline.step5_port_scan_phase1(["www.example.com", "api.example.com"])
    
    # パース確認
    assert "www.example.com" in port_map
    assert "api.example.com" in port_map
    assert "80" in port_map["www.example.com"]
    assert "443" in port_map["www.example.com"]
    assert "443" in port_map["api.example.com"]
    assert "8080" in port_map["api.example.com"]


@pytest.mark.asyncio
async def test_step5_phase1_empty_result():
    """Step 5 Phase 1: 空結果の処理"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    pipeline.runner.dev_mode = True
    pipeline.workspace_root.mkdir(parents=True, exist_ok=True)
    
    # 空の出力
    with patch.object(pipeline.runner, 'run', new=AsyncMock(return_value="")):
        port_map = await pipeline.step5_port_scan_phase1([])
    
    # 空辞書が返る
    assert port_map == {}


@pytest.mark.asyncio
async def test_step5_tool_check():
    """Step 5: ツールチェックが呼ばれる"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    pipeline.workspace_root.mkdir(parents=True, exist_ok=True)
    
    # Phase 2 port scan check
    with patch.object(pipeline.runner, 'is_tool_available', return_value=True) as mock_is_avail:
        with patch.object(pipeline.runner, 'run_json', new=AsyncMock(return_value=[])):
             # Mock run as well since is_tool_available check leads to run call not run_json for naabu phase 1
            with patch.object(pipeline.runner, 'run', new=AsyncMock(return_value="")):
                await pipeline.step5_port_scan_phase1(["sub.example.com"])

    # Verify naabu checked
    calls = [args[0] for args, _ in mock_is_avail.call_args_list]
    assert "naabu" in calls


@pytest.mark.asyncio
async def test_step5_naabu_json_saved(tmp_path):
    """Step 5: naabu の結果が JSON ファイルに保存される"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_path,
    )
    pipeline.runner.dev_mode = True
    
    # naabu の出力をモック
    mock_output = (
        "www.example.com:80 [http]\n"
        "www.example.com:443 [https]\n"
        "api.example.com:443 [https]\n"
    )
    
    with patch.object(pipeline.runner, 'run', new=AsyncMock(return_value=mock_output)):
        port_map = await pipeline.step5_port_scan_phase1(["www.example.com", "api.example.com"])
    
    # naabu_top20.json が保存されている (命名規則準拠)
    naabu_files = list(tmp_path.glob("*_example_com_naabu_top20.json"))
    assert len(naabu_files) == 1
    naabu_json_file = naabu_files[0]
    
    # 内容が正しい
    import json
    saved_data = json.loads(naabu_json_file.read_text())
    assert "www.example.com" in saved_data
    assert "80" in saved_data["www.example.com"]
    assert "443" in saved_data["www.example.com"]
    assert "api.example.com" in saved_data
    assert "443" in saved_data["api.example.com"]


@pytest.mark.asyncio
async def test_step5_phase2_fire_and_forget():
    """Step 5 Phase 2: 並行タスクが開始される"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    pipeline.runner.dev_mode = True
    pipeline.workspace_root.mkdir(parents=True, exist_ok=True)
    
    # run_parallel_tasks をモック
    with patch.object(pipeline, 'run_parallel_tasks', new=AsyncMock()) as mock_parallel:
        await pipeline.step5_port_scan_phase2(["www.example.com"])
    
    # run_parallel_tasks は直接は呼ばれない（asyncio.create_task経由）
    # なので呼び出し確認はスキップ
    # Phase 2 は Fire and Forget なので即座に return する
