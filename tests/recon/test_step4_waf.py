"""
Test Step 4: WAF Detection
"""

import pytest
from unittest.mock import AsyncMock, patch
from pathlib import Path

from src.recon.pipeline import ReconPipeline


@pytest.mark.asyncio
async def test_step4_waf_detection_dev_mode():
    """Step 4: DEV_MODE でモック出力を使用"""
    
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
    waf_map = await pipeline.step4_waf_detection(live_subs)
    
    # 検証
    assert isinstance(waf_map, dict)
    # モック出力には Cloudflare と None が含まれる
    assert len(waf_map) > 0


@pytest.mark.asyncio
async def test_step4_waf_parsing():
    """Step 4: wafw00f 出力パース"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    pipeline.runner.dev_mode = True
    pipeline.workspace_root.mkdir(parents=True, exist_ok=True)
    
    # モック出力
    mock_wafw00f = (
        "www.example.com is behind Cloudflare\n"
        "api.example.com is not behind a WAF\n"
        "test.example.com is behind AWS WAF\n"
    )
    
    with patch.object(pipeline.runner, 'run', new=AsyncMock(return_value=mock_wafw00f)):
        waf_map = await pipeline.step4_waf_detection(["www.example.com", "api.example.com", "test.example.com"])
    
    # パース確認
    assert waf_map["www.example.com"] == "Cloudflare"
    assert waf_map["api.example.com"] == "None"
    assert waf_map["test.example.com"] == "AWS WAF"


@pytest.mark.asyncio
async def test_step4_empty_result():
    """Step 4: 空結果の処理"""
    
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
        waf_map = await pipeline.step4_waf_detection([])
    
    # 空辞書が返る
    assert waf_map == {}


@pytest.mark.asyncio
async def test_step4_tool_check():
    """Step 4: ツール可用性チェックが呼ばれる"""
    
    pipeline = ReconPipeline(
        config={},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    
    with patch.object(pipeline.runner, 'is_tool_available', return_value=True) as mock_is_avail:
        with patch.object(pipeline.runner, 'run', new=AsyncMock(return_value="No WAF detected")):
            # Method name might be step4_waf_detection based on previous file view
            if hasattr(pipeline, 'step4_waf_check'):
                await pipeline.step4_waf_check(["sub.example.com"])
            else:
                await pipeline.step4_waf_detection(["sub.example.com"])

    # Verify wafw00f checked
    calls = [args[0] for args, _ in mock_is_avail.call_args_list]
    assert "wafw00f" in calls
async def test_step4_wafw00f_json_saved(tmp_path):
    """Step 4: wafw00f の結果が JSON ファイルに保存される"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_path,
    )
    pipeline.runner.dev_mode = True
    
    # wafw00f の出力をモック
    mock_output = (
        "www.example.com is behind Cloudflare\n"
        "api.example.com is not behind a WAF\n"
    )
    
    with patch.object(pipeline.runner, 'run', new=AsyncMock(return_value=mock_output)):
        waf_map = await pipeline.step4_waf_detection(["www.example.com", "api.example.com"])
        # wafw00f.json が保存されている (命名規則準拠)
        waf_files = list(tmp_path.glob("*_example_com_wafw00f.json"))
        assert len(waf_files) == 1
    wafw00f_file = waf_files[0]
    
    # 内容が正しい
    import json
    saved_data = json.loads(wafw00f_file.read_text())
    assert "www.example.com" in saved_data
    assert saved_data["www.example.com"] == "Cloudflare"
    assert saved_data["api.example.com"] == "None"
