"""
Test Step 3: Live Check & Technology
"""

import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path

from src.recon.pipeline import ReconPipeline


@pytest.mark.asyncio
async def test_step3_live_check_dev_mode():
    """Step 3: DEV_MODE でモック出力を使用"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    pipeline.runner.dev_mode = True
    
    # workspace 作成
    pipeline.workspace_root.mkdir(parents=True, exist_ok=True)
    
    # 既存のサブドメインリスト
    all_subs = ["www.example.com", "api.example.com", "dead.example.com"]
    
    # 実行
    live_subs, dead_subs = await pipeline.step3_live_check(all_subs)
    
    # 検証
    assert isinstance(live_subs, list)
    assert isinstance(dead_subs, list)
    assert len(live_subs) > 0
    # モック出力には "example.com" が含まれる
    assert any("example.com" in s for s in live_subs)


@pytest.mark.asyncio
async def test_step3_resolvers_fetch():
    """Step 3: Resolvers 取得の確認"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    pipeline.runner.dev_mode = True
    pipeline.workspace_root.mkdir(parents=True, exist_ok=True)
    
    # 実行
    resolvers_file = await pipeline.fetch_resolvers(count=25)
    
    # DEV_MODE ではモックリゾルバーが生成される (命名規則準拠)
    assert resolvers_file.exists()
    assert "_example_com_resolvers.txt" in resolvers_file.name
    content = resolvers_file.read_text()
    assert "8.8.8.8" in content or "1.1.1.1" in content


@pytest.mark.asyncio
async def test_step3_httpx_parsing():
    """Step 3: httpx JSON パース"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    pipeline.runner.dev_mode = True
    pipeline.workspace_root.mkdir(parents=True, exist_ok=True)
    
    # モック出力を設定
    mock_httpx_output = (
        '{"url":"https://www.example.com","status_code":200}\n'
        '{"url":"https://api.example.com","status_code":403}\n'
        '{"url":"https://dead.example.com","status_code":500}\n'  # エラーなので除外
    )
    
    with patch.object(pipeline.runner, 'run_json', new=AsyncMock(return_value=[
        {"url": "https://www.example.com", "status_code": 200},
        {"url": "https://api.example.com", "status_code": 403},
        {"url": "https://dead.example.com", "status_code": 500},
    ])):
        with patch.object(pipeline.runner, 'run', new=AsyncMock(return_value="www.example.com\napi.example.com\ndead.example.com\n")):
            live_subs, dead_subs = await pipeline.step3_live_check(["www.example.com", "api.example.com", "dead.example.com"])
    
    # status_code < 500 のみ live とみなす
    assert "www.example.com" in live_subs
    assert "api.example.com" in live_subs
    # 500エラーは除外される
    assert "dead.example.com" not in live_subs


@pytest.mark.asyncio
async def test_step3_tool_check():
    """Step 3: ツール可用性チェックが呼ばれる"""
    
    pipeline = ReconPipeline(
        config={},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    
    with patch.object(pipeline.runner, 'is_tool_available', return_value=True) as mock_is_avail:
        with patch.object(pipeline.runner, 'run', new=AsyncMock(return_value="sub.example.com")):
            with patch.object(pipeline.runner, 'run_json', new=AsyncMock(return_value=[])):
                await pipeline.step3_live_check(["sub.example.com"])

    # Verify shuffledns or httpx checked
    calls = [args[0] for args, _ in mock_is_avail.call_args_list]
    assert "shuffledns" in calls or "httpx" in calls


@pytest.mark.asyncio
async def test_step3_takeover_candidates_saved(tmp_path):
    """Step 3: takeover_candidates.json が保存される"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_path,
    )
    pipeline.runner.dev_mode = True
    
    # dead_subs が発生するようにモック
    all_subs = ["live.example.com", "dead.example.com"]
    with patch.object(pipeline.runner, 'run_json', new=AsyncMock(return_value=[
        {"url": "https://live.example.com", "status_code": 200},
    ])):
        with patch.object(pipeline.runner, 'run', new=AsyncMock(return_value="live.example.com\n")):
             await pipeline.step3_live_check(all_subs)
    
    # takeover_candidates.json が保存されている (命名規則準拠)
    takeover_files = list(tmp_path.glob("*_example_com_takeover_candidates.json"))
    assert len(takeover_files) == 1
    content = json.loads(takeover_files[0].read_text())
    assert any(item["subdomain"] == "dead.example.com" for item in content)


@pytest.mark.asyncio
async def test_step3_writes_whatweb_fixture_in_dev_mode(tmp_path):
    """Step 3: DEV_MODE では whatweb のファイル出力が fixture helper 経由で維持される"""

    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_path,
    )
    pipeline.runner.dev_mode = True

    with patch.object(pipeline.runner, "run_json", new=AsyncMock(return_value=[
        {"url": "https://www.example.com", "status_code": 200},
    ])):
        with patch.object(
            pipeline.runner,
            "run",
            new=AsyncMock(side_effect=[
                "www.example.com\n",
                '[ {"target":"https://www.example.com","plugins":{"HTTPServer":{"string":["nginx"]}}}]',
            ]),
        ):
            await pipeline.step3_live_check(["www.example.com"])

    whatweb_files = list(tmp_path.glob("*_example_com_whatweb.json"))
    assert len(whatweb_files) == 1
    assert "HTTPServer" in whatweb_files[0].read_text()


@pytest.mark.asyncio
async def test_step3_fetch_resolvers_uses_demo_provider(tmp_path):
    """Step 3: resolver fixture 生成は demo provider に委譲される"""

    class DemoProviderStub:
        def __init__(self):
            self.called = False

        def write_resolvers_file(self, output_path, count):
            self.called = True
            output_path.write_text("10.0.0.1\n10.0.0.2\n")
            return output_path

        def ensure_whatweb_file(self, output_path, output):
            output_path.write_text(output)
            return output_path

        def get_command_output(self, cmd, mock_output=""):
            return mock_output

        def is_tool_available(self, tool_name):
            return True

        def check_tools(self, tools):
            return None

    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_path,
    )
    demo_provider = DemoProviderStub()
    pipeline.runner.dev_mode = True
    pipeline.runner.demo_provider = demo_provider

    resolvers_file = await pipeline.fetch_resolvers(count=2)

    assert demo_provider.called is True
    assert resolvers_file.read_text() == "10.0.0.1\n10.0.0.2\n"


@pytest.mark.asyncio
async def test_step3_uses_demo_provider_for_whatweb_file(tmp_path):
    """Step 3: whatweb fixture 保存は demo provider に委譲される"""

    class DemoProviderStub:
        def __init__(self):
            self.called = False

        def write_resolvers_file(self, output_path, count):
            output_path.write_text("8.8.8.8\n")
            return output_path

        def ensure_whatweb_file(self, output_path, output):
            self.called = True
            output_path.write_text(output)
            return output_path

        def get_command_output(self, cmd, mock_output=""):
            return mock_output

        def is_tool_available(self, tool_name):
            return True

        def check_tools(self, tools):
            return None

    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_path,
    )
    pipeline.runner.dev_mode = True
    pipeline.runner.demo_provider = DemoProviderStub()

    with patch.object(pipeline.runner, "run_json", new=AsyncMock(return_value=[
        {"url": "https://www.example.com", "status_code": 200},
    ])):
        with patch.object(
            pipeline.runner,
            "run",
            new=AsyncMock(side_effect=[
                "www.example.com\n",
                '[ {"target":"https://www.example.com","plugins":{"HTTPServer":{"string":["nginx"]}}}]',
            ]),
        ):
            await pipeline.step3_live_check(["www.example.com"])

    assert pipeline.runner.demo_provider.called is True
