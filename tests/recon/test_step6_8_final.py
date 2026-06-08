"""
Test Step 6-8: Classification, Save, and Return
"""

import pytest
import json
import shutil
from pathlib import Path

from src.recon.pipeline import ReconPipeline


@pytest.fixture
def tmp_workspace(tmp_path):
    """テスト用ワークスペース"""
    workspace = tmp_path / "recon_test"
    workspace.mkdir(parents=True, exist_ok=True)
    yield workspace
    shutil.rmtree(workspace, ignore_errors=True)


@pytest.mark.asyncio
async def test_step6_classify_empty_workspace(tmp_workspace):
    """Step 6: 空ワークスペースでは空の結果を返す"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_workspace,
    )
    
    result = await pipeline.step6_classify()
    
    # 空の結果
    assert isinstance(result, dict)
    assert len(result) == 0


@pytest.mark.asyncio
async def test_step6_classify_by_status(tmp_workspace):
    """Step 6: HTTPステータスで分類"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_workspace,
    )
    
    # httpx.json を作成
    httpx_data = [
        {"url": "https://www.example.com", "status_code": 200},
        {"url": "https://api.example.com", "status_code": 200},
        {"url": "https://admin.example.com", "status_code": 403},
        {"url": "https://login.example.com", "status_code": 302},
    ]
    httpx_file = pipeline._get_path("httpx", "json")
    httpx_file.write_text(json.dumps(httpx_data))
    
    # 実行
    result = await pipeline.step6_classify()
    
    # 検証
    assert "live_200" in result
    assert "live_403" in result
    assert "live_401_302" in result
    
    # live_200 には 2 件
    live_200_data = json.loads(result["live_200"].read_text())
    assert len(live_200_data) == 2


@pytest.mark.asyncio
async def test_step6_classify_by_subdomain_name(tmp_workspace):
    """Step 6: サブドメイン名で分類"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_workspace,
    )
    
    # httpx.json を作成
    httpx_data = [
        {"url": "https://dev.example.com", "status_code": 200},
        {"url": "https://staging.example.com", "status_code": 200},
        {"url": "https://internal.example.com", "status_code": 200},
        {"url": "https://payment.example.com", "status_code": 200},
    ]
    httpx_file = pipeline._get_path("httpx", "json")
    httpx_file.write_text(json.dumps(httpx_data))
    
    # 実行
    result = await pipeline.step6_classify()
    
    # 検証
    assert "dev_staging" in result
    assert "internal_names" in result
    assert "high_value" in result


@pytest.mark.asyncio
async def test_step6_waf_integration(tmp_workspace):
    """Step 6: WAF情報が統合される"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_workspace,
    )
    
    # httpx.json を作成
    httpx_data = [
        {"url": "https://www.example.com", "status_code": 200},
    ]
    httpx_file = pipeline._get_path("httpx", "json")
    httpx_file.write_text(json.dumps(httpx_data))
    
    # wafw00f.json を作成
    waf_data = {"www.example.com": "Cloudflare"}
    waf_file = pipeline._get_path("wafw00f", "json")
    waf_file.write_text(json.dumps(waf_data))
    
    # 実行
    result = await pipeline.step6_classify()
    
    # 検証
    assert "live_200" in result
    live_200_data = json.loads(result["live_200"].read_text())
    assert len(live_200_data) == 1
    assert live_200_data[0]["waf"] == "Cloudflare"


@pytest.mark.asyncio
async def test_step6_cloud_classification(tmp_workspace):
    """Step 6: クラウド分類"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_workspace,
    )
    
    # httpx.json
    httpx_data = [
        {"url": "https://aws.example.com", "status_code": 200},
        {"url": "https://azure.example.com", "status_code": 200},
        {"url": "https://gcp.example.com", "status_code": 200},
        {"url": "https://cf.example.com", "status_code": 200},
        {"url": "https://none.example.com", "status_code": 200},
    ]
    httpx_file = pipeline._get_path("httpx", "json")
    httpx_file.write_text(json.dumps(httpx_data))
    
    # wafw00f.json (WAF情報で分類)
    waf_data = {
        "aws.example.com": "AWS WAF",
        "cf.example.com": "Cloudflare",
    }
    waf_file = pipeline._get_path("wafw00f", "json")
    waf_file.write_text(json.dumps(waf_data))
    
    # whatweb.json (Tech情報で分類)
    whatweb_data = [
        {"target": "https://azure.example.com", "plugins": {"Microsoft-Azure": {}}},
        {"target": "https://gcp.example.com", "plugins": {"Google-Cloud-Storage": {}}},
    ]
    whatweb_file = pipeline._get_path("whatweb", "json")
    whatweb_file.write_text(json.dumps(whatweb_data))
    
    # 実行
    result = await pipeline.step6_classify()
    
    # 検証
    assert "cloud_aws" in result
    assert "cloud_azure" in result
    assert "cloud_gcp" in result
    assert "cloud_cloudflare" in result
    
    # 各カテゴリの件数確認
    aws_data = json.loads(result["cloud_aws"].read_text())
    assert len(aws_data) == 1
    assert aws_data[0]["subdomain"] == "aws.example.com"
    
    cf_data = json.loads(result["cloud_cloudflare"].read_text())
    assert len(cf_data) == 1
    assert cf_data[0]["subdomain"] == "cf.example.com"
    
    az_data = json.loads(result["cloud_azure"].read_text())
    assert len(az_data) == 1
    
    gcp_data = json.loads(result["cloud_gcp"].read_text())
    assert len(gcp_data) == 1


@pytest.mark.asyncio
async def test_step7_save_to_project_no_pm():
    """Step 7: ProjectManager なしの場合"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,  # PM なし
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    
    # 実行（エラーが出ないことを確認）
    await pipeline.step7_save_to_project({})
    
    # エラーなく完了すれば OK


@pytest.mark.asyncio
async def test_step7_save_to_project_with_pm(tmp_workspace):
    """Step 7: ProjectManager ありの場合"""
    from unittest.mock import MagicMock
    
    # Mock ProjectManager
    mock_pm = MagicMock()
    mock_pm.save_raw_scan = MagicMock()
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=mock_pm,
        target="*.example.com",
        workspace_root=tmp_workspace,
    )
    
    # テスト用ファイル作成
    test_file = tmp_workspace / "test.json"
    test_file.write_text('{"test": "content"}')
    
    classified = {"test_category": test_file}
    
    # 実行
    await pipeline.step7_save_to_project(classified)
    
    # 検証
    mock_pm.save_raw_scan.assert_called_once()


@pytest.mark.asyncio
async def test_step8_return_to_mc(tmp_workspace):
    """Step 8: MC へ結果返却（メタデータ形式）"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_workspace,
    )
    
    # テスト用ファイル作成
    test_file = tmp_workspace / "live_200.json"
    test_data = [
        {"subdomain": "www.example.com", "status_code": 200},
        {"subdomain": "api.example.com", "status_code": 200},
    ]
    test_file.write_text(json.dumps(test_data))
    
    classified_files = {"live_200": test_file}
    
    # 実行
    result = await pipeline.step8_return_to_mc(classified_files)
    
    # 検証
    assert isinstance(result, dict)
    assert "live_200" in result
    
    # メタデータ形式の確認
    live_200_meta = result["live_200"]
    assert "file" in live_200_meta
    assert "count" in live_200_meta
    assert "description" in live_200_meta
    assert live_200_meta["count"] == 2


@pytest.mark.asyncio
async def test_step8_empty_result():
    """Step 8: 空の結果"""
    
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=Path("/tmp/test"),
    )
    
    # 実行
    result = await pipeline.step8_return_to_mc({})
    
    # 検証
    assert isinstance(result, dict)
    assert len(result) == 0
