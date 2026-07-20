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
        {"url": "https://api.example.com", "status_code": 200},
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
    assert len(live_200_data) == 2
    # www.example.com should have WAF = Cloudflare
    www_entry = next((e for e in live_200_data if "www.example.com" in e.get("url", "")), None)
    assert www_entry is not None
    assert www_entry["waf"] == "Cloudflare"


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
    # SGK-2026-0261: _signal_bundle が常に含まれるようになった
    signal_keys = {"_signal_bundle"}
    actual_category_keys = [k for k in result if k not in signal_keys]
    assert len(actual_category_keys) == 0
    # signal bundle が存在し、空の signals であること
    assert "_signal_bundle" in result
    s_bundle = result["_signal_bundle"]
    assert isinstance(s_bundle, dict)
    assert len(s_bundle.get("_endpoint_signals", [])) == 0


# ── SGK-2026-0261 regression tests ──

@pytest.mark.asyncio
async def test_signal_bundle_real_urls(tmp_workspace):
    """SGK-2026-0261: signal bundle に実 URL が含まれ、file path ではないこと"""
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_workspace,
    )

    # classified_files: live_200 カテゴリに実 URL を含む JSON を作成
    json_data = [
        {"url": "https://www.example.com", "subdomain": "www.example.com", "status_code": 200},
        {"url": "https://api.example.com", "subdomain": "api.example.com", "status_code": 200},
    ]
    live_200_file = tmp_workspace / "live_200.json"
    live_200_file.write_text(json.dumps(json_data))

    classified_files = {"live_200": live_200_file}
    result = await pipeline.step8_return_to_mc(classified_files)

    bundle = result.get("_signal_bundle", {})
    signals = bundle.get("_endpoint_signals", [])
    assert len(signals) >= 2, f"Expected >=2 signals, got {len(signals)}"

    for sig in signals:
        url = sig.get("url", "")
        assert url.startswith("http"), f"Signal URL should be real HTTP URL, got: {url}"
        assert not url.endswith(".json"), f"Signal URL should not be a file path: {url}"
        assert sig.get("method", "") in ("GET", "POST", "")


@pytest.mark.asyncio
async def test_signal_bundle_param_signals(tmp_workspace):
    """SGK-2026-0261: signal bundle に entity_type=param の signal が生成されること"""
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_workspace,
    )

    json_data = [
        {"url": "https://app.example.com/search?q=test&id=42&redirect=/home", "status_code": 200, "method": "GET"},
        {"url": "https://app.example.com/profile", "status_code": 200, "method": "GET",
         "forms": [{"method": "POST", "inputs": [{"name": "username"}, {"name": "password"}]}]},
    ]
    live_200_file = tmp_workspace / "live_200.json"
    live_200_file.write_text(json.dumps(json_data))

    result = await pipeline.step8_return_to_mc({"live_200": live_200_file})

    bundle = result.get("_signal_bundle", {})
    signals = bundle.get("_endpoint_signals", [])

    # endpoint signals (entity_type="endpoint")
    endpoint_sigs = [s for s in signals if s.get("entity_type") == "endpoint"]
    assert len(endpoint_sigs) >= 2, f"Expected >=2 endpoint signals, got {len(endpoint_sigs)}"

    # param signals (entity_type="param")
    param_sigs = [s for s in signals if s.get("entity_type") == "param"]
    assert len(param_sigs) >= 3, f"Expected >=3 param signals (q, id, redirect, username, password), got {len(param_sigs)}"

    # param_name が設定されていること
    param_names = {s.get("primary_label", "") for s in param_sigs}
    expected_params = {"q", "id", "redirect", "username", "password"}
    assert expected_params.issubset(param_names) or expected_params & param_names, \
        f"Param signals should include {expected_params}, got {param_names}"

    # param location が query/form であること
    locations = {s.get("params", [{}])[0].get("location", "") if s.get("params") else "" for s in param_sigs}
    assert "query" in locations or "form" in locations, f"Param locations: {locations}"


@pytest.mark.asyncio
async def test_signal_bundle_real_source_observations(tmp_workspace):
    """SGK-2026-0261: source_observations が entry の source フィールドから来ること"""
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_workspace,
    )

    json_data = [
        {"url": "https://www.example.com", "status_code": 200, "source": "katana"},
    ]
    live_200_file = tmp_workspace / "live_200.json"
    live_200_file.write_text(json.dumps(json_data))

    result = await pipeline.step8_return_to_mc({"live_200": live_200_file})

    bundle = result.get("_signal_bundle", {})
    signals = bundle.get("_endpoint_signals", [])
    assert len(signals) >= 1

    sig = signals[0]
    sources = sig.get("source_observations", [])
    assert "katana" in sources, f"source_observations should include 'katana', got {sources}"
    assert sig.get("subdomain_context") is not None or sig.get("url", "").startswith("http"), \
        "Signal should have either subdomain_context or real URL"
    assert "confidence" in sig


@pytest.mark.asyncio
async def test_signal_bundle_auth_surface(tmp_workspace):
    """SGK-2026-0261: auth 系カテゴリから auth_required な signal が生成されること"""
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_workspace,
    )

    # live_401_302 カテゴリ（認証が必要なサブドメイン）
    json_data = [
        {"url": "https://login.example.com", "subdomain": "login.example.com", "status_code": 401},
    ]
    live_401_file = tmp_workspace / "live_401_302.json"
    live_401_file.write_text(json.dumps(json_data))

    result = await pipeline.step8_return_to_mc({"live_401_302": live_401_file})

    bundle = result.get("_signal_bundle", {})
    signals = bundle.get("_endpoint_signals", [])
    assert len(signals) >= 1

    sig = signals[0]
    assert sig.get("auth_required") is True, \
        f"live_401_302 signal should have auth_required=True, got: {sig.get('auth_required')}"
    assert sig.get("entity_type") == "auth_surface", \
        f"Expected auth_surface entity_type, got: {sig.get('entity_type')}"
    assert "login" in sig.get("url", "").lower()


@pytest.mark.asyncio
async def test_signal_bundle_host_surface_summary(tmp_workspace):
    """SGK-2026-0261: host_surface_summary にカテゴリ集計と tech_stack が含まれること"""
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_workspace,
    )

    json_data = [
        {"url": "https://www.example.com", "status_code": 200},
        {"url": "https://api.example.com", "status_code": 200},
        {"url": "https://admin.example.com", "status_code": 403},
    ]
    live_200_file = tmp_workspace / "live_200.json"
    live_200_file.write_text(json.dumps(json_data[:2]))
    live_403_file = tmp_workspace / "live_403.json"
    live_403_file.write_text(json.dumps(json_data[2:]))

    result = await pipeline.step8_return_to_mc({"live_200": live_200_file, "live_403": live_403_file})

    bundle = result.get("_signal_bundle", {})
    summary = bundle.get("_host_surface_summary", {})

    assert isinstance(summary, dict)
    assert summary.get("total_signals", 0) >= 3
    assert "surface_types" in summary
    assert "legacy_keys" in summary
    assert "discovered_urls" in summary.get("legacy_keys", {})
