
import pytest
from unittest.mock import AsyncMock, MagicMock
from src.core.attack.file_upload_tester import FileUploadTester

@pytest.fixture
def mock_client():
    client = AsyncMock()
    client.request = AsyncMock()
    return client

@pytest.fixture
def tester(mock_client):
    # Katana URL等のコンテキストを持たせない単純な構成
    return FileUploadTester(mock_client)

@pytest.mark.asyncio
async def test_upload_success_basic(tester, mock_client):
    # 0. Baseline Request
    mock_baseline = MagicMock()
    mock_baseline.status = 200
    mock_baseline.text = "Regular page"
    
    # 1. Successful Upload Response
    mock_upload_resp = MagicMock()
    mock_upload_resp.status = 200
    mock_upload_resp.text = "file successfully uploaded to /tmp/test.jpg"
    
    # 2. Failed Upload Response (for others)
    mock_fail_resp = MagicMock()
    mock_fail_resp.status = 403
    mock_fail_resp.text = "Forbidden"
    
    # Side effect: Baseline -> .htaccess -> various payloads
    # .htaccess is the first one in payloads list (inserted at index 0)
    mock_client.request.side_effect = [
        mock_baseline,     # Baseline
        mock_upload_resp,  # .htaccess
        mock_upload_resp,  # First PHP payload (direct)
        *[mock_fail_resp] * 20 # Others fail
    ]
    
    results = await tester.test_upload("http://example.com/api/upload", aggressive=True)
    
    # Check results
    assert len(results) >= 2
    assert results[0].success is True
    assert results[0].technique == ".htaccess Overwrite"
    
    # Suggested paths should be generated (Fallback Tier 3 at least)
    assert len(results[0].suggested_paths) > 0
    # Top suggestion should contain netloc/filename
    assert "example.com" in results[0].suggested_paths[0].url

@pytest.mark.asyncio
async def test_upload_with_context(mock_client):
    # Katana URL コンテキストを持たせたパステスト
    katana_urls = ["http://example.com/assets/img/logo.png"]
    tester = FileUploadTester(mock_client, katana_urls=katana_urls)
    
    mock_baseline = MagicMock()
    mock_baseline.status = 200
    mock_baseline.text = ""
    
    mock_success = MagicMock()
    mock_success.status = 201
    mock_success.text = "Created"
    
    mock_client.request.side_effect = [
        mock_baseline,
        mock_success, # .htaccess
        mock_success, # PHP
        *[MagicMock(status=404, text="")] * 20
    ]
    
    results = await tester.test_upload("http://example.com/upload.php", aggressive=True)
    
    # Tier 1 (Katana) should be prioritized
    # Katana URL が /assets/img/ なら /assets/img/shigoku_... が候補に挙がるはず
    top_paths = [p.url for p in results[0].suggested_paths[:10]]
    assert any("/assets/img/" in p for p in top_paths)

@pytest.mark.asyncio
async def test_non_aggressive_mode(tester):
    results = await tester.test_upload("http://example.com/upload", aggressive=False)
    assert len(results) == 0
