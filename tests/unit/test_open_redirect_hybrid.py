
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from src.core.agents.swarm.injection.open_redirect import OpenRedirectSpecialist
from src.core.agents.swarm.base import Task

@pytest.fixture
def specialist():
    return OpenRedirectSpecialist()

@pytest.mark.asyncio
async def test_open_redirect_hybrid_validation(specialist):
    """OpenRedirectSpecialist のハイブリッド検証ロジックをテスト"""
    
    target_url = "http://example.com/redirect?url=http://safe.com"
    param_name = "url"
    
    # Phase 1: Reflection Check のモック
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.headers = {"Location": "http://safe.com"}
    mock_response.text = AsyncMock(return_value="<html>no-reflection</html>")
    
    # _verify_with_playwright のモック (Phase 2)
    with patch.object(specialist._client, "request", return_value=mock_response) as mock_request, \
         patch.object(specialist, "_verify_with_playwright", return_value=True) as mock_verify:
        
        result = await specialist._test_redirect_param(target_url, param_name)
    
    # 3xx レスポンスでもなく、反射もしていない場合は Phase 2 に行かないはず
    # ...と思いきや、今の実装では status か reflection かどっちかで Phase 2 に行く
    # 200 OK で反射なしならスキップされるはず
    assert mock_verify.called is False
    assert result["vulnerable"] is False

@pytest.mark.asyncio
async def test_open_redirect_confirmed_via_reflection(specialist):
    """反射が検出された場合に Playwright 検証が走ることを確認"""
    
    target_url = "http://example.com/redirect?url=http://safe.com"
    param_name = "url"
    
    # Reflection を含むレスポンス
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.headers = {}
    
    # uuid をモックして固定の verify_host を生成させる
    mock_uuid_obj = MagicMock()
    mock_uuid_obj.__str__.return_value = "testuuidXXXXXXXX"
    
    with patch.object(specialist._client, "request", return_value=mock_response), \
         patch.object(specialist, "_verify_with_playwright", return_value=True) as mock_verify, \
         patch("src.core.agents.swarm.injection.open_redirect.uuid.uuid4", return_value=mock_uuid_obj):
        
        # test_id = str(uuid.uuid4())[:8] -> "testuuid"
        # verify_host = shigoku-verify-testuuid.evil.com
        
        # body に verify_host を含める
        mock_response.text = AsyncMock(return_value="shigoku-verify-testuuid.evil.com detected!")
        
        result = await specialist._test_redirect_param(target_url, param_name)
    
    assert mock_verify.called is True
    assert result["vulnerable"] is True
    assert result["method"] == "HYBRID"
