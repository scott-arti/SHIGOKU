
import pytest
import sys
from unittest.mock import MagicMock, AsyncMock, patch

# sys.modules を使って playwright モジュール自体を偽装する
mock_playwright_mod = MagicMock()
mock_async_api = MagicMock()
mock_playwright_mod.async_api = mock_async_api

with patch.dict('sys.modules', {'playwright': mock_playwright_mod, 'playwright.async_api': mock_async_api}):
    from src.tools.browser.playwright_validator import PlaywrightValidator

class TestPlaywrightValidator:

    @pytest.fixture
    def validator(self):
        with patch('src.tools.browser.playwright_validator.PlaywrightValidator._check_availability', return_value=True):
            v = PlaywrightValidator()
            v._is_available = True
            return v

    @pytest.mark.asyncio
    async def test_graceful_skip(self):
        """Playwrightがない場合のスキップ挙動"""
        with patch('src.tools.browser.playwright_validator.PlaywrightValidator._check_availability', return_value=False):
            v = PlaywrightValidator()
            v._is_available = False
            result = await v.validate_xss("http://test.com")
            assert result is False

    @pytest.mark.asyncio
    async def test_xss_detection_success(self, validator):
        """XSS検知（アラート発火）"""
        # 非同期コンテキストマネージャのモックを作成
        mock_playwright = AsyncMock()
        
        # async_playwright() が呼び出された時に返すコンテキストマネージャ
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_playwright)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        
        mock_ap_func = MagicMock(return_value=mock_cm)
        
        with patch.dict('sys.modules', {'playwright.async_api': mock_async_api}):
            with patch.object(mock_async_api, 'async_playwright', mock_ap_func):
                with patch.object(mock_async_api, 'Error', Exception):
                    
                    mock_browser = AsyncMock()
                    mock_playwright.chromium.launch.return_value = mock_browser
                    
                    mock_context = AsyncMock()
                    mock_browser.new_context.return_value = mock_context
                    
                    mock_page = AsyncMock()
                    mock_context.new_page.return_value = mock_page
                    
                    mock_page.on = MagicMock()
                    
                    captured_handler = None
                    def side_effect_on(event, handler):
                        nonlocal captured_handler
                        if event == "dialog":
                            captured_handler = handler
                            
                    mock_page.on.side_effect = side_effect_on
                    
                    async def side_effect_goto(*args, **kwargs):
                        if captured_handler:
                            mock_dialog = AsyncMock()
                            mock_dialog.message = "XSS Alert"
                            mock_dialog.type = "alert"
                            # 実際のハンドラはコルーチンとして呼ばれる
                            await captured_handler(mock_dialog)
                    
                    mock_page.goto.side_effect = side_effect_goto
                    
                    result = await validator.validate_xss("http://test.com")
                    
                    assert result is True
                    mock_page.goto.assert_called()

    @pytest.mark.asyncio
    async def test_xss_no_detection(self, validator):
        """XSS非検知"""
        mock_playwright = AsyncMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_playwright)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_ap_func = MagicMock(return_value=mock_cm)
        
        with patch.dict('sys.modules', {'playwright.async_api': mock_async_api}):
            with patch.object(mock_async_api, 'async_playwright', mock_ap_func):
                with patch.object(mock_async_api, 'Error', Exception):
                    mock_browser = AsyncMock()
                    mock_playwright.chromium.launch.return_value = mock_browser
                    mock_context = AsyncMock()
                    mock_browser.new_context.return_value = mock_context
                    mock_page = AsyncMock()
                    mock_context.new_page.return_value = mock_page
                    
                    mock_page.on = MagicMock()
                    
                    result = await validator.validate_xss("http://test.com")
                    
                    assert result is False

    @pytest.mark.asyncio
    async def test_frontend_idor_vulnerable(self, validator):
        """フロントエンドIDOR検知"""
        mock_playwright = AsyncMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_playwright)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_ap_func = MagicMock(return_value=mock_cm)
        
        with patch.dict('sys.modules', {'playwright.async_api': mock_async_api}):
            with patch.object(mock_async_api, 'async_playwright', mock_ap_func):
                with patch.object(mock_async_api, 'Error', Exception):
                    mock_browser = AsyncMock()
                    mock_playwright.chromium.launch.return_value = mock_browser
                    mock_context = AsyncMock()
                    mock_browser.new_context.return_value = mock_context
                    mock_page = MagicMock()
                    mock_context.new_page.return_value = mock_page
                    
                    # route() 呼び出しをシミュレーションするためのハンドラ退避
                    captured_route_handler = None
                    async def side_effect_route(url, handler):
                        nonlocal captured_route_handler
                        captured_route_handler = handler
                        
                    mock_page.route = AsyncMock(side_effect=side_effect_route)
                    
                    # response() 呼び出しをシミュレーションするためのハンドラ退避
                    captured_res_handler = None
                    def side_effect_on(event, handler):
                        nonlocal captured_res_handler
                        if event == "response":
                            captured_res_handler = handler
                            
                    mock_page.on = MagicMock(side_effect=side_effect_on)
                    
                    async def side_effect_goto(*args, **kwargs):
                        # API レスポンスを発火させる
                        if captured_res_handler:
                            mock_response = MagicMock()
                            mock_request = MagicMock()
                            mock_request.resource_type = "fetch"
                            mock_response.request = mock_request
                            mock_response.url = "http://api.test.com/users/999"
                            mock_response.status = 200
                            await captured_res_handler(mock_response)
                            
                    mock_page.goto = AsyncMock(side_effect=side_effect_goto)
                    mock_page.wait_for_timeout = AsyncMock()
                    mock_page.content = AsyncMock(return_value="<html><body>Data for user 999</body></html>")
                    
                    result = await validator.validate_frontend_idor("http://test.com", "123", "999")
                    
                    if not result["is_vulnerable"]:
                        print(f"DEBUG FRONTEND IDOR RESULT: {result}")

                    assert result["is_vulnerable"] is True
                    assert "200" in result["details"]
                    
    @pytest.mark.asyncio
    async def test_csrf_simulation_vulnerable(self, validator):
        """CSRFシミュレーション検知"""
        mock_playwright = AsyncMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_playwright)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_ap_func = MagicMock(return_value=mock_cm)
        
        with patch.dict('sys.modules', {'playwright.async_api': mock_async_api}):
            with patch.object(mock_async_api, 'async_playwright', mock_ap_func):
                with patch.object(mock_async_api, 'Error', Exception):
                    mock_browser = AsyncMock()
                    mock_playwright.chromium.launch.return_value = mock_browser
                    mock_context = AsyncMock()
                    mock_browser.new_context.return_value = mock_context
                    mock_page = AsyncMock()
                    mock_context.new_page.return_value = mock_page
                    
                    mock_response = AsyncMock()
                    mock_response.status = 200
                    mock_page.wait_for_response.return_value = mock_response
                    
                    result = await validator.validate_csrf_simulation("http://api.test.com/update", "POST", {"user": "hacked"})
                    
                    assert result is True
                    mock_page.wait_for_response.assert_called()
