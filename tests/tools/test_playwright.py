
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from src.tools.browser.playwright_validator import PlaywrightValidator

@pytest.mark.asyncio
async def test_availability_check():
    """Playwrightの有無によるフラグチェック"""
    # 実際にあるかどうかで結果が変わるが、エラーにならないことを確認
    validator = PlaywrightValidator()
    assert isinstance(validator.is_available, bool)

@pytest.mark.asyncio
async def test_validate_xss_unavailable():
    """Playwrightがない場合にFalseを返すか"""
    with patch("src.tools.browser.playwright_validator.PlaywrightValidator._check_availability", return_value=False):
        validator = PlaywrightValidator()
        result = await validator.validate_xss("http://example.com")
        assert result is False

@pytest.mark.asyncio
async def test_validate_xss_success():
    """XSS検知成功（Mock）"""
    # Create mock module structure
    mock_playwright_module = MagicMock()
    
    # async_playwright is a synchronous function that returns an async context manager
    mock_async_playwright = MagicMock()
    mock_playwright_module.async_playwright = mock_async_playwright
    mock_playwright_module.Error = Exception

    # Mock context managers and page
    mock_context_manager = AsyncMock()
    mock_async_playwright.return_value = mock_context_manager
    
    # Setup p object (yielded by async_playwright context manager)
    mock_p = MagicMock()
    mock_context_manager.__aenter__.return_value = mock_p
    
    # p.chromium.launch is async
    mock_browser = AsyncMock()
    mock_p.chromium.launch = AsyncMock(return_value=mock_browser)
    
    mock_context = AsyncMock()
    mock_browser.new_context.return_value = mock_context
    
    mock_page = AsyncMock()
    mock_context.new_page.return_value = mock_page
    
    # page.on is synchronous
    mock_page.on = MagicMock()
    
    # page.wait_for_timeout should wait to allow callback to be triggered
    async def delayed_wait(*args, **kwargs):
        await asyncio.sleep(0.2)
    mock_page.wait_for_timeout = AsyncMock(side_effect=delayed_wait)
    mock_page.goto = AsyncMock()
    
    # Patch sys.modules to simulate playwright exists
    with patch.dict("sys.modules", {
        "playwright": MagicMock(),
        "playwright.async_api": mock_playwright_module
    }):
        # Re-import or create instance inside patch to ensure check_availability passes
        # But check_availability uses local import.
        
        # We also need to patch _check_availability to return True, OR ensure the import inside it works.
        # Since we patched sys.modules, the import inside _check_availability should work!
        
        validator = PlaywrightValidator()
        assert validator.is_available is True
        
        # Test execution
        task = asyncio.create_task(validator.validate_xss("http://example.com"))
        
        # Simulate dialog event
        await asyncio.sleep(0.1)
        
        # Retrieve the callback passed to page.on
        # page.on("dialog", handle_dialog)
        args, _ = mock_page.on.call_args
        event_name, callback = args
        assert event_name == "dialog"
        
        mock_dialog = AsyncMock()
        mock_dialog.type = "alert"
        mock_dialog.message = "1"
        
        await callback(mock_dialog)
        
        result = await task
        assert result is True
        mock_dialog.dismiss.assert_called_once()
