
import logging
import asyncio
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

class PlaywrightValidator:
    """
    Playwrightを用いたヘッドレスブラウザ検証ツール
    
    Reflected XSS などのクライアントサイド脆弱性を、実際のブラウザでJavaScriptを発火させて検証する。
    Playwright がインストールされていない場合は Graceful に機能無効化する。
    """
    
    def __init__(self):
        self._is_available = self._check_availability()
        self._browser_args = [
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu"
        ]

    def _check_availability(self) -> bool:
        """Playwright モジュールの存在確認"""
        try:
            from playwright.async_api import async_playwright
            return True
        except ImportError:
            logger.warning("[Headless] Playwright module not found. Browser verification will be skipped.")
            return False

    @property
    def is_available(self) -> bool:
        return self._is_available

    async def validate_xss(self, url: str, timeout: float = 10.0, cookies: Optional[List[Dict[str, Any]]] = None) -> bool:
        """
        URLにアクセスし、alert() ダイアログが出るか、またはコンソールに特定のログが出るか検証する
        
        Args:
            url: 検証対象URL（ペイロード込み）
            timeout: タイムアウト（秒）
            cookies: ブラウザコンテキストにセットするCookie
            
        Returns:
            XSSが発火したと判定された場合 True
        """
        if not self._is_available:
            return False
            
        try:
            from playwright.async_api import async_playwright, Error as PlaywrightError
        except ImportError:
            return False
        
        xss_triggered = False
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=self._browser_args
                )
                
                # コンテキスト作成
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                )
                
                if cookies:
                    await context.add_cookies(cookies)
                
                page = await context.new_page()
                
                # ダイアログハンドラ
                async def handle_dialog(dialog):
                    nonlocal xss_triggered
                    # alert, confirm, prompt などを検知
                    logger.info(f"[Headless] Dialog detected! Type: {dialog.type}, Message: {dialog.message}")
                    xss_triggered = True
                    await dialog.dismiss()
                    
                page.on("dialog", handle_dialog)

                # コンソールログ監視（alert()の代わりや、特定の文字列出力による検知）
                async def handle_console(msg):
                    nonlocal xss_triggered
                    # 'SHIGOKU_XSS_CONFIRMED' という文字列が含まれていれば発火とみなす
                    if "SHIGOKU_XSS_CONFIRMED" in msg.text:
                        logger.info(f"[Headless] XSS Confirmed via console log: {msg.text}")
                        xss_triggered = True
                
                page.on("console", handle_console)
                
                try:
                    # ページ遷移
                    await page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")
                    
                    # 描画とスクリプト実行を少し待つ
                    await page.wait_for_timeout(2000)
                    
                except PlaywrightError as e:
                    # タイムアウトやナビゲーションエラーは無視（XSSは発火しているかもしれない）
                    logger.debug(f"[Headless] Navigation error (expected): {e}")
                except Exception as e:
                    logger.error(f"[Headless] Unexpected error during navigation: {e}")
                finally:
                    await context.close()
                    await browser.close()
                    
        except Exception as e:
            logger.error(f"[Headless] Browser launch failed: {e}")
            return False
            
        return xss_triggered

    async def validate_xss_with_form(
        self, 
        url: str, 
        form_index: int, 
        target_input: str, 
        payload: str, 
        timeout: float = 10.0, 
        cookies: Optional[List[Dict[str, Any]]] = None
    ) -> bool:
        """
        URLにアクセスし、特定のフォームにペイロードを入力して送信し、
        alert() ダイアログが出るか、またはコンソールに特定のログが出るか検証する
        """
        if not self._is_available:
            return False
            
        try:
            from playwright.async_api import async_playwright, Error as PlaywrightError
        except ImportError:
            return False
        
        xss_triggered = False
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=self._browser_args
                )
                
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                )
                
                if cookies:
                    await context.add_cookies(cookies)
                
                page = await context.new_page()
                
                # ダイアログハンドラ
                async def handle_dialog(dialog):
                    nonlocal xss_triggered
                    logger.info(f"[Headless] Dialog detected! Type: {dialog.type}, Message: {dialog.message}")
                    xss_triggered = True
                    await dialog.dismiss()
                    
                page.on("dialog", handle_dialog)

                async def handle_console(msg):
                    nonlocal xss_triggered
                    if "SHIGOKU_XSS_CONFIRMED" in msg.text:
                        logger.info(f"[Headless] XSS Confirmed via console log: {msg.text}")
                        xss_triggered = True
                
                page.on("console", handle_console)
                
                try:
                    await page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")
                    await page.wait_for_timeout(1000)
                    
                    form_elements = await page.query_selector_all("form")
                    if form_index < len(form_elements):
                        target_form = form_elements[form_index]
                        
                        input_element = await target_form.query_selector(f"[name='{target_input}']")
                        if input_element:
                            await input_element.fill(payload)
                            
                            try:
                                async with page.expect_navigation(timeout=timeout*1000):
                                    submit_button = await target_form.query_selector("input[type='submit'], button[type='submit']")
                                    if submit_button:
                                        await submit_button.click()
                                    else:
                                        await input_element.press('Enter')
                            except PlaywrightError:
                                pass
                            
                            await page.wait_for_timeout(2000)
                    else:
                        logger.warning(f"[Headless] Form index {form_index} out of bounds.")
                    
                except PlaywrightError as e:
                    logger.debug(f"[Headless] Navigation error (expected): {e}")
                except Exception as e:
                    logger.error(f"[Headless] Unexpected error during navigation/form submission: {e}")
                finally:
                    await context.close()
                    await browser.close()
                    
        except Exception as e:
            logger.error(f"[Headless] Browser launch failed: {e}")
            return False
            
        return xss_triggered

    async def extract_forms(self, url: str, timeout: float = 10.0, cookies: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """
        ページ内の入力フォームを抽出する。
        
        Args:
            url: 対象URL
            timeout: タイムアウト
            cookies: Cookie
            
        Returns:
            List[Dict]: フォーム情報のリスト
        """
        if not self._is_available:
            return []
            
        from playwright.async_api import async_playwright
        
        forms = []
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, args=self._browser_args)
                context = await browser.new_context(ignore_https_errors=True)
                if cookies:
                    await context.add_cookies(cookies)
                page = await context.new_page()
                
                await page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")
                
                # フォーム情報の抽出
                form_elements = await page.query_selector_all("form")
                for form in form_elements:
                    action = await form.get_attribute("action") or ""
                    method = await form.get_attribute("method") or "get"
                    
                    inputs = []
                    input_elements = await form.query_selector_all("input, textarea, select")
                    for inp in input_elements:
                        name = await inp.get_attribute("name")
                        if name:
                            inp_type = await inp.get_attribute("type") or "text"
                            inputs.append({"name": name, "type": inp_type})
                    
                    forms.append({
                        "action": action,
                        "method": method.lower(),
                        "inputs": inputs
                    })
                
                await browser.close()
        except Exception as e:
            logger.error(f"[Headless] Form extraction failed: {e}")
            
        return forms

    async def validate_dom_reflection(self, url: str, marker: str, timeout: float = 10.0, cookies: Optional[List[Dict[str, Any]]] = None) -> bool:
        """
        ブラウザでページを開き、JS実行後の DOM 内に指定したマーカーが存在するか確認する。
        DOM-Based XSS のプローブ検証に使用。
        """
        if not self._is_available:
            return False
            
        from playwright.async_api import async_playwright, Error as PlaywrightError
        
        found = False
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, args=self._browser_args)
                context = await browser.new_context(ignore_https_errors=True)
                if cookies:
                    await context.add_cookies(cookies)
                page = await context.new_page()
                
                try:
                    await page.goto(url, timeout=timeout * 1000, wait_until="networkidle")
                    content = await page.content()
                    if marker in content:
                        found = True
                except PlaywrightError:
                    pass
                finally:
                    await browser.close()
        except Exception as e:
            logger.error(f"[Headless] DOM verification failed: {e}")
            
        return found
        
    async def validate_frontend_idor(
        self, 
        base_url: str, 
        original_id: str, 
        test_id: str, 
        timeout: float = 10.0, 
        cookies: Optional[List[Dict[str, Any]]] = None
    ) -> dict:
        """
        SPAなどフロントエンドアプリにおけるIDOR（Insecure Direct Object Reference）を検証する。
        Fetch/XHRリクエストをインターセプトし、オリジナルIDをテスト先IDに書き換えることで、
        意図しないデータがUIにレンダリングされるか（またはAPIが200を返すか）を確認する。
        
        Returns:
            dict: { "is_vulnerable": bool, "details": "..." }
        """
        if not self._is_available:
            return {"is_vulnerable": False, "details": "Playwright not available"}
            
        from playwright.async_api import async_playwright, Error as PlaywrightError
        
        result = {"is_vulnerable": False, "details": "", "api_status": 0}
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, args=self._browser_args)
                context = await browser.new_context(ignore_https_errors=True)
                if cookies:
                    await context.add_cookies(cookies)
                page = await context.new_page()
                
                intercepted_requests = []
                successful_apis = []
                
                async def handle_route(route):
                    request = route.request
                    url = request.url
                    # 対象IDが含まれるAPIリクエストをインターセプトして書き換え
                    if request.resource_type in ["fetch", "xhr"] and original_id in url:
                        new_url = url.replace(original_id, test_id)
                        intercepted_requests.append({"original": url, "new": new_url})
                        await route.continue_(url=new_url)
                    else:
                        await route.continue_()
                
                await page.route("**/*", handle_route)
                
                async def handle_response(response):
                    if response.request.resource_type in ["fetch", "xhr"] and test_id in response.url:
                        if response.status == 200:
                            successful_apis.append(response.url)
                            result["api_status"] = response.status
                            
                page.on("response", handle_response)
                
                try:
                    await page.goto(base_url, timeout=timeout * 1000, wait_until="networkidle")
                    await page.wait_for_timeout(2000) # DOMの更新を待つ
                    
                    if successful_apis:
                        page_content = await page.content()
                        # アプリがエラー画面を出さず、かつAPIが成功していれば脆弱とみなす
                        error_keywords = ["access denied", "unauthorized", "forbidden", "not found", "403", "401", "error"]
                        has_error_ui = any(kw in page_content.lower() for kw in error_keywords)
                        
                        if not has_error_ui:
                            result["is_vulnerable"] = True
                            result["details"] = f"Frontend IDOR successful. Intercepted API responded with 200 OK for ID: {test_id} and UI did not show errors."
                        else:
                            result["details"] = "API 200 OK, but UI displayed an error message."
                    else:
                        result["details"] = "No successful intercepted API requests."
                        
                except PlaywrightError as e:
                    result["details"] = f"Navigation error: {e}"
                finally:
                    await browser.close()
        except Exception as e:
            logger.error(f"[Headless] Frontend IDOR verification failed: {e}")
            result["details"] = f"Error: {e}"
            
        return result

    async def validate_csrf_simulation(
        self, 
        target_api: str, 
        method: str, 
        post_data: dict, 
        cookies: Optional[List[Dict[str, Any]]] = None
    ) -> bool:
        """
        CSRF攻撃をシミュレートする（別オリジンからのクロスサイトリクエスト）。
        単純なHTMLフォームからターゲットAPIにPOSTリクエストを送信し、成功するかどうかを検証する。
        """
        if not self._is_available:
            return False
            
        from playwright.async_api import async_playwright
        
        is_vulnerable = False
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, args=self._browser_args)
                # CSRFシミュレーションなので、通常の認証クッキーを持たせつつ、
                # アタッカー由来の別のコンテキスト（例えばattacker.com）からリクエストを送るような擬似環境を作る
                context = await browser.new_context(ignore_https_errors=True)
                if cookies:
                    # 認証クッキーをSameSite=None等の条件で無理やりセットするか、対象ドメインにセットする
                    await context.add_cookies(cookies)
                    
                page = await context.new_page()
                
                # 攻撃者の罠ページを生成
                inputs = "".join([f'<input type="hidden" name="{k}" value="{v}">' for k, v in post_data.items()])
                
                # Content-Typeが application/x-www-form-urlencoded または multipart/form-data になる単純なフォーム
                attacker_html = f"""
                <html>
                  <body>
                    <form id="csrf-form" action="{target_api}" method="{method}">
                      {inputs}
                      <input type="submit" value="Submit">
                    </form>
                    <script>
                      document.getElementById('csrf-form').submit();
                    </script>
                  </body>
                </html>
                """
                
                # dataスキーマを利用して、別オリジン（nullオリジンや無関係なオリジン）として扱う
                await page.goto(f"data:text/html;charset=utf-8,{attacker_html}")
                
                # リクエスト遷移後のレスポンスを確認
                try:
                    # フォーム送信先（target_api）のレスポンスを待つ
                    response = await page.wait_for_response(lambda r: target_api in r.url, timeout=5000)
                    
                    # 200系であればCSRF成功（SameSiteクッキーやCSRFトークンによる防御がなかった）
                    if 200 <= response.status < 300:
                        is_vulnerable = True
                        logger.info(f"[Headless] CSRF successful. Status: {response.status}")
                except Exception as e:
                    # タイムアウト等でブロックされた場合は安全
                    logger.debug(f"[Headless] CSRF blocked or failed: {e}")
                    
                finally:
                    await browser.close()
        except Exception as e:
            logger.error(f"[Headless] CSRF simulation failed: {e}")
            
        return is_vulnerable
