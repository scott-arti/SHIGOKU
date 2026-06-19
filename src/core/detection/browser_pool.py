"""
Browser Pool - Phase X-3
X3-2〜X3-3: SmartXSSHunter統合・メモリリーク対策

設計方針:
- Playwright がなければ graceful degradation（動作継続）
- 100件ごとのブラウザ再起動でメモリリークを防止
- asyncio.Semaphore でプールサイズを厳守
- すべての使用は async with で RAII 保証
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import AsyncIterator, Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# Playwright はオプション依存
try:
    from playwright.async_api import (
        async_playwright,
        Browser as PlaywrightBrowser,
        Page as PlaywrightPage,
        Playwright,
    )
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False
    PlaywrightBrowser = None  # type: ignore
    PlaywrightPage = None     # type: ignore
    Playwright = None         # type: ignore


# ---------------------------------------------------------------------------
# Pool Metrics
# ---------------------------------------------------------------------------

@dataclass
class BrowserPoolMetrics:
    """Browser Pool 動作メトリクス（CTO 検証用）"""
    total_pages_opened: int = 0
    total_restarts: int = 0
    peak_concurrency: int = 0
    current_concurrency: int = 0
    pool_timeouts: int = 0
    _current: int = field(default=0, repr=False)

    def record_page_open(self) -> None:
        self.total_pages_opened += 1
        self._current += 1
        if self._current > self.peak_concurrency:
            self.peak_concurrency = self._current
        self.current_concurrency = self._current

    def record_page_close(self) -> None:
        self._current = max(0, self._current - 1)
        self.current_concurrency = self._current

    def record_restart(self) -> None:
        self.total_restarts += 1

    def record_timeout(self) -> None:
        self.pool_timeouts += 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_pages_opened": self.total_pages_opened,
            "total_restarts": self.total_restarts,
            "peak_concurrency": self.peak_concurrency,
            "pool_timeouts": self.pool_timeouts,
        }


# ---------------------------------------------------------------------------
# Managed Browser entry
# ---------------------------------------------------------------------------

class _ManagedBrowser:
    """
    プール内の 1 ブラウザインスタンスを管理するラッパー。

    max_requests を超えると自動再起動して request_count をリセットする。
    """

    def __init__(
        self,
        slot_id: int,
        max_requests: int,
        metrics: BrowserPoolMetrics,
    ) -> None:
        self.slot_id = slot_id
        self.max_requests = max_requests
        self.request_count = 0
        self.metrics = metrics
        self._browser: Optional[Any] = None  # PlaywrightBrowser
        self._playwright: Optional[Any] = None

    async def start(self) -> None:
        """ブラウザを起動"""
        if not _PLAYWRIGHT_AVAILABLE:
            return
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=True)
        logger.debug("[BrowserPool] Browser started (slot=%d)", self.slot_id)

    async def stop(self) -> None:
        """ブラウザを停止"""
        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception:
                pass
        self._browser = None
        self._playwright = None

    async def restart(self) -> None:
        """再起動（メモリリーク防止: 100件ごと）"""
        logger.debug(
            "[BrowserPool] Restarting browser (slot=%d, requests=%d)",
            self.slot_id, self.request_count,
        )
        await self.stop()
        await self.start()
        self.request_count = 0
        self.metrics.record_restart()

    async def new_page(self) -> Any:
        """新しいページを取得。必要なら再起動を挟む"""
        if self.request_count >= self.max_requests:
            await self.restart()

        self.request_count += 1
        self.metrics.record_page_open()

        if not _PLAYWRIGHT_AVAILABLE or self._browser is None:
            return _MockPage(self.slot_id)

        return await self._browser.new_page()


# ---------------------------------------------------------------------------
# Mock Page (Playwright なし / テスト用)
# ---------------------------------------------------------------------------

class _MockPage:
    """Playwright 未インストール時のフォールバック"""

    def __init__(self, slot_id: int) -> None:
        self.slot_id = slot_id
        self._dialog_handlers: List[Any] = []
        self.url: Optional[str] = None

    async def goto(self, url: str, **kwargs) -> None:
        self.url = url
        await asyncio.sleep(0.005)

    def on(self, event: str, handler: Any) -> None:
        if event == "dialog":
            self._dialog_handlers.append(handler)

    async def add_init_script(self, script: str) -> None:
        pass

    async def evaluate(self, script: str, arg: Any = None) -> Any:
        return False

    async def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# BrowserPool
# ---------------------------------------------------------------------------

class BrowserPool:
    """
    ブラウザプール（X3-2・X3-3）

    - `size` 個のブラウザスロットを管理
    - Semaphore で同時使用数を `size` に制限
    - `max_requests_per_browser` で自動再起動
    - async with pool.acquire() で安全に使用

    Usage:
        pool = BrowserPool(size=5, max_requests_per_browser=100)
        await pool.start()
        async with pool.acquire() as browser:
            page = await browser.new_page()
            await page.goto(url)
            await page.close()
        await pool.stop()
    """

    def __init__(
        self,
        size: int = 5,
        max_requests_per_browser: int = 100,
        acquire_timeout: float = 10.0,
    ) -> None:
        self.size = size
        self.max_requests = max_requests_per_browser
        self.acquire_timeout = acquire_timeout
        self.metrics = BrowserPoolMetrics()

        self._semaphore = asyncio.Semaphore(size)
        self._browsers: List[_ManagedBrowser] = []
        self._available: asyncio.Queue[_ManagedBrowser] = asyncio.Queue()
        self._started = False

    async def start(self) -> None:
        """プール内の全ブラウザを起動"""
        if self._started:
            return

        for i in range(self.size):
            browser = _ManagedBrowser(i, self.max_requests, self.metrics)
            await browser.start()
            self._browsers.append(browser)
            await self._available.put(browser)

        self._started = True
        logger.info(
            "[BrowserPool] Started %d browser(s) (max_requests=%d)",
            self.size, self.max_requests,
        )

    async def stop(self) -> None:
        """全ブラウザを停止"""
        for browser in self._browsers:
            await browser.stop()
        self._started = False
        logger.info("[BrowserPool] All browsers stopped")

    @asynccontextmanager
    async def acquire(self, retry: int = 1) -> AsyncIterator[_ManagedBrowser]:
        """
        ブラウザを借り出す RAII コンテキストマネージャ。

        タイムアウト時は exponential backoff で最大 retry 回再試行する。
        全試行失敗時のみ TimeoutError を送出する。

        Args:
            retry: タイムアウト後の再試行回数（デフォルト 1 回）

        Example:
            async with pool.acquire() as browser:
                page = await browser.new_page()
                ...
                await page.close()
        """
        if not self._started:
            await self.start()

        browser: Optional[_ManagedBrowser] = None
        for attempt in range(retry + 1):
            try:
                browser = await asyncio.wait_for(
                    self._available.get(),
                    timeout=min(self.acquire_timeout * (2 ** attempt), 30.0),  # backoff (cap 30s)
                )
                break
            except asyncio.TimeoutError:
                self.metrics.record_timeout()
                if attempt == retry:
                    raise TimeoutError(
                        f"[BrowserPool] No browser available after {retry + 1} attempt(s)"
                    )
                logger.warning(
                    "[BrowserPool] Acquire timeout, retrying (attempt=%d/%d)",
                    attempt + 1, retry + 1,
                )

        if browser is None:
            raise TimeoutError("[BrowserPool] No browser acquired (unexpected)")

        try:
            yield browser
        finally:
            self.metrics.record_page_close()
            await self._available.put(browser)

    def get_metrics(self) -> Dict[str, Any]:
        return self.metrics.to_dict()


# ---------------------------------------------------------------------------
# XSSVerificationResult
# ---------------------------------------------------------------------------

@dataclass
class XSSVerificationResult:
    """ブラウザ検証の結果"""
    url: str
    parameter: str
    payload: str
    executed: bool
    evidence: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# BrowserPoolXSSVerifier  (X3-2 統合レイヤー)
# ---------------------------------------------------------------------------

class BrowserPoolXSSVerifier:
    """
    Browser Pool を使った XSS 発火確認モジュール。

    SmartXSSHunter から呼び出されるサービスクラス。
    Playwright がなければ静的反射チェックにフォールバック。
    """

    def __init__(self, pool: Optional[BrowserPool] = None) -> None:
        self._pool = pool  # 外部注入可能・None なら遅延初期化
        self._owns_pool = pool is None

    async def _get_pool(self) -> BrowserPool:
        if self._pool is None:
            self._pool = BrowserPool(size=5, max_requests_per_browser=100)
            await self._pool.start()
        return self._pool

    async def verify(
        self,
        url: str,
        parameter: str,
        payload: str,
        *,
        dialog_timeout: float = 3.0,
    ) -> XSSVerificationResult:
        """
        単一 URL/パラメータ/ペイロードの XSS 発火確認。

        Playwright があればブラウザで確認。
        なければ HTML 反射チェックにフォールバック。
        """
        if not _PLAYWRIGHT_AVAILABLE:
            return await self._verify_static(url, parameter, payload)

        pool = await self._get_pool()

        try:
            async with pool.acquire() as browser:
                page = await browser.new_page()
                return await self._run_browser_check(
                    page, url, parameter, payload, dialog_timeout
                )
        except TimeoutError as e:
            logger.warning("[BrowserPool] Acquire timeout: %s", e)
            return XSSVerificationResult(
                url=url, parameter=parameter, payload=payload,
                executed=False, error="pool_timeout",
            )

    async def verify_batch(
        self,
        tasks: List[Dict[str, str]],
        *,
        dialog_timeout: float = 3.0,
    ) -> List[XSSVerificationResult]:
        """
        複数の (url, parameter, payload) を並列検証。

        Pool サイズに収まる範囲で並列実行されるため
        Semaphore によりメモリを抑制できる。
        """
        coros = [
            self.verify(
                t["url"], t["parameter"], t["payload"],
                dialog_timeout=dialog_timeout,
            )
            for t in tasks
        ]
        return list(await asyncio.gather(*coros, return_exceptions=False))

    async def verify_stored(
        self,
        url: str,
        payload: str,
        *,
        dialog_timeout: float = 3.0,
    ) -> XSSVerificationResult:
        """
        Stored XSS 用発火確認。

        display_url をそのまま開き、保存済みペイロードが発火して
        JavaScript ダイアログが表示されるかを確認する。
        Playwright が未導入の場合は静的反射チェックにフォールバック。

        Returns:
            XSSVerificationResult: evidence に StoredXSSDetector と同じ
            `method` / `url` / `dialog_message` または `snippet` キーを含む dict。
        """
        if not _PLAYWRIGHT_AVAILABLE:
            return await self._verify_static_stored(url, payload)

        pool = await self._get_pool()
        try:
            async with pool.acquire() as browser:
                page = await browser.new_page()
                return await self._run_stored_browser_check(
                    page, url, payload, dialog_timeout
                )
        except TimeoutError as e:
            logger.warning("[BrowserPool] Acquire timeout: %s", e)
            return XSSVerificationResult(
                url=url, parameter="", payload=payload,
                executed=False, error="pool_timeout",
            )

    async def close(self) -> None:
        if self._owns_pool and self._pool is not None:
            await self._pool.stop()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _run_browser_check(
        self,
        page: Any,
        url: str,
        parameter: str,
        payload: str,
        dialog_timeout: float,
    ) -> XSSVerificationResult:
        """ブラウザページで XSS 発火を確認"""
        dialog_fired = asyncio.Event()
        dialog_message: Optional[str] = None

        async def on_dialog(dialog: Any) -> None:
            nonlocal dialog_message
            dialog_message = dialog.message
            dialog_fired.set()
            try:
                await dialog.dismiss()
            except Exception:
                pass

        page.on("dialog", on_dialog)

        # ペイロードをURLに埋め込む
        sep = "&" if "?" in url else "?"
        test_url = f"{url}{sep}{parameter}={payload}"

        try:
            await page.goto(test_url, wait_until="networkidle", timeout=10_000)
        except Exception as e:
            logger.debug("[BrowserPool] goto failed: %s", e)

        executed = False
        try:
            await asyncio.wait_for(dialog_fired.wait(), timeout=dialog_timeout)
            executed = True
        except asyncio.TimeoutError:
            pass

        try:
            await page.close()
        except Exception:
            pass

        return XSSVerificationResult(
            url=url,
            parameter=parameter,
            payload=payload,
            executed=executed,
            evidence={
                "dialog_message": dialog_message,
                "test_url": test_url,
            },
        )

    async def _run_stored_browser_check(
        self,
        page: Any,
        url: str,
        payload: str,
        dialog_timeout: float,
    ) -> XSSVerificationResult:
        """display_url をそのまま開いて Stored XSS 発火を確認"""
        dialog_fired = asyncio.Event()
        dialog_message: Optional[str] = None

        async def on_dialog(dialog: Any) -> None:
            nonlocal dialog_message
            dialog_message = dialog.message
            dialog_fired.set()
            try:
                await dialog.dismiss()
            except Exception:
                pass

        page.on("dialog", on_dialog)

        try:
            await page.goto(url, wait_until="networkidle", timeout=10_000)
        except Exception as e:
            logger.debug("[BrowserPool] goto failed: %s", e)

        executed = False
        try:
            await asyncio.wait_for(dialog_fired.wait(), timeout=dialog_timeout)
            executed = True
        except asyncio.TimeoutError:
            pass

        try:
            await page.close()
        except Exception:
            pass

        return XSSVerificationResult(
            url=url,
            parameter="",
            payload=payload,
            executed=executed,
            evidence={
                "method": "playwright_dialog",
                "url": url,
                "dialog_message": dialog_message,
            },
        )

    async def _verify_static_stored(
        self, url: str, payload: str
    ) -> XSSVerificationResult:
        """Playwright がない場合の Stored XSS 静的反射チェック"""
        try:
            import urllib.request
            with urllib.request.urlopen(url, timeout=5) as resp:
                body = resp.read().decode(errors="replace")
            key = payload.replace('"', "").replace("'", "")[:20]
            idx = body.lower().find(key.lower())
            executed = idx != -1
            snippet = ""
            if executed:
                start = max(0, idx - 50)
                end = min(len(body), idx + len(key) + 50)
                snippet = body[start:end]
            return XSSVerificationResult(
                url=url, parameter="", payload=payload,
                executed=executed,
                evidence={
                    "method": "static_reflection_check",
                    "url": url,
                    "snippet": snippet,
                },
            )
        except Exception as e:
            return XSSVerificationResult(
                url=url, parameter="", payload=payload,
                executed=False, error=str(e),
            )

    async def _verify_static(
        self, url: str, parameter: str, payload: str
    ) -> XSSVerificationResult:
        """Playwright がない場合の静的反射チェック"""
        try:
            import urllib.request
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{parameter}={payload}"
            with urllib.request.urlopen(test_url, timeout=5) as resp:
                body = resp.read().decode(errors="replace")
            key = payload[:20].lower()
            executed = key in body.lower()
            return XSSVerificationResult(
                url=url, parameter=parameter, payload=payload,
                executed=executed,
                evidence={"method": "static_reflection", "test_url": test_url},
            )
        except Exception as e:
            return XSSVerificationResult(
                url=url, parameter=parameter, payload=payload,
                executed=False, error=str(e),
            )
