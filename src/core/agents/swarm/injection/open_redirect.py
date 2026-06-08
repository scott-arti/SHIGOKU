"""
OpenRedirectSpecialist: オープンリダイレクト脆弱性検査

URL パラメータのリダイレクト機能に対する攻撃を実行する。
"""

import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.core.infra.network_client import AsyncNetworkClient
import uuid
import asyncio
from playwright.async_api import async_playwright

logger = logging.getLogger(__name__)


class OpenRedirectSpecialist(Specialist):
    """
    Open Redirect Vulnerability Specialist
    
    リダイレクトパラメータを悪用したオープンリダイレクト攻撃を検出する。
    """
    
    name = "OpenRedirectSpecialist"
    description = "Detects Open Redirect vulnerabilities via URL parameter manipulation"
    timeout_seconds = 180
    is_aggressive = False  # リダイレクトは比較的安全
    
    # 攻撃ペイロードテンプレート（{uuid} を置換して使用）
    REDIRECT_PAYLOAD_TEMPLATES = [
        "https://shigoku-verify-{uuid}.evil.com/",
        "//shigoku-verify-{uuid}.evil.com/",
        "/\\shigoku-verify-{uuid}.evil.com/",
        "///shigoku-verify-{uuid}.evil.com/",
        "https:shigoku-verify-{uuid}.evil.com/",
        "javascript:location.href='http://shigoku-verify-{uuid}.evil.com/'",
    ]
    
    # リダイレクトパラメータ名のパターン
    REDIRECT_PARAM_NAMES = [
        "redirect", "redir", "url", "next", "return", "returnto",
        "return_to", "goto", "dest", "destination", "target", "page",
        "continue", "navigation", "nav", "link", "uri", "location"
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        # max_turns の初期化（ThoughtLoop 用）
        self.max_turns = 8
        
        # クライアント初期化 (ProxyManager 連携)
        proxy_manager = None
        try:
            from src.core.infra.proxy_manager import get_proxy_manager
            proxy_manager = get_proxy_manager()
        except (ImportError, Exception) as e:
            logger.debug("Proxy manager initialization failed: %s", e)

        self._client = AsyncNetworkClient(proxy_manager=proxy_manager)

    async def close(self):
        """リソース解放"""
        if self._client and hasattr(self._client, "close"):
            await self._client.close()

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        """
        Specialist としてのエントリーポイント
        
        Args:
            task: タスク情報
            quick_mode: True の場合、軽量モードで実行（ターン数制限あり）
        """
        # quick_mode の場合、ターン数を制限
        original_max_turns = self.max_turns
        if quick_mode:
            self.max_turns = 8  # 3 ターンでは不十分なため
        
        try:
            findings = await self._execute_redirect_internal(task)
            return findings
        finally:
            self.max_turns = original_max_turns

    async def _execute_redirect_internal(self, task: Task) -> List[Finding]:
        """
        タスクを実行し、オープンリダイレクト脆弱性を検出する

        Args:
            task: ターゲット情報を含むタスク

        Returns:
            List[Finding]: 検出された脆弱性リスト
        """
        findings = []
        target_url = task.target
        cookies_header = ""
        if isinstance(task.params, dict):
            auth = task.params.get("_auth", {})
            if isinstance(auth, dict):
                cookies_header = str(auth.get("cookies", "") or "")
        
        # URL パース
        parsed = urlparse(target_url)
        if not parsed.query:
            logger.debug("No query parameters in %s", target_url)
            return []
        
        params = parse_qs(parsed.query)
        
        # リダイレクトパラメータを特定
        redirect_params = self._find_redirect_params(params)
        
        if not redirect_params:
            logger.debug("No redirect parameters found in %s", target_url)
            return []
        
        # 各リダイレクトパラメータに対して攻撃を実行
        for param_name in redirect_params:
            result = await self._test_redirect_param(target_url, param_name, cookies_header=cookies_header)
            
            if result.get("vulnerable"):
                findings.append(Finding(
                    vuln_type=VulnType.OPEN_REDIRECT,
                    severity=Severity.MEDIUM,
                    title=f"Open Redirect in parameter '{param_name}'",
                    description=f"Parameter '{param_name}' is vulnerable to open redirect attacks. "
                               f"Attacker can redirect users to arbitrary external URLs.",
                    target_url=target_url,
                    evidence=Evidence(
                        request_method="GET",
                        request_url=result.get("exploit_url", ""),
                        response_status=result.get("response_status", 0),
                        response_headers=result.get("response_headers", {}),
                        response_body=f"Redirect location: {result.get('redirect_location', '')}",
                    ),
                    source_agent=self.name,
                    confidence=0.85,
                    tags=["open_redirect", "url_manipulation"],
                    additional_info={
                        "parameter": param_name,
                        "payload": result.get("payload", ""),
                        "payloads_used": [result.get("payload", "")] if result.get("payload") else [],
                        "tested_params": [param_name],
                        "redirect_to": result.get("redirect_location", ""),
                    }
                ))
        
        return findings

    def _find_redirect_params(self, params: Dict[str, List[str]]) -> List[str]:
        """
        リダイレクト関連のパラメータ名を特定する
        
        Args:
            params: URL パラメータの辞書
        
        Returns:
            リダイレクトパラメータ名のリスト
        """
        redirect_params = []
        
        for param_name in params.keys():
            param_lower = param_name.lower()
            
            # パラメータ名がリダイレクト関連かチェック
            if any(pattern in param_lower for pattern in self.REDIRECT_PARAM_NAMES):
                redirect_params.append(param_name)
                continue
            
            # パラメータ値が URL かもチェック
            values = params[param_name]
            for value in values:
                if value.startswith(("http://", "https://", "//", "/")):
                    redirect_params.append(param_name)
                    break
        
        return list(set(redirect_params))

    async def _test_redirect_param(
        self, 
        target_url: str, 
        param_name: str,
        cookies_header: str = "",
    ) -> Dict[str, Any]:
        """
        特定のパラメータに対してハイブリッド（反射＋Playwright）テストを実行
        """
        result = {
            "vulnerable": False,
            "payload": "",
            "redirect_location": "",
            "exploit_url": "",
            "response_status": 0,
            "response_headers": {},
            "method": "HYBRID", # Reflection + Browser
        }
        
        parsed = urlparse(target_url)
        # 既存のパラメータを保持しつつターゲットのみ置換
        base_params = parse_qs(parsed.query)
        
        for template in self.REDIRECT_PAYLOAD_TEMPLATES:
            test_id = str(uuid.uuid4())[:8]
            verify_host = f"shigoku-verify-{test_id}.evil.com"
            payload = template.format(uuid=test_id)
            
            # ペイロードを注入
            current_params = base_params.copy()
            current_params[param_name] = [payload]
            new_query = urlencode(current_params, doseq=True)
            exploit_url = urlunparse(parsed._replace(query=new_query))
            
            try:
                # --- Phase 1: Fast Reflection Check ---
                request_headers = {"Cookie": cookies_header} if cookies_header else None
                response = await self._client.request(
                    method="GET",
                    url=exploit_url,
                    headers=request_headers,
                    allow_redirects=False,
                    timeout=30,
                )

                status = int(getattr(response, "status", 0) or 0)
                headers = dict(getattr(response, "headers", {}) or {})
                body = str(getattr(response, "body", "") or "")

                # 反射確認: Locationヘッダー、またはレスポンスボディ内
                location = str(headers.get("Location", headers.get("location", "")) or "")
                reflection_found = (verify_host in location.lower()) or (verify_host in body.lower())
                
                if not reflection_found and status not in [301, 302, 303, 307, 308]:
                    # 何も反射せず、3xxでもない場合はスキップして高速化
                    continue
                
                logger.debug(f"Phase 1 potential find: {verify_host} reflected or status {status}")

                # --- Phase 2: Playwright Dynamic Hook Confirmation ---
                # 反射、または3xxレスポンスの場合はブラウザで最終的な挙動を確認
                is_confirmed = await self._verify_with_playwright(
                    exploit_url,
                    verify_host,
                    cookies_header=cookies_header,
                )

                # Playwright で取り切れないケース向けフォールバック
                if not is_confirmed and (
                    (status in [301, 302, 303, 307, 308] and verify_host in location.lower())
                    or reflection_found
                ):
                    is_confirmed = True
                
                if is_confirmed:
                    result.update({
                        "vulnerable": True,
                        "payload": payload,
                        "redirect_location": location or verify_host,
                        "exploit_url": exploit_url,
                        "response_status": status,
                        "response_headers": headers,
                    })
                    logger.info("[!!!] Open Redirect CONFIRMED via Playwright: %s -> %s", exploit_url, verify_host)
                    break
                
            except Exception as e:
                logger.debug("Error testing payload %s: %s", payload, e)
                continue
        
        return result

    async def _verify_with_playwright(self, url: str, verify_host: str, cookies_header: str = "") -> bool:
        """
        Playwright を使用して、実際にリダイレクトが発生するかイベントレベルで確認する
        """
        logger.debug("Starting Playwright verification for: %s", url)
        is_redirected = False
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                # Context 設定 (Cookie等が必要な場合はここに追加)
                # 注: Specialist.execute の上位で BaseManagerAgent._execute_tool が
                #     params に cookies を入れているはずだが、Playwrightのセッションにも必要
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Shigoku/1.0"
                )

                if cookies_header:
                    cookie_pairs = [chunk.strip() for chunk in cookies_header.split(";") if chunk.strip()]
                    if cookie_pairs:
                        parsed_target = urlparse(url)
                        cookie_items = []
                        for pair in cookie_pairs:
                            if "=" not in pair:
                                continue
                            name, value = pair.split("=", 1)
                            cookie_items.append({
                                "name": name.strip(),
                                "value": value.strip(),
                                "domain": parsed_target.hostname or "",
                                "path": "/",
                            })
                        if cookie_items:
                            await context.add_cookies(cookie_items)
                
                page = await context.new_page()
                
                # イベントリスナー: リクエストまたはナビゲーションで verify_host を検知
                def handle_request(request):
                    nonlocal is_redirected
                    if verify_host in request.url:
                        is_redirected = True
                
                page.on("request", handle_request)
                
                try:
                    # ページの読み込みと待機 (リダイレクトやJS実行を待つ)
                    await page.goto(url, wait_until="networkidle", timeout=15000)
                    # 少し待機して遅延リダイレクトに対応
                    await asyncio.sleep(2)
                except Exception as e:
                    logger.debug("Playwright navigation error (expected if redirected): %s", e)

                await browser.close()
                
        except Exception as e:
            logger.warning("Playwright verification failed: %s", e)
            
        return is_redirected

    def _is_external_redirect(self, location: str, payload: str) -> bool:
        """
        外部ドメインへのリダイレクトか判定する
        
        Args:
            location: Location ヘッダーの値
            payload: 使用したペイロード
        
        Returns:
            外部リダイレクトなら True
        """
        # プロトコル相対 URL (//evil.com)
        if location.startswith("//"):
            return True
        
        # 絶対 URL で外部ドメイン
        if location.startswith(("http://", "https://")):
            try:
                loc_parsed = urlparse(location)
                # 一般的な信頼できるドメインは除外
                trusted_domains = [
                    "google.com", "www.google.com",
                    "example.com", "www.example.com",
                ]
                if loc_parsed.netloc.lower() not in trusted_domains:
                    return True
            except Exception:
                pass
        
        # ペイロードに外部ドメインが含まれているか
        if "evil.com" in payload.lower() or "attacker.com" in payload.lower():
            return True
        
        return False
