"""
Open Redirect Tester - オープンリダイレクトテスター

リダイレクトパラメータ検証
"""

import logging
from typing import List, Dict, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, urlencode

logger = logging.getLogger(__name__)


@dataclass
class OpenRedirectResult:
    """オープンリダイレクト検出結果"""
    url: str
    parameter: str
    payload: str
    vulnerable: bool = False
    redirect_location: str = ""
    severity: str = "medium"


class OpenRedirectTester:
    """
    オープンリダイレクトテスター
    
    機能:
    - リダイレクトパラメータ検出
    - 各種バイパステクニック
    - 外部サイトへのリダイレクト検証
    """
    
    # よくあるリダイレクトパラメータ
    COMMON_PARAMS = [
        "url", "redirect", "redirect_url", "redirect_uri",
        "return", "returnTo", "return_url", "return_to",
        "next", "next_url", "goto", "go", "dest", "destination",
        "rurl", "target", "link", "continue", "out", "ref",
    ]
    
    # テストペイロード
    TEST_PAYLOADS = [
        # 外部サイト
        "https://evil.com",
        "//evil.com",
        
        # プロトコル相対
        "///evil.com",
        "////evil.com",
        
        # バックスラッシュ
        "\\\\evil.com",
        "/\\evil.com",
        
        # ドメイン偽装
        "https://evil.com/target.com",
        "https://target.com.evil.com",
        "https://target.com@evil.com",
        
        # エンコード
        "https:%2f%2fevil.com",
        "https://evil.com%2f",
        
        # データURL
        "data:text/html,<script>alert(1)</script>",
        
        # JavaScript
        "javascript:alert(1)",
    ]
    
    def __init__(self):
        self.results: List[OpenRedirectResult] = []
    
    def test(
        self,
        url: str,
        parameters: List[str] = None
    ) -> List[OpenRedirectResult]:
        """
        オープンリダイレクトテスト
        
        Args:
            url: テスト対象URL
            parameters: テスト対象パラメータ（Noneなら自動検出）
        """
        if parameters is None:
            parameters = self._detect_redirect_params(url)
        
        results = []
        
        for param in parameters:
            for payload in self.TEST_PAYLOADS:
                result = self._test_payload(url, param, payload)
                if result:
                    results.append(result)
                    self.results.append(result)
        
        return results
    
    def _detect_redirect_params(self, url: str) -> List[str]:
        """URLからリダイレクトパラメータを検出"""
        parsed = urlparse(url)
        params_in_url = []
        
        # クエリパラメータから検出
        if parsed.query:
            for part in parsed.query.split("&"):
                if "=" in part:
                    param = part.split("=")[0]
                    if param.lower() in [p.lower() for p in self.COMMON_PARAMS]:
                        params_in_url.append(param)
        
        # 検出できなければよくあるパラメータを使用
        if not params_in_url:
            params_in_url = self.COMMON_PARAMS[:5]
        
        return params_in_url
    
    def _test_payload(
        self,
        url: str,
        parameter: str,
        payload: str
    ) -> Optional[OpenRedirectResult]:
        """
        ペイロードテスト（プレースホルダー）
        """
        logger.info("Testing redirect: %s=%s on %s", parameter, payload[:20], url)
        
        # プレースホルダー
        # response = requests.get(url, params={parameter: payload}, allow_redirects=False)
        # location = response.headers.get("Location", "")
        # 
        # if self._is_vulnerable(payload, location):
        #     return OpenRedirectResult(...)
        
        return None
    
    def _is_vulnerable(self, payload: str, location: str) -> bool:
        """脆弱性判定"""
        if not location:
            return False
        
        # 外部サイトへのリダイレクト
        if "evil.com" in location:
            return True
        
        # JavaScriptプロトコル
        if location.lower().startswith("javascript:"):
            return True
        
        return False
    
    def get_vulnerable(self) -> List[OpenRedirectResult]:
        """脆弱と判定されたもの"""
        return [r for r in self.results if r.vulnerable]
    
    def get_summary(self) -> Dict:
        """サマリー"""
        return {
            "total_tests": len(self.results),
            "vulnerable": len(self.get_vulnerable()),
        }
    
    def get_summary_for_ai(self) -> str:
        """AI向けサマリー"""
        summary = self.get_summary()
        return (
            f"Open Redirect Test: {summary['total_tests']} tests\n"
            f"Vulnerable: {summary['vulnerable']}"
        )


def create_open_redirect_tester() -> OpenRedirectTester:
    """OpenRedirectTester作成ヘルパー"""
    return OpenRedirectTester()
