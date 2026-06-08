"""
CRLF Tester - CRLFインジェクション/ヘッダーインジェクションテスター

レスポンス分割検出
"""

import http.client
import logging
import ssl
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import quote, urlparse

logger = logging.getLogger(__name__)


@dataclass
class CRLFResult:
    """CRLF検出結果"""
    url: str
    parameter: str
    payload: str
    vulnerable: bool = False
    injected_header: str = ""
    severity: str = "medium"


class CRLFTester:
    """
    CRLFインジェクションテスター

    機能:
    - ヘッダーインジェクション検出（http.client で生CRLF送信）
    - レスポンス分割検出
    - 各種エンコードバイパス
    """

    TIMEOUT = 10

    # CRLFペイロード
    # 注意: payload は URL-encoded 文字列として渡す。
    #       _test_payload() は urlencode を使わず quote(param)=payload で直結する（B9）。
    PAYLOADS = [
        # 基本
        "%0d%0aX-Injected: shigoku",
        "%0aX-Injected: shigoku",
        "%0dX-Injected: shigoku",

        # ダブルエンコード
        "%250d%250aX-Injected: shigoku",

        # Unicode
        "%E5%98%8A%E5%98%8DX-Injected: shigoku",

        # 改行バリエーション（リテラル文字列）
        "\\r\\nX-Injected: shigoku",
        "\\nX-Injected: shigoku",

        # Set-Cookie注入
        "%0d%0aSet-Cookie: shigoku=test",

        # Location 注入（B1: マーカー "shigoku" 付き）
        "%0d%0aLocation: https://shigoku.evil.com",

        # Content-Type 注入（B1: XSS誘発）
        "%0d%0aContent-Type: text/html; charset=shigoku",

        # Link ヘッダー注入（B1: キャッシュポイズニング）
        "%0d%0aLink: <https://shigoku.evil.com>; rel=preload",
    ]

    def __init__(self, auth_headers: Optional[Dict] = None):
        self.auth_headers: Dict[str, str] = dict(auth_headers or {})
        self.results: List[CRLFResult] = []

    def test(
        self,
        url: str,
        parameters: List[str],
    ) -> List[CRLFResult]:
        """
        CRLFインジェクションテスト

        Args:
            url: テスト対象URL
            parameters: テスト対象パラメータ名リスト
        """
        results = []
        for param in parameters:
            for payload in self.PAYLOADS:
                result = self._test_payload(url, param, payload)
                if result:
                    results.append(result)
                    self.results.append(result)
        return results

    def _test_payload(
        self,
        url: str,
        parameter: str,
        payload: str,
    ) -> Optional[CRLFResult]:
        """
        http.client で生CRLF送信し、レスポンスヘッダーを検査する。

        httpx は httpcore レイヤーで \\r\\n を除去するため使用しない（B2）。

        B9: payload は既にURL-encoded文字列なので urlencode は使わず直結する。
        B10: conn.close() を finally で確実に呼ぶ（接続リーク防止）。
        B11: resp.read() でボディを消費する（ResponseNotReady 防止）。
        B12: Set-Cookie 複数値を結合して _is_vulnerable() に渡す。
        B14: ssl / http.client はファイル先頭でインポート済み。
        """
        logger.info("Testing CRLF: %s=%s on %s", parameter, payload[:30], url)
        parsed = urlparse(url)
        # B9: quote(parameter) で param 名だけエンコード、payload はそのまま結合。
        # Python 3.12 の http.client._validate_path はリテラルスペース（U+0020）を
        # InvalidURL として拒否するため、payload 内のスペースを %20 に変換する。
        safe_payload = payload.replace(" ", "%20")
        path = f"{parsed.path or '/'}?{quote(parameter, safe='')}={safe_payload}"
        req_headers = dict(self.auth_headers)
        conn: Optional[http.client.HTTPConnection] = None
        try:
            if parsed.scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(
                    parsed.netloc, timeout=self.TIMEOUT, context=ctx
                )
            else:
                conn = http.client.HTTPConnection(
                    parsed.netloc, timeout=self.TIMEOUT
                )
            conn.request("GET", path, headers=req_headers)
            resp = conn.getresponse()
            _ = resp.read()  # B11: ボディ消費
            # B12: Set-Cookie 複数値を全て結合（dict変換では後の値で上書きされる）
            multi: defaultdict = defaultdict(list)
            for k, v in resp.getheaders():
                multi[k.lower()].append(v)
            resp_headers = {
                k: v[0] if len(v) == 1 else " ".join(v)
                for k, v in multi.items()
            }
        except Exception:
            return None
        finally:
            if conn:  # B10: 例外発生時も確実にクローズ
                conn.close()

        vulnerable, injected_header = self._is_vulnerable(resp_headers)
        if vulnerable:
            return CRLFResult(
                url=url,
                parameter=parameter,
                payload=payload,
                vulnerable=True,
                injected_header=injected_header,
                severity="medium",
            )
        return None

    def _is_vulnerable(self, headers: Dict) -> tuple:
        """
        脆弱性判定。注入マーカー "shigoku" または注入ヘッダー名の存在を確認する。

        Args:
            headers: lowercase 正規化済み・Set-Cookie は複数値結合済みの dict
                     （_test_payload() で前処理済み）

        Returns:
            (vulnerable: bool, injected_header_name: str)
        """
        # X-Injected: shigoku
        if "x-injected" in headers:
            return True, "X-Injected"

        # Set-Cookie 注入（B12: 複数値は _test_payload で結合済み）
        if "shigoku" in str(headers.get("set-cookie", "")):
            return True, "Set-Cookie"

        # Location 注入（B1: 最も重要なCRLF攻撃ベクター）
        if "shigoku" in str(headers.get("location", "")):
            return True, "Location"

        # Content-Type 注入（B1: XSS誘発に使われる）
        if "shigoku" in str(headers.get("content-type", "")):
            return True, "Content-Type"

        # Link ヘッダー注入（B1: キャッシュポイズニング）
        if "shigoku" in str(headers.get("link", "")):
            return True, "Link"

        return False, ""

    async def scan_async(self, url: str, parameters: List[str]) -> List[CRLFResult]:
        """
        非同期ラッパー。auth_headers は __init__ で設定済み（B8: 引数なし）。
        """
        import asyncio
        return await asyncio.to_thread(self.test, url, parameters)

    def get_vulnerable(self) -> List[CRLFResult]:
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
            f"CRLF Test: {summary['total_tests']} tests\n"
            f"Vulnerable: {summary['vulnerable']}"
        )


def create_crlf_tester(auth_headers: Optional[Dict] = None) -> CRLFTester:
    """CRLFTester作成ヘルパー（既存呼び出しと互換: auth_headers=None がデフォルト）"""
    return CRLFTester(auth_headers=auth_headers)
