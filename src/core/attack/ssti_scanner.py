"""
SSTI Scanner - Server-Side Template Injection スキャナー

テンプレートエンジンの不適切な入力処理による
SSTI脆弱性を検出する非破壊的スキャナー。

⚠️ 注意: 検出のみ、Exploitation は行わない
"""

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Optional

import httpx

from src.core.utils.payload_encoder import PayloadEncoder

logger = logging.getLogger(__name__)


class TemplateEngine(Enum):
    """テンプレートエンジン種別"""
    UNKNOWN = "unknown"
    JINJA2 = "jinja2"
    THYMELEAF = "thymeleaf"
    ERB = "erb"
    TWIG = "twig"
    FREEMARKER = "freemarker"
    SMARTY = "smarty"
    VELOCITY = "velocity"
    MAKO = "mako"
    BLADE = "blade"
    HANDLEBARS = "handlebars"
    MUSTACHE = "mustache"
    PEBBLE = "pebble"


@dataclass
class SSTIResult:
    """SSTI検出結果"""
    url: str
    parameter: str
    vulnerable: bool = False
    engine: TemplateEngine = TemplateEngine.UNKNOWN
    payload: str = ""
    expected: str = ""
    evidence: str = ""
    confidence: float = 0.0
    severity: str = "critical"


class SSTIScanner:
    """
    SSTI スキャナー
    
    機能:
    - テンプレートエンジン別 Payload マップ
    - ユニークマーカー方式（誤検知削減）
    - 段階的テストアプローチ
    - Fingerprinter 連携
    
    ⚠️ 検出のみ、破壊的ペイロードは使用しない
    """
    
    # テンプレートエンジン別ペイロード
    # 算術演算のみ使用（安全・非破壊）
    PAYLOADS: Dict[str, List[str]] = {
        "universal": [
            "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", 
            "${{7*7}}", "{7*7}", "{{= 7*7}}"
        ],
        "jinja2": [
            "{{7*7}}", "{{7*'7'}}"
        ],
        "thymeleaf": [
            "${7*7}", "[[${7*7}]]"
        ],
        "erb": [
            "<%= 7*7 %>", "<%= 7 * 7 %>"
        ],
        "twig": [
            "{{7*7}}", "{{7*'7'}}"
        ],
        "freemarker": [
            "${7*7}", "<#assign x=7*7>${x}"
        ],
        "smarty": [
            "{7*7}", "{math equation=\"7*7\"}"
        ],
        "velocity": [
            "#set($x=7*7)$x",
        ],
        "mako": [
            "${7*7}", "${str(7*7)}"
        ],
        "blade": [
            "{{ 7*7 }}", "{!! 7*7 !!}"
        ],
        "handlebars": [
            "{{7*7}}"
        ],
        "mustache": [
            "{{7*7}}"
        ],
        "pebble": [
            "{{ 7*7 }}"
        ],
    }
    
    # 確認ペア（誤検知削減用）
    CONFIRMATION_PAIRS = [
        (7, 7, 49),   # 7*7 = 49
        (8, 6, 48),   # 8*6 = 48
    ]
    
    # フレームワーク/言語 → エンジン推測マッピング
    FRAMEWORK_TO_ENGINE: Dict[str, List[str]] = {
        "Django": ["jinja2"],
        "Flask": ["jinja2"],
        "Rails": ["erb"],
        "Laravel": ["blade"],
        "Symfony": ["twig"],
        "Spring": ["thymeleaf", "freemarker"],
        "Express": ["handlebars", "mustache"],
    }
    
    LANG_TO_ENGINE: Dict[str, List[str]] = {
        "Python": ["jinja2", "mako"],
        "Java": ["thymeleaf", "freemarker", "velocity", "pebble"],
        "PHP": ["twig", "smarty", "blade"],
        "Ruby": ["erb"],
    }
    
    def __init__(
        self,
        timeout: float = 10.0,
        delay: float = 0.5,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        auth_headers: Optional[Dict[str, str]] = None,
    ):
        """
        Args:
            timeout: HTTPリクエストタイムアウト（秒）
            delay: リクエスト間の遅延（秒）
            user_agent: User-Agent ヘッダー
            auth_headers: 認証ヘッダー（Cookie, Authorization 等）
        """
        self.timeout = timeout
        self.delay = delay
        self.user_agent = user_agent
        self.auth_headers: Dict[str, str] = auth_headers or {}
        self.results: List[SSTIResult] = []
        self.encoder = PayloadEncoder()
        self._client: Optional[httpx.Client] = None
    
    def _get_client(self) -> httpx.Client:
        """HTTPクライアント取得（遅延初期化）"""
        if self._client is None:
            base_headers: Dict[str, str] = {"User-Agent": self.user_agent}
            base_headers.update(self.auth_headers)
            self._client = httpx.Client(
                timeout=self.timeout,
                headers=base_headers,
                follow_redirects=True,
            )
        return self._client
    
    def close(self):
        """クライアントのクリーンアップ"""
        if self._client:
            self._client.close()
            self._client = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def scan(
        self,
        url: str,
        parameters: List[str],
        method: str = "GET",
        engines: Optional[List[str]] = None,
        use_encoding: bool = False,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[SSTIResult]:
        """
        SSTIスキャン実行
        
        Args:
            url: テスト対象URL
            parameters: テスト対象パラメータ
            method: HTTPメソッド
            engines: テスト対象エンジン（Noneでuniversal）
            use_encoding: ペイロードエンコードを使用するか
            auth_headers: 認証ヘッダー（Cookie, Authorization 等）
        
        Returns:
            検出結果リスト
        """
        if auth_headers:
            self.auth_headers.update(auth_headers)
            self._client = None
        results = []
        target_engines = engines or ["universal"]
        
        logger.info("Starting SSTI scan on %s with %d parameters", url, len(parameters))
        
        for param in parameters:
            result = self._test_parameter(
                url, param, method, target_engines, use_encoding, self.auth_headers
            )
            if result and result.vulnerable:
                results.append(result)
                self.results.append(result)
                logger.warning(
                    "SSTI detected: %s param=%s engine=%s",
                    url, param, result.engine.value
                )
        
        return results
    
    def _test_parameter(
        self,
        url: str,
        parameter: str,
        method: str,
        engines: List[str],
        use_encoding: bool,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> Optional[SSTIResult]:
        """
        単一パラメータのSSTIテスト（段階的アプローチ）
        """
        _ = auth_headers  # _get_client() 経由でインスタンス共通ヘッダーとして適用済み
        # Step 1: Polyglot でまず検出を試みる
        for engine in engines:
            payloads = self.PAYLOADS.get(engine, self.PAYLOADS["universal"])
            
            for payload_template in payloads:
                # ユニークマーカー生成
                marker = secrets.token_hex(4)
                
                # 最初の計算式: 7*7=49
                payload = self._build_payload(payload_template, 7, 7, marker)
                expected = f"49{marker}"
                
                # エンコードが有効な場合、亜種も生成
                test_payloads = [payload]
                if use_encoding:
                    test_payloads.append(self.encoder.url_encode(payload))
                    test_payloads.append(self.encoder.double_url_encode(payload))
                
                for test_payload in test_payloads:
                    response = self._send_request(url, parameter, test_payload, method)
                    
                    if response and expected in response.text:
                        # Step 2: 確認ペアテスト
                        if self._confirm_ssti(url, parameter, payload_template, method, marker):
                            detected_engine = self._detect_engine(engine, payload_template)
                            
                            return SSTIResult(
                                url=url,
                                parameter=parameter,
                                vulnerable=True,
                                engine=detected_engine,
                                payload=payload,
                                expected=expected,
                                evidence=response.text[:500],
                                confidence=0.95,
                            )
                    
                    # 遅延挿入
                    time.sleep(self.delay)
        
        return None
    
    def _build_payload(
        self, 
        template: str, 
        a: int, 
        b: int, 
        marker: str
    ) -> str:
        """ペイロード構築（数値とマーカーを挿入）"""
        # テンプレート内の 7*7 を a*b に置換
        payload = template.replace("7*7", f"{a}*{b}")
        payload = payload.replace("7*'7'", f"{a}*'{b}'")
        payload = payload.replace("7 * 7", f"{a} * {b}")
        payload = payload.replace("7,2", f"{a},{b}")
        return f"{payload}{marker}"
    
    def _confirm_ssti(
        self,
        url: str,
        parameter: str,
        payload_template: str,
        method: str,
        marker: str,
    ) -> bool:
        """
        確認ペアテスト
        
        異なる計算式（8*6=48）でも正しく計算されるか確認。
        これにより、偶然の一致（レスポンスに49が含まれるだけ）を除外。
        """
        # 8*6=48 で確認
        payload = self._build_payload(payload_template, 8, 6, marker)
        expected = f"48{marker}"
        
        response = self._send_request(url, parameter, payload, method)
        time.sleep(self.delay)
        
        if response and expected in response.text:
            logger.debug("SSTI confirmed with secondary payload")
            return True
        
        return False
    
    def _detect_engine(self, hint: str, payload_template: str) -> TemplateEngine:
        """エンジン特定"""
        if hint != "universal" and hint in [e.value for e in TemplateEngine]:
            return TemplateEngine(hint)
        
        # ペイロード形式からエンジンを推測
        if "{{" in payload_template and "}}" in payload_template:
            if "*'" in payload_template:
                return TemplateEngine.JINJA2
            return TemplateEngine.JINJA2  # Jinja2/Twig の可能性
        elif "${" in payload_template:
            return TemplateEngine.FREEMARKER
        elif "<%=" in payload_template:
            return TemplateEngine.ERB
        elif "{7*7}" in payload_template or "{math" in payload_template:
            return TemplateEngine.SMARTY
        elif "#set" in payload_template:
            return TemplateEngine.VELOCITY
        
        return TemplateEngine.UNKNOWN
    
    def _send_request(
        self,
        url: str,
        parameter: str,
        payload: str,
        method: str,
    ) -> Optional[httpx.Response]:
        """HTTPリクエスト送信"""
        client = self._get_client()
        
        try:
            m = method.upper()
            if m == "GET":
                response = client.get(url, params={parameter: payload})
            elif m == "POST":
                response = client.post(url, data={parameter: payload})
            elif m == "JSON":
                response = client.post(url, json={parameter: payload})
            else:
                logger.warning("Unsupported method: %s", method)
                return None
            
            return response
        
        except httpx.TimeoutException:
            logger.debug("Request timeout for %s", url)
            return None
        except httpx.RequestError as e:
            logger.debug("Request error for %s: %s", url, e)
            return None
    
    def scan_with_fingerprint(
        self,
        url: str,
        parameters: List[str],
        tech_stack: List[str],
        method: str = "GET",
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[SSTIResult]:
        """
        Fingerprinter結果を利用したスキャン
        
        Args:
            url: テスト対象URL
            parameters: テスト対象パラメータ
            tech_stack: 検出された技術スタック（例: ["Django", "Python"]）
            method: HTTPメソッド
            auth_headers: 認証ヘッダー（Cookie, Authorization 等）
        
        Returns:
            検出結果リスト
        """
        engines = self._get_engines_from_stack(tech_stack)
        
        if not engines:
            engines = ["universal"]
        
        logger.info("Using engines based on tech stack: %s", engines)
        return self.scan(url, parameters, method, engines, auth_headers=auth_headers)

    async def scan_async(
        self,
        url: str,
        parameters: List[str],
        method: str = "GET",
        engines: Optional[List[str]] = None,
        use_encoding: bool = False,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[SSTIResult]:
        """非同期 SSTIスキャン（asyncio.to_thread でブロッキング回避）"""
        return await asyncio.to_thread(
            self.scan, url, parameters, method, engines, use_encoding, auth_headers
        )

    async def scan_with_fingerprint_async(
        self,
        url: str,
        parameters: List[str],
        tech_stack: List[str],
        method: str = "GET",
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[SSTIResult]:
        """非同期 Fingerprinter連携スキャン"""
        return await asyncio.to_thread(
            self.scan_with_fingerprint, url, parameters, tech_stack, method, auth_headers
        )
    
    def _get_engines_from_stack(self, tech_stack: List[str]) -> List[str]:
        """技術スタックからエンジンを推測"""
        engines = set()
        
        for tech in tech_stack:
            # フレームワークマッピング
            if tech in self.FRAMEWORK_TO_ENGINE:
                engines.update(self.FRAMEWORK_TO_ENGINE[tech])
            # 言語マッピング
            if tech in self.LANG_TO_ENGINE:
                engines.update(self.LANG_TO_ENGINE[tech])
        
        return list(engines) if engines else []
    
    def get_results(self) -> List[SSTIResult]:
        """検出結果取得"""
        return self.results
    
    def get_vulnerable_count(self) -> int:
        """脆弱性検出数"""
        return len([r for r in self.results if r.vulnerable])
    
    def get_summary(self) -> Dict:
        """サマリー"""
        by_engine = {}
        for r in self.results:
            if r.vulnerable:
                engine_name = r.engine.value
                by_engine.setdefault(engine_name, 0)
                by_engine[engine_name] += 1
        
        return {
            "total_tests": len(self.results),
            "vulnerable": self.get_vulnerable_count(),
            "by_engine": by_engine,
        }
    
    def get_summary_for_ai(self) -> str:
        """AI向けサマリー"""
        summary = self.get_summary()
        return (
            f"SSTI Scan: {summary['total_tests']} parameters tested\n"
            f"Vulnerable: {summary['vulnerable']}\n"
            f"Engines: {summary['by_engine']}"
        )


def create_ssti_scanner(
    timeout: float = 10.0,
    delay: float = 0.5,
) -> SSTIScanner:
    """SSTIScanner作成ヘルパー"""
    return SSTIScanner(timeout=timeout, delay=delay)
