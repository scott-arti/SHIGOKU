"""
HostHeaderInjection: Host Header Injection検出モジュール

Hostヘッダー書き換えによるキャッシュポイズニングや
パスワードリセットリンク改ざんを検出する。

Phase 3機能: config/features.yaml でオン/オフ可能
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import requests

from src.core.models.finding import Finding, Severity, VulnType, Evidence
from src.core.config.feature_config import get_feature_config

logger = logging.getLogger(__name__)


@dataclass
class HostHeaderResult:
    """検出結果"""
    vulnerable: bool
    injection_type: str = ""
    payload: str = ""
    response_status: int = 0
    evidence: str = ""
    confidence: float = 0.0


class HostHeaderInjectionTester:
    """
    Host Header Injection検出
    
    検出パターン:
    1. X-Forwarded-Host によるリダイレクト
    2. Host ヘッダー書き換えによるキャッシュポイズニング
    3. パスワードリセットリンクの改ざん
    
    使用例:
        tester = HostHeaderInjectionTester()
        findings = tester.test("https://example.com/reset-password")
    """

    # テストペイロード
    PAYLOADS = [
        # 基本的なHostヘッダー書き換え
        {"Host": "evil.com"},
        {"Host": "evil.com", "X-Forwarded-Host": "evil.com"},
        {"X-Forwarded-Host": "evil.com"},
        {"X-Host": "evil.com"},
        {"X-Forwarded-Server": "evil.com"},
        
        # ポート付き
        {"Host": "evil.com:80"},
        {"Host": "evil.com:443"},
        
        # サブドメイン偽装
        {"Host": "target.evil.com"},
        
        # キャッシュポイズニング用
        {"Host": "evil.com", "X-Original-URL": "/admin"},
        {"Host": "evil.com", "X-Rewrite-URL": "/admin"},
    ]

    # 脆弱性の兆候パターン
    VULN_PATTERNS = [
        (r'https?://evil\.com', "host_reflection"),
        (r'href=["\']https?://evil\.com', "link_injection"),
        (r'Location:\s*https?://evil\.com', "redirect_injection"),
        (r'<form[^>]*action=["\']https?://evil\.com', "form_action_injection"),
    ]

    def __init__(self):
        config = get_feature_config().phase3.attack_modules
        self._enabled = config.host_header_injection
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "SHIGOKU-Scanner/1.0"
        })

    def is_enabled(self) -> bool:
        """機能が有効かチェック"""
        return self._enabled

    def test(self, url: str, timeout: int = 10) -> list[Finding]:
        """
        URLに対してHost Header Injectionをテスト
        
        Args:
            url: テスト対象URL
            timeout: タイムアウト（秒）
            
        Returns:
            発見したFindingのリスト
        """
        if not self.is_enabled():
            logger.info("HostHeaderInjection is disabled")
            return []

        findings = []
        parsed = urlparse(url)
        original_host = parsed.netloc

        for payload in self.PAYLOADS:
            try:
                result = self._test_payload(url, payload, original_host, timeout)
                
                if result.vulnerable:
                    finding = self._create_finding(url, result)
                    findings.append(finding)
                    
                    logger.info(
                        "Host Header Injection found: %s (%s)",
                        url,
                        result.injection_type
                    )

            except Exception as e:
                logger.debug("Test failed for payload %s: %s", payload, e)

        return findings

    def _test_payload(
        self, 
        url: str, 
        payload: dict, 
        original_host: str,
        timeout: int
    ) -> HostHeaderResult:
        """単一ペイロードをテスト"""
        # ヘッダーを構築
        headers = {**payload}
        
        try:
            response = self._session.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
                verify=False
            )
            
            # レスポンス解析
            body = response.text
            combined = f"{dict(response.headers)}\n{body}"
            
            for pattern, injection_type in self.VULN_PATTERNS:
                if re.search(pattern, combined, re.IGNORECASE):
                    return HostHeaderResult(
                        vulnerable=True,
                        injection_type=injection_type,
                        payload=str(payload),
                        response_status=response.status_code,
                        evidence=self._extract_evidence(combined, pattern),
                        confidence=0.8
                    )
            
            # リダイレクトチェック
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get("Location", "")
                if "evil.com" in location:
                    return HostHeaderResult(
                        vulnerable=True,
                        injection_type="open_redirect",
                        payload=str(payload),
                        response_status=response.status_code,
                        evidence=f"Location: {location}",
                        confidence=0.9
                    )

        except Exception as e:
            logger.debug("Request failed: %s", e)

        return HostHeaderResult(vulnerable=False)

    def _extract_evidence(self, content: str, pattern: str) -> str:
        """証拠を抽出"""
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 50)
            end = min(len(content), match.end() + 50)
            return f"...{content[start:end]}..."
        return ""

    def _create_finding(self, url: str, result: HostHeaderResult) -> Finding:
        """Findingを作成"""
        severity_map = {
            "redirect_injection": Severity.HIGH,
            "link_injection": Severity.MEDIUM,
            "host_reflection": Severity.MEDIUM,
            "form_action_injection": Severity.HIGH,
            "open_redirect": Severity.MEDIUM,
        }

        return Finding(
            vuln_type=VulnType.HOST_HEADER_INJECTION,
            severity=severity_map.get(result.injection_type, Severity.MEDIUM),
            title=f"Host Header Injection ({result.injection_type})",
            description=(
                f"The application is vulnerable to Host Header Injection. "
                f"The injected host value is reflected in the response, "
                f"which can lead to cache poisoning, password reset poisoning, "
                f"or open redirect attacks."
            ),
            target_url=url,
            evidence=Evidence(
                request_method="GET",
                request_url=url,
                request_headers={"Payload": result.payload},
                response_status=result.response_status,
                response_body=result.evidence[:500],
            ),
            reproduction_steps=[
                f"1. Send a request to {url}",
                f"2. Include the following headers: {result.payload}",
                "3. Observe that the injected host appears in the response",
            ],
            impact=(
                "An attacker can manipulate the Host header to:\n"
                "- Poison web cache with malicious content\n"
                "- Hijack password reset links\n"
                "- Bypass access controls\n"
                "- Conduct phishing attacks"
            ),
            confidence=result.confidence,
            source_agent="host_header_injection_tester",
            cwe_id="CWE-644",
        )

    def test_password_reset(self, url: str, email: str = "test@example.com") -> list[Finding]:
        """
        パスワードリセット機能に対するテスト
        
        Args:
            url: パスワードリセットURL
            email: テスト用メールアドレス
            
        Returns:
            発見したFindingのリスト
        """
        if not self.is_enabled():
            return []

        findings = []
        
        # POSTリクエストでパスワードリセットを試行
        payloads = [
            {"Host": "evil.com"},
            {"X-Forwarded-Host": "evil.com"},
        ]

        for headers in payloads:
            try:
                response = self._session.post(
                    url,
                    data={"email": email},
                    headers=headers,
                    timeout=10,
                    allow_redirects=False,
                    verify=False
                )
                
                # レスポンスにevil.comが含まれていれば脆弱
                if "evil.com" in response.text.lower():
                    finding = Finding(
                        vuln_type=VulnType.HOST_HEADER_INJECTION,
                        severity=Severity.HIGH,
                        title="Password Reset Poisoning via Host Header",
                        description=(
                            "The password reset functionality is vulnerable to "
                            "Host Header injection. An attacker can receive the "
                            "victim's password reset token by manipulating the Host header."
                        ),
                        target_url=url,
                        evidence=Evidence(
                            request_method="POST",
                            request_url=url,
                            request_headers=headers,
                            response_status=response.status_code,
                        ),
                        reproduction_steps=[
                            f"1. Send POST request to {url}",
                            f"2. Include Host/X-Forwarded-Host: evil.com",
                            "3. Password reset email contains evil.com link",
                        ],
                        impact="Attacker can hijack password reset tokens",
                        confidence=0.9,
                        source_agent="host_header_injection_tester",
                        cwe_id="CWE-644",
                    )
                    findings.append(finding)

            except Exception as e:
                logger.debug("Password reset test failed: %s", e)

        return findings


# シングルトンインスタンス
_tester_instance: Optional[HostHeaderInjectionTester] = None


def get_host_header_tester() -> HostHeaderInjectionTester:
    """HostHeaderInjectionTesterのシングルトンインスタンスを取得"""
    global _tester_instance
    if _tester_instance is None:
        _tester_instance = HostHeaderInjectionTester()
    return _tester_instance
