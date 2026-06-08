"""
LDAP Injection Tester ユニットテスト
"""
import pytest
from src.core.attack.ldap_tester import (
    LDAPInjectionTester,
    LDAPInjectionType,
    create_ldap_tester,
)


class TestLDAPInjectionTester:
    """LDAPInjectionTester テストクラス"""

    @pytest.fixture
    def tester(self):
        return create_ldap_tester()

    def test_filter_bypass_payloads_exist(self, tester):
        """フィルターバイパスペイロードが存在するか"""
        assert len(tester.FILTER_BYPASS_PAYLOADS) > 0
        # ワイルドカードを含む
        payloads = [p[0] for p in tester.FILTER_BYPASS_PAYLOADS]
        assert "*" in payloads

    def test_auth_bypass_payloads_exist(self, tester):
        """認証バイパスペイロードが存在するか"""
        assert len(tester.AUTH_BYPASS_PAYLOADS) > 0

    def test_test_filter_bypass(self, tester):
        """フィルターバイパステスト実行"""
        results = tester._test_filter_bypass(
            url="http://example.com/search",
            parameter="q",
            method="GET",
        )
        assert len(results) > 0
        for r in results:
            assert r.injection_type == LDAPInjectionType.FILTER_BYPASS

    def test_test_auth_bypass(self, tester):
        """認証バイパステスト実行"""
        results = tester._test_auth_bypass(
            url="http://example.com/login",
            parameter="username",
            method="POST",
        )
        assert len(results) > 0
        for r in results:
            assert r.injection_type == LDAPInjectionType.AUTHENTICATION_BYPASS

    def test_test_authentication(self, tester):
        """認証フォームテスト"""
        results = tester.test_authentication(
            url="http://example.com/login",
            username_param="user",
            password_param="pass",
            valid_username="admin",
        )
        assert len(results) > 0
        # 複数の認証バイパスコンボ
        assert any("*" in r.payload for r in results)

    def test_analyze_response_ldap_error(self, tester):
        """LDAPエラー検出テスト"""
        original = "OK"
        response = "LDAP error: Invalid search filter"
        
        vuln, confidence, evidence = tester._analyze_response(response, original)
        assert vuln is True
        assert confidence > 0.8

    def test_analyze_response_auth_success(self, tester):
        """認証成功検出テスト"""
        original = "Please login"
        response = "Welcome admin!"
        
        vuln, confidence, evidence = tester._analyze_response(response, original)
        assert vuln is True

    def test_get_summary(self, tester):
        """サマリー取得テスト"""
        tester.test(
            url="http://example.com/search",
            parameters=["q"],
        )
        
        summary = tester.get_summary()
        assert "total_tests" in summary
        assert "vulnerable" in summary
        assert "by_type" in summary
