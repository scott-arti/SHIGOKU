"""
NoSQL Injection Tester ユニットテスト
"""
import pytest
from src.core.attack.nosql_tester import (
    NoSQLInjectionTester,
    NoSQLDatabase,
    InjectionType,
    create_nosql_tester,
)


class TestNoSQLInjectionTester:
    """NoSQLInjectionTester テストクラス"""

    @pytest.fixture
    def tester(self):
        return create_nosql_tester()

    def test_detect_database_mongodb(self, tester):
        """MongoDB検出テスト"""
        url = "http://example.com:27017/api"
        result = tester._detect_database(url)
        assert result == NoSQLDatabase.MONGODB

    def test_detect_database_couchdb(self, tester):
        """CouchDB検出テスト"""
        url = "http://couchdb.example.com:5984/db"
        result = tester._detect_database(url)
        assert result == NoSQLDatabase.COUCHDB

    def test_detect_database_redis(self, tester):
        """Redis検出テスト"""
        url = "http://redis.example.com:6379"
        result = tester._detect_database(url)
        assert result == NoSQLDatabase.REDIS

    def test_get_payloads_mongodb_json(self, tester):
        """MongoDBのJSONペイロード取得テスト"""
        payloads = tester._get_payloads(NoSQLDatabase.MONGODB, "json")
        assert len(payloads) > 0
        # オペレーターペイロードが含まれる
        payload_strs = [p[0] for p in payloads]
        assert any("$ne" in p for p in payload_strs)
        assert any("$where" in p for p in payload_strs)

    def test_get_payloads_mongodb_form(self, tester):
        """MongoDBのFormペイロード取得テスト"""
        payloads = tester._get_payloads(NoSQLDatabase.MONGODB, "form")
        assert len(payloads) > 0
        # URLクエリ形式
        assert any("[$ne]" in p[0] for p in payloads)

    def test_test_authentication_bypass(self, tester):
        """認証バイパステスト"""
        results = tester.test_authentication_bypass(
            url="http://example.com/login",
            username_param="user",
            password_param="pass",
        )
        assert len(results) > 0
        # すべてが認証バイパスタイプ
        for r in results:
            assert r.injection_type == InjectionType.AUTHENTICATION_BYPASS

    def test_analyze_response_length_diff(self, tester):
        """レスポンス長差異検出テスト"""
        original = "short"
        response = "much longer response with additional data" * 10
        
        vuln, confidence, evidence = tester._analyze_response(
            response, original, NoSQLDatabase.MONGODB
        )
        assert vuln is True
        assert confidence > 0.5

    def test_analyze_response_error_pattern(self, tester):
        """エラーパターン検出テスト"""
        original = "OK"
        response = "MongoError: Invalid query syntax"
        
        vuln, confidence, evidence = tester._analyze_response(
            response, original, NoSQLDatabase.MONGODB
        )
        assert vuln is True
        assert "MongoError" in evidence

    def test_get_summary(self, tester):
        """サマリー取得テスト"""
        # テスト実行
        tester.test(
            url="http://example.com/api",
            parameters=["q"],
            database=NoSQLDatabase.MONGODB,
        )
        
        summary = tester.get_summary()
        assert "total_tests" in summary
        assert "vulnerable" in summary
        assert "by_database" in summary
