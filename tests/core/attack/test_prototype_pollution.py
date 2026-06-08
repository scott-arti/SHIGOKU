"""
Prototype Pollution Tester ユニットテスト
"""
import pytest
import json
from src.core.attack.prototype_pollution_tester import (
    PrototypePollutionTester,
    PollutionVector,
    create_prototype_pollution_tester,
)


class TestPrototypePollutionTester:
    """PrototypePollutionTester テストクラス"""

    @pytest.fixture
    def tester(self):
        return create_prototype_pollution_tester()

    def test_query_payloads_exist(self, tester):
        """クエリペイロードが存在"""
        assert len(tester.QUERY_PAYLOADS) > 0
        # __proto__ ペイロードを含む
        assert any("__proto__" in p[0] for p in tester.QUERY_PAYLOADS)

    def test_json_payloads_exist(self, tester):
        """JSONペイロードが存在"""
        assert len(tester.JSON_PAYLOADS) > 0
        # 辞書内に __proto__ キーが存在
        assert any("__proto__" in str(p) for p in tester.JSON_PAYLOADS)

    def test_test_query_pollution(self, tester):
        """クエリ汚染テスト実行"""
        results = tester._test_query_pollution(
            url="http://example.com/api",
            method="GET",
            existing_params=None,
        )
        assert len(results) > 0
        for r in results:
            assert r.vector == PollutionVector.QUERY_STRING

    def test_test_json_pollution(self, tester):
        """JSON汚染テスト実行"""
        results = tester._test_json_pollution(
            url="http://example.com/api",
            method="POST",
        )
        assert len(results) > 0
        for r in results:
            assert r.vector == PollutionVector.JSON_BODY

    def test_verify_pollution_marker_found(self, tester):
        """汚染マーカー検出"""
        response = '{"result": "shigoku_test"}'
        assert tester._verify_pollution("http://example.com", response) is True

    def test_verify_pollution_marker_not_found(self, tester):
        """汚染マーカー非検出"""
        response = '{"result": "normal"}'
        assert tester._verify_pollution("http://example.com", response) is False

    def test_check_pollution_in_object_nested(self, tester):
        """ネストされたオブジェクトでの汚染チェック"""
        obj = {"user": {"profile": {"polluted": "yes"}}}
        assert tester._check_pollution_in_object(obj) is True

    def test_check_pollution_in_object_not_found(self, tester):
        """汚染なし"""
        obj = {"user": {"name": "test"}}
        assert tester._check_pollution_in_object(obj) is False

    def test_test_specific_property(self, tester):
        """特定プロパティ汚染テスト"""
        tester.test_specific_property(
            url="http://example.com/api",
            property_name="isAdmin",
            property_value="true",
        )
        assert len(tester.results) > 0

    def test_test_full(self, tester):
        """統合テスト"""
        results = tester.test(
            url="http://example.com/api",
            method="POST",
            test_query=True,
            test_json=True,
        )
        # クエリとJSONの両方
        assert len(results) > len(tester.QUERY_PAYLOADS)

    def test_get_summary(self, tester):
        """サマリー取得"""
        tester.test(url="http://example.com", method="POST")
        
        summary = tester.get_summary()
        assert "total_tests" in summary
        assert "by_vector" in summary
