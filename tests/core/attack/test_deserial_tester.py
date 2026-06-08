"""
Deserialization Tester ユニットテスト
"""
import pytest
import base64
from src.core.attack.deserial_tester import (
    DeserializationTester,
    SerializationFormat,
    VulnerabilityLevel,
    create_deserialization_tester,
)


class TestDeserializationTester:
    """DeserializationTester テストクラス"""

    @pytest.fixture
    def tester(self):
        return create_deserialization_tester()

    def test_detect_java_serialized(self, tester):
        """Java シリアライズデータ検出"""
        # Java magic bytes (base64)
        data = "rO0ABXNyABBqYXZhLmxhbmcuT2JqZWN0AA=="
        result = tester.detect_serialized_data(data)
        assert result is not None
        assert result[0] == SerializationFormat.JAVA

    def test_detect_php_serialized(self, tester):
        """PHP シリアライズデータ検出"""
        data = 'O:8:"stdClass":1:{s:4:"name";s:4:"test";}'
        result = tester.detect_serialized_data(data)
        assert result is not None
        assert result[0] == SerializationFormat.PHP

    def test_detect_python_pickle(self, tester):
        """Python Pickle データ検出"""
        # Pickle v3 magic bytes (base64)
        data = base64.b64encode(b'\x80\x03}q\x00.').decode()
        result = tester.detect_serialized_data(data)
        assert result is not None
        assert result[0] == SerializationFormat.PYTHON_PICKLE

    def test_detect_ruby_marshal(self, tester):
        """Ruby Marshal データ検出"""
        # Ruby Marshal magic bytes (base64)
        data = base64.b64encode(b'\x04\x08I"\x0bhello\x06:\x06ET').decode()
        result = tester.detect_serialized_data(data)
        assert result is not None
        assert result[0] == SerializationFormat.RUBY_MARSHAL

    def test_detect_no_serialization(self, tester):
        """非シリアライズデータ"""
        data = "just a normal string"
        result = tester.detect_serialized_data(data)
        assert result is None

    def test_scan_parameters(self, tester):
        """パラメータスキャン"""
        params = {
            "data": "rO0ABXNyABBqYXZhLmxhbmcuT2JqZWN0AA==",
            "name": "Bob",
        }
        results = tester.scan_parameters(
            url="http://example.com/api",
            parameters=params,
        )
        assert len(results) == 1
        assert results[0].parameter == "data"
        assert results[0].format == SerializationFormat.JAVA

    def test_get_gadget_candidates_java(self, tester):
        """Java Gadget候補取得"""
        candidates = tester._get_gadget_candidates(SerializationFormat.JAVA)
        assert len(candidates) > 0
        # InvokerTransformerが含まれる
        assert any("InvokerTransformer" in c for c in candidates)

    def test_get_gadget_candidates_php(self, tester):
        """PHP Gadget候補取得"""
        candidates = tester._get_gadget_candidates(SerializationFormat.PHP)
        assert len(candidates) > 0

    def test_analyze_error_response_java(self, tester):
        """Javaエラーレスポンス分析"""
        response = "java.io.InvalidClassException: local class incompatible"
        found, evidence = tester._analyze_error_response(
            response, SerializationFormat.JAVA
        )
        assert found is True
        assert "InvalidClassException" in evidence

    def test_get_summary(self, tester):
        """サマリー取得"""
        params = {"data": "rO0ABXNyAA=="}
        tester.scan_parameters("http://example.com", params)
        
        summary = tester.get_summary()
        assert "total_detections" in summary
        assert "by_format" in summary
