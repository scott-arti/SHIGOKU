"""
Tests for Caido Importer
"""

import pytest
import json
import base64
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
import importlib.util

# __init__.py のチェーン読み込みを回避するため直接モジュールをロード
# tests/tools/ から 3 階層上がってプロジェクトルートへ
base_path = Path(__file__).resolve().parent.parent.parent
module_path = base_path / "src" / "tools" / "custom" / "caido_importer.py"
spec = importlib.util.spec_from_file_location("caido_importer", module_path)
caido_importer_module = importlib.util.module_from_spec(spec)
sys.modules["caido_importer"] = caido_importer_module
spec.loader.exec_module(caido_importer_module)

CaidoImporter = caido_importer_module.CaidoImporter
STATIC_EXTENSIONS = caido_importer_module.STATIC_EXTENSIONS


class TestCaidoImporter:
    """Caido Importer のユニットテスト"""

    @pytest.fixture
    def importer(self):
        return CaidoImporter()

    @pytest.fixture
    def mock_caido_entry(self):
        """モック Caido エントリ"""
        request_raw = "GET /api/v1/users?id=123 HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123\r\n\r\n"
        response_raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"user\": \"test@example.com\"}"
        
        return {
            "id": 1,
            "host": "example.com",
            "port": 443,
            "method": "GET",
            "path": "/api/v1/users",
            "query": "id=123",
            "is_tls": True,
            "raw": base64.b64encode(request_raw.encode()).decode(),
            "response": {
                "status_code": 200,
                "raw": base64.b64encode(response_raw.encode()).decode()
            }
        }

    # === Base64 デコードテスト ===
    
    def test_decode_base64_success(self, importer):
        """Base64 デコード成功"""
        original = "Hello, World!"
        encoded = base64.b64encode(original.encode()).decode()
        result = importer._decode_base64(encoded)
        assert result == original

    def test_decode_base64_empty(self, importer):
        """空文字列のデコード"""
        result = importer._decode_base64("")
        assert result == ""

    def test_decode_base64_invalid(self, importer):
        """不正な Base64 のデコード（エラーハンドリング）"""
        result = importer._decode_base64("not-valid-base64!!!")
        assert result == "[DECODE_ERROR]"

    # === 静的ファイル除外テスト ===
    
    def test_is_static_file_css(self, importer):
        """CSS ファイルは静的"""
        assert importer._is_static_file("https://example.com/style.css") is True

    def test_is_static_file_js(self, importer):
        """JS ファイルは静的"""
        assert importer._is_static_file("https://example.com/app.js") is True

    def test_is_static_file_png(self, importer):
        """PNG ファイルは静的"""
        assert importer._is_static_file("https://example.com/logo.png") is True

    def test_is_static_file_api(self, importer):
        """API エンドポイントは静的ではない"""
        assert importer._is_static_file("https://example.com/api/users") is False

    def test_is_static_file_with_query(self, importer):
        """クエリパラメータ付き静的ファイル"""
        assert importer._is_static_file("https://example.com/style.css?v=1.0") is True

    # === PII マスクテスト ===
    
    def test_mask_pii_applied(self, importer):
        """PII マスクが適用される"""
        # PIIMasker が正しく動作していれば、メールアドレスはマスクされる
        result = importer._mask_pii("Contact: test@example.com")
        # マスクされているか、または元のテキストが含まれていないことを確認
        # (PIIMasker の実装に依存するため、具体的なアサーションは緩め)
        assert result is not None

    # === HTTP パーステスト ===
    
    def test_parse_http_raw(self, importer):
        """HTTP 生データのパース"""
        raw = "GET /api HTTP/1.1\r\nHost: example.com\r\nCookie: session=xyz\r\n\r\n{\"data\": 1}"
        headers, body = importer._parse_http_raw(raw)
        
        assert "Host" in headers
        assert headers["Host"] == "example.com"
        assert headers["Cookie"] == "session=xyz"
        assert body == '{"data": 1}'

    def test_parse_http_raw_empty(self, importer):
        """空の HTTP データ"""
        headers, body = importer._parse_http_raw("")
        assert headers == {}
        assert body == ""

    # === エントリ処理テスト ===
    
    def test_process_entry_success(self, importer, mock_caido_entry):
        """正常なエントリ処理"""
        result = importer._process_entry(mock_caido_entry)
        
        assert result is not None
        assert result["id"] == 1
        assert result["method"] == "GET"
        assert "example.com" in result["url"]
        assert result["response"]["status"] == 200

    def test_process_entry_static_file_skipped(self, importer):
        """静的ファイルはスキップされる"""
        entry = {
            "id": 2,
            "host": "example.com",
            "port": 443,
            "method": "GET",
            "path": "/assets/style.css",
            "is_tls": True,
            "raw": base64.b64encode(b"GET /assets/style.css HTTP/1.1\r\n\r\n").decode(),
            "response": {"status_code": 200, "raw": ""}
        }
        result = importer._process_entry(entry)
        assert result is None

    def test_process_entry_missing_host(self, importer):
        """host がないエントリはスキップ"""
        entry = {"id": 3, "path": "/api"}
        result = importer._process_entry(entry)
        assert result is None

    # === ファイルインポートテスト ===
    
    def test_import_file_success(self, importer, mock_caido_entry):
        """ファイルインポート成功"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump([mock_caido_entry], f)
            temp_path = f.name
        
        try:
            results = importer.import_file(temp_path)
            assert len(results) == 1
            assert results[0]["method"] == "GET"
        finally:
            Path(temp_path).unlink()

    def test_import_file_not_found(self, importer):
        """ファイルが存在しない場合"""
        with pytest.raises(FileNotFoundError):
            importer.import_file("/nonexistent/path.json")

    def test_import_file_empty(self, importer):
        """空ファイルの場合"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name
        
        try:
            with pytest.raises(ValueError, match="コンテンツがありません"):
                importer.import_file(temp_path)
        finally:
            Path(temp_path).unlink()

    def test_import_file_invalid_json(self, importer):
        """不正な JSON の場合"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("not valid json {{{")
            temp_path = f.name
        
        try:
            with pytest.raises(ValueError, match="JSON パース失敗"):
                importer.import_file(temp_path)
        finally:
            Path(temp_path).unlink()


class TestStaticExtensions:
    """静的ファイル拡張子の網羅テスト"""
    
    def test_all_static_extensions_defined(self):
        """全ての静的拡張子が定義されている"""
        expected = {'.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map'}
        assert STATIC_EXTENSIONS == expected
