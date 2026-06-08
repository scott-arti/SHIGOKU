"""
Tests for Tagging Filter
"""

import pytest
import json
import tempfile
from pathlib import Path
from datetime import datetime

import sys
import importlib.util

# __init__.py のチェーン読み込みを回避するため直接モジュールをロード
# tests/core/intel/ から 4 階層上がってプロジェクトルートへ
base_path = Path(__file__).resolve().parent.parent.parent.parent
module_path = base_path / "src" / "core" / "intel" / "tagging_filter.py"
spec = importlib.util.spec_from_file_location("tagging_filter", module_path)
tagging_filter_module = importlib.util.module_from_spec(spec)
sys.modules["tagging_filter"] = tagging_filter_module
spec.loader.exec_module(tagging_filter_module)

TaggingFilter = tagging_filter_module.TaggingFilter
STATIC_EXTENSIONS = tagging_filter_module.STATIC_EXTENSIONS
AUTH_HEADERS = tagging_filter_module.AUTH_HEADERS


class TestTaggingFilter:
    """Tagging Filter のユニットテスト"""

    @pytest.fixture
    def filter_instance(self):
        return TaggingFilter(project_name="test_project")

    # === URL 正規化テスト ===
    
    def test_normalize_url_query_sort(self, filter_instance):
        """クエリパラメータがソートされる"""
        url = "https://example.com/api?z=3&a=1&m=2"
        normalized = filter_instance._normalize_url(url)
        assert "a=1" in normalized
        # クエリがソートされていることを確認
        assert normalized.index("a=1") < normalized.index("m=2")
        assert normalized.index("m=2") < normalized.index("z=3")

    def test_normalize_url_port_80_removed(self, filter_instance):
        """HTTP ポート 80 は省略される"""
        url = "http://example.com:80/api"
        normalized = filter_instance._normalize_url(url)
        assert ":80" not in normalized

    def test_normalize_url_port_443_removed(self, filter_instance):
        """HTTPS ポート 443 は省略される"""
        url = "https://example.com:443/api"
        normalized = filter_instance._normalize_url(url)
        assert ":443" not in normalized

    def test_normalize_url_non_standard_port_kept(self, filter_instance):
        """非標準ポートは保持される"""
        url = "https://example.com:8443/api"
        normalized = filter_instance._normalize_url(url)
        assert ":8443" in normalized

    def test_normalize_url_fragment_removed(self, filter_instance):
        """フラグメントは除去される"""
        url = "https://example.com/page#section1"
        normalized = filter_instance._normalize_url(url)
        assert "#section1" not in normalized

    # === 重複排除テスト ===
    
    def test_unique_key_generation(self, filter_instance):
        """一意キーの生成"""
        key1 = filter_instance._get_unique_key("GET", "https://example.com/api?b=2&a=1")
        key2 = filter_instance._get_unique_key("GET", "https://example.com/api?a=1&b=2")
        assert key1 == key2  # クエリソートにより同一

    def test_unique_key_different_methods(self, filter_instance):
        """異なるメソッドは異なるキー"""
        key1 = filter_instance._get_unique_key("GET", "https://example.com/api")
        key2 = filter_instance._get_unique_key("POST", "https://example.com/api")
        assert key1 != key2

    # === 静的ファイル除外テスト ===
    
    def test_is_static_file_css(self, filter_instance):
        assert filter_instance._is_static_file("https://example.com/style.css") is True

    def test_is_static_file_api(self, filter_instance):
        assert filter_instance._is_static_file("https://example.com/api/users") is False

    # === 認証コンテキスト抽出テスト ===
    
    def test_extract_auth_context_authorization(self, filter_instance):
        """Authorization ヘッダーの抽出"""
        headers = {"Authorization": "Bearer token123", "Content-Type": "application/json"}
        context = filter_instance._extract_auth_context(headers)
        assert "Authorization" in context
        assert context["Authorization"] == "Bearer token123"
        assert "Content-Type" not in context

    def test_extract_auth_context_cookie(self, filter_instance):
        """Cookie ヘッダーの抽出"""
        headers = {"Cookie": "session=abc123"}
        context = filter_instance._extract_auth_context(headers)
        assert "Cookie" in context

    def test_extract_auth_context_empty(self, filter_instance):
        """認証ヘッダーがない場合"""
        headers = {"Content-Type": "text/html"}
        context = filter_instance._extract_auth_context(headers)
        assert context == {}

    # === 証拠抽出テスト ===
    
    def test_extract_evidence_debug_info(self, filter_instance):
        """debug_info タグがある場合に証拠抽出"""
        body = "Error: stack trace at line 42\n" + "x" * 300
        evidence = filter_instance._extract_evidence(body, ["debug_info"])
        assert len(evidence) <= 203  # 200 + "..."
        assert "Error" in evidence

    def test_extract_evidence_no_debug(self, filter_instance):
        """debug_info タグがない場合は空"""
        body = "Normal response body"
        evidence = filter_instance._extract_evidence(body, ["auth"])
        assert evidence == ""

    # === タグ付けテスト ===
    
    def test_classify_auth_login_path(self, filter_instance):
        """login パスは auth タグ"""
        entry = {"url": "https://example.com/login", "method": "POST", "body": "", "response": {"body": "", "status": 200}}
        tags = filter_instance._classify_entry(entry)
        assert "auth" in tags

    def test_classify_auth_password_body(self, filter_instance):
        """password を含む body は auth タグ"""
        entry = {"url": "https://example.com/api", "method": "POST", "body": "password=secret", "response": {"body": "", "status": 200}}
        tags = filter_instance._classify_entry(entry)
        assert "auth" in tags

    def test_classify_admin_200(self, filter_instance):
        """admin パス + 200 OK は admin タグ"""
        entry = {"url": "https://example.com/admin/dashboard", "method": "GET", "body": "", "response": {"body": "", "status": 200}}
        tags = filter_instance._classify_entry(entry)
        assert "admin" in tags

    def test_classify_admin_403_no_tag(self, filter_instance):
        """admin パス + 403 は admin タグなし"""
        entry = {"url": "https://example.com/admin", "method": "GET", "body": "", "response": {"body": "", "status": 403}}
        tags = filter_instance._classify_entry(entry)
        assert "admin" not in tags

    def test_classify_id_param_query(self, filter_instance):
        """id= パラメータは id_param タグ"""
        entry = {"url": "https://example.com/user?id=123", "method": "GET", "body": "", "response": {"body": "", "status": 200}}
        tags = filter_instance._classify_entry(entry)
        assert "id_param" in tags

    def test_classify_id_param_body(self, filter_instance):
        """body 内の user_id も id_param タグ"""
        entry = {"url": "https://example.com/api", "method": "POST", "body": "user_id=456", "response": {"body": "", "status": 200}}
        tags = filter_instance._classify_entry(entry)
        assert "id_param" in tags

    def test_classify_redirect_param(self, filter_instance):
        """redirect パラメータは redirect_param タグ"""
        entry = {"url": "https://example.com/auth?redirect=https://evil.com", "method": "GET", "body": "", "response": {"body": "", "status": 302}}
        tags = filter_instance._classify_entry(entry)
        assert "redirect_param" in tags

    def test_classify_file_param(self, filter_instance):
        """file パラメータは file_param タグ"""
        entry = {"url": "https://example.com/download?file=/etc/passwd", "method": "GET", "body": "", "response": {"body": "", "status": 200}}
        tags = filter_instance._classify_entry(entry)
        assert "file_param" in tags

    def test_classify_upload_path(self, filter_instance):
        """upload パスは upload タグ"""
        entry = {"url": "https://example.com/api/upload", "method": "POST", "body": "", "response": {"body": "", "status": 200}}
        tags = filter_instance._classify_entry(entry)
        assert "upload" in tags

    def test_classify_debug_info(self, filter_instance):
        """エラーメッセージは debug_info タグ"""
        entry = {"url": "https://example.com/api", "method": "GET", "body": "", "response": {"body": "Error: stack trace at line 42", "status": 500}}
        tags = filter_instance._classify_entry(entry)
        assert "debug_info" in tags

    def test_classify_multiple_tags(self, filter_instance):
        """複数タグの付与"""
        entry = {"url": "https://example.com/admin/login?id=1", "method": "POST", "body": "password=test", "response": {"body": "", "status": 200}}
        tags = filter_instance._classify_entry(entry)
        assert "auth" in tags
        assert "admin" in tags
        assert "id_param" in tags

    def test_classify_uncategorized(self, filter_instance):
        """タグなしは空リスト"""
        entry = {"url": "https://example.com/about", "method": "GET", "body": "", "response": {"body": "About us page", "status": 200}}
        tags = filter_instance._classify_entry(entry)
        assert tags == []

    # === ファイル処理テスト ===
    
    def test_process_file_output(self, filter_instance):
        """ファイル処理と出力"""
        entries = [
            {"id": 1, "url": "https://example.com/login", "method": "POST", "headers": {}, "body": "password=x", "response": {"body": "", "status": 200}},
            {"id": 2, "url": "https://example.com/admin", "method": "GET", "headers": {}, "body": "", "response": {"body": "", "status": 200}},
            {"id": 3, "url": "https://example.com/about", "method": "GET", "headers": {}, "body": "", "response": {"body": "", "status": 200}},
        ]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = Path(tmpdir) / "input.json"
            with open(input_file, 'w') as f:
                json.dump(entries, f)
            
            stats = filter_instance.process_file(str(input_file), tmpdir)
            
            # 統計確認
            assert stats["auth"] >= 1
            assert stats["admin"] >= 1
            assert stats["uncategorized"] >= 1
            
            # ファイル存在確認
            date_str = datetime.now().strftime("%Y%m%d")
            auth_file = Path(tmpdir) / f"{date_str}_test_project_tagged_auth.jsonl"
            assert auth_file.exists()

    def test_process_file_deduplication(self, filter_instance):
        """重複エントリの排除"""
        entries = [
            {"id": 1, "url": "https://example.com/api?b=2&a=1", "method": "GET", "headers": {}, "body": "", "response": {"body": "", "status": 200}},
            {"id": 2, "url": "https://example.com/api?a=1&b=2", "method": "GET", "headers": {}, "body": "", "response": {"body": "", "status": 200}},  # 重複
        ]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = Path(tmpdir) / "input.json"
            with open(input_file, 'w') as f:
                json.dump(entries, f)
            
            stats = filter_instance.process_file(str(input_file), tmpdir)
            
            # 重複排除されて 1 件のみ
            total_processed = sum(stats.values())
            assert total_processed == 1


class TestAuthHeaders:
    """認証ヘッダー定義のテスト"""
    
    def test_auth_headers_defined(self):
        """全ての認証ヘッダーが定義されている"""
        expected = {'authorization', 'cookie', 'x-auth-token', 'x-csrf-token', 'x-xsrf-token', 'set-cookie'}
        assert AUTH_HEADERS == expected
