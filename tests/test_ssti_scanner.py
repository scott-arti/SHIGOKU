"""
SSTI Scanner Unit Tests

SSTIScanner と PayloadEncoder の振る舞いテスト
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import httpx

from src.core.utils.payload_encoder import PayloadEncoder, create_payload_encoder
from src.core.attack.ssti_scanner import (
    SSTIScanner,
    SSTIResult,
    TemplateEngine,
    create_ssti_scanner,
)
from src.core.intel.fingerprinter import Fingerprinter, TechInfo


class TestPayloadEncoder:
    """PayloadEncoder のテスト"""
    
    def test_url_encode(self):
        """URL エンコードのテスト"""
        encoder = PayloadEncoder()
        result = encoder.url_encode("{{7*7}}")
        assert "%7B%7B7%2A7%7D%7D" == result
    
    def test_url_encode_with_safe(self):
        """safe パラメータ付きURL エンコードのテスト"""
        encoder = PayloadEncoder()
        result = encoder.url_encode("{{7*7}}", safe="{}")
        assert "{" in result and "}" in result
    
    def test_double_url_encode(self):
        """Double URL エンコードのテスト"""
        encoder = PayloadEncoder()
        result = encoder.double_url_encode("{{7*7}}")
        # % が %25 になっていることを確認
        assert "%25" in result
    
    def test_html_entity_encode(self):
        """HTML Entity エンコードのテスト"""
        encoder = PayloadEncoder()
        result = encoder.html_entity_encode("<>")
        assert "&#60;" in result  # <
        assert "&#62;" in result  # >
    
    def test_html_entity_hex_encode(self):
        """HTML Entity 16進数エンコードのテスト"""
        encoder = PayloadEncoder()
        result = encoder.html_entity_hex_encode("<>")
        assert "&#x3c;" in result  # <
        assert "&#x3e;" in result  # >
    
    def test_unicode_encode(self):
        """Unicode エンコードのテスト"""
        encoder = PayloadEncoder()
        result = encoder.unicode_encode("AB")
        assert "\\u0041" in result  # A
        assert "\\u0042" in result  # B
    
    def test_encode_all_variants(self):
        """全エンコード亜種生成のテスト"""
        encoder = PayloadEncoder()
        variants = encoder.encode_all_variants("{{7*7}}")
        assert len(variants) == 11
        assert "{{7*7}}" in variants  # オリジナル
    
    def test_create_helper(self):
        """ヘルパー関数のテスト"""
        encoder = create_payload_encoder()
        assert isinstance(encoder, PayloadEncoder)


class TestSSTIScanner:
    """SSTIScanner のテスト"""
    
    def test_create_scanner(self):
        """スキャナー作成のテスト"""
        scanner = create_ssti_scanner()
        assert isinstance(scanner, SSTIScanner)
        assert scanner.timeout == 10.0
        assert scanner.delay == 0.5
    
    def test_create_scanner_with_params(self):
        """パラメータ付きスキャナー作成のテスト"""
        scanner = create_ssti_scanner(timeout=5.0, delay=1.0)
        assert scanner.timeout == 5.0
        assert scanner.delay == 1.0
    
    def test_payloads_exist(self):
        """ペイロードマップが存在することのテスト"""
        scanner = SSTIScanner()
        assert "universal" in scanner.PAYLOADS
        assert "jinja2" in scanner.PAYLOADS
        assert "thymeleaf" in scanner.PAYLOADS
        assert "blade" in scanner.PAYLOADS
    
    def test_build_payload(self):
        """ペイロード構築のテスト"""
        scanner = SSTIScanner()
        payload = scanner._build_payload("{{7*7}}", 7, 7, "abc123")
        assert "{{7*7}}" in payload
        assert "abc123" in payload
    
    def test_build_payload_with_different_numbers(self):
        """異なる計算式でのペイロード構築のテスト"""
        scanner = SSTIScanner()
        payload = scanner._build_payload("{{7*7}}", 8, 6, "marker")
        assert "{{8*6}}" in payload
        assert "marker" in payload
    
    def test_detect_engine_jinja2(self):
        """Jinja2 エンジン検出のテスト"""
        scanner = SSTIScanner()
        engine = scanner._detect_engine("jinja2", "{{7*7}}")
        assert engine == TemplateEngine.JINJA2
    
    def test_detect_engine_from_payload_erb(self):
        """ERB ペイロードからのエンジン検出のテスト"""
        scanner = SSTIScanner()
        engine = scanner._detect_engine("universal", "<%= 7*7 %>")
        assert engine == TemplateEngine.ERB
    
    def test_detect_engine_from_payload_freemarker(self):
        """Freemarker ペイロードからのエンジン検出のテスト"""
        scanner = SSTIScanner()
        engine = scanner._detect_engine("universal", "${7*7}")
        assert engine == TemplateEngine.FREEMARKER
    
    def test_get_engines_from_stack_django(self):
        """Django からのエンジン推測テスト"""
        scanner = SSTIScanner()
        engines = scanner._get_engines_from_stack(["Django"])
        assert "jinja2" in engines
    
    def test_get_engines_from_stack_java(self):
        """Java からのエンジン推測テスト"""
        scanner = SSTIScanner()
        engines = scanner._get_engines_from_stack(["Java"])
        assert "thymeleaf" in engines
        assert "freemarker" in engines
    
    def test_get_engines_from_stack_empty(self):
        """空スタックからのエンジン推測テスト"""
        scanner = SSTIScanner()
        engines = scanner._get_engines_from_stack([])
        assert engines == []
    
    def test_summary(self):
        """サマリー生成のテスト"""
        scanner = SSTIScanner()
        summary = scanner.get_summary()
        assert "total_tests" in summary
        assert "vulnerable" in summary
        assert "by_engine" in summary
    
    def test_summary_for_ai(self):
        """AI向けサマリー生成のテスト"""
        scanner = SSTIScanner()
        summary = scanner.get_summary_for_ai()
        assert "SSTI Scan" in summary
        assert "Vulnerable" in summary
    
    @patch.object(SSTIScanner, '_send_request')
    def test_scan_detects_ssti(self, mock_send):
        """SSTI検出のテスト（モック使用）"""
        # 49 + マーカーを含むレスポンスをモック
        mock_response = Mock()
        mock_response.text = "Result: 49"
        mock_send.return_value = mock_response
        
        scanner = SSTIScanner(delay=0)  # テスト用に遅延なし
        
        # モックが常にマーカーを含むようにパッチ
        with patch.object(scanner, '_build_payload', return_value="{{7*7}}testmarker"):
            with patch.object(scanner, '_confirm_ssti', return_value=True):
                results = scanner.scan("http://example.com", ["param"], engines=["jinja2"])
        
        # モックの検証
        assert mock_send.called
    
    def test_context_manager(self):
        """コンテキストマネージャーのテスト"""
        with SSTIScanner() as scanner:
            assert isinstance(scanner, SSTIScanner)
        # close 後はクライアントが None になるはず
        assert scanner._client is None


class TestFingerprinterTemplateEngines:
    """Fingerprinter テンプレートエンジン機能のテスト"""
    
    def test_template_engine_signatures_exist(self):
        """テンプレートエンジンシグネチャが存在することのテスト"""
        fp = Fingerprinter()
        template_engines = [
            "Jinja2", "Thymeleaf", "Twig", "Freemarker",
            "Smarty", "Velocity", "ERB", "Blade",
            "Mako", "Handlebars", "Mustache", "Pebble"
        ]
        for engine in template_engines:
            assert engine in fp.SIGNATURES
            assert fp.SIGNATURES[engine]["category"] == "TemplateEngine"
    
    def test_get_template_engines_from_framework(self):
        """フレームワークからのエンジン推測テスト"""
        fp = Fingerprinter()
        detected = [TechInfo(name="Django", category="Framework")]
        engines = fp.get_template_engines(detected)
        assert "jinja2" in engines
    
    def test_get_template_engines_from_lang(self):
        """言語からのエンジン推測テスト"""
        fp = Fingerprinter()
        detected = [TechInfo(name="PHP", category="Lang")]
        engines = fp.get_template_engines(detected)
        assert "twig" in engines or "smarty" in engines or "blade" in engines
    
    def test_get_template_engines_direct_detection(self):
        """直接検出からのエンジン取得テスト"""
        fp = Fingerprinter()
        detected = [TechInfo(name="Jinja2", category="TemplateEngine")]
        engines = fp.get_template_engines(detected)
        assert "jinja2" in engines
    
    def test_get_template_engines_empty(self):
        """空リストからのエンジン取得テスト"""
        fp = Fingerprinter()
        engines = fp.get_template_engines([])
        assert engines == []
    
    def test_get_template_engines_none(self):
        """Noneからのエンジン取得テスト"""
        fp = Fingerprinter()
        engines = fp.get_template_engines(None)
        assert engines == []
    
    def test_framework_to_engine_mapping(self):
        """フレームワーク→エンジンマッピングのテスト"""
        fp = Fingerprinter()
        assert "Django" in fp.FRAMEWORK_TO_ENGINE
        assert "Laravel" in fp.FRAMEWORK_TO_ENGINE
        assert "Jinja2" in fp.FRAMEWORK_TO_ENGINE["Django"]
        assert "Blade" in fp.FRAMEWORK_TO_ENGINE["Laravel"]
    
    def test_lang_to_engine_mapping(self):
        """言語→エンジンマッピングのテスト"""
        fp = Fingerprinter()
        assert "Python" in fp.LANG_TO_ENGINE
        assert "Java" in fp.LANG_TO_ENGINE
        assert "Jinja2" in fp.LANG_TO_ENGINE["Python"]


class TestTemplateEngineEnum:
    """TemplateEngine Enum のテスト"""
    
    def test_all_engines_exist(self):
        """全エンジンがEnumに存在することのテスト"""
        engines = [
            TemplateEngine.UNKNOWN,
            TemplateEngine.JINJA2,
            TemplateEngine.THYMELEAF,
            TemplateEngine.ERB,
            TemplateEngine.TWIG,
            TemplateEngine.FREEMARKER,
            TemplateEngine.SMARTY,
            TemplateEngine.VELOCITY,
            TemplateEngine.MAKO,
            TemplateEngine.BLADE,
            TemplateEngine.HANDLEBARS,
            TemplateEngine.MUSTACHE,
            TemplateEngine.PEBBLE,
        ]
        assert len(engines) == 13
    
    def test_engine_values(self):
        """エンジン値のテスト"""
        assert TemplateEngine.JINJA2.value == "jinja2"
        assert TemplateEngine.THYMELEAF.value == "thymeleaf"
        assert TemplateEngine.ERB.value == "erb"


class TestSSTIScannerHardening:
    """A1-1 安全化・強化の回帰テスト"""

    def test_velocity_payload_no_rce(self):
        """Velocity ペイロードにRCE命令が含まれないこと"""
        scanner = SSTIScanner()
        velocity_payloads = scanner.PAYLOADS.get("velocity", [])
        for p in velocity_payloads:
            assert "$class.inspect" not in p, (
                f"RCE payload found in Velocity: {p}"
            )

    def test_scan_with_auth_headers_applies_to_client(self):
        """auth_headers が httpx クライアントのヘッダーに適用されること"""
        scanner = SSTIScanner(auth_headers={"Cookie": "session=test123"})
        client = scanner._get_client()
        assert client.headers.get("Cookie") == "session=test123"
        scanner.close()

    def test_scan_updates_auth_headers_and_resets_client(self):
        """scan() に auth_headers を渡すとクライアントがリセットされること"""
        from unittest.mock import MagicMock, patch
        scanner = SSTIScanner()
        scanner._client = MagicMock()  # ダミークライアント設定

        with patch.object(scanner, "_test_parameter", return_value=None):
            scanner.scan(
                "http://example.com/?x=1",
                ["x"],
                auth_headers={"Cookie": "new=cookie"},
            )

        assert scanner._client is None  # リセットされている
        assert scanner.auth_headers.get("Cookie") == "new=cookie"

    @pytest.mark.asyncio
    async def test_scan_async_returns_list(self):
        """scan_async() がリストを返すこと"""
        from unittest.mock import patch
        scanner = SSTIScanner()
        with patch.object(scanner, "scan", return_value=[]):
            result = await scanner.scan_async(
                "http://example.com/?x=1",
                ["x"],
            )
        assert isinstance(result, list)
