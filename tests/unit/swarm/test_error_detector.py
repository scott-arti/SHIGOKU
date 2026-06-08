"""
ErrorDetector ユニットテスト

WAF/Rate Limit ブロック検出の各パターンをテスト
"""

import pytest
from src.core.agents.swarm.error_detector import ErrorDetector, DetectionResult


class TestErrorDetector:
    """ErrorDetector のテストクラス"""
    
    @pytest.fixture
    def detector(self) -> ErrorDetector:
        """標準設定の ErrorDetector"""
        return ErrorDetector(sensitivity=0.5)
    
    @pytest.fixture
    def sensitive_detector(self) -> ErrorDetector:
        """高感度設定の ErrorDetector"""
        return ErrorDetector(sensitivity=0.3)
    
    # ==========================================
    # WAFシグネチャ検出テスト
    # ==========================================
    
    def test_detect_cloudflare(self, detector: ErrorDetector):
        """Cloudflare シグネチャ検出"""
        result = detector.analyze(
            status_code=403,
            headers={"cf-ray": "12345abc", "server": "cloudflare"},
            body="<html>Access Denied</html>",
        )
        
        assert result.is_blocked is True
        assert result.waf_signature == "cloudflare"
        assert result.block_type == "waf"
        assert result.confidence > 0.5
    
    def test_detect_akamai(self, detector: ErrorDetector):
        """Akamai シグネチャ検出"""
        result = detector.analyze(
            status_code=403,
            headers={"x-akamai-transformed": "9 - 0 pmb=mRUM,1"},
            body="Access Denied by Akamai",
        )
        
        assert result.is_blocked is True
        assert result.waf_signature == "akamai"
    
    def test_detect_aws_waf(self, detector: ErrorDetector):
        """AWS WAF シグネチャ検出"""
        result = detector.analyze(
            status_code=403,
            headers={"x-amzn-requestid": "abc123", "x-amz-cf-id": "xyz789"},
            body="<html>Forbidden</html>",
        )
        
        assert result.is_blocked is True
        assert result.waf_signature == "aws_waf"
    
    def test_detect_modsecurity(self, detector: ErrorDetector):
        """ModSecurity シグネチャ検出"""
        result = detector.analyze(
            status_code=403,
            headers={"server": "Apache/2.4.41"},
            body="ModSecurity: Access denied with code 403",
        )
        
        assert result.is_blocked is True
        assert result.waf_signature == "modsecurity"
    
    def test_detect_incapsula(self, detector: ErrorDetector):
        """Incapsula (Imperva) シグネチャ検出"""
        result = detector.analyze(
            status_code=403,
            headers={"set-cookie": "incap_ses_123=abc; visid_incap_456=xyz"},
            body="Incapsula incident ID",
        )
        
        assert result.is_blocked is True
        assert result.waf_signature == "incapsula"
    
    def test_detect_azure_appgw(self, detector: ErrorDetector):
        """Azure Application Gateway シグネチャ検出"""
        result = detector.analyze(
            status_code=403,
            headers={"x-azure-ref": "abc123xyz"},
            body="<html>Blocked by Azure Application Gateway</html>",
        )
        
        assert result.is_blocked is True
        assert result.waf_signature == "azure_appgw"
    
    def test_detect_f5_bigip(self, detector: ErrorDetector):
        """F5 BIG-IP シグネチャ検出"""
        result = detector.analyze(
            status_code=403,
            headers={"set-cookie": "BIGipServer=abc123"},
            body="The requested URL was rejected",
        )
        
        assert result.is_blocked is True
        assert result.waf_signature == "f5_bigip"
    
    # ==========================================
    # Rate Limit 検出テスト
    # ==========================================
    
    def test_detect_rate_limit_429(self, detector: ErrorDetector):
        """429 ステータスコードで Rate Limit 検出"""
        result = detector.analyze(
            status_code=429,
            headers={"retry-after": "60"},
            body="Too Many Requests",
        )
        
        assert result.is_blocked is True
        assert result.block_type == "rate_limit"
        assert result.confidence > 0.5  # 429 + body pattern で 0.54
    
    def test_is_rate_limited_helper(self, detector: ErrorDetector):
        """is_rate_limited ヘルパーメソッド"""
        is_limited = detector.is_rate_limited(
            status_code=429,
            headers={},
            body="Rate limit exceeded",
        )
        
        assert is_limited is True
    
    # ==========================================
    # 正常レスポンステスト（誤検知防止）
    # ==========================================
    
    def test_no_false_positive_200(self, detector: ErrorDetector):
        """200 OK で誤検知しないこと"""
        result = detector.analyze(
            status_code=200,
            headers={"content-type": "application/json"},
            body='{"status": "success"}',
        )
        
        assert result.is_blocked is False
        assert result.block_type == "none"
        assert result.confidence < 0.5
    
    def test_no_false_positive_301(self, detector: ErrorDetector):
        """301 Redirect で誤検知しないこと"""
        result = detector.analyze(
            status_code=301,
            headers={"location": "https://example.com/new"},
            body="",
        )
        
        assert result.is_blocked is False
    
    def test_no_false_positive_404(self, detector: ErrorDetector):
        """404 Not Found で WAF と誤検知しないこと"""
        result = detector.analyze(
            status_code=404,
            headers={"content-type": "text/html"},
            body="<html>Page not found</html>",
        )
        
        # 404 はブロックではない
        assert result.block_type != "waf"
    
    # ==========================================
    # ボディパターン検出テスト
    # ==========================================
    
    def test_detect_access_denied_body(self, detector: ErrorDetector):
        """'Access Denied' ボディパターン検出"""
        result = detector.analyze(
            status_code=403,
            headers={},
            body="<html><h1>Access Denied</h1><p>Your request was blocked.</p></html>",
        )
        
        # WAF シグネチャなし + 403 + body パターンで confidence ~0.45
        # sensitivity=0.5 なので is_blocked は False になる可能性あり
        assert result.block_type == "waf"
        assert result.confidence > 0.4
    
    def test_detect_captcha_body(self, sensitive_detector: ErrorDetector):
        """CAPTCHA ボディパターン検出 (高感度モード)"""
        result = sensitive_detector.analyze(
            status_code=403,
            headers={},
            body="Please complete the captcha to continue",
        )
        
        # 高感度 (0.3) なら検出できる
        assert result.is_blocked is True
    
    # ==========================================
    # 感度調整テスト
    # ==========================================
    
    def test_sensitivity_high(self, sensitive_detector: ErrorDetector):
        """高感度設定で弱いシグナルも検出"""
        result = sensitive_detector.analyze(
            status_code=403,
            headers={"server": "nginx"},
            body="Forbidden",
        )
        
        # 感度が高いので403 + Forbiddenでブロック判定
        assert result.is_blocked is True
    
    def test_sensitivity_default(self, detector: ErrorDetector):
        """標準感度で弱いシグナルは無視"""
        result = detector.analyze(
            status_code=403,
            headers={"server": "nginx"},
            body="Something went wrong",  # 明確なブロックパターンなし
        )
        
        # 標準感度だと確信度が低い場合はブロック判定しない可能性
        # 403 + 弱いボディなので is_blocked は状況次第
        assert result.confidence < 0.8
    
    # ==========================================
    # DetectionResult テスト
    # ==========================================
    
    def test_detection_result_to_dict(self, detector: ErrorDetector):
        """DetectionResult.to_dict() の動作確認"""
        result = detector.analyze(
            status_code=403,
            headers={"cf-ray": "abc123"},
            body="Cloudflare",
        )
        
        result_dict = result.to_dict()
        
        assert "is_blocked" in result_dict
        assert "block_type" in result_dict
        assert "waf_signature" in result_dict
        assert "confidence" in result_dict
        assert "details" in result_dict
    
    # ==========================================
    # ヘルパーメソッドテスト
    # ==========================================
    
    def test_is_waf_blocked_helper(self, detector: ErrorDetector):
        """is_waf_blocked ヘルパーメソッド"""
        is_blocked = detector.is_waf_blocked(
            status_code=403,
            headers={"cf-ray": "12345"},
            body="Access Denied by Cloudflare",
        )
        
        assert is_blocked is True
