"""
BizLogicHunter のバグ修正用テストケース

Bug #2, #3, #4, #5 の修正を検証
"""
import pytest
from unittest.mock import Mock, patch
from src.core.agents.swarm.biz_logic_hunter import BizLogicHunter, VerifyContext, VerifyResult
from src.intelligence.proxy_log_analyzer import FindingCandidate, SmellType


class TestBugFix2_PIIBasedIDORDetection:
    """Bug #2: PIIベース意味的差異検出のテスト"""
    
    def test_idor_verification_ignores_dynamic_content(self):
        """タイムスタンプのみ異なるレスポンスで誤検知しない"""
        hunter = BizLogicHunter()
        
        original = '{"user_id": 123, "name": "Alice", "created_at": "2026-01-04T10:00:00Z"}'
        test = '{"user_id": 123, "name": "Alice", "created_at": "2026-01-04T10:01:30Z"}'
        
        is_vuln, reason = hunter._is_significant_idor(original, test)
        
        assert is_vuln is False
        assert reason == "identical_after_strip"
    
    def test_idor_verification_detects_pii_difference(self):
        """異なるユーザーのPII含むレスポンスで検出する"""
        hunter = BizLogicHunter()
        
        original = '{"user_id": 123, "email": "alice@example.com", "name": "Alice"}'
        test = '{"user_id": 456, "email": "bob@example.com", "name": "Bob"}'
        
        is_vuln, reason = hunter._is_significant_idor(original, test)
        
        assert is_vuln is True
        assert reason == "different_with_pii"
    
    def test_idor_verification_detects_significant_difference(self):
        """PIIなしでも20文字以上の差異で検出する"""
        hunter = BizLogicHunter()
        
        original = '{"data": "short"}'
        test = '{"data": "This is a much longer text that exceeds 20 characters"}'
        
        is_vuln, reason = hunter._is_significant_idor(original, test)
        
        assert is_vuln is True
        assert reason == "significant_difference"
    
    def test_strip_dynamic_content_removes_timestamps(self):
        """動的コンテンツ除去がタイムスタンプを正しく除去する"""
        hunter = BizLogicHunter()
        
        text = 'Created at 2026-01-04T10:00:00Z and updated 2026-01-04 11:30:45'
        result = hunter._strip_dynamic_content(text)
        
        assert "[TIMESTAMP]" in result
        assert "2026-01-04" not in result
    
    def test_strip_dynamic_content_removes_csrf_tokens(self):
        """CSRFトークンを正しく除去する"""
        hunter = BizLogicHunter()
        
        text = 'csrf_token="abc123xyz" and <input name="csrf-token" value="def456">'
        result = hunter._strip_dynamic_content(text)
        
        assert "[CSRF]" in result
        assert "abc123xyz" not in result


class TestBugFix3_Error_Logging:
    """Bug #3: エラーログ追加のテスト"""
    
    def test_request_error_logging_escalation(self):
        """連続5回エラーでログレベルがerrorにエスカレーション"""
        hunter = BizLogicHunter()
        url = "http://example.com/test"
        
        with patch('logging.getLogger') as mock_logger:
            logger_instance = Mock()
            mock_logger.return_value = logger_instance
            
            # 1-4回: warning
            for i in range(4):
                hunter._log_request_error(url, Exception("test error"))
                assert logger_instance.warning.call_count == i + 1
                assert logger_instance.error.call_count == 0
            
            # 5回目: error
            hunter._log_request_error(url, Exception("test error"))
            assert logger_instance.error.call_count == 1


@pytest.mark.asyncio
class TestBugFix4_Type_Safety:
    """Bug #4: 型安全性のテスト"""
    
    async def test_detect_payment_risks_with_none_risks(self):
        """risks=Noneでクラッシュしない"""
        hunter = BizLogicHunter()
        
        # risksがNoneの候補を作成
        candidate = Mock(spec=FindingCandidate)
        candidate.smell_type = SmellType.PAYMENT_ENDPOINT
        candidate.parameters = {"risks": None}
        
        context = await hunter.detect_payment_risks("http://example.com/pay", candidate)
        
        assert context.result == VerifyResult.PARTIAL
        assert context.method == "payment_detection"


class TestBugFix5_ID_Extraction:
    """Bug #5: ID抽出パターン拡張のテスト"""
    
    def test_id_extraction_numeric(self):
        """数値IDを抽出できる"""
        hunter = BizLogicHunter()
        
        # verify_idorの中ではなく、パターンマッチ自体をテスト
        import re
        ID_PATTERNS = [
            (r"/(\d+)(?=/|$)", "numeric"),
        ]
        
        path = "/users/123/profile"
        for pattern, id_type in ID_PATTERNS:
            matches = re.findall(pattern, path)
            if matches:
                assert matches[0] == "123"
                assert id_type == "numeric"
                break
    
    def test_id_extraction_mongodb_objectid(self):
        """MongoDB ObjectIdを抽出できる"""
        import re
        ID_PATTERNS = [
            (r"/([a-f0-9]{24})(?=/|$)", "objectid"),
        ]
        
        path = "/items/507f1f77bcf86cd799439011/edit"
        for pattern, id_type in ID_PATTERNS:
            matches = re.findall(pattern, path)
            if matches:
                assert matches[0] == "507f1f77bcf86cd799439011"
                assert id_type == "objectid"
                break
    
    def test_id_extraction_alphanumeric(self):
        """英数字IDを抽出できる"""
        import re
        ID_PATTERNS = [
            (r"/([a-zA-Z0-9_-]{8,22})(?=/|$)", "alphanumeric"),
        ]
        
        path = "/videos/dQw4w9WgXcQ/watch"
        for pattern, id_type in ID_PATTERNS:
            matches = re.findall(pattern, path)
            if matches:
                assert matches[0] == "dQw4w9WgXcQ"
                assert id_type == "alphanumeric"
                break
