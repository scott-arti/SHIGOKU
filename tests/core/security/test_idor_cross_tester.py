"""
Tests for IDORCrossTester
"""
from dataclasses import dataclass
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

from src.core.security.idor_cross_tester import (
    CrossTestResult,
    CrossTestReport,
    IDORCrossTester,
    IDORTestCandidate,
    create_idor_cross_tester,
)
from src.core.security.multi_account_session import MultiAccountSessionManager


class MockSessionManager:
    """テスト用のモックセッションマネージャー"""
    
    def __init__(self, configured: bool = True):
        self._configured = configured
        self._responses = {}
    
    def is_configured(self) -> bool:
        return self._configured
    
    def set_response(self, session_name: str, status_code: int, body: str):
        """モックレスポンスを設定"""
        response = MagicMock()
        response.status_code = status_code
        response.text = body
        self._responses[session_name] = response
    
    def make_request_as(self, session_name: str, method: str, url: str, **kwargs):
        return self._responses.get(session_name)


class TestCrossTestResult:
    """CrossTestResultのテスト"""

    def test_enum_values(self):
        """列挙値が正しく定義されていること"""
        assert CrossTestResult.IDOR_CONFIRMED.value == "idor_confirmed"
        assert CrossTestResult.ACCESS_DENIED.value == "access_denied"
        assert CrossTestResult.INCONCLUSIVE.value == "inconclusive"
        assert CrossTestResult.ERROR.value == "error"
        assert CrossTestResult.NOT_CONFIGURED.value == "not_configured"


class TestIDORCrossTester:
    """IDORCrossTesterのテスト"""

    def test_not_configured(self):
        """セッション未設定の場合NOT_CONFIGUREDを返す"""
        session_manager = MockSessionManager(configured=False)
        tester = IDORCrossTester(session_manager)
        
        candidate = IDORTestCandidate(endpoint="https://example.com/api/users/123")
        report = tester.execute_cross_test(candidate)
        
        assert report.result == CrossTestResult.NOT_CONFIGURED

    def test_idor_confirmed(self):
        """Attackerがvictimと同じデータを取得できる場合IDOR確定"""
        session_manager = MockSessionManager()
        victim_body = '{"id": 123, "email": "victim@example.com", "name": "Victim User"}'
        attacker_body = '{"id": 123, "email": "victim@example.com", "name": "Victim User"}'
        
        session_manager.set_response("victim", 200, victim_body)
        session_manager.set_response("attacker", 200, attacker_body)
        
        tester = IDORCrossTester(session_manager)
        
        candidate = IDORTestCandidate(endpoint="https://example.com/api/users/123")
        
        with patch.object(tester, '_guard') as mock_guard:
            from src.core.security.ethics_guard import ActionResult
            mock_guard.check_action.return_value = (ActionResult.ALLOWED, "")
            
            report = tester.execute_cross_test(candidate)
        
        assert report.result == CrossTestResult.IDOR_CONFIRMED
        assert report.finding is not None
        assert "IDOR" in report.finding.title
        assert report.details.get("contains_pii") is True

    def test_access_denied(self):
        """Attackerが403を受ける場合は正常にブロック"""
        session_manager = MockSessionManager()
        victim_body = '{"id": 123, "email": "victim@example.com"}'
        attacker_body = '{"error": "Forbidden"}'
        
        session_manager.set_response("victim", 200, victim_body)
        session_manager.set_response("attacker", 403, attacker_body)
        
        tester = IDORCrossTester(session_manager)
        
        candidate = IDORTestCandidate(endpoint="https://example.com/api/users/123")
        
        with patch.object(tester, '_guard') as mock_guard:
            from src.core.security.ethics_guard import ActionResult
            mock_guard.check_action.return_value = (ActionResult.ALLOWED, "")
            
            report = tester.execute_cross_test(candidate)
        
        assert report.result == CrossTestResult.ACCESS_DENIED
        assert report.finding is None
        assert report.details.get("reason") == "Properly blocked"

    def test_access_denied_401(self):
        """Attackerが401を受ける場合も正常にブロック"""
        session_manager = MockSessionManager()
        victim_body = '{"id": 123}'
        
        session_manager.set_response("victim", 200, victim_body)
        session_manager.set_response("attacker", 401, '{"error": "Unauthorized"}')
        
        tester = IDORCrossTester(session_manager)
        
        candidate = IDORTestCandidate(endpoint="https://example.com/api/users/123")
        
        with patch.object(tester, '_guard') as mock_guard:
            from src.core.security.ethics_guard import ActionResult
            mock_guard.check_action.return_value = (ActionResult.ALLOWED, "")
            
            report = tester.execute_cross_test(candidate)
        
        assert report.result == CrossTestResult.ACCESS_DENIED

    def test_inconclusive_victim_blocked(self):
        """Victimもアクセスできない場合は判定不能"""
        session_manager = MockSessionManager()
        
        session_manager.set_response("victim", 403, '{"error": "Forbidden"}')
        session_manager.set_response("attacker", 403, '{"error": "Forbidden"}')
        
        tester = IDORCrossTester(session_manager)
        
        candidate = IDORTestCandidate(endpoint="https://example.com/api/users/123")
        
        with patch.object(tester, '_guard') as mock_guard:
            from src.core.security.ethics_guard import ActionResult
            mock_guard.check_action.return_value = (ActionResult.ALLOWED, "")
            
            report = tester.execute_cross_test(candidate)
        
        assert report.result == CrossTestResult.INCONCLUSIVE
        assert "Victim cannot access" in report.details.get("reason", "")

    def test_inconclusive_different_data(self):
        """異なるデータが返る場合は判定不能（部分的IDOR可能性）"""
        session_manager = MockSessionManager()
        victim_body = '{"id": 123, "email": "victim@example.com", "name": "Victim"}'
        attacker_body = '{"id": 456, "email": "attacker@example.com", "name": "Attacker"}'  # 全く異なる
        
        session_manager.set_response("victim", 200, victim_body)
        session_manager.set_response("attacker", 200, attacker_body)
        
        tester = IDORCrossTester(session_manager)
        
        candidate = IDORTestCandidate(endpoint="https://example.com/api/users/123")
        
        with patch.object(tester, '_guard') as mock_guard:
            from src.core.security.ethics_guard import ActionResult
            mock_guard.check_action.return_value = (ActionResult.ALLOWED, "")
            
            report = tester.execute_cross_test(candidate)
        
        # 類似度が低いため INCONCLUSIVEになる可能性
        assert report.result in (CrossTestResult.INCONCLUSIVE, CrossTestResult.IDOR_CONFIRMED)

    def test_collect_victim_resource_ids(self):
        """VictimのレスポンスからIDを抽出"""
        session_manager = MockSessionManager()
        response_body = '''
        {
            "items": [
                {"id": 123, "name": "Item 1"},
                {"id": 456, "name": "Item 2"},
                {"user_id": 789, "userId": 999}
            ]
        }
        '''
        session_manager.set_response("victim", 200, response_body)
        
        tester = IDORCrossTester(session_manager)
        
        with patch.object(tester, '_guard') as mock_guard:
            from src.core.security.ethics_guard import ActionResult
            mock_guard.check_action.return_value = (ActionResult.ALLOWED, "")
            
            ids = tester.collect_victim_resource_ids("https://example.com/api/items")
        
        assert "123" in ids
        assert "456" in ids
        assert "789" in ids
        assert "999" in ids

    def test_calculate_body_similarity_identical(self):
        """同一ボディの類似度は1.0"""
        session_manager = MockSessionManager()
        tester = IDORCrossTester(session_manager)
        
        body = '{"id": 123, "email": "test@example.com"}'
        similarity = tester._calculate_body_similarity(body, body)
        
        assert similarity == 1.0

    def test_calculate_body_similarity_empty(self):
        """空ボディの類似度は0.0"""
        session_manager = MockSessionManager()
        tester = IDORCrossTester(session_manager)
        
        similarity = tester._calculate_body_similarity("", '{"id": 123}')
        
        assert similarity == 0.0

    def test_test_history(self):
        """テスト履歴が記録される"""
        session_manager = MockSessionManager()
        session_manager.set_response("victim", 200, '{"id": 123}')
        session_manager.set_response("attacker", 403, '{}')
        
        tester = IDORCrossTester(session_manager)
        
        candidate = IDORTestCandidate(endpoint="https://example.com/api/users/123")
        
        with patch.object(tester, '_guard') as mock_guard:
            from src.core.security.ethics_guard import ActionResult
            mock_guard.check_action.return_value = (ActionResult.ALLOWED, "")
            
            tester.execute_cross_test(candidate)
        
        history = tester.get_test_history()
        assert len(history) == 1
        assert history[0].candidate.endpoint == "https://example.com/api/users/123"
        
        tester.clear_history()
        assert len(tester.get_test_history()) == 0


class TestCreateIDORCrossTester:
    """create_idor_cross_tester関数のテスト"""

    def test_create(self):
        """IDORCrossTesterが作成される"""
        session_manager = MockSessionManager()
        tester = create_idor_cross_tester(session_manager, "TestProgram")
        
        assert isinstance(tester, IDORCrossTester)
        assert tester.program_name == "TestProgram"
