"""
RaceConditionTester ユニットテスト

並列リクエスト送信と結果分析ロジックの検証
"""

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock
from src.core.attack.race_condition_tester import RaceConditionTester
from src.core.infra.network_client import AsyncNetworkClient, NetworkResponse

class TestRaceConditionTester:
    
    @pytest.fixture
    def mock_client(self):
        client = AsyncMock(spec=AsyncNetworkClient)
        # request メソッドは NetworkResponse を返す
        client.request.return_value = NetworkResponse(
            status=200, 
            body="OK", 
            headers={}, 
            elapsed=0.1,
            url="http://test.com"
        )
        return client
    
    @pytest.mark.asyncio
    async def test_race_execution(self, mock_client):
        """並列実行テスト"""
        tester = RaceConditionTester(client=mock_client, default_concurrency=5)
        
        results = await tester.test_race(
            method="POST",
            url="http://test.com/api/coupon",
            json={"coupon": "SALE2024"}
        )
        
        assert len(results) == 5
        assert mock_client.request.call_count == 5
        
    @pytest.mark.asyncio
    async def test_concurrency_control(self, mock_client):
        """並列数制御テスト"""
        tester = RaceConditionTester(client=mock_client, default_concurrency=3)
        
        # 通常
        await tester.test_race("GET", "http://test.com")
        assert mock_client.request.call_count == 3
        mock_client.request.reset_mock()
        
        # Aggressive
        await tester.test_race("GET", "http://test.com", aggressive=True)
        assert mock_client.request.call_count == 10
        mock_client.request.reset_mock()
        
        # Custom
        await tester.test_race("GET", "http://test.com", custom_concurrency=7)
        assert mock_client.request.call_count == 7
        
    def test_analyze_results(self, mock_client):
        """結果分析テスト"""
        tester = RaceConditionTester(client=mock_client)
        
        def make_resp(status, body):
            return NetworkResponse(
                status=status, 
                body=body, 
                headers={}, 
                elapsed=0.1, 
                url="http://test.com"
            )
        
        # 成功1回（正常）
        r1 = [
            make_resp(200, "OK"),
            make_resp(400, "Used"),
            make_resp(400, "Used")
        ]
        assert tester.analyze_results(r1) is False
        
        # 成功2回（異常＝脆弱性あり）
        r2 = [
            make_resp(200, "OK"),
            make_resp(200, "OK"), # Race成功
            make_resp(400, "Used")
        ]
        assert tester.analyze_results(r2) is True
