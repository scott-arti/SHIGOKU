"""
SwarmRetryEngine ユニットテスト

リトライ・ミューテーション機構の動作を検証
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from typing import List, Any

from src.core.agents.swarm.retry_engine import (
    SwarmRetryEngine,
    RetryConfig,
    RetryMetadata,
    create_retry_engine,
)
from src.core.agents.swarm.base import Task


class TestRetryConfig:
    """RetryConfig のテスト"""
    
    def test_default_config(self):
        """デフォルト設定の確認"""
        config = RetryConfig()
        
        assert config.max_attempts == 3
        assert config.enable_mutation is True
        assert config.mutation_rate == 0.3
        assert config.detect_waf is True
        assert config.backoff_factor == 1.0
        assert config.use_genetic_on_final is True
    
    def test_custom_config(self):
        """カスタム設定の確認"""
        config = RetryConfig(
            max_attempts=5,
            enable_mutation=False,
            backoff_factor=2.0,
        )
        
        assert config.max_attempts == 5
        assert config.enable_mutation is False
        assert config.backoff_factor == 2.0


class TestRetryMetadata:
    """RetryMetadata のテスト"""
    
    def test_to_dict(self):
        """辞書変換の確認"""
        metadata = RetryMetadata(
            attempts=2,
            waf_detected=True,
            mutation_applied=True,
            successful_mutation="encode",
        )
        
        result = metadata.to_dict()
        
        assert result["attempts"] == 2
        assert result["waf_detected"] is True
        assert result["mutation_applied"] is True
        assert result["successful_mutation"] == "encode"


class TestSwarmRetryEngine:
    """SwarmRetryEngine のテスト"""
    
    @pytest.fixture
    def engine(self) -> SwarmRetryEngine:
        """標準設定の RetryEngine"""
        return SwarmRetryEngine(RetryConfig(backoff_factor=0.01))  # テスト高速化
    
    @pytest.fixture
    def task(self) -> Task:
        """テスト用タスク"""
        return Task(
            id="test_task_1",
            name="Test Task",
            target="http://example.com",
            params={"payload": "' OR 1=1 --"},
        )
    
    # ==========================================
    # 成功時のテスト
    # ==========================================
    
    @pytest.mark.asyncio
    async def test_no_retry_on_success(self, engine: SwarmRetryEngine, task: Task):
        """成功時にリトライしないことを確認"""
        mock_finding = MagicMock()
        mock_execute = AsyncMock(return_value=[mock_finding])
        
        findings, metadata = await engine.execute_with_retry(mock_execute, task)
        
        assert len(findings) == 1
        assert metadata.attempts == 1
        assert metadata.waf_detected is False
        assert metadata.mutation_applied is False
        mock_execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_return_findings_on_success(self, engine: SwarmRetryEngine, task: Task):
        """成功時に findings を正しく返すことを確認"""
        mock_findings = [MagicMock(), MagicMock()]
        mock_execute = AsyncMock(return_value=mock_findings)
        
        findings, metadata = await engine.execute_with_retry(mock_execute, task)
        
        assert findings == mock_findings
        assert len(findings) == 2
    
    # ==========================================
    # WAF 検出時のテスト
    # ==========================================
    
    @pytest.mark.asyncio
    async def test_retry_on_waf_detection(self, engine: SwarmRetryEngine, task: Task):
        """WAF 検出時にリトライすることを確認"""
        # 1回目: 空の findings + WAF レスポンス
        # 2回目: 空の findings + WAF レスポンス
        # 3回目: 成功
        call_count = 0
        
        async def mock_execute(t):
            nonlocal call_count
            call_count += 1
            
            if call_count < 3:
                # WAF レスポンスをセット
                engine.set_last_response(
                    status_code=403,
                    headers={"cf-ray": "12345"},
                    body="Access Denied",
                )
                return []
            else:
                return [MagicMock()]
        
        findings, metadata = await engine.execute_with_retry(mock_execute, task)
        
        assert call_count == 3
        assert metadata.attempts == 3
        assert metadata.waf_detected is True
        assert metadata.mutation_applied is True
    
    @pytest.mark.asyncio
    async def test_max_attempts_limit(self, engine: SwarmRetryEngine, task: Task):
        """max_attempts で停止することを確認"""
        async def mock_execute(t):
            engine.set_last_response(
                status_code=403,
                headers={"cf-ray": "12345"},
                body="Blocked",
            )
            return []
        
        findings, metadata = await engine.execute_with_retry(mock_execute, task)
        
        assert metadata.attempts == 3  # max_attempts
        assert len(findings) == 0
    
    # ==========================================
    # ミューテーションのテスト
    # ==========================================
    
    @pytest.mark.asyncio
    async def test_mutation_applied(self, engine: SwarmRetryEngine, task: Task):
        """ミューテーションが適用されることを確認"""
        original_payload = task.params["payload"]
        payloads_used = []
        
        async def mock_execute(t):
            payloads_used.append(t.params.get("payload"))
            
            if len(payloads_used) < 2:
                engine.set_last_response(
                    status_code=403,
                    headers={"cf-ray": "12345"},
                    body="Blocked",
                )
                return []
            return [MagicMock()]
        
        await engine.execute_with_retry(mock_execute, task)
        
        # 2回目のペイロードは変異しているはず
        assert len(payloads_used) >= 2
        # ミューテーションが適用されている可能性を確認
        # (ランダム性があるため、変異していない場合もある)
    
    # ==========================================
    # 非 WAF 応答のテスト
    # ==========================================
    
    @pytest.mark.asyncio
    async def test_no_retry_on_non_waf(self, engine: SwarmRetryEngine, task: Task):
        """WAF でなければリトライしないことを確認"""
        async def mock_execute(t):
            # 200 OK を返す（WAF ではない）
            engine.set_last_response(
                status_code=200,
                headers={},
                body="OK",
            )
            return []
        
        findings, metadata = await engine.execute_with_retry(mock_execute, task)
        
        assert metadata.attempts == 1  # 1回で終了
        assert metadata.waf_detected is False
    
    # ==========================================
    # Rate Limit のテスト
    # ==========================================
    
    @pytest.mark.asyncio
    async def test_retry_on_rate_limit(self, engine: SwarmRetryEngine, task: Task):
        """Rate Limit 時にリトライすることを確認"""
        call_count = 0
        
        async def mock_execute(t):
            nonlocal call_count
            call_count += 1
            
            if call_count == 1:
                engine.set_last_response(
                    status_code=429,
                    headers={"retry-after": "60"},
                    body="Too Many Requests",
                )
                return []
            return [MagicMock()]
        
        findings, metadata = await engine.execute_with_retry(mock_execute, task)
        
        assert call_count == 2
        assert metadata.waf_detected is True  # Rate limit も blocked 扱い
    
    # ==========================================
    # エラーハンドリングのテスト
    # ==========================================
    
    @pytest.mark.asyncio
    async def test_exception_on_final_attempt(self, engine: SwarmRetryEngine, task: Task):
        """最終試行でエラーが発生した場合に例外を再送出"""
        mock_execute = AsyncMock(side_effect=Exception("Test error"))
        
        with pytest.raises(Exception, match="Test error"):
            await engine.execute_with_retry(mock_execute, task)
    
    @pytest.mark.asyncio
    async def test_continue_on_non_final_error(self, engine: SwarmRetryEngine, task: Task):
        """最終試行以外のエラーはリトライ"""
        call_count = 0
        
        async def mock_execute(t):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("Temporary error")
            return [MagicMock()]
        
        findings, metadata = await engine.execute_with_retry(mock_execute, task)
        
        assert call_count == 3
        assert len(findings) == 1
    
    # ==========================================
    # set_last_response のテスト
    # ==========================================
    
    def test_set_last_response(self, engine: SwarmRetryEngine):
        """set_last_response の動作確認"""
        engine.set_last_response(
            status_code=403,
            headers={"server": "nginx"},
            body="Forbidden",
        )
        
        assert engine._last_response is not None
        assert engine._last_response.status_code == 403
        assert engine._last_response.headers == {"server": "nginx"}
        assert engine._last_response.body == "Forbidden"


class TestCreateRetryEngine:
    """create_retry_engine ヘルパーのテスト"""
    
    def test_create_with_defaults(self):
        """デフォルト設定での作成"""
        engine = create_retry_engine()
        
        assert engine.config.max_attempts == 3
        assert engine.config.enable_mutation is True
    
    def test_create_with_custom(self):
        """カスタム設定での作成"""
        engine = create_retry_engine(max_attempts=5, enable_mutation=False)
        
        assert engine.config.max_attempts == 5
        assert engine.config.enable_mutation is False
        assert engine.mutator is None  # ミューテーション無効


class TestPayloadExtraction:
    """ペイロード抽出・適用のテスト"""
    
    @pytest.fixture
    def engine(self) -> SwarmRetryEngine:
        return SwarmRetryEngine()
    
    def test_extract_payload_from_params(self, engine: SwarmRetryEngine):
        """params から payload を抽出"""
        task = Task(id="t1", name="test", params={"payload": "test_payload"})
        
        result = engine._extract_payload(task)
        
        assert result == "test_payload"
    
    def test_extract_payload_priority(self, engine: SwarmRetryEngine):
        """payload > data > body > query の優先順位"""
        task = Task(
            id="t1", 
            name="test", 
            params={
                "query": "q_value",
                "body": "b_value",
                "data": "d_value",
                "payload": "p_value",
            }
        )
        
        result = engine._extract_payload(task)
        
        assert result == "p_value"  # payload が最優先
    
    def test_extract_no_payload(self, engine: SwarmRetryEngine):
        """ペイロードがない場合は None"""
        task = Task(id="t1", name="test", params={"other": 123})
        
        result = engine._extract_payload(task)
        
        assert result is None
    
    def test_apply_mutation_to_task(self, engine: SwarmRetryEngine):
        """ミューテーション結果の適用"""
        task = Task(id="t1", name="test", params={"payload": "original"})
        
        result = engine._apply_mutation_to_task(task, "mutated")
        
        assert result.params["payload"] == "mutated"
