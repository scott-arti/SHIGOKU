"""
バグ修正回帰テスト（2026-01-05 Phase 2実施分）

テスト対象:
- C-3: ExecutionContext.success_rateのゼロ除算防止（プロパティ化）
- H-2: MasterConductorの並行アクセスロック（RLock）
- H-4: _deserialize_task_queueのタプル返却
- H-5: タスクID生成のUUID統一
- M-1: IDORCrossTester類似度計算改善
- M-2: レスポンストランケート3000文字化
- M-5: allow_redirectsパラメータ追加
- L-1: タイムアウト設定化
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
import json
import threading


class TestC3_ExecutionContextSuccessRate:
    """C-3: ゼロ除算防止テスト"""
    
    def test_success_rate_zero_attempts(self):
        """試行回数0でもゼロ除算が発生しないこと"""
        from src.core.engine.master_conductor import ExecutionContext
        
        ctx = ExecutionContext()
        # ゼロ除算が発生しないこと
        assert ctx.success_rate == 0.0
        assert ctx.total_attempts == 0
        assert ctx.successful_attempts == 0
    
    def test_success_rate_after_update(self):
        """成功率更新後に正しい値が返ること"""
        from src.core.engine.master_conductor import ExecutionContext
        
        ctx = ExecutionContext()
        ctx.update_success_rate(True)
        ctx.update_success_rate(False)
        ctx.update_success_rate(True)
        
        assert ctx.total_attempts == 3
        assert ctx.successful_attempts == 2
        assert ctx.success_rate == pytest.approx(2/3)
    
    def test_success_rate_is_property(self):
        """success_rateがプロパティであること"""
        from src.core.engine.master_conductor import ExecutionContext
        
        ctx = ExecutionContext()
        # プロパティなので直接代入は不可
        with pytest.raises(AttributeError):
            ctx.success_rate = 0.5


class TestH2_ParallelAccessLock:
    """H-2: 並行アクセスロックテスト"""
    
    def test_conductor_has_state_lock(self):
        """ConductorにRLockが存在すること"""
        from src.core.engine.master_conductor import MasterConductor
        
        conductor = MasterConductor()
        assert hasattr(conductor, '_state_lock')
        assert isinstance(conductor._state_lock, type(threading.RLock()))
    
    def test_state_lock_is_reentrant(self):
        """ロックが再入可能であること"""
        from src.core.engine.master_conductor import MasterConductor
        
        conductor = MasterConductor()
        # 同じスレッドから2回取得してもデッドロックしないこと
        with conductor._state_lock:
            with conductor._state_lock:
                pass  # デッドロックしなければOK


class TestH4_DeserializeTaskQueueTuple:
    """H-4: タスクキューデシリアライズのタプル返却テスト"""
    
    def test_deserialize_returns_tuple(self):
        """_deserialize_task_queueがタプルを返すこと"""
        from src.core.engine.master_conductor import MasterConductor
        
        conductor = MasterConductor()
        
        valid_task = json.dumps({
            "id": "task_1",
            "name": "Test Task",
            "agent_type": "test",
            "action": "run",
            "params": {},
            "priority": 50,
            "parent_id": None
        })
        
        result = conductor._deserialize_task_queue([valid_task])
        
        assert isinstance(result, tuple)
        assert len(result) == 2
        tasks, failed = result
        assert len(tasks) == 1
        assert len(failed) == 0
    
    def test_deserialize_tracks_failed_tasks(self):
        """デシリアライズ失敗タスクが追跡されること"""
        from src.core.engine.master_conductor import MasterConductor
        
        conductor = MasterConductor()
        
        valid_task = json.dumps({
            "id": "task_1",
            "name": "Test Task",
            "agent_type": "test",
            "action": "run",
        })
        invalid_task = "not valid json {"
        
        tasks, failed = conductor._deserialize_task_queue([valid_task, invalid_task])
        
        assert len(tasks) == 1
        assert len(failed) == 1


class TestH5_UUIDTaskId:
    """H-5: タスクID UUIDテスト"""
    
    def test_uuid_import_in_master_conductor(self):
        """master_conductor.pyでuuidがインポートされていること"""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "master_conductor",
            "/home/bbb/Documents/App/Shigoku/src/core/engine/master_conductor.py"
        )
        # ソースコードを読み込んでuuidインポートを確認
        with open("/home/bbb/Documents/App/Shigoku/src/core/engine/master_conductor.py", "r") as f:
            source = f.read()
        
        assert "import uuid" in source
        assert "uuid.uuid4()" in source or "uuid4().hex" in source


class TestM1_BodySimilarityImproved:
    """M-1: レスポンスボディ類似度計算改善テスト"""
    
    def test_similarity_with_identical_bodies(self):
        """同一ボディで1.0が返ること"""
        from src.core.security.idor_cross_tester import IDORCrossTester
        
        tester = IDORCrossTester.__new__(IDORCrossTester)
        
        body = '{"id": 1, "name": "test"}'
        similarity = tester._calculate_body_similarity(body, body)
        
        assert similarity == 1.0
    
    def test_similarity_ignores_timestamp(self):
        """タイムスタンプを無視して類似度を計算すること"""
        from src.core.security.idor_cross_tester import IDORCrossTester
        
        tester = IDORCrossTester.__new__(IDORCrossTester)
        
        body1 = '{"id": 1, "name": "test", "timestamp": "2026-01-01T00:00:00Z"}'
        body2 = '{"id": 1, "name": "test", "timestamp": "2026-01-05T12:00:00Z"}'
        
        similarity = tester._calculate_body_similarity(body1, body2)
        
        # タイムスタンプを除去すると同一なので高い類似度
        assert similarity == 1.0
    
    def test_similarity_with_empty_bodies(self):
        """空ボディで0.0が返ること"""
        from src.core.security.idor_cross_tester import IDORCrossTester
        
        tester = IDORCrossTester.__new__(IDORCrossTester)
        
        assert tester._calculate_body_similarity("", "test") == 0.0
        assert tester._calculate_body_similarity("test", "") == 0.0
        assert tester._calculate_body_similarity("", "") == 0.0
    
    def test_normalize_response_removes_dynamic_fields(self):
        """_normalize_responseが動的フィールドを除去すること"""
        from src.core.security.idor_cross_tester import IDORCrossTester
        
        tester = IDORCrossTester.__new__(IDORCrossTester)
        
        body = '{"id": 1, "token": "abc123", "csrf": "xyz", "data": "important"}'
        normalized = tester._normalize_response(body)
        
        # JSON形式であること
        data = json.loads(normalized)
        assert "id" in data
        assert "data" in data
        assert "token" not in data
        assert "csrf" not in data


class TestM5_AllowRedirectsParameter:
    """M-5: allow_redirectsパラメータテスト"""
    
    def test_make_request_as_accepts_allow_redirects(self):
        """make_request_asがallow_redirectsパラメータを受け付けること"""
        from src.core.security.multi_account_session import MultiAccountSessionManager
        import inspect
        
        sig = inspect.signature(MultiAccountSessionManager.make_request_as)
        params = list(sig.parameters.keys())
        
        assert 'allow_redirects' in params
    
    def test_allow_redirects_default_false(self):
        """allow_redirectsのデフォルト値がFalseであること"""
        from src.core.security.multi_account_session import MultiAccountSessionManager
        import inspect
        
        sig = inspect.signature(MultiAccountSessionManager.make_request_as)
        allow_redirects_param = sig.parameters['allow_redirects']
        
        assert allow_redirects_param.default is False


class TestL1_TimeoutConfiguration:
    """L-1: タイムアウト設定化テスト"""
    
    def test_config_has_agent_execution_timeout(self):
        """設定にagent_execution_timeoutが存在すること"""
        from src.config import settings
        
        assert hasattr(settings, 'agent_execution_timeout')
        assert settings.agent_execution_timeout == 60
    
    def test_timeout_is_configurable_via_env(self):
        """環境変数でタイムアウトを変更できること"""
        import os
        
        # 環境変数を設定（テスト後にリセット）
        original = os.environ.get('SHIGOKU_AGENT_EXECUTION_TIMEOUT')
        try:
            os.environ['SHIGOKU_AGENT_EXECUTION_TIMEOUT'] = '120'
            
            # 新しいSettingsインスタンスを作成
            from src.config import Settings
            new_settings = Settings()
            
            assert new_settings.agent_execution_timeout == 120
        finally:
            if original is None:
                os.environ.pop('SHIGOKU_AGENT_EXECUTION_TIMEOUT', None)
            else:
                os.environ['SHIGOKU_AGENT_EXECUTION_TIMEOUT'] = original
