import pytest
from unittest.mock import MagicMock, patch
import time

from src.core.engine.resource_manager import SystemResourceManager
from src.core.engine.parallel_orchestrator import ParallelOrchestrator, TaskConfig

@pytest.fixture
def mock_orchestrator():
    orch = MagicMock(spec=ParallelOrchestrator)
    # TaskConfigをリアルオブジェクトとして作成（MagicMockだと属性アクセスが変になるため）
    orch.configs = {
        "default": TaskConfig(category="default", workers=3, min_workers=1, max_workers=10),
        "high_load": TaskConfig(category="high_load", workers=10, min_workers=1, max_workers=20)
    }
    
    # get_category_metricsのモック
    # side_effectではなくreturn_valueで辞書を返すようにする（簡易化）
    # 個別のテストケースで override させる
    orch.get_category_metrics.return_value = {
        "avg_latency": 0.5, 
        "throttle_rate": 0.0, 
        "active_tasks": 5
    }
    
    # update_config のモック動作を実装 (実際に configs を書き換える)
    def update_config_side_effect(category, workers=None, rate_limit=None):
        if category in orch.configs:
            if workers is not None:
                orch.configs[category].workers = workers
            # rate_limit は省略
            
    orch.update_config.side_effect = update_config_side_effect
    
    return orch

@pytest.fixture
def resource_manager(mock_orchestrator):
    # Singletonリセット (テスト用ハック)
    SystemResourceManager._instance = None
    rm = SystemResourceManager(mock_orchestrator)
    rm.check_interval = 0.1 # 高速化
    return rm

def test_emergency_brake(resource_manager, mock_orchestrator):
    """緊急ブレーキ: メモリ不足時は並列数を半減"""
    with patch("psutil.virtual_memory") as mock_mem:
        mock_mem.return_value.percent = 90.0 # Critical
        
        # 実行
        resource_manager._check_and_tune()
        
        # 検証: workersが半減しているか (3->1, 10->5)
        # update_configが呼ばれたかチェック
        calls = mock_orchestrator.update_config.call_args_list
        assert len(calls) >= 2
        
        # args[1] (workers) を確認
        # default: 3 // 2 = 1
        # high_load: 10 // 2 = 5
        
        # 呼び出し引数をセットで確認
        updated_workers = {}
        for call in calls:
            cat = call[0][0]
            w = call[1]['workers']
            updated_workers[cat] = w
            
        assert updated_workers['default'] == 1
        assert updated_workers['high_load'] == 5

def test_scale_up(resource_manager, mock_orchestrator):
    """スケールアップ: 余裕がある時は並列数を増加"""
    # 初期状態を確認
    assert mock_orchestrator.configs["default"].workers == 3
    assert mock_orchestrator.configs["high_load"].workers == 10

    with patch("psutil.virtual_memory") as mock_mem, \
         patch("psutil.cpu_percent") as mock_cpu:
        
        mock_mem.return_value.percent = 50.0 # Safe
        mock_cpu.return_value = 20.0
        
        # Orchestratorのメトリクスを「低遅延」に設定
        mock_orchestrator.get_category_metrics.return_value = {
            "avg_latency": 0.1, # Target(1.0) * 0.5 (0.5) より小さい
            "throttle_rate": 0.0,
            "active_tasks": 5
        }
        
        resource_manager._check_and_tune()
        
        # 検証: configsの値が直接更新されているか
        assert mock_orchestrator.configs["default"].workers == 4
        assert mock_orchestrator.configs["high_load"].workers == 11

def test_scale_down_on_latency(resource_manager, mock_orchestrator):
    """スケールダウン: 遅延発生時は並列数を減少"""
    with patch("psutil.virtual_memory") as mock_mem, \
         patch("psutil.cpu_percent") as mock_cpu:
        
        mock_mem.return_value.percent = 50.0
        mock_cpu.return_value = 20.0
        
        # Orchestratorのメトリクスを「高遅延」に設定
        mock_orchestrator.get_category_metrics.return_value = {
            "avg_latency": 2.0, # Target(1.0) * 1.5 (1.5) より大きい
            "throttle_rate": 0.0,
            "active_tasks": 5
        }
        
        resource_manager._check_and_tune()
        
        # 検証: workersが減少しているか
        assert mock_orchestrator.configs["default"].workers == 2
        assert mock_orchestrator.configs["high_load"].workers == 9
