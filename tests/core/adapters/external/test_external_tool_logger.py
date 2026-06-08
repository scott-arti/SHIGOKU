"""
ExternalToolLoggerのテスト

ロギング詳細度制御とパフォーマンス閾値の動作検証
"""

import json
import logging
from unittest.mock import MagicMock, patch

import pytest

from src.core.adapters.external.external_tool_logger import (
    ExternalToolLogger,
    LogLevelConfig,
    PerformanceThresholds,
)
from src.core.adapters.external.base_external_adapter import ToolResult, ToolStatus


@pytest.fixture
def mock_logger():
    """モックロガー"""
    return MagicMock(spec=logging.Logger)


def test_info_execution_basic():
    """INFOレベル実行ログの基本テスト"""
    logger = ExternalToolLogger("dalfox")
    
    result = ToolResult(
        status=ToolStatus.SUCCESS,
        data={"findings": []},
        execution_time_ms=150.0
    )
    
    # モックロガーを設定
    with patch.object(logger, 'logger') as mock_log:
        logger.info_execution(["dalfox", "-u", "http://test.com"], result)
        
        # infoが呼ばれていること
        assert mock_log.info.called


def test_info_execution_with_performance_warning():
    """パフォーマンス警告付き実行ログテスト"""
    thresholds = PerformanceThresholds(
        warning_slow_factor=2.0,
        baseline_execution_time_ms=100.0
    )
    logger = ExternalToolLogger("dalfox", thresholds=thresholds)
    
    # 基準の2倍以上（200ms以上）で警告
    result = ToolResult(
        status=ToolStatus.SUCCESS,
        data={},
        execution_time_ms=250.0  # 2.5倍
    )
    
    with patch.object(logger, 'logger') as mock_log:
        logger.info_execution(["dalfox", "-u", "test"], result)
        
        # warningが呼ばれていること
        assert mock_log.warning.called
        
        # 警告メッセージにパフォーマンス情報が含まれる
        call_args = mock_log.warning.call_args[0][0]
        log_data = json.loads(call_args)
        assert "performance_warning" in log_data


def test_performance_threshold_not_triggered():
    """パフォーマンス閾値未達時のテスト"""
    thresholds = PerformanceThresholds(
        warning_slow_factor=5.0,
        baseline_execution_time_ms=1000.0
    )
    logger = ExternalToolLogger("dalfox", thresholds=thresholds)
    
    # 正常な実行時間（基準の5倍未満）
    result = ToolResult(
        status=ToolStatus.SUCCESS,
        data={},
        execution_time_ms=500.0  # 0.5倍（基準1000msに対して）
    )
    
    with patch.object(logger, 'logger') as mock_log:
        logger.info_execution(["dalfox"], result)
        
        # warningは呼ばれない
        assert not mock_log.warning.called
        # infoが呼ばれる
        assert mock_log.info.called


def test_debug_execution():
    """DEBUGレベル実行ログテスト"""
    logger = ExternalToolLogger("dalfox")
    
    result = ToolResult(
        status=ToolStatus.SUCCESS,
        data={"findings": [{"param": "q"}]},
        execution_time_ms=200.0,
        raw_output="test output",
        error_message=None,
        metadata={"version": "2.9.2"}
    )
    
    with patch.object(logger, 'logger') as mock_log:
        logger.debug_execution(
            ["dalfox", "-u", "http://test.com"],
            result,
            context={"target": "http://test.com"}
        )
        
        # debugが呼ばれていること
        assert mock_log.debug.called
        
        # 詳細情報が含まれる
        call_args = mock_log.debug.call_args[0][0]
        log_data = json.loads(call_args, strict=False)
        assert log_data["tool"] == "dalfox"
        assert "raw_output" in log_data
        assert "context" in log_data


def test_error_execution():
    """エラーログテスト"""
    logger = ExternalToolLogger("dalfox")
    
    exception = Exception("Connection timeout")
    
    with patch.object(logger, 'logger') as mock_log:
        logger.error_execution(
            ["dalfox", "-u", "http://test.com"],
            exception,
            context={"retry_count": 1}
        )
        
        # errorが呼ばれていること
        assert mock_log.error.called
        
        call_args = mock_log.error.call_args[0][0]
        log_data = json.loads(call_args, strict=False)
        assert log_data["status"] == "error"
        assert log_data["error_type"] == "Exception"
        assert "Connection timeout" in log_data["error_message"]


def test_log_result_summary():
    """結果サマリーログテスト"""
    logger = ExternalToolLogger("dalfox")
    
    results = [
        ToolResult(status=ToolStatus.SUCCESS, data={}, execution_time_ms=100.0),
        ToolResult(status=ToolStatus.SUCCESS, data={}, execution_time_ms=150.0),
        ToolResult(status=ToolStatus.FAILURE, data=None, execution_time_ms=50.0),
        ToolResult(status=ToolStatus.TIMEOUT, data=None, execution_time_ms=300.0),
    ]
    
    with patch.object(logger, 'logger') as mock_log:
        logger.log_result_summary(results)
        
        # infoが呼ばれていること
        assert mock_log.info.called
        
        call_args = mock_log.info.call_args[0][0]
        log_data = json.loads(call_args, strict=False)
        
        # サマリー情報が含まれる
        summary = log_data["batch_summary"]
        assert summary["total"] == 4
        assert summary["success"] == 2
        assert summary["failure"] == 1
        assert summary["timeout"] == 1
        assert summary["avg_time_ms"] == 150.0  # (100+150+50+300)/4


def test_baseline_calculation():
    """基準実行時間の計算テスト"""
    thresholds = PerformanceThresholds(baseline_execution_time_ms=1000.0)
    logger = ExternalToolLogger("dalfox", thresholds=thresholds)
    
    # 複数回の実行時間を記録
    for time_ms in [100.0, 200.0, 300.0]:
        result = ToolResult(
            status=ToolStatus.SUCCESS,
            data={},
            execution_time_ms=time_ms
        )
        logger.info_execution(["dalfox"], result)
    
    # 基準時間は移動平均（200ms）
    baseline = logger._get_baseline_time()
    assert baseline == 200.0


def test_get_logger_factory():
    """ロガーファクトリ関数テスト"""
    from src.core.adapters.external.external_tool_logger import get_logger
    
    logger = get_logger("nuclei")
    
    assert isinstance(logger, ExternalToolLogger)
    assert logger.tool_name == "nuclei"
