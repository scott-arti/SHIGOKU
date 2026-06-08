"""
セキュリティ強制メカニズムのテスト

CTO指摘項目の改善策を検証
"""

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from src.core.adapters.external.binary_manager import BinaryManager, SecurityError


def test_security_enforcement_blocks_false_prohibit_chmod():
    """prohibit_pre_verification_chmod=False時にSecurityErrorが発生することを検証"""
    # 危険な設定ファイルを作成
    config_content = {
        "tools": {},
        "global": {
            "security": {
                "prohibit_pre_verification_chmod": False,  # 危険な設定
                "use_temp_directory_for_download": True
            }
        }
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(config_content, f)
        config_path = Path(f.name)
    
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            installation_dir = Path(temp_dir) / "binaries"
            
            # SecurityErrorが発生することを検証
            with pytest.raises(SecurityError) as exc_info:
                bm = BinaryManager.__new__(BinaryManager)
                bm.installation_dir = installation_dir
                bm.config_path = config_path
                bm._verified_binaries = set()
                bm._enforce_security_settings()
            
            assert "CRITICAL SECURITY VIOLATION" in str(exc_info.value)
            assert "prohibit_pre_verification_chmod is set to False" in str(exc_info.value)
            
    finally:
        config_path.unlink()


def test_security_enforcement_allows_true_prohibit_chmod():
    """prohibit_pre_verification_chmod=True時に正常に動作することを検証"""
    config_content = {
        "tools": {},  # ツール設定なし（セキュリティ設定のみ検証）
        "global": {
            "security": {
                "prohibit_pre_verification_chmod": True,  # 安全な設定
                "use_temp_directory_for_download": True
            }
        }
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(config_content, f)
        config_path = Path(f.name)
    
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            installation_dir = Path(temp_dir) / "binaries"
            installation_dir.mkdir(parents=True, exist_ok=True)
            
            bm = BinaryManager.__new__(BinaryManager)
            bm.installation_dir = installation_dir
            bm.config_path = config_path
            bm._verified_binaries = set()
            bm.binaries_config = {}
            
            # SecurityErrorが発生しないことを検証
            bm._enforce_security_settings()  # 例外が発生しない
            
    finally:
        config_path.unlink()


def test_verification_flags_persistence():
    """検証済みフラグの永続化と復元を検証"""
    with tempfile.TemporaryDirectory() as temp_dir:
        installation_dir = Path(temp_dir) / "binaries"
        installation_dir.mkdir(parents=True, exist_ok=True)
        verification_file = installation_dir.parent / "verified_binaries.json"
        
        # 初期状態：空の検証済みセット
        bm1 = BinaryManager.__new__(BinaryManager)
        bm1.installation_dir = installation_dir
        bm1._verified_binaries = set()
        bm1._verification_file = verification_file
        
        # 検証済みフラグを追加
        bm1._verified_binaries.add("dalfox")
        bm1._verified_binaries.add("nuclei")
        
        # 永続化
        bm1._save_verification_flags()
        
        # ファイルが作成されたことを検証
        assert verification_file.exists()
        
        # ファイル内容を検証
        with open(verification_file, 'r') as f:
            data = json.load(f)
        
        assert "dalfox" in data["verified_tools"]
        assert "nuclei" in data["verified_tools"]
        
        # 新しいインスタンスで復元
        bm2 = BinaryManager.__new__(BinaryManager)
        bm2.installation_dir = installation_dir
        bm2._verified_binaries = set()
        bm2._verification_file = verification_file
        bm2._load_verification_flags()
        
        # 復元されたことを検証
        assert "dalfox" in bm2._verified_binaries
        assert "nuclei" in bm2._verified_binaries


def test_semaphore_stats_with_wait_time():
    """セマフォ統計情報に待機時間が含まれることを検証"""
    import asyncio
    from src.core.adapters.external.external_tool_executor import ExternalToolExecutor, ExecutorConfig
    from src.core.adapters.external.base_external_adapter import BaseExternalAdapter, ToolInput, ToolResult, ToolStatus
    
    class MockSlowAdapter(BaseExternalAdapter):
        def __init__(self, delay: float = 0.1):
            super().__init__("mock_slow")
            self.delay = delay
        
        async def execute(self, input_data: ToolInput) -> ToolResult:
            await asyncio.sleep(self.delay)
            return ToolResult(
                status=ToolStatus.SUCCESS,
                data={},
                execution_time_ms=self.delay * 1000
            )
        
        def validate_inputs(self, input_data: ToolInput):
            return True, None
        
        async def health_check(self) -> bool:
            return True
    
    config = ExecutorConfig(max_concurrent=1)  # 並行度1に制限
    executor = ExternalToolExecutor(config)
    
    adapter = MockSlowAdapter(delay=0.1)
    
    # 2つ同時に実行（2つ目は待機が必要）
    async def run_test():
        return await asyncio.gather(
            executor.execute(adapter, ToolInput(target="test1")),
            executor.execute(adapter, ToolInput(target="test2"))
        )
    
    asyncio.run(run_test())
    
    # 統計情報を取得
    stats = executor.get_semaphore_stats()
    
    # 待機時間が記録されていることを検証
    assert stats["avg_waiting_time_ms"] > 0
    assert stats["max_concurrent_reached"] >= 1
    assert stats["total_executed"] == 2


def test_constants_usage():
    """constantsモジュールの使用を検証"""
    from src.core.adapters.external.constants import (
        ToolStatusValue,
        DEFAULT_MAX_CONCURRENT,
        DEFAULT_WARNING_SLOW_FACTOR
    )
    
    # ToolStatusValueが正しく定義されていることを検証
    assert ToolStatusValue.SUCCESS == "success"
    assert ToolStatusValue.FAILURE == "failure"
    assert ToolStatusValue.TIMEOUT == "timeout"
    assert ToolStatusValue.ERROR == "error"
    
    # デフォルト値が定義されていることを検証
    assert DEFAULT_MAX_CONCURRENT == 5
    assert DEFAULT_WARNING_SLOW_FACTOR == 5.0
