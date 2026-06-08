import asyncio
import logging
import sys
import os
import time
from unittest.mock import MagicMock, patch

# プロジェクトルートをパスに追加
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from src.core.engine.master_conductor import MasterConductor
from src.core.infra.event_bus import get_event_bus, Event, EventType

# ロギング設定
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


async def _wait_for_condition(predicate, timeout_s: float = 1.0, poll_interval_s: float = 0.05) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_s
    while loop.time() < deadline:
        if predicate():
            return
        try:
            await asyncio.wait_for(asyncio.Event().wait(), timeout=poll_interval_s)
        except TimeoutError:
            continue
    raise AssertionError("Timed out waiting for expected chaining side effect.")

async def verify_chaining_flow():
    logger.info("🚀 Starting Vulnerability Chaining Verification (Refined)...")
    
    # EventBus取得
    event_bus = get_event_bus()
    
    # MasterConductorのセットアップ
    with patch("src.core.engine.master_conductor.ExecutionContext"), \
         patch("src.core.engine.master_conductor.settings") as mock_settings, \
         patch("src.core.engine.master_conductor.AttackPlanner"), \
         patch("src.core.engine.master_conductor.AsyncDatabaseWriter"), \
         patch("src.core.engine.master_conductor.get_findings_repository"), \
         patch("src.core.engine.task_queue.DynamicTaskQueue") as mock_queue_cls, \
         patch("src.core.engine.flag_watcher.FlagWatcher") as mock_watcher_cls:
        
        mock_settings.environment = "BUG_BOUNTY"
        mock_settings.ctf_flag_format = "flag{.*}"
        mock_settings.max_derived_tasks_per_session = 50
        
        # モックのキューインスタンス
        mock_queue = MagicMock()
        mock_queue_cls.return_value = mock_queue
        mock_queue.get_by_id.return_value = None
        
        # FlagWatcher のシングルトン対応
        mock_watcher = MagicMock()
        mock_watcher_cls.get_instance.return_value = mock_watcher
        
        # 依存モジュールのモック
        mock_pm = MagicMock()
        mock_lc = MagicMock()
        
        conductor = MasterConductor(
            project_manager=mock_pm,
            llm_client=mock_lc
        )
        
        # 内部状態の調整
        conductor._derived_task_count = 0
        conductor._injected_task_ids = set()
        conductor.context = MagicMock()
        conductor.context.target_info = {}
        
        # 1. 脆弱性発見イベント(idor)をエミット
        vuln_event = Event(
            type=EventType.VULN_FOUND,
            payload={
                "vuln_type": "idor",
                "target": "https://example.com/api/user/123",
                "severity": "high"
            }
        )
        
        logger.info("📡 Emitting VULN_FOUND (idor) event...")
        await event_bus.emit(vuln_event)
        await _wait_for_condition(lambda: len(mock_queue.add.call_args_list) > 0)
        
        # 2. 検証: タスクが追加されたか
        added_tasks = [call.args[0] for call in mock_queue.add.call_args_list]
            
        logger.info(f"📊 Tasks added to queue: {[t.name for t in added_tasks]}")
        
        assert len(added_tasks) > 0, "Chaining task was NOT added to queue."
        assert any("chain_auth_escalation" in t.name for t in added_tasks), "Expected 'chain_auth_escalation' task missing."
        
        logger.info("✅ IDOR chaining verified.")

        # 3. 脆弱性発見イベント(secret_leak)をエミット
        mock_queue.add.reset_mock()
        leak_event = Event(
            type=EventType.VULN_FOUND,
            payload={
                "vuln_type": "secret_leak",
                "target": "https://example.com/.env",
                "severity": "critical"
            }
        )
        
        logger.info("📡 Emitting VULN_FOUND (secret_leak) event...")
        await event_bus.emit(leak_event)
        await _wait_for_condition(lambda: len(mock_queue.add.call_args_list) > 0)
        
        added_tasks = [call.args[0] for call in mock_queue.add.call_args_list]
        logger.info(f"📊 Tasks added to queue: {[t.name for t in added_tasks]}")
        
        assert any("chain_intel_recon" in t.name for t in added_tasks), "Expected 'chain_intel_recon' task missing."
        
        logger.info("✅ Secret leak chaining verified.")
        
        logger.info("🎉 ALL Vulnerability Chaining tests PASSED!")

if __name__ == "__main__":
    asyncio.run(verify_chaining_flow())
