import pytest
from unittest.mock import MagicMock, patch
from src.core.engine.master_conductor import MasterConductor
from src.core.domain.model.task import Task

@pytest.fixture
def mc():
    with patch('src.core.engine.master_conductor_facade.settings') as mock_settings:
        mock_settings.environment = "BUG_BOUNTY"
        mock_settings.ctf_target = None
        mock_settings.ctf_flag_format = "flag\\{.*\\}"
        mock_settings.checkpoint_interval = 5
        mock_settings.task_queue_max_memory = 5000
        mock_settings.notify_on_task_start = False
        mock_settings.notify_on_task_complete = False
        mock_settings.notify_on_error = False
        mock_settings.enable_react_observation = False
        
        return MasterConductor(
            llm_client=MagicMock(),
            graph=MagicMock()
        )

def test_mc_persona_initialization():
    with patch('src.core.engine.master_conductor_facade.settings') as mock_settings:
        # Bug Bounty Mode
        mock_settings.environment = "BUG_BOUNTY"
        mock_settings.ctf_target = None
        mock_settings.ctf_flag_format = "flag\\{.*\\}"
        mock_settings.enable_react_observation = False
        mc_bb = MasterConductor()
        assert "BUG BOUNTY" in mc_bb.system_prompt
        assert mc_bb.mode == "BUG_BOUNTY"
        
        # CTF Mode
        mock_settings.ctf_target = "TargetBox"
        mock_settings.ctf_flag_format = "flag{.*}"
        mc_ctf = MasterConductor()
        assert "CTF" in mc_ctf.system_prompt
        assert "flag{.*}" in mc_ctf.system_prompt
        assert mc_ctf.mode == "CTF"

def test_mc_strategic_loop_execution(mc):
    # 戦略的レビューが正しく呼び出されるか検証
    mc.optimizer = MagicMock()
    mc.optimizer.should_review.side_effect = [True, False, False]
    
    task = Task(id="t1", name="Test Task", params={"target": "http://example.com"})
    mc.task_queue.add(task)
    
    # モックのディスパッチ結果
    with patch.object(mc, '_dispatch', return_value={"success": True}):
        mc.execute_with_replan(max_tasks=1)
        
    # 最初のタスク（step 0）で should_review が True になるため、一回呼び出されるはず
    assert mc.optimizer.review_strategy.called
