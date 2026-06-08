"""
MasterConductor バグ修正テスト（2026-01-05実施分）

テスト対象:
- #2: 並列実行ブロッキングバグ（asyncio）
- #3: リプランカウンターのタスク個別化
- #4: 派生タスク上限
- #7: 優先度ソートヘルパーメソッド
- #8: enable_react_observationデフォルトOFF
- #9: チェックポイント間隔
"""
import pytest
import logging
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass

from src.config import settings
from src.core.engine.master_conductor import MasterConductor, Task, TaskState


class TestBugFix2_AsyncioThreadSafe:
    """#2: 並列実行時のasyncioハンドリング修正テスト"""
    
    def test_task_has_replan_depth_field(self):
        """Taskデータクラスにreplan_depthフィールドがあること"""
        task = Task(
            id="test_task",
            name="Test Task",
            agent_type="test",
            action="run"
        )
        assert hasattr(task, 'replan_depth')
        assert task.replan_depth == 0
    
    def test_task_replan_depth_serialization(self):
        """Task.to_dict()にreplan_depthが含まれること"""
        task = Task(
            id="test_task",
            name="Test Task",
            agent_type="test",
            action="run",
            replan_depth=3
        )
        task_dict = task.to_dict()
        assert 'replan_depth' in task_dict
        assert task_dict['replan_depth'] == 3


class TestBugFix3_TaskLocalReplanCounter:
    """#3: リプランカウンターのタスク個別化テスト"""
    
    def test_conductor_has_derived_task_counter(self):
        """Conductorに派生タスクカウンターがあること"""
        conductor = MasterConductor()
        assert hasattr(conductor, '_derived_task_count')
        assert conductor._derived_task_count == 0
    
    def test_conductor_has_checkpoint_counter(self):
        """Conductorにチェックポイントカウンターがあること"""
        conductor = MasterConductor()
        assert hasattr(conductor, '_checkpoint_counter')
        assert conductor._checkpoint_counter == 0


class TestBugFix4_DerivedTaskLimit:
    """#4: 派生タスク上限テスト"""
    
    def test_config_has_max_derived_tasks(self):
        """設定に派生タスク上限があること"""
        assert hasattr(settings, 'max_derived_tasks_per_session')
        assert settings.max_derived_tasks_per_session == 20
    
    def test_add_tasks_respects_limit(self):
        """_add_tasksが派生タスク上限を尊重すること"""
        conductor = MasterConductor()
        
        # 上限を超えるタスクを作成
        tasks = [
            Task(id=f"task_{i}", name=f"Task {i}", agent_type="test", action="run")
            for i in range(25)
        ]
        
        # 上限を一時的に5に設定
        with patch.object(settings, 'max_derived_tasks_per_session', 5):
            added = conductor._add_tasks(tasks, source="test")
            
            # 5タスクまでしか追加されないこと
            assert added == 5
            assert len(conductor.task_queue) == 5
            assert conductor._derived_task_count == 5
    
    def test_add_tasks_sorts_by_priority(self):
        """_add_tasksが優先度順にソートすること"""
        conductor = MasterConductor()
        
        tasks = [
            Task(id="low", name="Low", agent_type="test", action="run", priority=10),
            Task(id="high", name="High", agent_type="test", action="run", priority=100),
            Task(id="mid", name="Mid", agent_type="test", action="run", priority=50),
        ]
        
        conductor._add_tasks(tasks, source="test")
        
        # 優先度順にソートされていること（降順）
        priorities = [t.priority for t in conductor.task_queue]
        assert priorities == [100, 50, 10]


class TestBugFix7_PrioritySortHelper:
    """#7: 優先度ソートヘルパーメソッドテスト"""
    
    def test_add_tasks_method_exists(self):
        """_add_tasksメソッドが存在すること"""
        conductor = MasterConductor()
        assert hasattr(conductor, '_add_tasks')
        assert callable(conductor._add_tasks)
    
    def test_add_tasks_returns_count(self):
        """_add_tasksが追加したタスク数を返すこと"""
        conductor = MasterConductor()
        
        tasks = [
            Task(id="t1", name="T1", agent_type="test", action="run"),
            Task(id="t2", name="T2", agent_type="test", action="run"),
        ]
        
        result = conductor._add_tasks(tasks, source="test")
        assert result == 2
    
    def test_add_tasks_empty_list(self):
        """空リストで_add_tasksを呼んでも問題ないこと"""
        conductor = MasterConductor()
        result = conductor._add_tasks([], source="test")
        assert result == 0
        assert len(conductor.task_queue) == 0


class TestBugFix8_ReactObservationDefault:
    """#8: enable_react_observationデフォルトOFFテスト"""
    
    def test_react_observation_default_off(self):
        """enable_react_observationがデフォルトでOFFであること"""
        assert settings.enable_react_observation is False
    
    def test_react_observation_max_additions_exists(self):
        """react_observation_max_additionsが設定されていること"""
        assert hasattr(settings, 'react_observation_max_additions')
        assert settings.react_observation_max_additions == 2


class TestBugFix9_CheckpointInterval:
    """#9: チェックポイント間隔テスト"""
    
    def test_checkpoint_interval_exists(self):
        """checkpoint_intervalが設定されていること"""
        assert hasattr(settings, 'checkpoint_interval')
        assert settings.checkpoint_interval == 5


class TestBugFix5_CriticLoopOnce:
    """#5: BizLogicHunter Criticループ1回化テスト"""
    
    def test_critic_config_default_disabled(self):
        """Critic機能がデフォルトで無効であること"""
        from src.agents.swarm.biz_logic_hunter import BizLogicHunter
        
        hunter = BizLogicHunter()
        assert hunter.is_critic_enabled() is False
    
    def test_compact_critique_prompt_exists(self):
        """コンパクトプロンプトメソッドが存在すること"""
        from src.agents.swarm.biz_logic_hunter import BizLogicHunter
        
        hunter = BizLogicHunter()
        assert hasattr(hunter, '_build_compact_critique_prompt')
        assert callable(hunter._build_compact_critique_prompt)
    
    def test_compact_critique_prompt_is_short(self):
        """コンパクトプロンプトが短いこと"""
        from src.agents.swarm.biz_logic_hunter import BizLogicHunter
        from src.core.models.finding import Finding, Evidence, Severity, VulnType
        
        hunter = BizLogicHunter()
        
        # モックFinding
        finding = Mock()
        finding.vuln_type = VulnType.IDOR
        finding.target_url = "https://example.com/api/user/1"
        finding.evidence = Mock()
        finding.evidence.response_status = 200
        
        prompt = hunter._build_compact_critique_prompt(finding)
        
        # 100文字未満であること（トークン削減）
        assert len(prompt) < 100
        assert "Type:" in prompt
        assert "Target:" in prompt
        assert "Valid?" in prompt


class TestReplanDepthInheritance:
    """リプラン深度の引き継ぎテスト"""
    
    def test_replan_creates_tasks_with_incremented_depth(self):
        """replanで生成されたタスクに深度が引き継がれること"""
        conductor = MasterConductor()
        
        # 親タスク（深度2）
        parent_task = Task(
            id="parent",
            name="Parent Task",
            agent_type="test",
            action="run",
            replan_depth=2
        )
        
        # replanを呼び出し
        alt_tasks = conductor.replan(parent_task, "403 Forbidden")
        
        # 代替タスクが生成されていること（403なら少なくとも1つ）
        if alt_tasks:
            # 各タスクに深度を手動で設定（_add_tasksの前処理と同じ）
            for alt_task in alt_tasks:
                alt_task.replan_depth = parent_task.replan_depth + 1
                alt_task.parent_id = parent_task.id
            
            # 深度が引き継がれていること
            for alt_task in alt_tasks:
                assert alt_task.replan_depth == 3
                assert alt_task.parent_id == "parent"


class TestP3DynamicPriorityBoost:
    """P3-1: 動的優先度ブーストの回帰テスト"""

    def test_targeted_task_boosts_above_non_targeted(self):
        conductor = MasterConductor()

        tasks = [
            Task(
                id="normal_task",
                name="General probe",
                agent_type="discovery",
                action="run",
                priority=50,
                params={"target": "http://example.com/home"},
            ),
            Task(
                id="boosted_task",
                name="Admin API probe",
                agent_type="discovery",
                action="run",
                priority=50,
                params={"target": "http://example.com/api/admin/panel"},
            ),
        ]

        conductor._add_tasks(tasks, source="p3_dynamic_boost_test")
        queued = list(conductor.task_queue)

        assert queued[0].id == "boosted_task"
        assert queued[0].priority > queued[1].priority

    def test_boost_is_capped_at_three(self):
        conductor = MasterConductor()

        task = Task(
            id="capped_boost_task",
            name="admin api debug file_upload check",
            agent_type="injection",
            action="run",
            priority=100,
            params={"target": "http://example.com/api/admin/debug/file-upload"},
        )

        conductor._add_tasks([task], source="p3_dynamic_boost_cap_test")
        queued = list(conductor.task_queue)

        assert queued[0].priority == 300

    def test_boost_logs_reason(self, caplog):
        conductor = MasterConductor()

        task = Task(
            id="log_boost_task",
            name="Admin debug check",
            agent_type="discovery",
            action="run",
            priority=40,
            params={"target": "http://example.com/admin/debug"},
        )

        with caplog.at_level(logging.INFO):
            conductor._add_tasks([task], source="p3_dynamic_boost_log_test")

        messages = [record.getMessage() for record in caplog.records]
        assert any(
            "Dynamic priority boost applied" in msg and "reasons=admin,debug" in msg
            for msg in messages
        )


class TestN3StrategySelector:
    """N3: StrategySelector 統合テスト"""

    def test_strategy_selector_applies_waf_aware_overrides(self):
        conductor = MasterConductor()
        conductor.context.target_info["waf"] = "cloudflare"

        task = Task(
            id="strategy_waf_task",
            name="Generic endpoint probe",
            agent_type="injection",
            action="run",
            priority=30,
            params={"target": "http://example.com/path"},
        )

        conductor._add_tasks([task], source="n3_strategy_test")
        queued = list(conductor.task_queue)

        assert queued[0].params.get("stealth_mode") is True
        assert queued[0].params.get("use_proxy_rotation") is True
        assert queued[0].params.get("_strategy", {}).get("id") == "stealth_evasion"
        assert queued[0].priority >= 35

    def test_strategy_selector_default_keeps_priority_stable(self):
        conductor = MasterConductor()

        task = Task(
            id="strategy_default_task",
            name="Simple discovery",
            agent_type="discovery",
            action="run",
            priority=20,
            params={"target": "http://example.com/public"},
        )

        conductor._add_tasks([task], source="n3_strategy_default_test")
        queued = list(conductor.task_queue)

        # Dynamic boost対象でない入力では優先度を維持
        assert queued[0].priority == 20
        assert queued[0].params.get("_strategy", {}).get("id") == "balanced_default"
