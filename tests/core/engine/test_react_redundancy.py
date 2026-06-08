import pytest
from unittest.mock import Mock, patch
from src.core.engine.master_conductor import MasterConductor
from src.core.domain.model.task import Task


def _react_setting_map(**overrides):
    defaults = {
        "enable_react_observation": True,
        "react_observation_retry_max": 1,
        "react_observation_retry_budget_per_run": 20,
        "react_observation_queue_maxsize": 100,
        "max_inflight_react_requests_global": 8,
        "react_observation_low_value_task_patterns": "read,list,fetch",
        "react_observation_max_calls_per_run": 50,
        "react_observation_max_calls_per_target": 10,
        "react_observation_sampling_rate": 1.0,
        "react_observation_circuit_breaker_latency_seconds": 8.0,
        "react_observation_circuit_breaker_threshold": 5,
        "react_observation_circuit_breaker_cooldown_seconds": 120,
    }
    defaults.update(overrides)
    return defaults


class TestReActRedundancy:
    @pytest.fixture
    def mock_llm(self):
        mock = Mock()
        # Mock response for LLM
        response = Mock()
        response.choices = [Mock(message=Mock(content='{"additional_attacks": [{"name": "Extra Scan", "agent_type": "universal", "action": "scan", "rationale": "found apache", "params": {}}]}'))]
        mock.generate.return_value = response
        return mock

    def test_observe_and_rethink_cache(self, mock_llm):
        """同じタスク・結果に対してキャッシュが機能することを確認"""
        conductor = MasterConductor(llm_client=mock_llm)
        setting_map = _react_setting_map(enable_react_observation=True)
        task = Task(id="task1", name="Port Scan", params={"target": "example.com"})
        result = {"success": True, "data": {"technologies": ["apache"]}}

        with patch.object(conductor, "_react_setting", side_effect=lambda name, default: setting_map.get(name, default)):
            # 1回目の呼び出し
            tasks1 = conductor._observe_and_rethink(task, result)
            assert len(tasks1) == 1
            assert tasks1[0].name == "Extra Scan"
            assert mock_llm.generate.call_count == 1

            # 2回目の呼び出し（同じ引数）
            tasks2 = conductor._observe_and_rethink(task, result)
            assert len(tasks2) == 1
            assert tasks2[0].name == "Extra Scan"
            # LLMは呼ばれず、キャッシュから返されるはず
            assert mock_llm.generate.call_count == 1
        
    def test_observe_and_rethink_different_task_same_result(self, mock_llm):
        """別々のタスクIDでも、タスク名と結果が同じならキャッシュを使いつつIDは正しく振り直されることを確認"""
        conductor = MasterConductor(llm_client=mock_llm)
        setting_map = _react_setting_map(enable_react_observation=True)
        task1 = Task(id="task1", name="Scan", params={"target": "example.com"})
        task2 = Task(id="task2", name="Scan", params={"target": "example.com"})
        result = {"success": True, "data": {"technologies": ["apache"]}}

        with patch.object(conductor, "_react_setting", side_effect=lambda name, default: setting_map.get(name, default)):
            # Task1で実行
            tasks1 = conductor._observe_and_rethink(task1, result)
            assert mock_llm.generate.call_count == 1

            # Task2で実行 (同じ名前、同じ結果)
            tasks2 = conductor._observe_and_rethink(task2, result)
            assert mock_llm.generate.call_count == 1 # キャッシュヒット

            # IDが各タスクに対して正しく生成されているか確認
            assert tasks1[0].id == "task1_react_0"
            assert tasks2[0].id == "task2_react_0"
            assert tasks1[0].name == tasks2[0].name

    def test_observe_and_rethink_different_result_no_cache(self, mock_llm):
        """結果が異なればキャッシュされず、新しくLLMが呼ばれることを確認"""
        conductor = MasterConductor(llm_client=mock_llm)
        setting_map = _react_setting_map(enable_react_observation=True)
        task = Task(id="task1", name="Scan", params={"target": "example.com"})

        with patch.object(conductor, "_react_setting", side_effect=lambda name, default: setting_map.get(name, default)):
            # 1回目の実行
            conductor._observe_and_rethink(task, {"success": True, "data": {"technologies": ["apache"]}})
            assert mock_llm.generate.call_count == 1

            # 2回目の実行 (異なる技術)
            conductor._observe_and_rethink(task, {"success": True, "data": {"technologies": ["nginx"]}})
            assert mock_llm.generate.call_count == 2

    def test_observe_and_rethink_retry_once_then_success(self):
        """LLM失敗後に retry で成功することを確認"""
        setting_map = _react_setting_map(
            enable_react_observation=True,
            react_observation_retry_max=1,
            react_observation_retry_budget_per_run=5,
        )
        mock_llm = Mock()
        response = Mock()
        response.choices = [Mock(message=Mock(content='{"additional_attacks": [{"name": "Retry Scan", "agent_type": "universal", "action": "scan", "rationale": "retry ok", "params": {}}]}'))]
        mock_llm.generate.side_effect = [RuntimeError("temporary"), response]

        conductor = MasterConductor(llm_client=mock_llm)
        with patch.object(conductor, "_react_setting", side_effect=lambda name, default: setting_map.get(name, default)):
            task = Task(id="task_retry", name="Scan", params={"target": "example.com"})
            result = {"success": True, "data": {"technologies": ["apache"]}}
            tasks = conductor._observe_and_rethink(task, result)
            assert len(tasks) == 1
            assert tasks[0].name == "Retry Scan"
            assert mock_llm.generate.call_count == 2
