from src.core.domain.model.task import Task
from src.core.intelligence.strategy_selector import StrategySelector


class TestStrategySelector:
    def test_default_strategy_is_robust(self):
        selector = StrategySelector()
        task = Task(id="t1", name="Generic Recon", agent_type="discovery", action="scan")

        decision = selector.select(task=task, target_info={}, mode="bugbounty")

        assert decision.strategy_id == "balanced_default"
        assert decision.priority_delta == 0
        assert "balanced_mode" in decision.param_overrides

    def test_waf_strategy_selected_from_context(self):
        selector = StrategySelector()
        task = Task(id="t2", name="Endpoint test", agent_type="injection", action="scan")

        decision = selector.select(
            task=task,
            target_info={"waf": "cloudflare"},
            mode="bugbounty",
        )

        assert decision.strategy_id == "stealth_evasion"
        assert decision.priority_delta > 0
        assert decision.param_overrides.get("stealth_mode") is True

    def test_auth_strategy_selected_from_task_signals(self):
        selector = StrategySelector()
        task = Task(
            id="t3",
            name="OAuth login callback probe",
            agent_type="auth",
            action="execute",
            params={"target": "https://example.com/oauth/callback"},
        )

        decision = selector.select(task=task, target_info={}, mode="bugbounty")

        assert decision.strategy_id == "auth_deep_dive"
        assert decision.priority_delta == 0
        assert decision.param_overrides.get("auth_focus") is True

