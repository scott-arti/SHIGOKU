import time
import pytest

from src.core.agents.swarm.discovery.graphql import (
    GraphQLNavigator,
    CONTRACT_VERSION,
)
from src.core.agents.swarm.discovery.manager import GraphQLNavigatorContractAdapter


def test_other_category_alert_none_when_total_zero():
    assert GraphQLNavigator.evaluate_other_category_alert(other_count=100, total_count=0) is None


def test_other_category_alert_none_when_count_below_min():
    assert GraphQLNavigator.evaluate_other_category_alert(other_count=19, total_count=100) is None


def test_other_category_alert_warning_threshold():
    assert GraphQLNavigator.evaluate_other_category_alert(other_count=20, total_count=1000) == "warning"


def test_other_category_alert_critical_threshold():
    assert GraphQLNavigator.evaluate_other_category_alert(other_count=40, total_count=1000) == "critical"


def test_other_category_alert_critical_precedence_over_warning():
    assert GraphQLNavigator.evaluate_other_category_alert(other_count=200, total_count=5000) == "critical"


@pytest.mark.asyncio
async def test_alert_level_escalation_fires():
    """warning → critical へのエスカレーションが通知される"""
    nav = GraphQLNavigator(config={"graphql_probe_alert_cooldown_seconds": 300.0})
    nav._last_alert_level = "warning"
    nav._last_alert_at = time.monotonic()
    # inject enough "other" entries to trigger critical (>3% and >=20)
    now = time.monotonic()
    nav._error_category_window = [(now, "other")] * 40 + [(now, "ok")] * 960
    result = await nav._record_category_and_maybe_alert("other")
    assert result == "critical"
    assert nav._last_alert_level == "critical"


@pytest.mark.asyncio
async def test_alert_same_level_suppressed_within_cooldown():
    """クールダウン内の同level再発は通知されない（バグ①修正確認）"""
    nav = GraphQLNavigator(config={"graphql_probe_alert_cooldown_seconds": 300.0})
    nav._last_alert_level = "warning"
    nav._last_alert_at = time.monotonic()
    now = time.monotonic()
    nav._error_category_window = [(now, "other")] * 20 + [(now, "ok")] * 980
    result = await nav._record_category_and_maybe_alert("other")
    assert result is None


@pytest.mark.asyncio
async def test_alert_same_level_refires_after_cooldown():
    """クールダウン経過後は同levelでも再通知される（バグ①修正確認）"""
    nav = GraphQLNavigator(config={"graphql_probe_alert_cooldown_seconds": 0.0})
    nav._last_alert_level = "warning"
    nav._last_alert_at = time.monotonic() - 1.0
    now = time.monotonic()
    nav._error_category_window = [(now, "other")] * 20 + [(now, "ok")] * 980
    result = await nav._record_category_and_maybe_alert("other")
    assert result == "warning"


@pytest.mark.asyncio
async def test_alert_resets_when_rate_drops():
    """レートが閾値以下に下がると last_alert_level がリセットされる"""
    nav = GraphQLNavigator(config={})
    nav._last_alert_level = "critical"
    nav._last_alert_at = time.monotonic()
    nav._error_category_window = []
    result = await nav._record_category_and_maybe_alert("ok")
    assert result is None
    assert nav._last_alert_level is None
    assert nav._last_alert_at == 0.0


def test_contract_version_single_source():
    """CONTRACT_VERSION が graphql.py の single source から import されている"""
    assert GraphQLNavigatorContractAdapter.contract_version == CONTRACT_VERSION
    assert GraphQLNavigatorContractAdapter().contract_version == CONTRACT_VERSION


def test_contract_version_value():
    """CONTRACT_VERSION の値が期待どおり"""
    assert CONTRACT_VERSION == "1.0.0"


def test_other_category_log_dir_uses_env_override(monkeypatch):
    """環境変数 SHIGOKU_OTHER_CATEGORY_LOG_DIR が既定値として反映される"""
    monkeypatch.setenv("SHIGOKU_OTHER_CATEGORY_LOG_DIR", "/tmp/shigoku-other-log")
    nav = GraphQLNavigator(config={})
    assert nav._runtime.other_category_log_dir == "/tmp/shigoku-other-log"
