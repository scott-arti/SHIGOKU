"""SGK-2026-0504: レジストリ駆動ハンター配線のテスト。

新設ハンターを『データ』として宣言するだけで、自律走行の入口（登録→routing→dispatch）に
載ることを検証する。旧9種の挙動は不変（回帰なし）であることも確認する。

- 登録: `InjectionManagerAgent` が `NEW_HUNTER_SPECS` から `self.specialists` へ登録する。
- routing: `SPECIALIST_MAP` が hypothesis→key を得て、`build_unknown_hypotheses` が
  JSON API 面で `nosql` 仮説を出す（pilot）。
- dispatch: `_run_registered_hunter` が汎用に起動し、`_run_unknown_hypothesis_scans` の
  ループが登録キーをその汎用経路へ流す。
"""

import pytest

from src.core.agents.swarm.base import Specialist
from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.agents.swarm.injection.manager_internal.hunter_registry import (
    HUNTER_SPEC_BY_KEY,
    HunterSpec,
    hypothesis_specialist_pairs,
)
from src.core.agents.swarm.injection.manager_internal.specialist_router import (
    SPECIALIST_MAP,
    select_specialists,
)
from src.core.agents.swarm.injection.manager_internal.unknown_hypotheses import (
    build_unknown_hypotheses,
)
from src.core.agents.swarm.injection.smart_nosql import SmartNoSQLHunter
from src.core.models.finding import Evidence, Finding, Severity, VulnType


JSON_API_URL = "https://target.example/api/v2/coupon/validate-coupon"
JSON_API_PARAMS = {
    "url_evidence": {
        "response_headers": {"Content-Type": "application/json"},
        "response_status": 200,
    }
}


def _make_finding(url: str) -> Finding:
    return Finding(
        vuln_type=VulnType.NOSQL_INJECTION,
        severity=Severity.HIGH,
        title="fake",
        description="fake finding",
        target_url=url,
        evidence=Evidence(
            request_method="POST",
            request_url=url,
            request_headers={},
            response_status=200,
            response_body="",
        ),
        source_agent="fake",
        confidence=0.9,
        additional_info={"tested_params": ["couponCode"]},
    )


class _RecordingHunter(Specialist):
    """execute_with_retry の呼び出しを記録する fixture ハンター（retry engine を経由しない）。"""

    name = "RecordingHunter"

    def __init__(self, config=None, finding_url: str = JSON_API_URL, emit: bool = True):
        super().__init__(config)
        self.calls = 0
        self.last_quick_mode = None
        self._finding_url = finding_url
        self._emit = emit

    async def execute(self, task, quick_mode: bool = False):  # pragma: no cover - 直接は使わない
        return []

    async def execute_with_retry(self, task, quick_mode: bool = False, **kwargs):
        self.calls += 1
        self.last_quick_mode = quick_mode
        return [_make_finding(self._finding_url)] if self._emit else []


def _make_manager() -> InjectionManagerAgent:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}
    return manager


# --- routing / registry（純粋関数） ---------------------------------------------------


def test_specialist_map_includes_all_registry_hypotheses():
    pairs = hypothesis_specialist_pairs()
    assert pairs, "registry should declare at least one hunter"
    for hypothesis, key in pairs.items():
        assert SPECIALIST_MAP.get(hypothesis) == key
    assert SPECIALIST_MAP["nosql"] == "nosql"


def test_registry_does_not_override_legacy_routing():
    # 旧9種の routing は不変
    assert SPECIALIST_MAP["sqli"] == "sqli"
    assert SPECIALIST_MAP["api"] == "sqli"
    assert SPECIALIST_MAP["idor"] == "sqli"
    assert SPECIALIST_MAP["graphql"] == "graphql"


def test_select_specialists_routes_registered_when_available():
    assert select_specialists(["nosql"], available_specialists={"nosql"}) == ["nosql"]


def test_select_specialists_filters_registered_when_unavailable():
    assert select_specialists(["nosql"], available_specialists=set()) == []


def test_build_unknown_hypotheses_emits_nosql_on_json_api():
    profile = build_unknown_hypotheses(
        JSON_API_URL, JSON_API_PARAMS, available_specialists={"nosql", "sqli"}
    )
    assert "nosql" in profile["hypotheses"]
    assert "nosql" in profile["selected_specialists"]


def test_build_unknown_hypotheses_no_nosql_on_non_json_surface():
    profile = build_unknown_hypotheses(
        "https://target.example/search?q=1", {}, available_specialists={"nosql", "sqli"}
    )
    assert "nosql" not in profile["hypotheses"]


# --- 登録 -----------------------------------------------------------------------------


def test_manager_registers_registry_hunters():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    assert "nosql" in manager.specialists
    assert isinstance(manager.specialists["nosql"], SmartNoSQLHunter)


# --- 汎用 dispatch --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_registered_hunter_dispatches_generic_key(monkeypatch):
    """nosql 固有でなく、任意の登録キーを汎用に起動できることを fixture で証明する。"""
    manager = _make_manager()
    fake = _RecordingHunter(finding_url=JSON_API_URL)
    spec = HunterSpec(
        key="faketype",
        module="test.fake",
        class_name="RecordingHunter",
        hypotheses=("faketype",),
        vuln_name="Fake Vuln",
        severity="HIGH",
    )
    monkeypatch.setitem(HUNTER_SPEC_BY_KEY, "faketype", spec)
    manager.specialists["faketype"] = fake

    result = await manager._run_registered_hunter("faketype", url=JSON_API_URL, quick_mode=True)

    assert fake.calls == 1
    assert fake.last_quick_mode is True
    assert result["findings_count"] == 1
    assert len(manager.current_context["findings"]) == 1


@pytest.mark.asyncio
async def test_run_registered_hunter_unavailable_returns_error():
    manager = _make_manager()
    manager.specialists.pop("nosql", None)
    result = await manager._run_registered_hunter("nosql", url=JSON_API_URL)
    assert result["findings_count"] == 0
    assert "not available" in result["error"]


# --- 自律走行の入口（primary path）が登録ハンターを起動する -------------------------------


@pytest.mark.asyncio
async def test_unknown_hypothesis_dispatch_routes_registered_hunter():
    """JSON API 面で `_run_unknown_hypothesis_scans` が nosql を汎用経路へ流すことを確認。"""
    manager = _make_manager()
    fake = _RecordingHunter(finding_url=JSON_API_URL)
    # nosql だけを available にして sqli/xss 等の実ネットワーク実行を避ける
    manager.specialists = {"nosql": fake}

    await manager._run_unknown_hypothesis_scans(JSON_API_URL, JSON_API_PARAMS, False)

    assert fake.calls == 1
