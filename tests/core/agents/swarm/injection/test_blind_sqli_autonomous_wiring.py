"""SGK-2026-0506: blind_sqli を自律走行へ配線（URL 駆動の汎用自己適応）のテスト。

- 登録/routing/汎用 dispatch に blind_sqli が載る。
- `_effective_target` が対象 URL から mode/param/base_value を汎用に導出する（ラボ固有ヒント不使用）。
- 後方互換: クエリ無し・明示 mode は従来挙動（path/id/1）を保つ。
"""

import pytest

from src.core.agents.swarm.base import Specialist, Task
from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.agents.swarm.injection.manager_internal.specialist_router import (
    SPECIALIST_MAP,
    select_specialists,
)
from src.core.agents.swarm.injection.manager_internal.unknown_hypotheses import (
    build_unknown_hypotheses,
)
from src.core.agents.swarm.injection.smart_blind_sqli import SmartBlindSQLiHunter
from src.core.models.finding import Evidence, Finding, Severity, VulnType


SQLI_QUERY_URL = "https://target.example/items?id=7&q=x"


class _RecordingHunter(Specialist):
    name = "RecordingHunter"

    def __init__(self, config=None):
        super().__init__(config)
        self.calls = 0

    async def execute(self, task, quick_mode: bool = False):  # pragma: no cover
        return []

    async def execute_with_retry(self, task, quick_mode: bool = False, **kwargs):
        self.calls += 1
        return [
            Finding(
                vuln_type=VulnType.SQL_INJECTION,
                severity=Severity.HIGH,
                title="fake",
                description="fake",
                target_url=task.target,
                evidence=Evidence(
                    request_method="GET",
                    request_url=task.target,
                    request_headers={},
                    response_status=200,
                    response_body="",
                ),
                source_agent="fake",
                confidence=0.9,
                additional_info={"tested_params": ["id"]},
            )
        ]


# --- routing / registry ---------------------------------------------------------------


def test_specialist_map_has_blind_sqli():
    assert SPECIALIST_MAP.get("blind_sqli") == "blind_sqli"


def test_hypotheses_emit_blind_sqli_on_sqli_query_surface():
    profile = build_unknown_hypotheses(
        SQLI_QUERY_URL, {}, available_specialists={"sqli", "blind_sqli"}
    )
    assert "blind_sqli" in profile["hypotheses"]
    assert "blind_sqli" in profile["selected_specialists"]


def test_no_blind_sqli_without_query_params():
    # sqli 面でもクエリ param が無ければ blind_sqli は出さない（自己適応が効かないため）
    profile = build_unknown_hypotheses(
        "https://target.example/search", {}, available_specialists={"sqli", "blind_sqli"}
    )
    assert "sqli" in profile["hypotheses"]
    assert "blind_sqli" not in profile["hypotheses"]


def test_manager_registers_blind_sqli():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    assert "blind_sqli" in manager.specialists
    assert isinstance(manager.specialists["blind_sqli"], SmartBlindSQLiHunter)


# --- URL 駆動の自己適応（非カーブフィット） --------------------------------------------


def _hunter() -> SmartBlindSQLiHunter:
    return SmartBlindSQLiHunter()


def test_effective_target_query_url_self_adapts():
    h = _hunter()
    t = Task(id="t", name="b", target="https://target.example/items?id=7&q=x", params={})
    mode, base_url, param, base_value = h._effective_target(t)
    assert mode == "query"
    assert param == "id"          # 先頭クエリ param（URL 由来・ハードコードなし）
    assert base_value == "7"      # その param の現在値（URL 由来）
    injected = h._build_url(t, "7 AND 1=1")
    assert "id=7+AND+1%3D1" in injected  # query param へ注入
    assert "q=x" in injected             # 他の param は保持


def test_effective_target_path_url_backward_compatible():
    h = _hunter()
    t = Task(id="t", name="b", target="https://target.example/home/5", params={})
    mode, _base_url, param, base_value = h._effective_target(t)
    assert (mode, param, base_value) == ("path", "id", "1")


def test_effective_target_explicit_mode_wins():
    h = _hunter()
    # クエリがあっても明示 path なら従来通り path（後方互換）
    t = Task(
        id="t", name="b", target="https://target.example/items?id=7",
        params={"blind_sqli_mode": "path"},
    )
    mode, _base_url, param, base_value = h._effective_target(t)
    assert (mode, param, base_value) == ("path", "id", "1")


# --- 自律走行の入口が blind_sqli を汎用経路へ流す ---------------------------------------


@pytest.mark.asyncio
async def test_unknown_hypothesis_dispatch_routes_blind_sqli():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}
    fake = _RecordingHunter()
    manager.specialists = {"blind_sqli": fake}  # sqli 等の実ネットワーク実行を避け blind_sqli に隔離

    await manager._run_unknown_hypothesis_scans(SQLI_QUERY_URL, {}, False)

    assert fake.calls == 1
