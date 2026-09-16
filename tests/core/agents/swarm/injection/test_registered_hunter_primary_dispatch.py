"""SGK-2026-0507: 登録ハンターが本流ディスパッチ(vuln_type 経路)へ相乗り実行されるかのテスト。

`_process_single_url` は分類器が割り当てた vuln_type で分岐する（本流）。0504/0506 の unknown 経路
配線は既定で発火しないため、`attach_vuln_types` に一致する登録ハンターを既存分岐の後に走らせる。
- blind_sqli は "sqli" 面、nosql は "api" 面に相乗り。
- 相乗り対象外の vuln_type（"xss"）では起動しない。
"""

import pytest
from unittest.mock import AsyncMock

from src.core.agents.swarm.base import Specialist
from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.agents.swarm.injection.manager_internal.hunter_registry import (
    HUNTER_SPEC_BY_KEY,
)


class _RecordingHunter(Specialist):
    name = "RecordingHunter"

    def __init__(self, config=None):
        super().__init__(config)
        self.calls = 0

    async def execute(self, task, quick_mode: bool = False):  # pragma: no cover
        return []

    async def execute_with_retry(self, task, quick_mode: bool = False, **kwargs):
        self.calls += 1
        return []  # fail-close 相当（追加 finding 無し）。相乗り起動されたかだけを検証する。


def _manager() -> InjectionManagerAgent:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": [], "params": {}}
    # 本流の primary hunter は no-op 化（ネットワーク回避）
    manager.run_sqli_hunter = AsyncMock(return_value={"findings_count": 0, "tested_params": []})
    manager.run_xss_hunter = AsyncMock(
        return_value={"findings_count": 0, "tested_params": [], "reflection_observed": False, "evidence": ""}
    )
    manager._run_api_minimal_check = AsyncMock(return_value={"findings_count": 0, "tested_params": []})
    return manager


def test_attach_metadata_declared():
    assert HUNTER_SPEC_BY_KEY["blind_sqli"].attach_vuln_types == ("sqli",)
    assert HUNTER_SPEC_BY_KEY["nosql"].attach_vuln_types == ("api",)


@pytest.mark.asyncio
async def test_sqli_vuln_type_attaches_blind_sqli():
    manager = _manager()
    fake = _RecordingHunter()
    manager.specialists["blind_sqli"] = fake
    await manager._process_single_url("https://target.example/items?id=1", "sqli", {})
    assert fake.calls == 1


@pytest.mark.asyncio
async def test_api_vuln_type_attaches_nosql():
    manager = _manager()
    fake = _RecordingHunter()
    manager.specialists["nosql"] = fake
    await manager._process_single_url("https://target.example/api/v2/x", "api", {})
    assert fake.calls == 1


@pytest.mark.asyncio
async def test_unrelated_vuln_type_does_not_attach():
    manager = _manager()
    nosql_fake = _RecordingHunter()
    blind_fake = _RecordingHunter()
    manager.specialists["nosql"] = nosql_fake
    manager.specialists["blind_sqli"] = blind_fake
    await manager._process_single_url("https://target.example/s?q=1", "xss", {})
    assert nosql_fake.calls == 0
    assert blind_fake.calls == 0
