from types import SimpleNamespace

from src.core.engine.attack_planner import AttackPlanner


class _FakeKG:
    def __init__(self, endpoints: list[dict[str, str]]):
        self._endpoints = endpoints
        self.requested_domain: str | None = None

    def get_attack_surface(self, domain: str) -> dict:
        return {"technologies": []}

    def get_untested_endpoints(self, domain: str) -> list[dict[str, str]]:
        self.requested_domain = domain
        return list(self._endpoints)


def test_infer_tasks_filters_out_of_scope_untested_endpoints() -> None:
    kg = _FakeKG(
        [
            {"url": "http://127.0.0.1:8888/api/v1/users", "method": "GET"},
            {"url": "https://target.example.com/admin", "method": "GET"},
        ]
    )
    context = SimpleNamespace(
        target_domain="",
        target_info={"target": "http://127.0.0.1:8888/"},
        discovered_assets=[],
    )

    planner = AttackPlanner()
    tasks = planner.infer_tasks(kg, context)

    assert kg.requested_domain == "127.0.0.1"
    assert len(tasks) == 1
    assert tasks[0].target == "http://127.0.0.1:8888/api/v1/users"
    assert tasks[0].params.get("target") == "http://127.0.0.1:8888/api/v1/users"


def test_infer_tasks_skips_when_scope_host_cannot_be_resolved() -> None:
    kg = _FakeKG([{"url": "https://target.example.com/api/v1/users", "method": "GET"}])
    context = SimpleNamespace(target_domain="", target_info={}, discovered_assets=[])

    planner = AttackPlanner()
    tasks = planner.infer_tasks(kg, context)

    assert tasks == []
