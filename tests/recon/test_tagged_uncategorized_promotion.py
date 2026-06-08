from pathlib import Path
from types import SimpleNamespace
import json
from urllib.parse import parse_qs, urlparse

import pytest

from src.recon.pipeline import ReconPipeline


class _DummyProjectManager:
    def __init__(self, project_dir: Path):
        self.project_dir = project_dir


class _DummyMC:
    def __init__(self):
        self.context = SimpleNamespace(target_info={})
        self.added_tasks = []

    def _add_tasks(self, tasks, source=None):  # pragma: no cover - callback shape only
        self.added_tasks.extend(tasks)


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def _new_pipeline(tmp_path: Path, config: dict | None = None) -> ReconPipeline:
    project_dir = tmp_path / "project"
    pm = _DummyProjectManager(project_dir=project_dir)
    mc = _DummyMC()
    return ReconPipeline(
        config=config or {},
        project_manager=pm,
        target="https://app.example.com/",
        master_conductor=mc,
    )


def test_promote_uncategorized_generic_categories(tmp_path: Path):
    pipeline = _new_pipeline(tmp_path)
    tagged_dir = (tmp_path / "project" / "tagged_urls")
    uncategorized_file = tagged_dir / "20260401_target_tagged_uncategorized.jsonl"

    _write_jsonl(
        uncategorized_file,
        [
            {"url": "https://app.example.com/admin/settings"},
            {"url": "https://app.example.com/catalog/search?query=apple"},
            {"url": "https://app.example.com/checkout"},
            {"url": "https://app.example.com/reviews/new"},
            {"url": "https://app.example.com/files/download?file=report.pdf"},
            {"url": "https://app.example.com/api/v1/challenges?name=test"},
            {"url": "https://app.example.com/#/account"},
            {"url": "https://app.example.com/ws/events?transport=websocket&t=123&sid=aaa"},
            {"url": "https://app.example.com/ops/healthz"},
            {"url": "https://app.example.com/about"},
        ],
    )

    promoted = pipeline._promote_uncategorized_tagged_file(uncategorized_file)

    expected = {
        "admin",
        "product_search",
        "basket_order",
        "feedback_review",
        "file_exposure_upload",
        "api_data",
        "client_route_dom",
        "realtime",
        "meta_observability",
    }
    assert expected.issubset(set(promoted.keys()))
    for category in expected:
        assert promoted[category].exists()

    with open(uncategorized_file, "r", encoding="utf-8") as fh:
        remaining = [json.loads(line) for line in fh if line.strip()]
    assert len(remaining) == 1
    assert remaining[0]["url"].endswith("/about")


def test_promote_uncategorized_coverage_oriented_categories(tmp_path: Path):
    pipeline = _new_pipeline(tmp_path)
    tagged_dir = (tmp_path / "project" / "tagged_urls")
    uncategorized_file = tagged_dir / "20260401_target_tagged_uncategorized.jsonl"

    _write_jsonl(
        uncategorized_file,
        [
            {"url": "https://app.example.com/chatbot/genai/state", "method": "GET"},
            {"url": "https://app.example.com/users/42/role?user_id=2", "method": "GET"},
            {"url": "https://app.example.com/wallet/redeem?coupon=VIP", "method": "POST"},
        ],
    )

    promoted = pipeline._promote_uncategorized_tagged_file(uncategorized_file)

    assert "api_data" in promoted
    assert "admin" in promoted
    assert "basket_order" in promoted

    with open(uncategorized_file, "r", encoding="utf-8") as fh:
        remaining = [json.loads(line) for line in fh if line.strip()]
    assert remaining == []


def test_promote_uncategorized_promotes_account_and_profile_to_auth(tmp_path: Path):
    pipeline = _new_pipeline(tmp_path)
    tagged_dir = (tmp_path / "project" / "tagged_urls")
    uncategorized_file = tagged_dir / "20260401_target_tagged_uncategorized.jsonl"

    _write_jsonl(
        uncategorized_file,
        [
            {"url": "https://app.example.com/account", "method": "GET"},
            {"url": "https://app.example.com/profile", "method": "GET"},
            {"url": "https://app.example.com/about", "method": "GET"},
        ],
    )

    promoted = pipeline._promote_uncategorized_tagged_file(uncategorized_file)
    assert "auth" in promoted

    with open(promoted["auth"], "r", encoding="utf-8") as fh:
        auth_urls = {json.loads(line)["url"] for line in fh if line.strip()}
    assert auth_urls == {
        "https://app.example.com/account",
        "https://app.example.com/profile",
    }

    with open(uncategorized_file, "r", encoding="utf-8") as fh:
        remaining = [json.loads(line)["url"] for line in fh if line.strip()]
    assert remaining == ["https://app.example.com/about"]


@pytest.mark.parametrize(
    ("category", "url", "expected_agent"),
    [
        ("admin", "https://app.example.com/admin/application-version", "bizlogic"),
        ("product_search", "https://app.example.com/catalog/search?q=desk", "InjectionManagerAgent"),
        ("basket_order", "https://app.example.com/orders/checkout", "LogicSwarm"),
        ("feedback_review", "https://app.example.com/reviews", "InjectionManagerAgent"),
        ("file_exposure_upload", "https://app.example.com/files/upload", "InjectionManagerAgent"),
        ("api_data", "https://app.example.com/api/v1/challenges?name=test", "InjectionManagerAgent"),
        ("client_route_dom", "https://app.example.com/#/profile", "InjectionManagerAgent"),
        ("realtime", "https://app.example.com/ws/events?transport=websocket", "DiscoverySwarm"),
        ("meta_observability", "https://app.example.com/ops/healthz", "DiscoverySwarm"),
    ],
)
def test_generate_tasks_for_new_categories_routes_to_expected_agents(
    tmp_path: Path, category: str, url: str, expected_agent: str
):
    pipeline = _new_pipeline(tmp_path)
    mc = pipeline.mc
    tagged_dir = tmp_path / "project" / "tagged_urls"
    tagged_file = tagged_dir / f"20260401_target_tagged_{category}.jsonl"
    _write_jsonl(tagged_file, [{"url": url, "method": "GET", "forms": []}])

    tags = pipeline._map_tagged_category_to_tags(category)
    pipeline._generate_tasks_for_tagged_urls(category, tagged_file, tags)

    assert mc.added_tasks, f"Expected at least one task for category={category}"
    assert mc.added_tasks[-1].agent_type == expected_agent


def test_generate_tasks_for_realtime_deduplicates_volatile_query_params(tmp_path: Path):
    pipeline = _new_pipeline(tmp_path)
    mc = pipeline.mc
    tagged_dir = tmp_path / "project" / "tagged_urls"
    tagged_file = tagged_dir / "20260401_target_tagged_realtime.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/ws/events?transport=websocket&t=1&sid=a", "method": "GET", "forms": []},
            {"url": "https://app.example.com/ws/events?transport=websocket&t=2&sid=a", "method": "GET", "forms": []},
            {"url": "https://app.example.com/ws/events?transport=websocket&t=3&sid=b", "method": "GET", "forms": []},
            {"url": "https://app.example.com/ws/events?transport=polling&t=9", "method": "GET", "forms": []},
        ],
    )

    tags = pipeline._map_tagged_category_to_tags("realtime")
    pipeline._generate_tasks_for_tagged_urls("realtime", tagged_file, tags)

    assert mc.added_tasks, "Expected realtime task to be generated"
    realtime_task = mc.added_tasks[-1]
    targets = realtime_task.params.get("targets", [])
    assert isinstance(targets, list)
    assert len(targets) == 2


def test_generate_tasks_for_realtime_applies_budget_cap(tmp_path: Path):
    pipeline = _new_pipeline(tmp_path, config={"scan": {"realtime_target_budget": 1}})
    mc = pipeline.mc
    tagged_dir = tmp_path / "project" / "tagged_urls"
    tagged_file = tagged_dir / "20260401_target_tagged_realtime.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/ws/events?transport=websocket&t=1&sid=a", "method": "GET", "forms": []},
            {"url": "https://app.example.com/ws/events?transport=polling&t=9", "method": "GET", "forms": []},
        ],
    )

    tags = pipeline._map_tagged_category_to_tags("realtime")
    pipeline._generate_tasks_for_tagged_urls("realtime", tagged_file, tags)

    assert mc.added_tasks, "Expected realtime task to be generated"
    realtime_task = mc.added_tasks[-1]
    targets = realtime_task.params.get("targets", [])
    assert isinstance(targets, list)
    assert len(targets) == 1


def test_generate_tasks_for_id_param_applies_phase2_caps_and_disables_risk_force(tmp_path: Path):
    pipeline = _new_pipeline(tmp_path)
    mc = pipeline.mc
    tagged_dir = tmp_path / "project" / "tagged_urls"
    tagged_file = tagged_dir / "20260401_target_tagged_id_param.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/api/v1/users?id=1", "method": "GET", "forms": []},
        ],
    )

    tags = pipeline._map_tagged_category_to_tags("id_param")
    pipeline._generate_tasks_for_tagged_urls("id_param", tagged_file, tags)

    id_param_tasks = [t for t in mc.added_tasks if str(getattr(t, "id", "")).startswith("id_param_scan_")]
    assert id_param_tasks, "Expected id_param scan task to be generated"
    scan_task = id_param_tasks[0]
    params = getattr(scan_task, "params", {}) or {}
    assert params.get("phase2_max_seconds") == 120
    assert params.get("phase2_max_seconds_risk_forced") == 60
    assert params.get("phase2_risk_force_vuln_types") == []


def test_generate_tasks_for_xss_candidate_skips_low_value_static_asset_urls(tmp_path: Path):
    pipeline = _new_pipeline(tmp_path)
    mc = pipeline.mc
    tagged_dir = tmp_path / "project" / "tagged_urls"
    tagged_file = tagged_dir / "20260401_target_tagged_xss_candidate.jsonl"
    static_noise = "https://app.example.com/static/js/%27%29,D=f%28%27%3Cscript%20type=text/javascript%3E"
    dynamic_target = "https://app.example.com/profile?query=test"
    _write_jsonl(
        tagged_file,
        [
            {"url": static_noise, "method": "GET", "forms": []},
            {"url": dynamic_target, "method": "GET", "forms": []},
        ],
    )

    tags = pipeline._map_tagged_category_to_tags("xss_candidate")
    pipeline._generate_tasks_for_tagged_urls("xss_candidate", tagged_file, tags)

    xss_tasks = [t for t in mc.added_tasks if str(getattr(t, "id", "")).startswith("xss_candidate_scan_")]
    assert xss_tasks, "Expected xss_candidate task to be generated"
    targets = xss_tasks[0].params.get("targets", [])
    assert dynamic_target in targets
    assert static_noise not in targets
    assert len(targets) == 1


def test_generate_tasks_for_xss_candidate_scans_beyond_early_noise_window(tmp_path: Path):
    pipeline = _new_pipeline(tmp_path)
    mc = pipeline.mc
    tagged_dir = tmp_path / "project" / "tagged_urls"
    tagged_file = tagged_dir / "20260401_target_tagged_xss_candidate.jsonl"

    rows: list[dict] = []
    for i in range(30):
        rows.append(
            {
                "url": f"https://app.example.com/static/js/noise_{i}.js",
                "method": "GET",
                "forms": [],
            }
        )
    dynamic_target = "https://app.example.com/profile?query=desk"
    rows.append({"url": dynamic_target, "method": "GET", "forms": []})
    _write_jsonl(tagged_file, rows)

    tags = pipeline._map_tagged_category_to_tags("xss_candidate")
    pipeline._generate_tasks_for_tagged_urls("xss_candidate", tagged_file, tags)

    xss_tasks = [t for t in mc.added_tasks if str(getattr(t, "id", "")).startswith("xss_candidate_scan_")]
    assert xss_tasks, "Expected xss_candidate task to be generated"
    targets = xss_tasks[0].params.get("targets", [])
    assert dynamic_target in targets
    assert all("/static/js/noise_" not in t for t in targets)


def test_generate_tasks_for_tagged_urls_honors_tagged_candidate_target_cap(tmp_path: Path):
    pipeline = _new_pipeline(tmp_path, config={"scan": {"tagged_candidate_target_cap": 3}})
    mc = pipeline.mc
    tagged_dir = tmp_path / "project" / "tagged_urls"
    tagged_file = tagged_dir / "20260401_target_tagged_api_data.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": f"https://app.example.com/api/v1/items?id={i}", "method": "GET", "forms": []}
            for i in range(10)
        ],
    )

    tags = pipeline._map_tagged_category_to_tags("api_data")
    pipeline._generate_tasks_for_tagged_urls("api_data", tagged_file, tags)

    api_tasks = [t for t in mc.added_tasks if str(getattr(t, "id", "")).startswith("api_data_scan_")]
    assert api_tasks, "Expected api_data task to be generated"
    targets = api_tasks[0].params.get("targets", [])
    assert isinstance(targets, list)
    assert len(targets) == 3


def test_promote_uncategorized_realtime_normalized_dedup_and_budget(tmp_path: Path):
    pipeline = _new_pipeline(tmp_path, config={"scan": {"realtime_target_budget": 2}})
    tagged_dir = tmp_path / "project" / "tagged_urls"
    uncategorized_file = tagged_dir / "20260401_target_tagged_uncategorized.jsonl"
    _write_jsonl(
        uncategorized_file,
        [
            {"url": "https://app.example.com/socket.io/?EIO=4&transport=polling&t=1&sid=a"},
            {"url": "https://app.example.com/socket.io/?EIO=4&transport=polling&t=2&sid=a"},
            {"url": "https://app.example.com/socket.io/?EIO=4&transport=polling&t=3&sid=b"},
            {"url": "https://app.example.com/socket.io/?EIO=4&transport=polling&channel=one&t=9"},
            {"url": "https://app.example.com/socket.io/?EIO=4&transport=polling&channel=two&t=10"},
            {"url": "https://app.example.com/about"},
        ],
    )

    promoted = pipeline._promote_uncategorized_tagged_file(uncategorized_file)
    realtime_file = promoted.get("realtime")
    assert realtime_file is not None
    assert realtime_file.exists()

    with open(realtime_file, "r", encoding="utf-8") as fh:
        promoted_rows = [json.loads(line) for line in fh if line.strip()]
    assert len(promoted_rows) == 2

    def _normalize(url: str) -> str:
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        query.pop("t", None)
        query.pop("sid", None)
        pairs = []
        for key in sorted(query.keys()):
            for val in query.get(key, []):
                pairs.append((key, val))
        stable_query = "&".join(f"{k}={v}" for k, v in pairs)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{stable_query}" if stable_query else f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    normalized = {_normalize(str(row.get("url", ""))) for row in promoted_rows}
    assert len(normalized) == 2

    with open(uncategorized_file, "r", encoding="utf-8") as fh:
        remaining_rows = [json.loads(line) for line in fh if line.strip()]
    assert len(remaining_rows) == 1
    assert str(remaining_rows[0].get("url", "")).endswith("/about")


def test_promote_uncategorized_splits_external_and_invalid_candidates(tmp_path: Path):
    project_dir = tmp_path / "project"
    pm = _DummyProjectManager(project_dir=project_dir)
    mc = _DummyMC()
    pipeline = ReconPipeline(
        config={},
        project_manager=pm,
        target="https://app.example.com/",
        master_conductor=mc,
    )
    tagged_dir = tmp_path / "project" / "tagged_urls"
    uncategorized_file = tagged_dir / "20260401_target_tagged_uncategorized.jsonl"
    _write_jsonl(
        uncategorized_file,
        [
            {"url": "https://owasp.org"},
            {"url": "https://github.com/juice-shop/juice-shop/issues"},
            {"url": "https://pwning.owasp-juice.shop/companion-guide/latest/part1/challenges.html"},
            {"url": "https://app.example.com/%7B%7Bhref%7D%7D"},
            {"url": "https://app.example.com/%27+L(i[8])+'"},
            {"url": "https://app.example.com/about"},
        ],
    )

    promoted = pipeline._promote_uncategorized_tagged_file(uncategorized_file)

    assert "external_link" in promoted
    assert "invalid_candidate" in promoted

    with open(promoted["external_link"], "r", encoding="utf-8") as fh:
        external_rows = [json.loads(line) for line in fh if line.strip()]
    assert len(external_rows) == 3

    with open(promoted["invalid_candidate"], "r", encoding="utf-8") as fh:
        invalid_rows = [json.loads(line) for line in fh if line.strip()]
    assert len(invalid_rows) == 2

    with open(uncategorized_file, "r", encoding="utf-8") as fh:
        remaining_rows = [json.loads(line) for line in fh if line.strip()]
    assert len(remaining_rows) == 1
    assert str(remaining_rows[0].get("url", "")).endswith("/about")


# ---------------------------------------------------------------------------
# CORS candidate 分類テスト (A-2)
# ---------------------------------------------------------------------------

def test_promote_uncategorized_acao_header_becomes_cors_candidate(tmp_path: Path):
    """classify() が Access-Control-Allow-Origin レスポンスヘッダーを cors_candidate に分類する"""
    pipeline = _new_pipeline(tmp_path)
    tagged_dir = tmp_path / "project" / "tagged_urls"
    uncategorized_file = tagged_dir / "20260401_target_tagged_uncategorized.jsonl"

    _write_jsonl(
        uncategorized_file,
        [
            {
                "url": "https://app.example.com/api/data",
                "method": "GET",
                "response_headers": {"Access-Control-Allow-Origin": "https://evil.com"},
            },
            {
                "url": "https://app.example.com/about",
                "method": "GET",
            },
        ],
    )

    promoted = pipeline._promote_uncategorized_tagged_file(uncategorized_file)

    assert "cors_candidate" in promoted, "ACAO ヘッダーを持つ URL は cors_candidate に昇格すること"
    assert promoted["cors_candidate"].exists()

    with open(promoted["cors_candidate"], "r", encoding="utf-8") as fh:
        cors_rows = [json.loads(line) for line in fh if line.strip()]
    assert len(cors_rows) == 1
    assert cors_rows[0]["url"] == "https://app.example.com/api/data"

    with open(uncategorized_file, "r", encoding="utf-8") as fh:
        remaining = [json.loads(line) for line in fh if line.strip()]
    assert len(remaining) == 1
    assert remaining[0]["url"].endswith("/about")


def test_promote_uncategorized_acao_header_nested_response_key(tmp_path: Path):
    """Katana JSONL 形式（response.headers 以下にネスト）でも cors_candidate に分類する"""
    pipeline = _new_pipeline(tmp_path)
    tagged_dir = tmp_path / "project" / "tagged_urls"
    uncategorized_file = tagged_dir / "20260401_target_tagged_uncategorized.jsonl"

    _write_jsonl(
        uncategorized_file,
        [
            {
                "url": "https://app.example.com/api/v2/users",
                "method": "GET",
                "response": {
                    "headers": {"Access-Control-Allow-Origin": "*"},
                    "status_code": 200,
                },
            },
        ],
    )

    promoted = pipeline._promote_uncategorized_tagged_file(uncategorized_file)

    assert "cors_candidate" in promoted, "response.headers 以下の ACAO も cors_candidate に昇格すること"


def test_map_tagged_category_cors_candidate_returns_tag(tmp_path: Path):
    """_map_tagged_category_to_tags が cors_candidate カテゴリに対して正しいタグを返す"""
    pipeline = _new_pipeline(tmp_path)
    tags = pipeline._map_tagged_category_to_tags("cors_candidate")
    assert "cors_candidate" in tags


def test_generate_tasks_cors_candidate_routes_to_injection_manager(tmp_path: Path):
    """_generate_tasks_for_tagged_urls が cors_candidate を InjectionManagerAgent へルーティングする"""
    pipeline = _new_pipeline(tmp_path)
    mc = pipeline.mc
    tagged_dir = tmp_path / "project" / "tagged_urls"
    tagged_file = tagged_dir / "20260401_target_tagged_cors_candidate.jsonl"
    _write_jsonl(
        tagged_file,
        [{"url": "https://app.example.com/api/data", "method": "GET", "forms": []}],
    )

    tags = pipeline._map_tagged_category_to_tags("cors_candidate")
    pipeline._generate_tasks_for_tagged_urls("cors_candidate", tagged_file, tags)

    assert mc.added_tasks, "cors_candidate タスクが生成されること"
    assert mc.added_tasks[-1].agent_type == "InjectionManagerAgent"


def test_generate_tasks_for_meta_observability_applies_budget_cap(tmp_path: Path):
    pipeline = _new_pipeline(tmp_path, config={"scan": {"meta_observability_target_budget": 2}})
    mc = pipeline.mc
    tagged_dir = tmp_path / "project" / "tagged_urls"
    tagged_file = tagged_dir / "20260401_target_tagged_meta_observability.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/assets/i18n/en.json", "method": "GET", "forms": []},
            {"url": "https://app.example.com/rest/languages", "method": "GET", "forms": []},
            {"url": "https://app.example.com/health", "method": "GET", "forms": []},
        ],
    )

    tags = pipeline._map_tagged_category_to_tags("meta_observability")
    pipeline._generate_tasks_for_tagged_urls("meta_observability", tagged_file, tags)

    assert mc.added_tasks, "Expected meta_observability task to be generated"
    meta_task = mc.added_tasks[-1]
    targets = meta_task.params.get("targets", [])
    assert isinstance(targets, list)
    assert len(targets) == 2
