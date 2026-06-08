from pathlib import Path
from types import SimpleNamespace
import json

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


def test_collect_recent_authz_history_urls_replays_authbypass(tmp_path: Path):
    project_dir = tmp_path / "project"
    tagged_dir = project_dir / "tagged_urls"
    tagged_dir.mkdir(parents=True, exist_ok=True)

    current_file = tagged_dir / "20260401_target_tagged_auth.jsonl"
    history_file = tagged_dir / "20260331_target_tagged_auth.jsonl"

    _write_jsonl(
        current_file,
        [
            {"url": "http://localhost:4280/vulnerabilities/weak_id/", "method": "GET"},
        ],
    )
    _write_jsonl(
        history_file,
        [
            {"url": "http://localhost:4280/vulnerabilities/authbypass/", "method": "GET"},
        ],
    )

    mc = _DummyMC()
    pm = _DummyProjectManager(project_dir=project_dir)
    pipeline = ReconPipeline(config={}, project_manager=pm, target="http://localhost:4280/", master_conductor=mc)

    replay = pipeline._collect_recent_authz_history_urls(
        file_path=current_file,
        current_urls=["http://localhost:4280/vulnerabilities/weak_id/"],
    )

    assert "http://localhost:4280/vulnerabilities/authbypass/" in replay


def test_generate_tasks_for_tagged_auth_replays_authbypass_and_uses_idor_probe(tmp_path: Path):
    project_dir = tmp_path / "project"
    tagged_dir = project_dir / "tagged_urls"
    tagged_dir.mkdir(parents=True, exist_ok=True)

    current_file = tagged_dir / "20260401_target_tagged_auth.jsonl"
    history_file = tagged_dir / "20260331_target_tagged_auth.jsonl"

    _write_jsonl(
        current_file,
        [
            {"url": "http://localhost:4280/vulnerabilities/weak_id/", "method": "GET", "forms": []},
        ],
    )
    _write_jsonl(
        history_file,
        [
            {"url": "http://localhost:4280/vulnerabilities/authbypass/", "method": "GET", "forms": []},
        ],
    )

    mc = _DummyMC()
    pm = _DummyProjectManager(project_dir=project_dir)
    pipeline = ReconPipeline(config={}, project_manager=pm, target="http://localhost:4280/", master_conductor=mc)

    pipeline._generate_tasks_for_tagged_urls("auth", current_file, ["auth_endpoint"])

    bizlogic_tasks = [t for t in mc.added_tasks if getattr(t, "agent_type", "") == "bizlogic"]
    assert bizlogic_tasks, "Expected BizLogic task to be generated for replayed authbypass target"

    matched = False
    for task in bizlogic_tasks:
        params = getattr(task, "params", {}) or {}
        candidate = params.get("candidate", {}) if isinstance(params, dict) else {}
        target = str(params.get("target", "") or "")
        if "/authbypass/" in target and "get_user_data.php?id=2" in target:
            assert candidate.get("smell_type") == "idor_candidate"
            assert (candidate.get("parameters", {}) or {}).get("id_param") == "id"
            matched = True
            break

    assert matched, "Expected replayed authbypass target to be normalized to get_user_data.php?id=2 with idor probe"


def test_generate_tasks_for_tagged_authz_avoids_duplicate_bizlogic_targets(tmp_path: Path):
    project_dir = tmp_path / "project"
    tagged_dir = project_dir / "tagged_urls"
    tagged_dir.mkdir(parents=True, exist_ok=True)

    auth_file = tagged_dir / "20260401_target_tagged_auth.jsonl"
    id_param_file = tagged_dir / "20260401_target_tagged_id_param.jsonl"

    rows = [
        {"url": "http://localhost:4280/vulnerabilities/authbypass/", "method": "GET", "forms": []},
        {"url": "http://localhost:4280/vulnerabilities/authbypass/get_user_data.php?id=2", "method": "GET", "forms": []},
    ]
    _write_jsonl(auth_file, rows)
    _write_jsonl(id_param_file, rows)

    mc = _DummyMC()
    pm = _DummyProjectManager(project_dir=project_dir)
    pipeline = ReconPipeline(config={}, project_manager=pm, target="http://localhost:4280/", master_conductor=mc)

    pipeline._generate_tasks_for_tagged_urls("auth", auth_file, ["auth_endpoint"])
    pipeline._generate_tasks_for_tagged_urls("id_param", id_param_file, ["idor_candidate"])

    bizlogic_targets = []
    for task in mc.added_tasks:
        if getattr(task, "agent_type", "") != "bizlogic":
            continue
        params = getattr(task, "params", {}) or {}
        bizlogic_targets.append(str(params.get("target", "") or "").lower())

    assert bizlogic_targets, "Expected at least one bizlogic task for authz targets"
    assert len(bizlogic_targets) == len(set(bizlogic_targets))


def test_generate_tasks_for_tagged_api_data_replays_recent_category_history(tmp_path: Path):
    project_dir = tmp_path / "project"
    tagged_dir = project_dir / "tagged_urls"
    tagged_dir.mkdir(parents=True, exist_ok=True)

    current_file = tagged_dir / "20260402_target_tagged_api_data.jsonl"
    history_file = tagged_dir / "20260401_target_tagged_uncategorized_promoted_api_data.jsonl"

    _write_jsonl(
        current_file,
        [
            {"url": "http://localhost:4280/api/current", "method": "GET", "forms": []},
        ],
    )
    _write_jsonl(
        history_file,
        [
            {"url": "http://localhost:4280/api/history/state?query=desk", "method": "GET", "forms": []},
            {"url": "http://external.example.net/api/history/state?query=desk", "method": "GET", "forms": []},
        ],
    )

    mc = _DummyMC()
    pm = _DummyProjectManager(project_dir=project_dir)
    pipeline = ReconPipeline(config={}, project_manager=pm, target="http://localhost:4280/", master_conductor=mc)

    pipeline._generate_tasks_for_tagged_urls("api_data", current_file, ["api_endpoint", "has_params"])

    api_tasks = [t for t in mc.added_tasks if str(getattr(t, "id", "")).startswith("api_data_scan_")]
    assert api_tasks, "Expected api_data task to be generated"
    targets = list(api_tasks[0].params.get("targets", []))

    assert "http://localhost:4280/api/current" in targets
    assert "http://localhost:4280/api/history/state?query=desk" in targets
    assert all("external.example.net" not in t for t in targets)


def test_generate_tasks_for_tagged_xss_candidate_uses_dense_history_replay_limit(tmp_path: Path):
    project_dir = tmp_path / "project"
    tagged_dir = project_dir / "tagged_urls"
    tagged_dir.mkdir(parents=True, exist_ok=True)

    current_file = tagged_dir / "20260402_target_tagged_xss_candidate.jsonl"
    history_file = tagged_dir / "20260401_target_tagged_xss_candidate.jsonl"

    _write_jsonl(
        current_file,
        [
            {"url": "http://localhost:4280/profile?query=current", "method": "GET", "forms": []},
        ],
    )
    history_rows = [
        {"url": f"http://localhost:4280/search?query=item{i}", "method": "GET", "forms": []}
        for i in range(8)
    ]
    _write_jsonl(history_file, history_rows)

    mc = _DummyMC()
    pm = _DummyProjectManager(project_dir=project_dir)
    pipeline = ReconPipeline(config={}, project_manager=pm, target="http://localhost:4280/", master_conductor=mc)

    pipeline._generate_tasks_for_tagged_urls("xss_candidate", current_file, ["xss_candidate", "sqli_candidate"])

    xss_tasks = [t for t in mc.added_tasks if str(getattr(t, "id", "")).startswith("xss_candidate_scan_")]
    assert xss_tasks, "Expected xss_candidate task to be generated"
    targets = list(xss_tasks[0].params.get("targets", []))

    for row in history_rows:
        assert row["url"] in targets


def test_collect_recent_authz_history_urls_replays_generic_auth_and_id_signals(tmp_path: Path):
    project_dir = tmp_path / "project"
    tagged_dir = project_dir / "tagged_urls"
    tagged_dir.mkdir(parents=True, exist_ok=True)

    current_file = tagged_dir / "20260403_target_tagged_auth.jsonl"
    history_auth_file = tagged_dir / "20260402_target_tagged_auth.jsonl"
    history_id_file = tagged_dir / "20260402_target_tagged_id_param.jsonl"

    _write_jsonl(
        current_file,
        [
            {"url": "http://localhost:4280/account/security", "method": "GET"},
        ],
    )
    _write_jsonl(
        history_auth_file,
        [
            {"url": "http://localhost:4280/account/profile", "method": "GET"},
        ],
    )
    _write_jsonl(
        history_id_file,
        [
            {"url": "http://localhost:4280/orders?order_id=2", "method": "GET"},
        ],
    )

    mc = _DummyMC()
    pm = _DummyProjectManager(project_dir=project_dir)
    pipeline = ReconPipeline(config={}, project_manager=pm, target="http://localhost:4280/", master_conductor=mc)

    replay = pipeline._collect_recent_authz_history_urls(
        file_path=current_file,
        current_urls=["http://localhost:4280/account/security"],
    )

    assert "http://localhost:4280/account/profile" in replay
    assert "http://localhost:4280/orders?order_id=2" in replay


def test_generate_tasks_for_tagged_id_param_replays_recent_id_history(tmp_path: Path):
    project_dir = tmp_path / "project"
    tagged_dir = project_dir / "tagged_urls"
    tagged_dir.mkdir(parents=True, exist_ok=True)

    current_file = tagged_dir / "20260404_target_tagged_id_param.jsonl"
    history_file = tagged_dir / "20260403_target_tagged_id_param.jsonl"

    _write_jsonl(
        current_file,
        [
            {"url": "http://localhost:4280/api/users?id=1", "method": "GET", "forms": []},
        ],
    )
    _write_jsonl(
        history_file,
        [
            {"url": "http://localhost:4280/api/orders?order_id=9", "method": "GET", "forms": []},
        ],
    )

    mc = _DummyMC()
    pm = _DummyProjectManager(project_dir=project_dir)
    pipeline = ReconPipeline(config={}, project_manager=pm, target="http://localhost:4280/", master_conductor=mc)

    pipeline._generate_tasks_for_tagged_urls("id_param", current_file, ["idor_candidate"])

    id_tasks = [t for t in mc.added_tasks if str(getattr(t, "id", "")).startswith("id_param_scan_")]
    assert id_tasks, "Expected id_param task to be generated"
    targets = list(id_tasks[0].params.get("targets", []))

    assert "http://localhost:4280/api/users?id=1" in targets
    assert "http://localhost:4280/api/orders?order_id=9" in targets
