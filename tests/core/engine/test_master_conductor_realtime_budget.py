from pathlib import Path
from types import SimpleNamespace
import json

from src.core.engine.master_conductor import MasterConductor


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def test_create_attack_tasks_caps_realtime_targets_with_normalized_dedup(tmp_path: Path):
    tagged_file = tmp_path / "tagged_realtime.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/socket.io/?EIO=4&transport=polling&t=1&sid=a"},
            {"url": "https://app.example.com/socket.io/?EIO=4&transport=polling&t=2&sid=a"},
            {"url": "https://app.example.com/socket.io/?EIO=4&transport=polling&channel=one&t=3&sid=b"},
            {"url": "https://app.example.com/socket.io/?EIO=4&transport=polling&channel=two&t=4"},
            {"url": "https://app.example.com/socket.io/?EIO=4&transport=websocket&t=10&sid=x"},
            {"url": "https://app.example.com/socket.io/?EIO=4&transport=websocket&channel=one&t=11&sid=y"},
            {"url": "https://app.example.com/socket.io/?EIO=4&transport=websocket&channel=two&t=12"},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(discovered_assets=[], target_info={"auth_tokens": {}, "tech_stack": []})
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_realtime": {
            "file": str(tagged_file),
            "count": 7,
            "description": "Tagged URLs (realtime)",
            "tags": ["api_endpoint", "auth_required"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    assert tasks, "Expected realtime attack task to be created"
    realtime_tasks = [task for task in tasks if task.params.get("category") == "realtime"]
    assert len(realtime_tasks) == 5
    assert all(task.agent_type == "DiscoverySwarm" for task in realtime_tasks)
    assert all("(5 targets)" in task.name for task in realtime_tasks)


def test_create_attack_tasks_skips_non_actionable_categories(tmp_path: Path):
    external_file = tmp_path / "tagged_external_link.jsonl"
    invalid_file = tmp_path / "tagged_invalid_candidate.jsonl"
    _write_jsonl(external_file, [{"url": "https://owasp.org"}])
    _write_jsonl(invalid_file, [{"url": "https://app.example.com/%7B%7Bhref%7D%7D"}])

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(discovered_assets=[], target_info={"auth_tokens": {}, "tech_stack": []})
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_external_link": {
            "file": str(external_file),
            "count": 1,
            "description": "Tagged URLs (external_link)",
            "tags": ["out_of_scope_candidate"],
        },
        "tagged_invalid_candidate": {
            "file": str(invalid_file),
            "count": 1,
            "description": "Tagged URLs (invalid_candidate)",
            "tags": ["invalid_url_candidate"],
        },
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    assert tasks == []


def test_create_attack_tasks_caps_meta_observability_targets(tmp_path: Path):
    tagged_file = tmp_path / "tagged_meta_observability.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/assets/i18n/en.json"},
            {"url": "https://app.example.com/assets/i18n/%7B%7Breddit%7D%7D"},
            {"url": "https://app.example.com/rest/languages"},
            {"url": "https://app.example.com/health"},
            {"url": "https://app.example.com/status"},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(discovered_assets=[], target_info={"auth_tokens": {}, "tech_stack": []})
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_meta_observability": {
            "file": str(tagged_file),
            "count": 5,
            "description": "Tagged URLs (meta_observability)",
            "tags": ["debug_info", "api_endpoint"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    assert tasks
    meta_tasks = [task for task in tasks if task.params.get("category") == "meta_observability"]
    assert len(meta_tasks) == 3
    assert all(task.agent_type == "DiscoverySwarm" for task in meta_tasks)
    assert all("(3 targets)" in task.name for task in meta_tasks)
