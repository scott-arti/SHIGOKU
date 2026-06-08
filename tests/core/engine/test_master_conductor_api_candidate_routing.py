from pathlib import Path
from types import SimpleNamespace
import json

from src.core.engine.master_conductor import MasterConductor
from src.core.engine.task_queue import create_dynamic_queue
from src.core.domain.model.task import Task


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def test_create_attack_tasks_routes_api_candidate_to_injection_swarm(tmp_path: Path):
    tagged_file = tmp_path / "tagged_api_candidate.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/api/v1/users?name=test", "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(discovered_assets=[], target_info={"auth_tokens": {}, "tech_stack": []})
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_api_candidate": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (api_candidate)",
            "tags": ["api_endpoint"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    assert tasks, "Expected at least one task to be created for api_candidate"
    assert any(getattr(task, "agent_type", "") == "InjectionSwarm" for task in tasks)
    api_candidate_tasks = [task for task in tasks if task.params.get("category") == "api_candidate"]
    assert api_candidate_tasks
    assert all(task.params.get("unknown_classification_only") is False for task in api_candidate_tasks)
    assert all(task.params.get("phase2_on_empty_phase1") is True for task in api_candidate_tasks)
    assert not any("Fallback Endpoints Scan" in getattr(task, "name", "") for task in tasks)


def test_create_attack_tasks_routes_csrf_candidate_to_injection_swarm(tmp_path: Path):
    tagged_file = tmp_path / "tagged_csrf_candidate.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/account/change-password", "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(discovered_assets=[], target_info={"auth_tokens": {}, "tech_stack": []})
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_csrf_candidate": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (csrf_candidate)",
            "tags": ["csrf_candidate"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    assert tasks, "Expected at least one task to be created for csrf_candidate"
    assert any(getattr(task, "agent_type", "") == "InjectionSwarm" for task in tasks)
    assert any(task.params.get("category") == "csrf_candidate" for task in tasks)
    assert not any("Fallback Endpoints Scan" in getattr(task, "name", "") for task in tasks)


def test_create_attack_tasks_skips_low_value_static_xss_candidate_targets(tmp_path: Path):
    tagged_file = tmp_path / "tagged_xss_candidate.jsonl"
    static_noise = "http://127.0.0.1:8888/static/js/%27%29,D=f%28%27%3Cscript%20type=text/javascript%3E"
    dynamic_target = "http://127.0.0.1:8888/profile?query=test"
    _write_jsonl(
        tagged_file,
        [
            {"url": static_noise, "method": "GET", "forms": []},
            {"url": dynamic_target, "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={"required_vuln_families": ["xss"], "auth_tokens": {}, "tech_stack": []},
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_xss_candidate": {
            "file": str(tagged_file),
            "count": 2,
            "description": "Tagged URLs (xss_candidate)",
            "tags": ["xss_candidate"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    xss_tasks = [task for task in tasks if task.params.get("category") == "xss_candidate"]
    assert xss_tasks, "Expected xss_candidate attack task"
    target = str(xss_tasks[0].params.get("target", "") or "")
    assert target == dynamic_target
    assert target != static_noise


def test_create_attack_tasks_xss_candidate_falls_back_to_discovered_asset_when_only_static(tmp_path: Path):
    tagged_file = tmp_path / "tagged_xss_candidate.jsonl"
    static_noise = "http://127.0.0.1:8888/static/js/%27%29,D=f%28%27%3Cscript%20type="
    fallback_dynamic = "http://127.0.0.1:8888/chatbot/genai/state"
    _write_jsonl(
        tagged_file,
        [
            {"url": static_noise, "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=["http://127.0.0.1:8888/", fallback_dynamic, "127.0.0.1"],
        target_info={"required_vuln_families": ["xss"], "auth_tokens": {}, "tech_stack": []},
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_xss_candidate": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (xss_candidate)",
            "tags": ["xss_candidate"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    xss_tasks = [task for task in tasks if task.params.get("category") == "xss_candidate"]
    assert xss_tasks, "Expected xss_candidate attack task"
    target = str(xss_tasks[0].params.get("target", "") or "")
    assert target == fallback_dynamic
    assert target != static_noise


def test_create_attack_tasks_skips_low_value_only_api_data_category_task(tmp_path: Path):
    tagged_file = tmp_path / "tagged_api_data.jsonl"
    static_noise = "http://127.0.0.1:8888/static/js/%27%29,D=f%28%27%3Cscript%20type="
    _write_jsonl(
        tagged_file,
        [
            {"url": static_noise, "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "http://127.0.0.1:8888/",
            "required_vuln_families": ["api", "injection", "csrf"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_api_data": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (api_data)",
            "tags": ["api_endpoint", "has_params"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    direct_api_tasks = [
        task for task in tasks
        if task.params.get("category") == "api_data"
        and task.params.get("source_category") == "tagged_api_data"
    ]
    assert not direct_api_tasks

    api_backfill_tasks = [
        task for task in tasks
        if task.params.get("category") == "api_data"
        and task.params.get("source_category") == "coverage_backfill"
    ]
    assert api_backfill_tasks
    assert api_backfill_tasks[0].params.get("target") == "http://127.0.0.1:8888/"


def test_create_attack_tasks_skips_low_value_only_csrf_category_task(tmp_path: Path):
    tagged_file = tmp_path / "tagged_csrf_candidate.jsonl"
    static_noise = "http://127.0.0.1:8888/static/js/%27%29,D=f%28%27%3Cscript%20type="
    _write_jsonl(
        tagged_file,
        [
            {"url": static_noise, "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "http://127.0.0.1:8888/",
            "required_vuln_families": ["csrf"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_csrf_candidate": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (csrf_candidate)",
            "tags": ["csrf_candidate"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    direct_csrf_tasks = [
        task for task in tasks
        if task.params.get("category") == "csrf_candidate"
        and task.params.get("source_category") == "tagged_csrf_candidate"
    ]
    assert not direct_csrf_tasks

    csrf_backfill_tasks = [
        task for task in tasks
        if task.params.get("category") == "csrf_candidate"
        and task.params.get("source_category") == "coverage_backfill"
    ]
    assert csrf_backfill_tasks
    assert csrf_backfill_tasks[0].params.get("target") == "http://127.0.0.1:8888/"


def test_create_attack_tasks_propagates_context_auth_headers(tmp_path: Path):
    tagged_file = tmp_path / "tagged_api_candidate.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/api/v1/me", "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "cookies": "session=abc123",
            "bearer_token": "jwt-token-123",
            "auth_headers": {"X-Tenant": "acme"},
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_api_candidate": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (api_candidate)",
            "tags": ["api_endpoint"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    assert tasks
    headers = tasks[0].params.get("auth_headers", {})
    assert headers.get("Cookie") == "session=abc123"
    assert headers.get("Authorization") == "Bearer jwt-token-123"
    assert headers.get("X-Tenant") == "acme"


def test_create_attack_tasks_backfills_csrf_candidate_when_missing(tmp_path: Path):
    tagged_file = tmp_path / "tagged_api_data.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/rest/products/search?q=desk", "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "required_vuln_families": ["access_control", "injection", "xss", "csrf", "auth", "business_logic", "api"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_api_data": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (api_data)",
            "tags": ["api_endpoint", "has_params"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    csrf_tasks = [task for task in tasks if task.params.get("category") == "csrf_candidate"]
    assert csrf_tasks, "Expected CSRF backfill task when csrf family is required but no csrf_candidate is tagged"
    assert all(task.agent_type == "InjectionSwarm" for task in csrf_tasks)
    assert all(task.params.get("source_category") == "coverage_backfill" for task in csrf_tasks)
    assert all(task.params.get("targets") for task in csrf_tasks)
    assert all(task.params.get("csrf_active_verify") is False for task in csrf_tasks)
    assert all(task.params.get("unknown_classification_only") is False for task in csrf_tasks)
    assert all(task.params.get("phase2_on_empty_phase1") is True for task in csrf_tasks)
    assert all(task.params.get("phase2_risk_force_vuln_types") == [] for task in csrf_tasks)
    assert all(task.params.get("phase2_max_seconds_risk_forced") == 30 for task in csrf_tasks)
    assert all(task.params.get("phase2_max_seconds") == 60 for task in csrf_tasks)


def test_create_attack_tasks_csrf_backfill_uses_in_scope_host_when_target_is_missing():
    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "host": "127.0.0.1",
            "required_vuln_families": ["csrf"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.target = ""

    tasks = mc._create_attack_tasks_from_recon({})

    csrf_tasks = [task for task in tasks if task.params.get("category") == "csrf_candidate"]
    assert csrf_tasks
    csrf_task = csrf_tasks[0]
    assert csrf_task.params.get("target") == "http://127.0.0.1/"
    evidence = csrf_task.params.get("_context", {}).get("csrf_seed_evidence_by_url", {})
    assert "http://127.0.0.1/" in evidence
    reasons = evidence["http://127.0.0.1/"].get("reasons", [])
    assert "in_scope_host_fallback" in reasons


def test_create_attack_tasks_forces_csrf_guard_task_when_seed_resolution_returns_empty():
    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "http://127.0.0.1:8888/",
            "required_vuln_families": ["csrf"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.target = "http://127.0.0.1:8888/"

    # Simulate worst-case planner path where both seed collection and refinement return empty.
    mc._collect_csrf_seed_targets = lambda recon_results, budget: ([], {})  # type: ignore[assignment]
    mc._refine_backfill_seed_targets = lambda targets, evidence_by_url, budget: ([], {})  # type: ignore[assignment]

    tasks = mc._create_attack_tasks_from_recon({})

    csrf_tasks = [task for task in tasks if task.params.get("category") == "csrf_candidate"]
    assert csrf_tasks
    guard_tasks = [task for task in csrf_tasks if task.params.get("source_category") == "coverage_backfill_guard"]
    assert guard_tasks, "Expected forced CSRF guard task when normal backfill path yields no candidates"
    guard_task = guard_tasks[0]
    assert guard_task.params.get("_coverage_guard_forced") is True
    assert guard_task.params.get("target") == "http://127.0.0.1:8888/"


def test_create_attack_tasks_forces_xss_guard_task_when_seed_resolution_returns_empty():
    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "",
            "required_vuln_families": ["xss"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.target = ""

    mc._collect_xss_seed_targets = lambda recon_results, budget: ([], {})  # type: ignore[assignment]
    mc._refine_backfill_seed_targets = lambda targets, evidence_by_url, budget: ([], {})  # type: ignore[assignment]
    mc._resolve_global_csrf_guard_target = lambda: "http://127.0.0.1:8888/"  # type: ignore[assignment]

    tasks = mc._create_attack_tasks_from_recon({})

    xss_tasks = [task for task in tasks if task.params.get("category") == "xss_candidate"]
    assert xss_tasks
    guard_tasks = [task for task in xss_tasks if task.params.get("source_category") == "coverage_backfill_guard"]
    assert guard_tasks, "Expected forced XSS guard task when normal backfill path yields no candidates"
    guard_task = guard_tasks[0]
    assert guard_task.params.get("_coverage_guard_forced") is True
    assert guard_task.params.get("target") == "http://127.0.0.1:8888/"


def test_global_csrf_guard_injects_once_when_required_and_missing():
    mc = MasterConductor.__new__(MasterConductor)
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "http://127.0.0.1:8888/",
            "required_vuln_families": ["csrf"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.task_queue = create_dynamic_queue()
    mc.completed_tasks = []
    mc.pending_hitl = []
    mc._injected_task_ids = set()
    mc._derived_task_count = 0
    mc.target = "http://127.0.0.1:8888/"

    first_injected = mc._ensure_global_csrf_guard_task(trigger_source="pytest")
    assert first_injected is True

    csrf_guard_tasks = [
        task for task in mc.task_queue.get_all()
        if task.params.get("category") == "csrf_candidate"
        and task.params.get("source_category") == "coverage_backfill_guard"
    ]
    assert len(csrf_guard_tasks) == 1
    assert csrf_guard_tasks[0].params.get("_coverage_guard_forced") is True

    second_injected = mc._ensure_global_csrf_guard_task(trigger_source="pytest")
    assert second_injected is False
    assert len([
        task for task in mc.task_queue.get_all()
        if task.params.get("category") == "csrf_candidate"
        and task.params.get("source_category") == "coverage_backfill_guard"
    ]) == 1


def test_global_xss_guard_injects_once_when_required_and_missing():
    mc = MasterConductor.__new__(MasterConductor)
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "http://127.0.0.1:8888/",
            "required_vuln_families": ["xss"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.task_queue = create_dynamic_queue()
    mc.completed_tasks = []
    mc.pending_hitl = []
    mc._injected_task_ids = set()
    mc._derived_task_count = 0
    mc.target = "http://127.0.0.1:8888/"

    first_injected = mc._ensure_global_xss_guard_task(trigger_source="pytest")
    assert first_injected is True

    xss_guard_tasks = [
        task for task in mc.task_queue.get_all()
        if task.params.get("category") == "xss_candidate"
        and task.params.get("source_category") == "coverage_backfill_guard"
    ]
    assert len(xss_guard_tasks) == 1
    assert xss_guard_tasks[0].params.get("_coverage_guard_forced") is True

    second_injected = mc._ensure_global_xss_guard_task(trigger_source="pytest")
    assert second_injected is False
    assert len([
        task for task in mc.task_queue.get_all()
        if task.params.get("category") == "xss_candidate"
        and task.params.get("source_category") == "coverage_backfill_guard"
    ]) == 1


def test_global_oob_guard_injects_once_when_auth_surface_exists_and_scn08_missing():
    mc = MasterConductor.__new__(MasterConductor)
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "http://127.0.0.1:8888/",
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.task_queue = create_dynamic_queue()
    mc.completed_tasks = [
        Task(
            id="auth_scan",
            name="Authentication Analysis (7 targets)",
            agent_type="AuthNinja",
            action="scan",
            phase="init",
            params={
                "category": "auth",
                "tags": ["auth_endpoint"],
                "target": "http://127.0.0.1:8888/profile",
                "targets": ["http://127.0.0.1:8888/profile"],
            },
            target="http://127.0.0.1:8888/profile",
            priority=70,
        )
    ]
    mc.pending_hitl = []
    mc._injected_task_ids = set()
    mc._derived_task_count = 0
    mc.target = "http://127.0.0.1:8888/"
    mc._get_context_cookie_string = lambda: ""
    mc._get_context_auth_headers = lambda: {}

    first_injected = mc._ensure_global_oob_guard_task(trigger_source="pytest")
    assert first_injected is True

    oob_guard_tasks = [
        task for task in mc.task_queue.get_all()
        if task.params.get("source_category") == "scenario_probe_guard"
        and task.params.get("scenario_probe") == "scn_08_oob_external_channel_flow"
    ]
    assert len(oob_guard_tasks) == 1
    guard_task = oob_guard_tasks[0]
    assert guard_task.params.get("_coverage_guard_forced") is True
    assert guard_task.params.get("category") == "auth"
    assert guard_task.params.get("target") == "http://127.0.0.1:8888/profile"

    second_injected = mc._ensure_global_oob_guard_task(trigger_source="pytest")
    assert second_injected is False


def test_create_attack_tasks_csrf_backfill_root_only_disables_phase2_on_empty(tmp_path: Path):
    tagged_file = tmp_path / "tagged_api_data.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/", "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "required_vuln_families": ["csrf"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_api_data": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (api_data)",
            "tags": ["api_endpoint", "has_params"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    csrf_tasks = [task for task in tasks if task.params.get("category") == "csrf_candidate"]
    assert csrf_tasks
    csrf_task = csrf_tasks[0]
    assert csrf_task.params.get("target") == "https://app.example.com/"
    assert csrf_task.params.get("phase2_on_empty_phase1") is False


def test_create_attack_tasks_backfills_api_injection_when_missing(tmp_path: Path):
    tagged_file = tmp_path / "tagged_xss_candidate.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/profile?query=test", "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "required_vuln_families": ["api", "injection"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_xss_candidate": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (xss_candidate)",
            "tags": ["xss_candidate"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    api_backfill_tasks = [
        task for task in tasks
        if task.params.get("category") == "api_data"
        and task.params.get("source_category") == "coverage_backfill"
    ]
    assert api_backfill_tasks, "Expected API/Injection backfill task when api family is missing"
    api_task = api_backfill_tasks[0]
    assert api_task.agent_type == "InjectionSwarm"
    assert api_task.params.get("targets")
    assert api_task.params.get("unknown_classification_only") is False
    assert api_task.params.get("phase2_on_empty_phase1") is True
    assert api_task.params.get("phase2_risk_force_vuln_types") == []
    assert api_task.params.get("phase2_max_seconds_risk_forced") == 45
    assert api_task.params.get("phase2_max_seconds") == 90


def test_create_attack_tasks_api_backfill_root_only_disables_phase2_on_empty(tmp_path: Path):
    tagged_file = tmp_path / "tagged_xss_candidate.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/", "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "required_vuln_families": ["api", "injection"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_xss_candidate": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (xss_candidate)",
            "tags": ["xss_candidate"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    api_backfill_tasks = [
        task for task in tasks
        if task.params.get("category") == "api_data"
        and task.params.get("source_category") == "coverage_backfill"
    ]
    assert api_backfill_tasks
    api_task = api_backfill_tasks[0]
    assert api_task.params.get("target") == "https://app.example.com/"
    assert api_task.params.get("phase2_on_empty_phase1") is False


def test_create_attack_tasks_api_backfill_uses_discovered_non_root_asset(tmp_path: Path):
    tagged_file = tmp_path / "tagged_xss_candidate.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/", "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[
            "https://app.example.com/",
            "https://app.example.com/orders/history?query=desk",
        ],
        target_info={
            "target": "https://app.example.com/",
            "required_vuln_families": ["api", "injection"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_xss_candidate": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (xss_candidate)",
            "tags": ["xss_candidate"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    api_backfill_tasks = [
        task for task in tasks
        if task.params.get("category") == "api_data"
        and task.params.get("source_category") == "coverage_backfill"
    ]
    assert api_backfill_tasks
    api_task = api_backfill_tasks[0]
    assert api_task.params.get("target") == "https://app.example.com/orders/history?query=desk"
    assert api_task.params.get("phase2_on_empty_phase1") is True


def test_create_attack_tasks_does_not_backfill_api_injection_when_already_covered(tmp_path: Path):
    tagged_file = tmp_path / "tagged_api_data.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/api/v1/users?name=test", "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "required_vuln_families": ["api", "injection"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_api_data": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (api_data)",
            "tags": ["api_endpoint", "has_params"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    api_backfill_tasks = [
        task for task in tasks
        if task.params.get("category") == "api_data"
        and task.params.get("source_category") == "coverage_backfill"
    ]
    assert not api_backfill_tasks


def test_create_attack_tasks_backfills_access_logic_when_missing(tmp_path: Path):
    tagged_file = tmp_path / "tagged_api_data.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/chatbot/genai/state", "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "required_vuln_families": ["access_control", "injection", "xss", "csrf", "auth", "business_logic", "api"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_api_data": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (api_data)",
            "tags": ["api_endpoint", "has_params"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    access_logic_tasks = [
        task for task in tasks
        if task.params.get("category") == "admin"
        and task.params.get("source_category") == "coverage_backfill"
    ]
    assert access_logic_tasks, "Expected access/business_logic backfill task when both families are missing"
    assert all(task.agent_type == "bizlogic" for task in access_logic_tasks)
    assert all("/chatbot/genai/state" in str(task.params.get("target", "")) for task in access_logic_tasks)


def test_create_attack_tasks_backfills_xss_when_missing(tmp_path: Path):
    tagged_file = tmp_path / "tagged_api_data.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/chatbot/genai/state", "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "required_vuln_families": ["xss"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_api_data": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (api_data)",
            "tags": ["api_endpoint", "has_params"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    xss_tasks = [
        task for task in tasks
        if task.params.get("category") == "xss_candidate"
        and task.params.get("source_category") == "coverage_backfill"
    ]
    assert xss_tasks, "Expected XSS backfill task when xss family is required but no xss_candidate is tagged"
    assert all(task.agent_type == "InjectionSwarm" for task in xss_tasks)
    assert all(task.params.get("unknown_classification_only") is False for task in xss_tasks)
    assert all(task.params.get("phase2_on_empty_phase1") is True for task in xss_tasks)
    assert all("/chatbot/genai/state" in str(task.params.get("target", "")) for task in xss_tasks)


def test_create_attack_tasks_backfills_xss_even_when_indirect_xss_mapped_category_exists(tmp_path: Path):
    tagged_file = tmp_path / "tagged_id_param.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/account/profile?id=1", "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "required_vuln_families": ["xss"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_id_param": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (id_param)",
            "tags": ["idor_candidate"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    # id_param は XSS ファミリーに間接マッピングされるが、XSS 専用カテゴリが無い場合は
    # coverage_backfill の xss_candidate を追加生成すること。
    xss_backfill_tasks = [
        task
        for task in tasks
        if task.params.get("category") == "xss_candidate"
        and str(task.params.get("source_category", "")).startswith("coverage_backfill")
    ]
    assert xss_backfill_tasks, "Expected direct xss_candidate backfill task even when id_param exists"


def test_create_attack_tasks_backfills_xss_with_root_fallback_when_no_high_value_seed(tmp_path: Path):
    tagged_file = tmp_path / "tagged_api_data.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/static/js/app.js", "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "required_vuln_families": ["xss"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_api_data": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (api_data)",
            "tags": ["api_endpoint", "has_params"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    xss_tasks = [
        task for task in tasks
        if task.params.get("category") == "xss_candidate"
        and task.params.get("source_category") == "coverage_backfill"
    ]
    assert xss_tasks
    xss_task = xss_tasks[0]
    assert xss_task.params.get("target") == "https://app.example.com/"
    assert xss_task.params.get("phase2_on_empty_phase1") is False


def test_create_attack_tasks_backfills_xss_tops_up_targets_from_discovered_assets(tmp_path: Path):
    tagged_file = tmp_path / "tagged_api_data.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/chatbot/genai/state", "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[
            "https://app.example.com/",
            "https://app.example.com/orders/history?query=desk",
            "https://app.example.com/static/js/app.js",
        ],
        target_info={
            "target": "https://app.example.com/",
            "required_vuln_families": ["xss"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_api_data": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (api_data)",
            "tags": ["api_endpoint", "has_params"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    xss_tasks = [
        task for task in tasks
        if task.params.get("category") == "xss_candidate"
        and task.params.get("source_category") == "coverage_backfill"
    ]
    assert xss_tasks, "Expected XSS backfill task when xss family is required"
    xss_params = xss_tasks[0].params
    xss_targets = xss_params.get("targets", [])
    assert isinstance(xss_targets, list)
    assert "https://app.example.com/chatbot/genai/state" in xss_targets
    assert "https://app.example.com/orders/history?query=desk" in xss_targets
    assert "https://app.example.com/static/js/app.js" not in xss_targets
    assert len(xss_targets) >= 2


def test_create_attack_tasks_skips_access_logic_backfill_when_admin_present(tmp_path: Path):
    tagged_admin_file = tmp_path / "tagged_admin.jsonl"
    _write_jsonl(
        tagged_admin_file,
        [
            {"url": "https://app.example.com/admin/dashboard", "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "required_vuln_families": ["access_control", "business_logic", "api"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_admin": {
            "file": str(tagged_admin_file),
            "count": 1,
            "description": "Tagged URLs (admin)",
            "tags": ["admin_panel"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    assert any(task.params.get("category") == "admin" for task in tasks)
    assert not any(str(task.id).startswith("access_logic_seed_") for task in tasks)


def test_create_attack_tasks_does_not_backfill_csrf_when_not_required(tmp_path: Path):
    tagged_file = tmp_path / "tagged_api_data.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/rest/products/search?q=desk", "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "required_vuln_families": ["access_control", "injection", "xss", "auth", "business_logic", "api"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_api_data": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (api_data)",
            "tags": ["api_endpoint", "has_params"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    assert not any(task.params.get("category") == "csrf_candidate" for task in tasks)


def test_create_attack_tasks_csrf_backfill_prefers_state_changing_target_over_root(tmp_path: Path):
    tagged_file = tmp_path / "tagged_api_data.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/", "method": "GET", "forms": []},
            {"url": "https://app.example.com/rest/user/change-password", "method": "POST", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "required_vuln_families": ["csrf"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_api_data": {
            "file": str(tagged_file),
            "count": 2,
            "description": "Tagged URLs (api_data)",
            "tags": ["api_endpoint", "has_params"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    csrf_tasks = [task for task in tasks if task.params.get("category") == "csrf_candidate"]
    assert csrf_tasks
    csrf_task = csrf_tasks[0]
    assert csrf_task.params.get("target") == "https://app.example.com/rest/user/change-password"
    assert "https://app.example.com/" not in (csrf_task.params.get("targets") or [])


def test_create_attack_tasks_csrf_backfill_uses_uncategorized_non_root_seed(tmp_path: Path):
    tagged_file = tmp_path / "tagged_uncategorized.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "http://127.0.0.1:8888/", "method": "GET", "forms": []},
            {"url": "http://127.0.0.1:8888/profile", "method": "GET", "forms": []},
            {"url": "http://127.0.0.1:8888/account", "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "http://127.0.0.1:8888/",
            "required_vuln_families": ["csrf"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_uncategorized": {
            "file": str(tagged_file),
            "count": 3,
            "description": "Tagged URLs (uncategorized)",
            "tags": [],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    csrf_tasks = [task for task in tasks if task.params.get("category") == "csrf_candidate"]
    assert csrf_tasks
    target = str(csrf_tasks[0].params.get("target", "") or "")
    assert target in {"http://127.0.0.1:8888/profile", "http://127.0.0.1:8888/account"}


def test_score_csrf_seed_candidate_skips_http_404_seed():
    mc = MasterConductor.__new__(MasterConductor)
    score, reasons = mc._score_csrf_seed_candidate(
        "http://127.0.0.1:8888/%F0%9F%A4%96",
        "uncategorized",
        {"method": "GET", "response_status": 404, "forms": []},
    )
    assert score <= -9999
    assert any("http_status:404" in str(reason) for reason in reasons)


def test_create_attack_tasks_backfill_skips_emoji_404_uncategorized_seed(tmp_path: Path):
    tagged_file = tmp_path / "tagged_uncategorized.jsonl"
    emoji_url = "http://127.0.0.1:8888/%F0%9F%A4%96"
    _write_jsonl(
        tagged_file,
        [
            {"url": "http://127.0.0.1:8888/", "method": "GET", "response_status": 200, "forms": []},
            {"url": "http://127.0.0.1:8888/manifest.json", "method": "GET", "response_status": 200, "forms": []},
            {"url": emoji_url, "method": "GET", "response_status": 404, "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "http://127.0.0.1:8888/",
            "required_vuln_families": ["xss", "csrf", "api", "injection", "access_control", "business_logic"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_uncategorized": {
            "file": str(tagged_file),
            "count": 3,
            "description": "Tagged URLs (uncategorized)",
            "tags": [],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    backfill_tasks = [task for task in tasks if task.params.get("source_category") == "coverage_backfill"]
    assert backfill_tasks
    assert all(str(task.params.get("target", "") or "") != emoji_url for task in backfill_tasks)


def test_resolve_recon_file_path_supports_projects_prefix_under_workspace(tmp_path: Path):
    workspace_root = tmp_path / "workspace"
    project_name = "app.example.com"
    project_dir = workspace_root / "projects" / project_name
    tagged_file_rel = f"projects/{project_name}/tagged_urls/20260402_target_tagged_api_data.jsonl"
    tagged_file_abs = workspace_root / tagged_file_rel
    _write_jsonl(tagged_file_abs, [{"url": "https://app.example.com/rest/user/change-password", "method": "POST", "forms": []}])

    mc = MasterConductor.__new__(MasterConductor)
    mc.project_manager = SimpleNamespace(project_dir=project_dir)
    mc.workspace = SimpleNamespace(root=workspace_root)

    resolved = mc._resolve_recon_file_path(tagged_file_rel)
    assert resolved is not None
    assert resolved == tagged_file_abs


def test_create_attack_tasks_backfills_csrf_from_projects_prefixed_recon_file(tmp_path: Path):
    workspace_root = tmp_path / "workspace"
    project_name = "app.example.com"
    project_dir = workspace_root / "projects" / project_name
    tagged_file_rel = f"projects/{project_name}/tagged_urls/20260402_target_tagged_api_data.jsonl"
    tagged_file_abs = workspace_root / tagged_file_rel
    _write_jsonl(
        tagged_file_abs,
        [
            {"url": "https://app.example.com/", "method": "GET", "forms": []},
            {"url": "https://app.example.com/rest/user/change-password", "method": "POST", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "required_vuln_families": ["csrf"],
            "auth_tokens": {},
            "tech_stack": [],
        },
    )
    mc.project_manager = SimpleNamespace(project_dir=project_dir)
    mc.workspace = SimpleNamespace(user_sessions={}, root=workspace_root)

    recon_results = {
        "tagged_api_data": {
            "file": tagged_file_rel,
            "count": 2,
            "description": "Tagged URLs (api_data)",
            "tags": ["api_endpoint", "has_params"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    csrf_tasks = [task for task in tasks if task.params.get("category") == "csrf_candidate"]
    assert csrf_tasks
    csrf_task = csrf_tasks[0]
    assert csrf_task.params.get("target") == "https://app.example.com/rest/user/change-password"
    assert csrf_task.params.get("phase2_risk_force_vuln_types") == []


def test_create_attack_tasks_id_param_sets_phase2_time_caps(tmp_path: Path):
    tagged_file = tmp_path / "tagged_id_param.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/api/v1/users?id=1", "method": "GET", "forms": []},
        ],
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(can_create_task=lambda _phase: (True, "ok"))
    mc.context = SimpleNamespace(discovered_assets=[], target_info={"auth_tokens": {}, "tech_stack": []})
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})

    recon_results = {
        "tagged_id_param": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (id_param)",
            "tags": ["sqli_candidate", "idor_candidate", "xss_candidate"],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    id_param_tasks = [task for task in tasks if task.params.get("category") == "id_param"]
    assert id_param_tasks
    id_task = id_param_tasks[0]
    assert id_task.agent_type == "InjectionSwarm"
    assert id_task.params.get("phase2_max_seconds") == 120
    assert id_task.params.get("phase2_max_seconds_risk_forced") == 60
    assert id_task.params.get("phase2_risk_force_vuln_types") == []
