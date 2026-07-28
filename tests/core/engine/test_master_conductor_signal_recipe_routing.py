from types import SimpleNamespace

from src.core.domain.model.task import Task
from src.core.engine.master_conductor import MasterConductor, _build_recipe_follow_up_decision
from src.core.engine.recipe_loader import Recipe, RecipeStep, RecipeLoader
from src.core.engine.recipe_contracts import RECIPE_TO_SWARM_REASON_CODES, RECIPE_FOLLOW_UP_REASONS


def test_create_attack_tasks_from_recon_expands_signal_targets_per_url():
    """Signal-first tasks must use the same per-URL expansion as legacy tasks."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(
        can_create_task=lambda _phase: (True, "ok"),
        can_create_attack_task=lambda _cat, _meta: (True, "ok"),
        get_phase_data=lambda _phase: SimpleNamespace(critical_findings=[]),
    )
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "tech_stack": [],
            "auth_headers": {},
            "cookies": {},
            "bearer_token": "",
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.run_ledger_recorder = SimpleNamespace(record=lambda **kw: None)
    mc.recipe_loader = None

    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-1",
            "_host_surface_summary": {},
            "_endpoint_signals": [
                {
                    "signal_id": "sig-xss-1",
                    "url": "https://app.example.com/search?q=one",
                    "primary_label": "xss_candidate",
                    "candidate_labels": ["xss_candidate"],
                    "seen_count": 1,
                },
                {
                    "signal_id": "sig-xss-2",
                    "url": "https://app.example.com/search?q=two",
                    "primary_label": "xss_candidate",
                    "candidate_labels": ["xss_candidate"],
                    "seen_count": 1,
                },
            ],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    xss_tasks = [task for task in tasks if task.params.get("category") == "xss_candidate"]
    assert len(xss_tasks) == 2
    assert {task.params["target"] for task in xss_tasks} == {
        "https://app.example.com/search?q=one",
        "https://app.example.com/search?q=two",
    }
    assert all(task.params["targets"] == [task.params["target"]] for task in xss_tasks)


def test_create_attack_tasks_from_recon_supplements_tagged_categories_missing_from_signal_bundle(tmp_path):
    """Signal-first routing must not drop legacy tagged categories absent from the bundle."""
    admin_file = tmp_path / "tagged_admin.jsonl"
    admin_file.write_text(
        '{"url":"https://app.example.com/admin","method":"GET","forms":[]}\n',
        encoding="utf-8",
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(
        can_create_task=lambda _phase: (True, "ok"),
        can_create_attack_task=lambda _cat, _meta: (True, "ok"),
        get_phase_data=lambda _phase: SimpleNamespace(critical_findings=[]),
    )
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "tech_stack": [],
            "auth_headers": {},
            "cookies": {},
            "bearer_token": "",
            "required_vuln_families": ["access_control", "xss"],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.run_ledger_recorder = SimpleNamespace(record=lambda **kw: None)
    mc.recipe_loader = None
    mc.mode = "vulntest"
    mc.plan_missing_link_probes = lambda existing_tasks, recon_results, runtime_policy=None: {
        "tasks": [],
        "state": "continue",
        "reason": "disabled_for_signal_supplement_test",
    }

    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-1",
            "_host_surface_summary": {},
            "_endpoint_signals": [
                {
                    "signal_id": "sig-xss-1",
                    "url": "https://app.example.com/search?q=one",
                    "primary_label": "xss_candidate",
                    "candidate_labels": ["xss_candidate"],
                    "seen_count": 1,
                }
            ],
        },
        "tagged_admin": {
            "file": str(admin_file),
            "count": 1,
            "description": "Tagged URLs (admin)",
            "tags": ["admin_panel"],
        },
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    assert any(task.params.get("category") == "xss_candidate" for task in tasks)
    admin_tasks = [
        task
        for task in tasks
        if task.params.get("category") == "admin"
        and task.params.get("source_category") == "tagged_admin"
    ]
    assert admin_tasks
    assert {task.params.get("target") for task in admin_tasks} == {"https://app.example.com/admin"}


def test_create_attack_tasks_from_recon_supplements_same_category_urls_missing_from_signal_bundle(tmp_path):
    """Signal-first routing must merge legacy tagged URLs at URL granularity."""
    signal_url = "https://app.example.com/vulnerabilities/sqli/?id=1"
    tagged_only_url = "https://app.example.com/vulnerabilities/sqli_blind/?id=2"
    id_file = tmp_path / "tagged_id_param.jsonl"
    id_file.write_text(
        "\n".join(
            [
                f'{{"url":"{signal_url}","method":"GET","forms":[]}}',
                f'{{"url":"{tagged_only_url}","method":"GET","forms":[]}}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(
        can_create_task=lambda _phase: (True, "ok"),
        can_create_attack_task=lambda _cat, _meta: (True, "ok"),
        get_phase_data=lambda _phase: SimpleNamespace(critical_findings=[]),
    )
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "tech_stack": [],
            "auth_headers": {},
            "cookies": {},
            "bearer_token": "",
            "required_vuln_families": ["injection"],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.run_ledger_recorder = SimpleNamespace(record=lambda **kw: None)
    mc.recipe_loader = None
    mc.mode = "vulntest"
    mc.plan_missing_link_probes = lambda existing_tasks, recon_results, runtime_policy=None: {
        "tasks": [],
        "state": "continue",
        "reason": "disabled_for_signal_url_level_supplement_test",
    }

    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-1",
            "_host_surface_summary": {},
            "_endpoint_signals": [
                {
                    "signal_id": "sig-id-1",
                    "url": signal_url,
                    "primary_label": "id_param",
                    "candidate_labels": ["sqli_candidate", "idor_candidate"],
                    "seen_count": 1,
                }
            ],
        },
        "tagged_id_param": {
            "file": str(id_file),
            "count": 2,
            "description": "Tagged URLs (id_param)",
            "tags": ["sqli_candidate", "idor_candidate"],
        },
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    signal_tasks = [
        task
        for task in tasks
        if task.params.get("category") == "id_param"
        and task.params.get("target") == signal_url
        and task.params.get("selection_origin") == "signal_bundle.id_param"
    ]
    legacy_extra_tasks = [
        task
        for task in tasks
        if task.params.get("category") == "id_param"
        and task.params.get("target") == tagged_only_url
        and task.params.get("source_category") == "tagged_id_param"
        and task.params.get("selection_origin") == "master_conductor.recon.id_param"
    ]
    legacy_duplicate_tasks = [
        task
        for task in tasks
        if task.params.get("category") == "id_param"
        and task.params.get("target") == signal_url
        and task.params.get("source_category") == "tagged_id_param"
    ]

    assert signal_tasks
    assert legacy_extra_tasks
    assert not legacy_duplicate_tasks


def test_create_attack_tasks_from_recon_routes_cors_supplement_to_injection_swarm(tmp_path):
    """CORS tagged supplements must run the CORS-capable injection scanner."""
    cors_file = tmp_path / "tagged_cors_candidate.jsonl"
    cors_file.write_text(
        '{"url":"https://app.example.com/vulnerabilities/api/v2/user/","method":"GET","forms":[],'
        '"response_headers":{"Access-Control-Allow-Origin":"*"}}\n',
        encoding="utf-8",
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(
        can_create_task=lambda _phase: (True, "ok"),
        can_create_attack_task=lambda _cat, _meta: (True, "ok"),
        get_phase_data=lambda _phase: SimpleNamespace(critical_findings=[]),
    )
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "tech_stack": [],
            "auth_headers": {},
            "cookies": {},
            "bearer_token": "",
            "required_vuln_families": ["api", "injection"],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.run_ledger_recorder = SimpleNamespace(record=lambda **kw: None)
    mc.recipe_loader = None
    mc.mode = "vulntest"
    mc.plan_missing_link_probes = lambda existing_tasks, recon_results, runtime_policy=None: {
        "tasks": [],
        "state": "continue",
        "reason": "disabled_for_cors_supplement_test",
    }

    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-1",
            "_host_surface_summary": {},
            "_endpoint_signals": [
                {
                    "signal_id": "sig-xss-1",
                    "url": "https://app.example.com/search?q=one",
                    "primary_label": "xss_candidate",
                    "candidate_labels": ["xss_candidate"],
                    "seen_count": 1,
                }
            ],
        },
        "tagged_cors_candidate": {
            "file": str(cors_file),
            "count": 1,
            "description": "Tagged URLs (cors_candidate)",
            "tags": ["cors_candidate"],
        },
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    cors_tasks = [
        task
        for task in tasks
        if task.params.get("category") == "cors_candidate"
        and task.params.get("source_category") == "tagged_cors_candidate"
    ]
    assert cors_tasks
    assert {task.agent_type for task in cors_tasks} == {"InjectionSwarm"}
    assert all("CORS Misconfiguration Scan" in task.name for task in cors_tasks)
    assert {task.params.get("target") for task in cors_tasks} == {
        "https://app.example.com/vulnerabilities/api/v2/user/"
    }
    assert all(task.params.get("selection_origin") == "master_conductor.recon.cors_candidate" for task in cors_tasks)


def test_create_attack_tasks_from_recon_adds_signal_companions_for_exec_and_weak_id():
    """Signal-first routing must preserve legacy high-value DVWA companion checks."""
    exec_url = "http://localhost:4280/vulnerabilities/exec/"
    weak_id_url = "http://localhost:4280/vulnerabilities/weak_id/"

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(
        can_create_task=lambda _phase: (True, "ok"),
        can_create_attack_task=lambda _cat, _meta: (True, "ok"),
        get_phase_data=lambda _phase: SimpleNamespace(critical_findings=[]),
    )
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "http://localhost:4280/",
            "tech_stack": [],
            "auth_headers": {},
            "cookies": {},
            "bearer_token": "",
            "required_vuln_families": ["access_control", "injection"],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.run_ledger_recorder = SimpleNamespace(record=lambda **kw: None)
    mc.recipe_loader = None
    mc.mode = "vulntest"
    mc.plan_missing_link_probes = lambda existing_tasks, recon_results, runtime_policy=None: {
        "tasks": [],
        "state": "continue",
        "reason": "disabled_for_signal_companion_test",
    }

    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-1",
            "_host_surface_summary": {},
            "_endpoint_signals": [
                {
                    "signal_id": "sig-exec-1",
                    "url": exec_url,
                    "primary_label": "id_param",
                    "candidate_labels": ["id_param", "sqli_candidate"],
                    "seen_count": 1,
                },
                {
                    "signal_id": "sig-weak-1",
                    "url": weak_id_url,
                    "primary_label": "auth",
                    "candidate_labels": ["auth_endpoint"],
                    "seen_count": 1,
                },
            ],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    command_tasks = [
        task
        for task in tasks
        if task.params.get("category") == "command_injection"
        and task.params.get("target") == exec_url
    ]
    assert command_tasks
    assert {task.agent_type for task in command_tasks} == {"InjectionManagerAgent"}
    assert all("Command Injection Focused Scan" in task.name for task in command_tasks)

    session_tasks = [
        task
        for task in tasks
        if task.agent_type == "sessionhijacker"
        and task.params.get("test_endpoint") == weak_id_url
    ]
    assert session_tasks
    assert all(task.name == "Session Weak-ID Analysis" for task in session_tasks)
    assert session_tasks[0].params["login_url"] == "http://localhost:4280/login.php"
    assert session_tasks[0].params["credentials"] == {"username": "admin", "password": "password"}


def test_create_attack_tasks_from_recon_replays_authz_history_as_bizlogic_companion(tmp_path):
    """Signal-first auth routing must not strand replayed authz URLs behind manual token checks."""
    project_dir = tmp_path / "project"
    tagged_dir = project_dir / "tagged_urls"
    tagged_dir.mkdir(parents=True)
    current_auth_file = tagged_dir / "20260724_target_tagged_auth.jsonl"
    history_auth_file = tagged_dir / "20260723_target_tagged_auth.jsonl"
    current_auth_file.write_text(
        '{"url":"http://localhost:4280/vulnerabilities/weak_id/","method":"GET","forms":[],"response_status":200}\n',
        encoding="utf-8",
    )
    history_auth_file.write_text(
        '{"url":"http://localhost:4280/vulnerabilities/authbypass/","method":"GET","forms":[],"response_status":200}\n',
        encoding="utf-8",
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(
        can_create_task=lambda _phase: (True, "ok"),
        can_create_attack_task=lambda _cat, _meta: (True, "ok"),
        get_phase_data=lambda _phase: SimpleNamespace(critical_findings=[]),
    )
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "http://localhost:4280/",
            "tech_stack": [],
            "auth_headers": {},
            "cookies": {},
            "bearer_token": "",
            "required_vuln_families": [],
        },
    )
    mc.project_manager = SimpleNamespace(project_dir=project_dir)
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.run_ledger_recorder = SimpleNamespace(record=lambda **kw: None)
    mc.recipe_loader = None
    mc.mode = "vulntest"
    mc.plan_missing_link_probes = lambda existing_tasks, recon_results, runtime_policy=None: {
        "tasks": [],
        "state": "continue",
        "reason": "disabled_for_authz_history_companion_test",
    }

    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-1",
            "_host_surface_summary": {},
            "_endpoint_signals": [
                {
                    "signal_id": "sig-weak-1",
                    "url": "http://localhost:4280/vulnerabilities/weak_id/",
                    "primary_label": "auth",
                    "candidate_labels": ["auth_endpoint"],
                    "seen_count": 1,
                },
            ],
        },
        "tagged_auth": {
            "file": str(current_auth_file),
            "count": 1,
            "description": "Tagged URLs (auth)",
            "tags": ["auth_endpoint"],
        },
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    bizlogic_tasks = [
        task
        for task in tasks
        if task.agent_type == "bizlogic"
        and task.params.get("target") == "http://localhost:4280/vulnerabilities/authbypass/get_user_data.php?id=2"
    ]
    assert bizlogic_tasks
    candidate = bizlogic_tasks[0].params["candidate"]
    assert candidate["smell_type"] == "idor_candidate"
    assert candidate["parameters"]["authz_probe"] == "authbypass_idor"


def test_create_attack_tasks_from_recon_adds_stored_xss_param_hints_for_signal_xss_s():
    """Signal-first stored-XSS tasks must include DVWA form parameter hints."""
    xss_s_url = "http://localhost:4280/vulnerabilities/xss_s/"

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(
        can_create_task=lambda _phase: (True, "ok"),
        can_create_attack_task=lambda _cat, _meta: (True, "ok"),
        get_phase_data=lambda _phase: SimpleNamespace(critical_findings=[]),
    )
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "http://localhost:4280/",
            "tech_stack": [],
            "auth_headers": {},
            "cookies": {},
            "bearer_token": "",
            "required_vuln_families": ["xss"],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.run_ledger_recorder = SimpleNamespace(record=lambda **kw: None)
    mc.recipe_loader = None
    mc.plan_missing_link_probes = lambda existing_tasks, recon_results, runtime_policy=None: {
        "tasks": [],
        "state": "continue",
        "reason": "disabled_for_stored_xss_hint_test",
    }

    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-1",
            "_host_surface_summary": {},
            "_endpoint_signals": [
                {
                    "signal_id": "sig-xss-s-1",
                    "url": xss_s_url,
                    "primary_label": "xss_candidate",
                    "candidate_labels": ["xss_candidate"],
                    "seen_count": 1,
                }
            ],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    xss_tasks = [
        task
        for task in tasks
        if task.params.get("category") == "xss_candidate"
        and task.params.get("target") == xss_s_url
    ]
    assert xss_tasks
    candidate_params = xss_tasks[0].params["_context"].get("candidate_params", [])
    assert "txtName" in candidate_params
    assert "mtxMessage" in candidate_params


def test_create_attack_tasks_from_recon_uses_context_mode_for_legacy_supplement_guard(tmp_path):
    """Vulntest sessions must not run legacy supplements through bugbounty-only guard."""
    redirect_file = tmp_path / "tagged_redirect_param.jsonl"
    redirect_file.write_text(
        '{"url":"https://app.example.com/open_redirect/","method":"GET","forms":[]}\n'
        '{"url":"https://app.example.com/open_redirect/low.php?redirect=/home","method":"GET","forms":[]}\n',
        encoding="utf-8",
    )

    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(
        can_create_task=lambda _phase: (True, "ok"),
        can_create_attack_task=lambda _cat, _meta: (True, "ok"),
        get_phase_data=lambda _phase: SimpleNamespace(critical_findings=[]),
    )
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "mode": "vulntest",
            "tech_stack": [],
            "auth_headers": {},
            "cookies": {},
            "bearer_token": "",
            "required_vuln_families": ["injection"],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.run_ledger_recorder = SimpleNamespace(record=lambda **kw: None)
    mc.recipe_loader = None
    mc.mode = "bugbounty"
    mc.plan_missing_link_probes = lambda existing_tasks, recon_results, runtime_policy=None: {
        "tasks": [],
        "state": "continue",
        "reason": "disabled_for_context_mode_guard_test",
    }

    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-1",
            "_host_surface_summary": {},
            "_endpoint_signals": [
                {
                    "signal_id": "sig-xss-1",
                    "url": "https://app.example.com/search?q=one",
                    "primary_label": "xss_candidate",
                    "candidate_labels": ["xss_candidate"],
                    "seen_count": 1,
                }
            ],
        },
        "tagged_redirect_param": {
            "file": str(redirect_file),
            "count": 2,
            "description": "Tagged URLs (redirect_param)",
            "tags": ["open_redirect", "ssrf_candidate"],
        },
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    redirect_tasks = [
        task
        for task in tasks
        if task.params.get("category") == "redirect_param"
        and task.params.get("source_category") == "tagged_redirect_param"
    ]
    assert redirect_tasks
    assert {task.params.get("target") for task in redirect_tasks} == {
        "https://app.example.com/open_redirect/",
        "https://app.example.com/open_redirect/low.php?redirect=/home",
    }
    assert all(task.params.get("targets") == [task.params.get("target")] for task in redirect_tasks)


def test_create_attack_tasks_from_recon_runs_probe_planner_after_signal_routing():
    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(
        can_create_task=lambda _phase: (True, "ok"),
        can_create_attack_task=lambda _cat, _meta: (True, "ok"),
        get_phase_data=lambda _phase: SimpleNamespace(critical_findings=[]),
    )
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "tech_stack": [],
            "auth_headers": {},
            "cookies": {},
            "bearer_token": "",
            "required_vuln_families": ["xss"],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.run_ledger_recorder = SimpleNamespace(record=lambda **kw: None)
    mc.recipe_loader = None
    planner_task = Task(
        id="planned-probe",
        name="Planned Probe",
        agent_type="InjectionSwarm",
        action="scan",
        phase="attack",
        params={
            "source_category": "scenario_probe_planner",
            "scenario_probe": "scn_11_multi_vector_chain",
            "category": "api_data",
            "target": "https://app.example.com/api/users?id=1",
            "targets": ["https://app.example.com/api/users?id=1"],
        },
        target="https://app.example.com/api/users?id=1",
        priority=78,
    )
    mc.plan_missing_link_probes = lambda existing_tasks, recon_results, runtime_policy=None: {
        "tasks": [planner_task],
        "state": "continue",
        "reason": "planned",
    }

    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-1",
            "_host_surface_summary": {},
            "_endpoint_signals": [
                {
                    "signal_id": "sig-xss-1",
                    "url": "https://app.example.com/search?q=one",
                    "primary_label": "xss_candidate",
                    "candidate_labels": ["xss_candidate"],
                    "seen_count": 1,
                }
            ],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    assert any(task.id == "planned-probe" for task in tasks)


def test_create_attack_tasks_from_recon_uses_candidate_labels_for_signal_category_resolution():
    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(
        can_create_task=lambda _phase: (True, "ok"),
        can_create_attack_task=lambda _cat, _meta: (True, "ok"),
        get_phase_data=lambda _phase: SimpleNamespace(critical_findings=[]),
    )
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "tech_stack": [],
            "auth_headers": {},
            "cookies": {},
            "bearer_token": "",
            "required_vuln_families": ["api", "injection"],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.run_ledger_recorder = SimpleNamespace(record=lambda **kw: None)
    mc.recipe_loader = None
    mc.plan_missing_link_probes = lambda existing_tasks, recon_results, runtime_policy=None: {
        "tasks": [],
        "state": "continue",
        "reason": "planned",
    }

    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-1",
            "_host_surface_summary": {},
            "_endpoint_signals": [
                {
                    "signal_id": "sig-file-1",
                    "url": "https://app.example.com/instructions.php?doc=readme",
                    "primary_label": "doc",
                    "entity_type": "parameter",
                    "candidate_labels": ["file_param"],
                    "seen_count": 1,
                },
                {
                    "signal_id": "sig-crlf-1",
                    "url": "https://app.example.com/redirect?url=next",
                    "primary_label": "url",
                    "entity_type": "parameter",
                    "candidate_labels": ["crlf_candidate"],
                    "seen_count": 1,
                },
            ],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    categorized_targets = {
        (task.params.get("category"), task.params.get("target"))
        for task in tasks
        if task.action != "run_recipe"
    }
    assert ("file_param", "https://app.example.com/instructions.php?doc=readme") in categorized_targets
    assert ("crlf_candidate", "https://app.example.com/redirect?url=next") in categorized_targets


def test_create_attack_tasks_from_recon_keeps_distinct_file_param_query_values():
    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(
        can_create_task=lambda _phase: (True, "ok"),
        can_create_attack_task=lambda _cat, _meta: (True, "ok"),
        get_phase_data=lambda _phase: SimpleNamespace(critical_findings=[]),
    )
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "tech_stack": [],
            "auth_headers": {},
            "cookies": {},
            "bearer_token": "",
            "required_vuln_families": ["api", "injection"],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.run_ledger_recorder = SimpleNamespace(record=lambda **kw: None)
    mc.recipe_loader = None
    mc.plan_missing_link_probes = lambda existing_tasks, recon_results, runtime_policy=None: {
        "tasks": [],
        "state": "continue",
        "reason": "planned",
    }

    file_targets = {
        "https://app.example.com/instructions.php?doc=readme",
        "https://app.example.com/instructions.php?doc=license",
        "https://app.example.com/instructions.php?doc=todo",
        "https://app.example.com/instructions.php?doc=faq",
    }
    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-1",
            "_host_surface_summary": {},
            "_endpoint_signals": [
                {
                    "signal_id": f"sig-file-{index}",
                    "url": url,
                    "primary_label": "file_param",
                    "candidate_labels": ["file_param"],
                    "seen_count": 1,
                }
                for index, url in enumerate(sorted(file_targets), start=1)
            ],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    file_tasks = [task for task in tasks if task.params.get("category") == "file_param"]
    assert len(file_tasks) == 4
    assert {task.params.get("target") for task in file_tasks} == file_targets


def test_create_attack_tasks_from_recon_adds_recipe_tasks_from_signal_bundle():
    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(
        can_create_task=lambda _phase: (True, "ok"),
        can_create_attack_task=lambda _cat, _meta: (True, "ok"),
        get_phase_data=lambda _phase: SimpleNamespace(critical_findings=[]),
    )
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "tech_stack": ["nginx"],
            "auth_headers": {},
            "cookies": {"session": "abc"},
            "bearer_token": "",
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.run_ledger_recorder = SimpleNamespace(record=lambda **kw: None)
    mc.plan_missing_link_probes = lambda existing_tasks, recon_results, runtime_policy=None: {
        "tasks": [],
        "state": "continue",
        "reason": "disabled_for_recipe_routing_test",
    }
    loader = RecipeLoader()
    loader.recipes["auth_recipe"] = Recipe(
        name="auth_recipe",
        description="Auth recipe",
        agent="swarm",
        trigger={
            "type": "signal",
            "required_signals": [
                "auth_surface",
                "auth_required",
                "auth_endpoint",
                "cookie_present",
            ],
        },
        steps=[RecipeStep(id="s1", name="auth-check", action="scan")],
    )
    mc.recipe_loader = loader

    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-1",
            "_host_surface_summary": {
                "host": "app.example.com",
                "total_endpoints": 1,
                "total_signals": 1,
                "category_counts": {"auth": 1},
                "surface_types": ["auth_surface"],
                "auth_level": "user",
                "tech_stack": ["nginx"],
                "coverage_confidence": 0.9,
                "tagged_urls_compat": {},
                "legacy_keys": {},
            },
            "_endpoint_signals": [
                {
                    "signal_id": "sig-auth-1",
                    "entity_type": "auth_surface",
                    "url": "https://app.example.com/login",
                    "method": "GET",
                    "primary_label": "auth",
                    "candidate_labels": ["auth_endpoint", "login_surface"],
                    "confidence": 0.82,
                    "why_suspicious": "login form discovered during recon",
                    "source_observations": ["katana"],
                    "auth_required": True,
                    "auth_context": {"cookie_present": True},
                    "params": [{"name": "redirect_uri", "location": "query"}],
                    "status": "active",
                    "seen_count": 1,
                }
            ],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    recipe_tasks = [t for t in tasks if t.action == "run_recipe"]
    assert len(recipe_tasks) == 1
    task = recipe_tasks[0]
    assert task.params["recipe_name"] == "auth_recipe"
    assert task.params["target"] == "https://app.example.com/login"
    assert task.params["recipe_signal_id"] == "sig-auth-1"
    assert task.params["selector_score"] > 0.0


def test_create_attack_tasks_from_recon_prefers_recipe_over_direct_swarm_for_same_signal():
    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(
        can_create_task=lambda _phase: (True, "ok"),
        can_create_attack_task=lambda _cat, _meta: (True, "ok"),
        get_phase_data=lambda _phase: SimpleNamespace(critical_findings=[]),
    )
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "tech_stack": ["nginx"],
            "auth_headers": {},
            "cookies": {"session": "abc"},
            "bearer_token": "",
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.run_ledger_recorder = SimpleNamespace(record=lambda **kw: None)
    mc.plan_missing_link_probes = lambda existing_tasks, recon_results, runtime_policy=None: {
        "tasks": [],
        "state": "continue",
        "reason": "disabled_for_recipe_routing_test",
    }
    loader = RecipeLoader()
    loader.recipes["auth_recipe"] = Recipe(
        name="auth_recipe",
        description="Auth recipe",
        agent="swarm",
        trigger={
            "type": "signal",
            "required_signals": [
                "auth_surface",
                "auth_required",
                "auth_endpoint",
                "cookie_present",
            ],
        },
        steps=[RecipeStep(id="s1", name="auth-check", action="scan")],
    )
    mc.recipe_loader = loader

    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-1",
            "_host_surface_summary": {
                "host": "app.example.com",
                "total_endpoints": 1,
                "total_signals": 1,
                "category_counts": {"auth": 1},
                "surface_types": ["auth_surface"],
                "auth_level": "user",
                "tech_stack": ["nginx"],
                "coverage_confidence": 0.9,
                "tagged_urls_compat": {},
                "legacy_keys": {},
            },
            "_endpoint_signals": [
                {
                    "signal_id": "sig-auth-1",
                    "entity_type": "auth_surface",
                    "url": "https://app.example.com/login",
                    "method": "GET",
                    "primary_label": "auth",
                    "candidate_labels": ["auth_endpoint", "login_surface"],
                    "confidence": 0.82,
                    "why_suspicious": "login form discovered during recon",
                    "source_observations": ["katana"],
                    "auth_required": True,
                    "auth_context": {"cookie_present": True},
                    "params": [{"name": "redirect_uri", "location": "query"}],
                    "status": "active",
                    "seen_count": 1,
                }
            ],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    recipe_tasks = [t for t in tasks if t.action == "run_recipe"]
    assert len(recipe_tasks) == 1
    assert not any(t.params.get("category") == "auth" for t in tasks if t.action == "scan")


def test_create_attack_tasks_from_recon_routes_manual_review_signal_to_direct_swarm():
    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(
        can_create_task=lambda _phase: (True, "ok"),
        can_create_attack_task=lambda _cat, _meta: (True, "ok"),
        get_phase_data=lambda _phase: SimpleNamespace(critical_findings=[]),
    )
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "tech_stack": ["nginx"],
            "auth_headers": {},
            "cookies": {"session": "abc"},
            "bearer_token": "",
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.run_ledger_recorder = SimpleNamespace(record=lambda **kw: None)
    mc.plan_missing_link_probes = lambda existing_tasks, recon_results, runtime_policy=None: {
        "tasks": [],
        "state": "continue",
        "reason": "disabled_for_recipe_routing_test",
    }
    loader = RecipeLoader()
    loader.recipes["auth_recipe"] = Recipe(
        name="auth_recipe",
        description="Auth recipe",
        agent="swarm",
        trigger={
            "type": "signal",
            "required_signals": [
                "auth_surface",
                "auth_required",
                "auth_endpoint",
                "cookie_present",
            ],
        },
        steps=[RecipeStep(id="s1", name="auth-check", action="scan")],
    )
    mc.recipe_loader = loader

    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-1",
            "_host_surface_summary": {
                "host": "app.example.com",
                "total_endpoints": 1,
                "total_signals": 1,
                "category_counts": {"auth": 1},
                "surface_types": ["auth_surface"],
                "auth_level": "user",
                "tech_stack": ["nginx"],
                "coverage_confidence": 0.9,
                "tagged_urls_compat": {},
                "legacy_keys": {},
            },
            "_endpoint_signals": [
                {
                    "signal_id": "sig-auth-1",
                    "entity_type": "auth_surface",
                    "url": "https://app.example.com/login",
                    "method": "GET",
                    "primary_label": "auth",
                    "candidate_labels": ["auth_endpoint", "login_surface"],
                    "confidence": 0.82,
                    "why_suspicious": "login form discovered during recon",
                    "source_observations": ["katana"],
                    "auth_required": True,
                    "auth_context": {"cookie_present": True},
                    "params": [{"name": "redirect_uri", "location": "query"}],
                    "status": "needs_swarm_review",
                    "seen_count": 1,
                }
            ],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    assert not any(t.action == "run_recipe" for t in tasks)
    auth_tasks = [t for t in tasks if t.params.get("category") == "auth"]
    assert len(auth_tasks) == 1
    assert auth_tasks[0].params["recipe_to_swarm_reason"] == "manual_review_required"


# ── SGK-2026-0259: auth recipe MC routing ─────────────────────────────

AUTH_RECIPE_NAMES_0259 = {
    "oauth_binding_drift",
    "session_invariant",
    "jwt_claim_enforcement",
    "refresh_rotation",
    "jwt_alg_none",
    "oauth_token_leak",
    "oauth_redirect_bypass",
}


def _mc_setup_with_auth_recipes(recipes_to_load=None):
    """Create a MasterConductor with phase_gate, context, and auth recipes in loader."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(
        can_create_task=lambda _phase: (True, "ok"),
        can_create_attack_task=lambda _cat, _meta: (True, "ok"),
        get_phase_data=lambda _phase: SimpleNamespace(critical_findings=[]),
    )
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "tech_stack": ["nginx"],
            "auth_headers": {},
            "cookies": {"session": "abc"},
            "bearer_token": "",
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.run_ledger_recorder = SimpleNamespace(record=lambda **kw: None)
    mc.plan_missing_link_probes = lambda existing_tasks, recon_results, runtime_policy=None: {
        "tasks": [],
        "state": "continue",
        "reason": "disabled_for_recipe_routing_test",
    }
    loader = RecipeLoader()
    if recipes_to_load:
        for name, recipe in recipes_to_load.items():
            loader.recipes[name] = recipe
    mc.recipe_loader = loader
    return mc


def _make_auth_recipe(name, required_signals):
    """Create a minimal auth recipe for routing tests."""
    return Recipe(
        name=name,
        description=f"Auth recipe {name}",
        agent="swarm",
        trigger={
            "type": "signal",
            "required_signals": required_signals,
            "success_condition": f"{name}_success",
            "stop_condition": f"{name}_stop",
        },
        steps=[RecipeStep(id="s1", name="auth-check", action="scan")],
    )


def _make_auth_signal(signal_id="sig-auth-1", primary_label="auth",
                      candidate_labels=None, confidence=0.82, status="active",
                      auth_context=None, url="https://app.example.com/login"):
    """Create a minimal auth endpoint signal for route testing."""
    return {
        "signal_id": signal_id,
        "entity_type": "auth_surface",
        "url": url,
        "method": "GET",
        "primary_label": primary_label,
        "candidate_labels": candidate_labels or ["auth_endpoint", "login_surface"],
        "confidence": confidence,
        "why_suspicious": "login form discovered during recon",
        "source_observations": ["katana"],
        "auth_required": True,
        "auth_context": auth_context or {"cookie_present": True},
        "params": [{"name": "redirect_uri", "location": "query"}],
        "status": status,
        "seen_count": 1,
    }


def test_auth_surface_signal_routes_to_auth_recipe_not_direct_swarm():
    """Signal bundle has auth surface signals, loader has auth recipes →
    at least 1 run_recipe task with recipe_name starting with 'auth_'."""
    mc = _mc_setup_with_auth_recipes({
        "oauth_binding_drift": _make_auth_recipe(
            "oauth_binding_drift",
            ["auth_surface", "auth_required", "auth_endpoint", "cookie_present"],
        ),
        "session_invariant": _make_auth_recipe(
            "session_invariant",
            ["auth_surface", "auth_required", "auth_endpoint", "session_cookie"],
        ),
    })

    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-1",
            "_host_surface_summary": {
                "host": "app.example.com",
                "total_endpoints": 1,
                "total_signals": 1,
                "category_counts": {"auth": 1},
                "surface_types": ["auth_surface"],
                "auth_level": "user",
                "tech_stack": ["nginx"],
                "coverage_confidence": 0.9,
                "tagged_urls_compat": {},
                "legacy_keys": {},
            },
            "_endpoint_signals": [
                _make_auth_signal(
                    signal_id="sig-auth-1",
                    primary_label="auth",
                    candidate_labels=["auth_endpoint", "login_surface"],
                    confidence=0.82,
                    auth_context={"cookie_present": True},
                )
            ],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    recipe_tasks = [t for t in tasks if t.action == "run_recipe"]
    assert len(recipe_tasks) >= 1, (
        f"Expected at least 1 run_recipe task, got {len(recipe_tasks)} tasks: "
        f"{[(t.action, t.params.get('recipe_name')) for t in tasks]}"
    )
    task = recipe_tasks[0]
    assert task.params["recipe_name"] in AUTH_RECIPE_NAMES_0259.union({"auth_recipe", "generic_auth"})


def test_auth_recipe_produces_follow_up_decision_on_success():
    """All-success auth recipe result bundle → no_follow_up_needed, recipe_completed_cleanly."""
    result_bundle = {
        "recipe_name": "session_invariant",
        "success": True,
        "summary": {
            "total_steps": 3, "success_count": 3, "failed_steps": 0,
            "blocked_steps": 0, "failed_ratio": 0.0, "major_failure": False,
            "all_blocked": False,
        },
        "steps": {
            "s1": {"status": "success", "data": {"probe_status": "ok"}},
            "s2": {"status": "success", "data": {"confirm": "passed"}},
            "s3": {"status": "success", "data": {"evidence": "collected"}},
        },
    }
    decision = _build_recipe_follow_up_decision(result_bundle)
    assert decision["decision"] == "no_follow_up_needed"
    assert "recipe_completed_cleanly" in decision["reasons"]


def test_weak_auth_signal_confidence_routes_to_direct_swarm():
    """Signal with confidence=0.2 (< threshold), status='needs_swarm_review' →
    no run_recipe tasks, swarm scan tasks present."""
    mc = _mc_setup_with_auth_recipes({
        "session_invariant": _make_auth_recipe(
            "session_invariant",
            ["auth_surface", "auth_endpoint", "cookie_present"],
        ),
    })

    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-1",
            "_host_surface_summary": {
                "host": "app.example.com",
                "total_endpoints": 1,
                "total_signals": 1,
                "category_counts": {"auth": 1},
                "surface_types": ["auth_surface"],
                "auth_level": "user",
                "tech_stack": ["nginx"],
                "coverage_confidence": 0.3,
                "tagged_urls_compat": {},
                "legacy_keys": {},
            },
            "_endpoint_signals": [
                _make_auth_signal(
                    signal_id="sig-weak-1",
                    primary_label="auth",
                    candidate_labels=["auth_endpoint"],
                    confidence=0.2,
                    status="needs_swarm_review",
                    auth_context={"cookie_present": True},
                )
            ],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    recipe_tasks = [t for t in tasks if t.action == "run_recipe"]
    assert len(recipe_tasks) == 0, (
        f"Expected 0 run_recipe tasks for weak signal, got {len(recipe_tasks)}"
    )
    swarm_tasks = [t for t in tasks if t.action != "run_recipe"]
    assert len(swarm_tasks) >= 1, (
        f"Expected at least 1 swarm scan task, got {len(swarm_tasks)}"
    )


def test_create_attack_tasks_from_recon_uses_top_recipe_per_signal():
    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(
        can_create_task=lambda _phase: (True, "ok"),
        can_create_attack_task=lambda _cat, _meta: (True, "ok"),
        get_phase_data=lambda _phase: SimpleNamespace(critical_findings=[]),
    )
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "tech_stack": ["nginx"],
            "auth_headers": {},
            "cookies": {"session": "abc"},
            "bearer_token": "",
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.run_ledger_recorder = SimpleNamespace(record=lambda **kw: None)
    loader = RecipeLoader()
    loader.recipes["generic_auth"] = Recipe(
        name="generic_auth",
        description="Generic auth recipe",
        agent="swarm",
        trigger={
            "type": "signal",
            "required_signals": [
                "auth_surface",
                "auth_required",
            ],
        },
        steps=[RecipeStep(id="s1", name="auth-check", action="scan")],
    )
    loader.recipes["oauth_binding_drift"] = Recipe(
        name="oauth_binding_drift",
        description="Specific auth recipe",
        agent="swarm",
        trigger={
            "type": "signal",
            "required_signals": [
                "auth_surface",
                "auth_required",
                "auth_endpoint",
                "cookie_present",
            ],
        },
        steps=[RecipeStep(id="s1", name="auth-check", action="scan")],
    )
    mc.recipe_loader = loader

    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-1",
            "_host_surface_summary": {
                "host": "app.example.com",
                "total_endpoints": 1,
                "total_signals": 1,
                "category_counts": {"auth": 1},
                "surface_types": ["auth_surface"],
                "auth_level": "user",
                "tech_stack": ["nginx"],
                "coverage_confidence": 0.9,
                "tagged_urls_compat": {},
                "legacy_keys": {},
            },
            "_endpoint_signals": [
                {
                    "signal_id": "sig-auth-1",
                    "entity_type": "auth_surface",
                    "url": "https://app.example.com/login",
                    "method": "GET",
                    "primary_label": "auth",
                    "candidate_labels": ["auth_endpoint", "login_surface"],
                    "confidence": 0.82,
                    "why_suspicious": "login form discovered during recon",
                    "source_observations": ["katana"],
                    "auth_required": True,
                    "auth_context": {"cookie_present": True},
                    "params": [{"name": "redirect_uri", "location": "query"}],
                    "status": "active",
                    "seen_count": 1,
                }
            ],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    recipe_tasks = [t for t in tasks if t.action == "run_recipe"]
    assert len(recipe_tasks) == 1
    assert recipe_tasks[0].params["recipe_name"] == "oauth_binding_drift"


def test_create_attack_tasks_from_recon_suppresses_unsupported_action_recipe():
    """Recipe with unsupported step action → no run_recipe task, falls to swarm."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(
        can_create_task=lambda _phase: (True, "ok"),
        can_create_attack_task=lambda _cat, _meta: (True, "ok"),
        get_phase_data=lambda _phase: SimpleNamespace(critical_findings=[]),
    )
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "tech_stack": ["nginx"],
            "auth_headers": {},
            "cookies": {"session": "abc"},
            "bearer_token": "",
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.run_ledger_recorder = SimpleNamespace(record=lambda **kw: None)
    mc.plan_missing_link_probes = lambda existing_tasks, recon_results, runtime_policy=None: {
        "tasks": [],
        "state": "continue",
        "reason": "disabled_for_recipe_routing_test",
    }
    loader = RecipeLoader()
    loader.recipes["evil_recipe"] = Recipe(
        name="evil_recipe",
        description="Recipe with unsupported action",
        agent="swarm",
        trigger={
            "type": "signal",
            "required_signals": [
                "auth_surface",
                "auth_required",
            ],
        },
        steps=[
            RecipeStep(id="s1", name="valid", action="scan"),
            RecipeStep(id="s2", name="unsupported", action="evil_hack"),
        ],
    )
    mc.recipe_loader = loader

    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-1",
            "_host_surface_summary": {
                "host": "app.example.com",
                "total_endpoints": 1,
                "total_signals": 1,
                "category_counts": {"auth": 1},
                "surface_types": ["auth_surface"],
                "auth_level": "user",
                "tech_stack": ["nginx"],
                "coverage_confidence": 0.9,
                "tagged_urls_compat": {},
                "legacy_keys": {},
            },
            "_endpoint_signals": [
                {
                    "signal_id": "sig-auth-1",
                    "entity_type": "auth_surface",
                    "url": "https://app.example.com/login",
                    "method": "GET",
                    "primary_label": "auth",
                    "candidate_labels": ["auth_endpoint"],
                    "confidence": 0.82,
                    "why_suspicious": "login form discovered",
                    "source_observations": ["katana"],
                    "auth_required": True,
                    "auth_context": {"cookie_present": True},
                    "params": [],
                    "status": "active",
                    "seen_count": 1,
                }
            ],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    # No recipe task should be created for evil_recipe
    assert not any(t.action == "run_recipe" for t in tasks)
    # Should fall to swarm with unsupported_action reason
    auth_tasks = [t for t in tasks if t.params.get("category") == "auth"]
    assert len(auth_tasks) >= 1
    assert "unsupported_action" in auth_tasks[0].params.get("recipe_to_swarm_reasons", [])


def test_create_attack_tasks_from_recon_uses_fixed_vocabulary_in_swarm_reason():
    """recipe_to_swarm_reason should be one of the fixed vocabulary codes."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(
        can_create_task=lambda _phase: (True, "ok"),
        can_create_attack_task=lambda _cat, _meta: (True, "ok"),
        get_phase_data=lambda _phase: SimpleNamespace(critical_findings=[]),
    )
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "tech_stack": [],
            "auth_headers": {},
            "cookies": {},
            "bearer_token": "",
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.run_ledger_recorder = SimpleNamespace(record=lambda **kw: None)
    # No recipe_loader → no recipe tasks, everything falls to swarm
    mc.recipe_loader = None

    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-1",
            "_host_surface_summary": {
                "host": "app.example.com",
                "total_endpoints": 1,
                "total_signals": 1,
                "category_counts": {"api_data": 1},
                "surface_types": ["api_endpoint"],
                "auth_level": "none",
                "tech_stack": [],
                "coverage_confidence": 0.5,
                "tagged_urls_compat": {},
                "legacy_keys": {},
            },
            "_endpoint_signals": [
                {
                    "signal_id": "sig-api-1",
                    "entity_type": "api_endpoint",
                    "url": "https://app.example.com/api/data",
                    "method": "GET",
                    "primary_label": "api_data",
                    "candidate_labels": ["api_endpoint"],
                    "confidence": 0.5,
                    "why_suspicious": "API endpoint discovered",
                    "source_observations": ["katana"],
                    "auth_required": False,
                    "auth_context": {},
                    "params": [],
                    "status": "active",
                    "seen_count": 1,
                }
            ],
        }
    }

    from src.core.engine.recipe_contracts import RECIPE_TO_SWARM_REASON_CODES

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    for t in tasks:
        if t.action == "scan" and "recipe_to_swarm_reason" in t.params:
            reason = t.params["recipe_to_swarm_reason"]
            assert reason in RECIPE_TO_SWARM_REASON_CODES, (
                f"recipe_to_swarm_reason '{reason}' not in fixed vocabulary"
            )


# ── SGK-2026-0260: follow-up decision tests ──────────────────────────────


def test_follow_up_decision_success_clean():
    """Full success with no new signals → no_follow_up_needed."""
    result_bundle = {
        "recipe_name": "auth_recipe",
        "success": True,
        "summary": {"total_steps": 3, "success_count": 3, "failed_steps": 0, "blocked_steps": 0, "failed_ratio": 0.0, "major_failure": False, "all_blocked": False},
        "steps": {
            "s1": {"status": "success", "data": {}},
            "s2": {"status": "success", "data": {}},
            "s3": {"status": "success", "data": {}},
        },
    }
    decision = _build_recipe_follow_up_decision(result_bundle)
    assert decision["decision"] == "no_follow_up_needed"
    assert "recipe_completed_cleanly" in decision["reasons"]


def test_follow_up_decision_all_blocked():
    """All steps blocked → no_follow_up_needed."""
    result_bundle = {
        "recipe_name": "auth_recipe",
        "success": False,
        "summary": {"total_steps": 2, "success_count": 0, "failed_steps": 0, "blocked_steps": 2, "failed_ratio": 0.0, "major_failure": True, "all_blocked": True},
        "steps": {
            "s1": {"status": "blocked", "reason": "blocked_by_scope_guard"},
            "s2": {"status": "blocked", "reason": "blocked_by_scope_guard"},
        },
    }
    decision = _build_recipe_follow_up_decision(result_bundle)
    assert decision["decision"] == "no_follow_up_needed"
    assert "recipe_completely_blocked" in decision["reasons"]


def test_follow_up_decision_all_failed():
    """All steps failed → recommend_manual_review."""
    result_bundle = {
        "recipe_name": "auth_recipe",
        "success": False,
        "summary": {"total_steps": 2, "success_count": 0, "failed_steps": 2, "blocked_steps": 0, "failed_ratio": 1.0, "major_failure": False, "all_blocked": False},
        "steps": {
            "s1": {"status": "failed", "reason": "tool_error"},
            "s2": {"status": "failed", "reason": "tool_error"},
        },
    }
    decision = _build_recipe_follow_up_decision(result_bundle)
    assert decision["decision"] == "recommend_manual_review"
    assert "recipe_failed" in decision["reasons"]


def test_follow_up_decision_new_signal_discovered():
    """Success with new attack surface evidence → recommend_specialized_swarm."""
    result_bundle = {
        "recipe_name": "auth_recipe",
        "success": True,
        "summary": {"total_steps": 3, "success_count": 3, "failed_steps": 0, "blocked_steps": 0, "failed_ratio": 0.0, "major_failure": False, "all_blocked": False},
        "steps": {
            "s1": {"status": "success", "data": {"new_attack_surface": "/oauth/callback"}},
            "s2": {"status": "success", "data": {}},
            "s3": {"status": "success", "data": {}},
        },
    }
    decision = _build_recipe_follow_up_decision(result_bundle)
    assert decision["decision"] == "recommend_specialized_swarm"
    assert "new_signal_discovered" in decision["reasons"]


def test_follow_up_decision_partial_success():
    """Some steps succeeded, some failed → recommend_specialized_swarm."""
    result_bundle = {
        "recipe_name": "auth_recipe",
        "success": False,
        "summary": {"total_steps": 3, "success_count": 1, "failed_steps": 2, "blocked_steps": 0, "failed_ratio": 0.66, "major_failure": False, "all_blocked": False},
        "steps": {
            "s1": {"status": "success", "data": {}},
            "s2": {"status": "failed", "reason": "timeout"},
            "s3": {"status": "failed", "reason": "dns_error"},
        },
    }
    decision = _build_recipe_follow_up_decision(result_bundle)
    assert decision["decision"] == "recommend_specialized_swarm"
    assert "recipe_partial_success" in decision["reasons"]


def test_follow_up_decision_uses_fixed_vocabulary():
    """All decision values should be in RECIPE_FOLLOW_UP_REASONS."""
    test_cases = [
        {"recipe_name": "r1", "success": True, "summary": {"total_steps": 1, "success_count": 1, "failed_steps": 0, "blocked_steps": 0, "failed_ratio": 0.0, "major_failure": False, "all_blocked": False}, "steps": {"s1": {"status": "success", "data": {}}}},
        {"recipe_name": "r2", "success": False, "summary": {"total_steps": 1, "success_count": 0, "failed_steps": 1, "blocked_steps": 0, "failed_ratio": 1.0, "major_failure": False, "all_blocked": False}, "steps": {"s1": {"status": "failed"}}},
        {"recipe_name": "r3", "success": False, "summary": {"total_steps": 0, "success_count": 0, "failed_steps": 0, "blocked_steps": 0}, "steps": {}},
        {"recipe_name": "r4", "success": True, "summary": {"total_steps": 1, "success_count": 1, "failed_steps": 0, "blocked_steps": 0, "failed_ratio": 0.0, "major_failure": False, "all_blocked": False}, "steps": {"s1": {"status": "success", "data": {"adjacent_endpoints": ["/api/v2/users"]}}}},
    ]
    for case in test_cases:
        decision = _build_recipe_follow_up_decision(case)
        assert decision["decision"] in RECIPE_FOLLOW_UP_REASONS, (
            f"Decision '{decision['decision']}' not in RECIPE_FOLLOW_UP_REASONS"
        )
        for reason in decision["reasons"]:
            assert reason in RECIPE_FOLLOW_UP_REASONS, (
                f"Reason '{reason}' not in RECIPE_FOLLOW_UP_REASONS"
            )


# ── SGK-2026-0260: cross-run suppression with KG recipe run keys ─────────


def test_create_attack_tasks_from_recon_suppresses_via_kg_recipe_run_keys():
    """When KG returns suppression keys from previous runs, matching
    signal+recipe combinations should be suppressed."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(
        can_create_task=lambda _phase: (True, "ok"),
        can_create_attack_task=lambda _cat, _meta: (True, "ok"),
        get_phase_data=lambda _phase: SimpleNamespace(critical_findings=[]),
    )
    mc.context = SimpleNamespace(
        discovered_assets=[],
        target_info={
            "target": "https://app.example.com/",
            "tech_stack": ["nginx"],
            "auth_headers": {},
            "cookies": {"session": "abc"},
            "bearer_token": "",
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.run_ledger_recorder = SimpleNamespace(record=lambda **kw: None)
    loader = RecipeLoader()
    loader.recipes["auth_recipe"] = Recipe(
        name="auth_recipe",
        description="Auth recipe",
        agent="swarm",
        trigger={
            "type": "signal",
            "required_signals": [
                "auth_surface",
                "auth_required",
                "auth_endpoint",
                "cookie_present",
            ],
        },
        steps=[RecipeStep(id="s1", name="auth-check", action="scan")],
    )
    mc.recipe_loader = loader

    # Mock KG to return a suppression key matching the signal
    mc.graph = SimpleNamespace(
        store_signal_bundle=lambda _: 0,
        get_recipe_runs_for_domain=lambda domain: {
            "previous_recipe_runs": ["auth_recipe"],
            "previous_recipe_outcomes": {"auth_recipe": "success"},
            "suppression_keys": [
                "signal:auth_recipe:sig-auth-1",  # matches the signal_id below
            ],
        },
    )

    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-1",
            "_host_surface_summary": {
                "host": "app.example.com",
                "total_endpoints": 1,
                "total_signals": 1,
                "category_counts": {"auth": 1},
                "surface_types": ["auth_surface"],
                "auth_level": "user",
                "tech_stack": ["nginx"],
                "coverage_confidence": 0.9,
                "tagged_urls_compat": {},
                "legacy_keys": {},
            },
            "_endpoint_signals": [
                {
                    "signal_id": "sig-auth-1",
                    "entity_type": "auth_surface",
                    "url": "https://app.example.com/login",
                    "method": "GET",
                    "primary_label": "auth",
                    "candidate_labels": ["auth_endpoint", "login_surface"],
                    "confidence": 0.82,
                    "why_suspicious": "login form discovered",
                    "source_observations": ["katana"],
                    "auth_required": True,
                    "auth_context": {"cookie_present": True},
                    "params": [],
                    "status": "active",
                    "seen_count": 1,
                }
            ],
        }
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    # Should NOT create a run_recipe task because suppression key matches
    recipe_tasks = [t for t in tasks if t.action == "run_recipe"]
    assert len(recipe_tasks) == 0, (
        f"Expected no run_recipe tasks when suppression key matches, got {len(recipe_tasks)}"
    )
    # Should fall to swarm with suppression_active reason
    swarm_tasks = [t for t in tasks if t.action != "run_recipe"]
    assert any(
        "suppression_active" in t.params.get("recipe_to_swarm_reasons", [])
        or "suppression_active" == t.params.get("recipe_to_swarm_reason", "")
        for t in swarm_tasks
    ), (
        "Expected swarm task with suppression_active reason"
    )
