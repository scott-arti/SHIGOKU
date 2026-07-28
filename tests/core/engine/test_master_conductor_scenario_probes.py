from pathlib import Path
from types import SimpleNamespace
import json

from src.config import settings
from src.core.domain.model.task import Task
from src.core.engine.intervention_policy import InterventionPolicy
from src.core.engine.master_conductor import MasterConductor


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def _new_mc(
    *,
    discovered_assets: list[str] | None = None,
    required_vuln_families: list[str] | None = None,
) -> MasterConductor:
    mc = MasterConductor.__new__(MasterConductor)
    mc.phase_gate = SimpleNamespace(
        can_create_task=lambda _phase: (True, "ok"),
        can_create_attack_task=lambda _category, _metadata: (True, "ok"),
        get_phase_data=lambda _phase: SimpleNamespace(critical_findings=[]),
    )
    mc.context = SimpleNamespace(
        discovered_assets=discovered_assets if discovered_assets is not None else ["https://app.example.com/profile?view=full"],
        target_info={
            "target": "https://app.example.com",
            "mode": "ctf",
            "auth_tokens": {},
            "tech_stack": [],
            "required_vuln_families": required_vuln_families if required_vuln_families is not None else ["api"],
        },
    )
    mc.project_manager = None
    mc.workspace = SimpleNamespace(user_sessions={})
    mc.intervention_policy = InterventionPolicy(settings.get_intervention_scenarios())
    mc.run_ledger_recorder = SimpleNamespace(record=lambda **_kwargs: None)
    mc.mode = "ctf"
    return mc


class _QueueSpy:
    def __init__(self) -> None:
        self.items: list[Task] = []

    def get_by_id(self, _task_id: str):
        return None

    def add(self, task: Task) -> None:
        self.items.append(task)

    def __len__(self) -> int:
        return len(self.items)


def test_add_tasks_keeps_recon_result_tasks_when_derived_limit_is_reached(monkeypatch):
    mc = _new_mc(required_vuln_families=["api"])
    mc.task_queue = _QueueSpy()
    mc._injected_task_ids = set()
    mc._derived_task_count = 1
    monkeypatch.setattr(settings, "max_derived_tasks_per_session", 1)

    normal_task = Task(
        id="normal-derived",
        name="Normal Derived",
        agent_type="InjectionSwarm",
        action="scan",
        phase="attack",
        params={"target": "https://app.example.com/api/v1/users?id=1"},
        target="https://app.example.com/api/v1/users?id=1",
        priority=50,
    )
    scenario_probe = Task(
        id="scenario-probe",
        name="Scenario Probe",
        agent_type="InjectionSwarm",
        action="scan",
        phase="attack",
        params={
            "source_category": "scenario_probe_planner",
            "scenario_probe": "scn_11_multi_vector_chain",
            "target": "https://app.example.com/api/v1/users?id=1",
        },
        target="https://app.example.com/api/v1/users?id=1",
        priority=50,
    )

    assert mc._add_tasks([normal_task, scenario_probe], source="recon_result") == 2
    assert [task.id for task in mc.task_queue.items] == ["normal-derived", "scenario-probe"]
    assert mc._derived_task_count == 1


def test_add_tasks_does_not_globally_exempt_scn06_when_dynamic_source_limit_is_reached(monkeypatch):
    mc = _new_mc(required_vuln_families=["api"])
    mc.task_queue = _QueueSpy()
    mc._injected_task_ids = set()
    mc._derived_task_count = 1
    monkeypatch.setattr(settings, "max_derived_tasks_per_session", 1)

    meta_task = Task(
        id="meta-observability",
        name="Meta/Observability Exposure Scan",
        agent_type="DiscoverySwarm",
        action="scan",
        phase="attack",
        params={
            "source_category": "tagged_meta_observability",
            "category": "meta_observability",
            "scenario_id": "scn_06_data_exposure_diff",
            "target": "https://app.example.com/config/config.inc.php.dist",
        },
        target="https://app.example.com/config/config.inc.php.dist",
        priority=50,
    )

    assert mc._add_tasks([meta_task], source="react") == 0
    assert mc.task_queue.items == []
    assert mc._derived_task_count == 1


def test_create_attack_tasks_adds_missing_probe_tasks_for_core_and_high_friction_scenarios(tmp_path: Path):
    tagged_file = tmp_path / "tagged_api_data.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/api/v1/users?id=1", "method": "GET", "forms": []},
        ],
    )
    recon_results = {
        "tagged_api_data": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (api_data)",
            "tags": ["api_endpoint", "has_params"],
        }
    }

    mc = _new_mc(required_vuln_families=["api"])
    tasks = mc._create_attack_tasks_from_recon(recon_results)

    probe_tasks = [task for task in tasks if task.params.get("source_category") == "scenario_probe_planner"]
    assert probe_tasks

    covered_numbers = set()
    for task in probe_tasks:
        scenario_id = str(task.params.get("scenario_probe", "") or "")
        tokens = scenario_id.split("_")
        if len(tokens) >= 2 and tokens[1].isdigit():
            covered_numbers.add(int(tokens[1]))

    assert covered_numbers == {1, 2, 4, 5, 6, 8, 10, 11, 12}
    assert any(
        task.params.get("category") == "api_data"
        and task.params.get("scenario_id") == "scn_03_injection_input_tampering"
        for task in tasks
    )
    assert all(task.params.get("target") for task in probe_tasks)


def test_create_missing_core_scenario_probe_tasks_does_not_treat_inferred_planned_signals_as_covered(monkeypatch):
    mc = _new_mc(required_vuln_families=["api", "business_logic"])
    seed_target = "https://app.example.com/api/v1/orders/9"
    seed_evidence = {
        seed_target: {
            "score": 10,
            "reasons": ["seed"],
            "category": "api_candidate",
            "method": "GET",
            "has_form_tag": False,
        }
    }
    monkeypatch.setattr(
        mc,
        "_collect_scenario_probe_seed_targets",
        lambda *args, **kwargs: ([seed_target], seed_evidence),
    )

    rate_limit_like_task = Task(
        id="generic-rate-limit",
        name="API Candidate Security Scan (1 targets)",
        agent_type="InjectionSwarm",
        action="scan",
        phase="attack",
        params={
            "category": "api_candidate",
            "source_category": "tagged_api_candidate",
            "scenario": "rate limit throttle burst request brute force request frequency",
            "attack_type": "rate limit",
            "description": "Traffic-pattern probe for throttling and brute-force resilience.",
            "target": seed_target,
            "targets": [seed_target],
        },
        target=seed_target,
        priority=80,
    )
    business_logic_like_task = Task(
        id="generic-business-logic",
        name="File Upload Vulnerability Scan (1 targets)",
        agent_type="LogicSwarm",
        action="scan",
        phase="attack",
        params={
            "category": "upload",
            "source_category": "tagged_upload",
            "scenario": "business logic semantic abuse approval flow policy bypass intent abuse pricing workflow checkout refund",
            "attack_type": "workflow value tampering",
            "description": "Low-impact workflow transition/value tampering probe for business-logic abuse candidates.",
            "target": "https://app.example.com/upload",
            "targets": ["https://app.example.com/upload"],
        },
        target="https://app.example.com/upload",
        priority=79,
    )

    probe_tasks = mc._create_missing_core_scenario_probe_tasks(
        existing_tasks=[rate_limit_like_task, business_logic_like_task],
        recon_results={},
    )
    probe_ids = {str(task.params.get("scenario_probe", "") or "") for task in probe_tasks}

    assert "scn_05_rate_limit_resilience" in probe_ids
    assert "scn_10_semantic_business_logic" in probe_ids


def test_create_missing_core_scenario_probe_tasks_respects_explicit_scn06_coverage(monkeypatch):
    mc = _new_mc(required_vuln_families=["api"])
    seed_target = "https://app.example.com/config/config.inc.php.dist"
    seed_evidence = {
        seed_target: {
            "score": 8,
            "reasons": ["meta_seed"],
            "category": "meta_observability",
            "method": "GET",
            "has_form_tag": False,
        }
    }
    monkeypatch.setattr(
        mc,
        "_collect_scenario_probe_seed_targets",
        lambda *args, **kwargs: ([seed_target], seed_evidence),
    )

    explicit_meta_task = Task(
        id="meta-observability",
        name="Meta/Observability Exposure Scan (1 targets)",
        agent_type="DiscoverySwarm",
        action="scan",
        phase="attack",
        params={
            "category": "meta_observability",
            "source_category": "tagged_meta_observability",
            "scenario_id": "scn_06_data_exposure_diff",
            "target": seed_target,
            "targets": [seed_target],
        },
        target=seed_target,
        priority=81,
    )

    probe_tasks = mc._create_missing_core_scenario_probe_tasks(
        existing_tasks=[explicit_meta_task],
        recon_results={},
    )
    probe_ids = {str(task.params.get("scenario_probe", "") or "") for task in probe_tasks}

    assert "scn_06_data_exposure_diff" not in probe_ids


def test_file_upload_probe_is_not_deferred_by_scn09_manual_policy(monkeypatch):
    mc = _new_mc(required_vuln_families=["api"])
    monkeypatch.setattr(settings, "defer_scn07_12_hitl_v1", True)
    monkeypatch.setattr(mc, "_get_intervention_decision", lambda _task: {
        "route": "shigoku_hitl",
        "scenario_id": "scn_09_multi_step_state_machine",
        "confidence": 1.0,
        "reasons": ["Matched scenario 'scn_09_multi_step_state_machine'"],
        "matched_signals": ["chain"],
    })
    monkeypatch.setattr(mc, "_notify_scn07_12_intervention", lambda *_args, **_kwargs: None)

    task = Task(
        id="upload-task",
        name="File Upload Vulnerability Scan (1 signals)",
        agent_type="LogicSwarm",
        action="run",
        phase="attack",
        params={
            "target": "http://localhost:4280/vulnerabilities/upload/",
            "tags": ["php", "rce_candidate", "file_upload"],
            "category": "upload",
            "safe_only": True,
        },
        target="http://localhost:4280/vulnerabilities/upload/",
        priority=80,
    )

    assert mc._run_intervention_precheck(task) is None
    assert task.state.value != "skipped"


def test_create_attack_tasks_marks_generated_upload_tasks_safe_only(tmp_path: Path):
    tagged_file = tmp_path / "tagged_upload.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {
                "url": "http://localhost:4280/vulnerabilities/upload/",
                "method": "GET",
                "forms": [],
            },
        ],
    )
    recon_results = {
        "tagged_upload": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (upload)",
            "tags": ["file_upload", "php", "rce_candidate"],
        },
    }

    mc = _new_mc(required_vuln_families=["business_logic"])
    mc.mode = "ctf"
    mc.context.target_info["mode"] = "ctf"
    tasks = mc._create_attack_tasks_from_recon(recon_results)

    upload_task = next(task for task in tasks if task.params.get("category") == "upload")
    assert upload_task.params.get("safe_only") is True
    assert upload_task.params.get("scenario_id") == "scn_09_multi_step_state_machine"


def test_create_attack_tasks_marks_signal_upload_tasks_safe_only():
    recon_results = {
        "_signal_bundle": {
            "_run_id": "run-safe-upload",
            "_endpoint_signals": [
                {
                    "signal_id": "sig-upload-1",
                    "url": "http://localhost:4280/vulnerabilities/upload/",
                    "primary_label": "upload",
                    "candidate_labels": ["file_upload", "php", "rce_candidate"],
                    "seen_count": 1,
                },
            ],
        }
    }

    mc = _new_mc(required_vuln_families=["business_logic"])
    mc.mode = "ctf"
    mc.context.target_info["mode"] = "ctf"

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    upload_task = next(task for task in tasks if task.params.get("category") == "upload")
    assert upload_task.params.get("safe_only") is True
    assert upload_task.params.get("scenario_id") == "scn_09_multi_step_state_machine"


def test_file_upload_probe_without_safe_only_stays_deferred_by_scn09_manual_policy(monkeypatch):
    mc = _new_mc(required_vuln_families=["api"])
    monkeypatch.setattr(settings, "defer_scn07_12_hitl_v1", True)
    monkeypatch.setattr(mc, "_get_intervention_decision", lambda _task: {
        "route": "shigoku_hitl",
        "scenario_id": "scn_09_multi_step_state_machine",
        "confidence": 1.0,
        "reasons": ["Matched scenario 'scn_09_multi_step_state_machine'"],
        "matched_signals": ["chain"],
    })
    monkeypatch.setattr(mc, "_notify_scn07_12_intervention", lambda *_args, **_kwargs: None)

    task = Task(
        id="upload-task",
        name="File Upload Vulnerability Scan (1 signals)",
        agent_type="LogicSwarm",
        action="run",
        phase="attack",
        params={
            "target": "http://localhost:4280/vulnerabilities/upload/",
            "tags": ["php", "rce_candidate", "file_upload"],
            "category": "upload",
        },
        target="http://localhost:4280/vulnerabilities/upload/",
        priority=80,
    )

    intervention = mc._run_intervention_precheck(task)

    assert intervention is not None
    assert intervention.get("manual_deferred") is True
    assert task.state.value == "skipped"


def test_add_tasks_keeps_distinct_scenario_probe_tasks_on_same_target(monkeypatch):
    mc = _new_mc(required_vuln_families=["api", "business_logic"])
    mc.task_queue = _QueueSpy()
    mc._injected_task_ids = set()
    mc._owned_injection_targets = set()
    mc._derived_task_count = 0
    mc.context.target_info["aggressive_targets"] = []

    seed_target = "https://app.example.com/api/v1/orders/9"
    seed_evidence = {
        seed_target: {
            "score": 10,
            "reasons": ["seed"],
            "category": "api_candidate",
            "method": "GET",
            "has_form_tag": False,
        }
    }
    monkeypatch.setattr(
        mc,
        "_collect_scenario_probe_seed_targets",
        lambda *args, **kwargs: ([seed_target], seed_evidence),
    )

    seed_idor = Task(
        id="seed-idor",
        name="Seed IDOR",
        agent_type="InjectionSwarm",
        action="scan",
        phase="attack",
        params={
            "category": "id_param",
            "scenario_id": "scn_01_idor_bola_object_access",
            "target": seed_target,
            "targets": [seed_target],
        },
        target=seed_target,
        priority=80,
    )
    seed_upload = Task(
        id="seed-upload",
        name="Seed Upload",
        agent_type="LogicSwarm",
        action="scan",
        phase="attack",
        params={
            "category": "upload",
            "target": "https://app.example.com/upload",
            "targets": ["https://app.example.com/upload"],
        },
        target="https://app.example.com/upload",
        priority=79,
    )

    probe_tasks = mc._create_missing_core_scenario_probe_tasks(
        existing_tasks=[seed_idor, seed_upload],
        recon_results={},
    )
    added = mc._add_tasks(probe_tasks, source="recon_result")
    queued_probe_ids = [task.params.get("scenario_probe") for task in mc.task_queue.items]

    assert added == len(probe_tasks)
    assert set(queued_probe_ids) == {
        "scn_02_mass_assignment_object_update",
        "scn_03_injection_input_tampering",
        "scn_04_endpoint_enumeration_bfla",
        "scn_05_rate_limit_resilience",
        "scn_06_data_exposure_diff",
        "scn_08_oob_external_channel_flow",
        "scn_10_semantic_business_logic",
        "scn_11_multi_vector_chain",
        "scn_12_advanced_ssrf_internal_topology",
    }
    assert all(
        str(task.params.get("selection_origin", "")).startswith("scenario_probe_planner:scn_")
        for task in mc.task_queue.items
    )


def test_create_attack_tasks_uses_step14_probe_planner_wrapper(tmp_path: Path, monkeypatch):
    tagged_file = tmp_path / "tagged_api_data.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/api/v1/users?id=1", "method": "GET", "forms": []},
        ],
    )
    recon_results = {
        "tagged_api_data": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (api_data)",
            "tags": ["api_endpoint", "has_params"],
        }
    }

    mc = _new_mc(required_vuln_families=["api"])
    planner_task = Task(
        id="planned_probe",
        name="Planned Probe",
        agent_type="InjectionSwarm",
        action="scan",
        phase="attack",
        params={
            "source_category": "scenario_probe_planner",
            "scenario_probe": "scn_11_multi_vector_chain",
            "category": "api_data",
            "target": "https://app.example.com/api/v1/users?id=1",
            "targets": ["https://app.example.com/api/v1/users?id=1"],
        },
        target="https://app.example.com/api/v1/users?id=1",
        tags=["api_endpoint"],
        priority=78,
    )

    monkeypatch.setattr(
        mc,
        "plan_missing_link_probes",
        lambda existing_tasks, recon_results, runtime_policy=None: {
            "tasks": [planner_task],
            "state": "continue",
            "reason": "planned",
        },
    )

    tasks = mc._create_attack_tasks_from_recon(recon_results)

    assert any(task.id == "planned_probe" for task in tasks)


def test_create_attack_tasks_does_not_add_scenario_probes_for_realtime_only(tmp_path: Path):
    tagged_file = tmp_path / "tagged_realtime.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/socket.io/?EIO=4&transport=websocket&t=1"},
        ],
    )
    recon_results = {
        "tagged_realtime": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (realtime)",
            "tags": ["api_endpoint", "auth_required"],
        }
    }

    mc = _new_mc(
        discovered_assets=[],
        required_vuln_families=["api"],
    )
    mc.context.target_info["target"] = ""
    tasks = mc._create_attack_tasks_from_recon(recon_results)

    assert tasks
    assert not any(task.params.get("source_category") == "scenario_probe_planner" for task in tasks)


def test_create_attack_tasks_enriches_auth_and_state_signal_metadata(tmp_path: Path):
    auth_file = tmp_path / "tagged_auth.jsonl"
    csrf_file = tmp_path / "tagged_csrf.jsonl"
    xss_file = tmp_path / "tagged_xss.jsonl"
    _write_jsonl(
        auth_file,
        [
            {"url": "https://app.example.com/account/profile", "method": "GET", "forms": []},
        ],
    )
    _write_jsonl(
        csrf_file,
        [
            {"url": "https://app.example.com/account/settings", "method": "POST", "forms": [{"action": "/account/settings"}]},
        ],
    )
    _write_jsonl(
        xss_file,
        [
            {"url": "https://app.example.com/search?q=test", "method": "GET", "forms": [{"action": "/search"}]},
        ],
    )

    recon_results = {
        "tagged_auth": {
            "file": str(auth_file),
            "count": 1,
            "description": "Tagged URLs (auth)",
            "tags": ["auth_endpoint"],
        },
        "tagged_csrf_candidate": {
            "file": str(csrf_file),
            "count": 1,
            "description": "Tagged URLs (csrf_candidate)",
            "tags": ["csrf_candidate"],
        },
        "tagged_xss_candidate": {
            "file": str(xss_file),
            "count": 1,
            "description": "Tagged URLs (xss_candidate)",
            "tags": ["xss_candidate"],
        },
    }

    mc = _new_mc(required_vuln_families=["api"])
    tasks = mc._create_attack_tasks_from_recon(recon_results)

    auth_task = next(
        task
        for task in tasks
        if task.params.get("category") == "auth" and task.params.get("source_category") == "tagged_auth"
    )
    csrf_task = next(task for task in tasks if task.params.get("category") == "csrf_candidate")
    xss_task = next(task for task in tasks if task.params.get("category") == "xss_candidate")

    assert auth_task.params.get("scenario_id") == "scn_07_token_trust_boundary"
    assert "jwt" in str(auth_task.params.get("scenario", "")).lower()
    assert "jwt_token" in auth_task.params.get("tags", [])

    assert csrf_task.params.get("scenario_id") == "scn_09_multi_step_state_machine"
    assert "state machine" in str(csrf_task.params.get("scenario", "")).lower()
    assert "workflow_candidate" in csrf_task.params.get("tags", [])
    assert xss_task.params.get("scenario_id") == "scn_03_injection_input_tampering"
    assert "input tampering" in str(xss_task.params.get("scenario", "")).lower()


def test_create_attack_tasks_prioritizes_coverage_critical_tasks(tmp_path: Path):
    api_file = tmp_path / "tagged_api_data.jsonl"
    _write_jsonl(
        api_file,
        [
            {"url": "https://app.example.com/api/v1/users?id=1", "method": "GET", "forms": []},
        ],
    )
    recon_results = {
        "tagged_api_data": {
            "file": str(api_file),
            "count": 1,
            "description": "Tagged URLs (api_data)",
            "tags": ["api_endpoint", "has_params"],
        },
    }

    mc = _new_mc(required_vuln_families=["api", "csrf"])
    tasks = mc._create_attack_tasks_from_recon(recon_results)

    assert tasks
    critical_positions = []
    regular_positions = []
    for idx, task in enumerate(tasks):
        params = task.params if isinstance(task.params, dict) else {}
        source_category = str(params.get("source_category", "") or "").strip().lower()
        category = str(params.get("category", "") or "").strip().lower()
        is_critical = source_category in {"coverage_backfill", "scenario_probe_planner"} or category == "csrf_candidate"
        if is_critical:
            critical_positions.append(idx)
        else:
            regular_positions.append(idx)

    assert critical_positions
    assert regular_positions
    assert max(critical_positions) < min(regular_positions)


def test_create_attack_tasks_sets_explicit_target_for_main_tasks(tmp_path: Path):
    auth_file = tmp_path / "tagged_auth.jsonl"
    _write_jsonl(
        auth_file,
        [
            {"url": "https:/app.example.com/account/profile", "method": "GET", "forms": []},
        ],
    )
    recon_results = {
        "tagged_auth": {
            "file": str(auth_file),
            "count": 1,
            "description": "Tagged URLs (auth)",
            "tags": ["auth_endpoint"],
        },
    }

    mc = _new_mc(required_vuln_families=["auth"])
    tasks = mc._create_attack_tasks_from_recon(recon_results)

    auth_tasks = [task for task in tasks if str(task.params.get("category", "")).strip().lower() == "auth"]
    assert auth_tasks
    for task in auth_tasks:
        assert str(task.target or "").strip()
        assert str(task.params.get("target", "") or "").strip()
        assert str(task.params.get("target", "")).startswith(("http://", "https://"))


def test_create_attack_tasks_admin_category_maps_to_scn01(tmp_path: Path):
    admin_file = tmp_path / "tagged_admin.jsonl"
    _write_jsonl(
        admin_file,
        [
            {"url": "https://app.example.com/dashboard", "method": "GET", "forms": []},
        ],
    )
    recon_results = {
        "tagged_admin": {
            "file": str(admin_file),
            "count": 1,
            "description": "Tagged URLs (admin)",
            "tags": ["admin_panel"],
        },
    }

    mc = _new_mc(required_vuln_families=["access_control"])
    tasks = mc._create_attack_tasks_from_recon(recon_results)

    admin_task = next(task for task in tasks if task.params.get("category") == "admin")
    assert admin_task.params.get("scenario_id") == "scn_01_idor_bola_object_access"
    assert "object level authorization" in str(admin_task.params.get("attack_type", "")).lower()


def test_create_attack_tasks_scenario_probes_keep_multiple_seed_targets(tmp_path: Path, monkeypatch):
    tagged_file = tmp_path / "tagged_api_data.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/api/v1/users?id=1", "method": "GET", "forms": []},
        ],
    )
    recon_results = {
        "tagged_api_data": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (api_data)",
            "tags": ["api_endpoint", "has_params"],
        }
    }

    mc = _new_mc(required_vuln_families=["api"])
    expected_targets = [
        "https://app.example.com/api/v1/users?id=1",
        "https://app.example.com/account/profile",
    ]
    expected_evidence = {
        expected_targets[0]: {"score": 12, "reasons": ["seed_a"]},
        expected_targets[1]: {"score": 11, "reasons": ["seed_b"]},
    }

    def _mock_collect(*_args, **_kwargs):
        return expected_targets, expected_evidence

    monkeypatch.setattr(mc, "_collect_scenario_probe_seed_targets", _mock_collect)
    tasks = mc._create_attack_tasks_from_recon(recon_results)

    probe_tasks = [task for task in tasks if task.params.get("source_category") == "scenario_probe_planner"]
    assert probe_tasks
    for task in probe_tasks:
        scenario_id = str(task.params.get("scenario_probe", "") or "")
        if scenario_id == "scn_10_semantic_business_logic":
            assert task.params.get("targets") == ["https://app.example.com/api/v1/users?id=1"]
            assert task.params.get("count") == 1
            assert task.target == "https://app.example.com/api/v1/users?id=1"
        else:
            assert task.params.get("targets") == expected_targets
            assert task.params.get("count") == len(expected_targets)
            assert task.target == expected_targets[0]
        evidence_by_url = task.params.get("_context", {}).get("scenario_probe_evidence_by_url", {})
        if scenario_id == "scn_10_semantic_business_logic":
            assert set(evidence_by_url.keys()) == {"https://app.example.com/api/v1/users?id=1"}
        else:
            assert set(evidence_by_url.keys()) == set(expected_targets)


def test_create_attack_tasks_scn10_prefers_workflow_like_targets_over_auth_surface(tmp_path: Path, monkeypatch):
    tagged_file = tmp_path / "tagged_api_data.jsonl"
    _write_jsonl(
        tagged_file,
        [
            {"url": "https://app.example.com/api/v1/users?id=1", "method": "GET", "forms": []},
        ],
    )
    recon_results = {
        "tagged_api_data": {
            "file": str(tagged_file),
            "count": 1,
            "description": "Tagged URLs (api_data)",
            "tags": ["api_endpoint", "has_params"],
        }
    }

    mc = _new_mc(required_vuln_families=["api"])
    expected_targets = [
        "https://app.example.com/account/settings",
        "https://app.example.com/checkout/cart",
    ]
    expected_evidence = {
        expected_targets[0]: {"score": 15, "reasons": ["auth_seed"], "category": "auth", "method": "GET", "has_form_tag": False},
        expected_targets[1]: {
            "score": 14,
            "reasons": ["workflow_seed"],
            "category": "basket_order",
            "method": "POST",
            "has_form_tag": True,
        },
    }

    def _mock_collect(*_args, **_kwargs):
        return expected_targets, expected_evidence

    monkeypatch.setattr(mc, "_collect_scenario_probe_seed_targets", _mock_collect)
    tasks = mc._create_attack_tasks_from_recon(recon_results)

    scn10_task = next(
        task
        for task in tasks
        if task.params.get("source_category") == "scenario_probe_planner"
        and task.params.get("scenario_probe") == "scn_10_semantic_business_logic"
    )

    assert scn10_task.params.get("targets") == ["https://app.example.com/checkout/cart"]
    evidence_by_url = scn10_task.params.get("_context", {}).get("scenario_probe_evidence_by_url", {})
    assert set(evidence_by_url.keys()) == {"https://app.example.com/checkout/cart"}
    assert evidence_by_url["https://app.example.com/checkout/cart"]["category"] == "basket_order"


def test_create_attack_tasks_auth_replays_history_targets_when_sparse(tmp_path: Path):
    project_dir = tmp_path / "projects" / "app.example.com"
    tagged_dir = project_dir / "tagged_urls"
    current_auth_file = tagged_dir / "20260413_target_tagged_auth.jsonl"
    history_auth_file = tagged_dir / "20260412_target_tagged_auth.jsonl"

    _write_jsonl(
        current_auth_file,
        [
            {"url": "https://app.example.com/account/profile", "method": "GET", "forms": []},
        ],
    )
    _write_jsonl(
        history_auth_file,
        [
            {"url": "https://app.example.com/account/settings", "method": "GET", "forms": []},
            {"url": "https://external.example.net/account", "method": "GET", "forms": []},
            {"url": "https://app.example.com/account/security", "method": "GET", "forms": []},
        ],
    )

    recon_results = {
        "tagged_auth": {
            "file": str(current_auth_file),
            "count": 1,
            "description": "Tagged URLs (auth)",
            "tags": ["auth_endpoint"],
        },
    }

    mc = _new_mc(required_vuln_families=["auth"])
    mc.project_manager = SimpleNamespace(project_dir=project_dir)
    mc.workspace = SimpleNamespace(user_sessions={}, root=tmp_path)
    mc.context.target_info["target"] = "https://app.example.com/"

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    auth_tasks = [
        task
        for task in tasks
        if task.params.get("category") == "auth" and task.params.get("source_category") == "tagged_auth"
    ]
    task_targets = {str(task.params.get("target", "") or "") for task in auth_tasks}
    # SGK-2026-0367: per-URL evidence — look up each URL's task and check its evidence
    settings_url_task = next(
        (t for t in auth_tasks if t.params.get("target") == "https://app.example.com/account/settings"),
        None,
    )
    settings_evidence = (
        (settings_url_task.params.get("_context", {}) or {}).get("url_evidence_by_url", {})
        if settings_url_task else {}
    )

    assert len(auth_tasks) >= 3
    assert "https://app.example.com/account/profile" in task_targets
    assert "https://app.example.com/account/settings" in task_targets
    assert "https://app.example.com/account/security" in task_targets
    assert "https://external.example.net/account" not in task_targets
    assert settings_evidence.get("https://app.example.com/account/settings", {}).get("source") == "mc_history_replay"


def test_create_attack_tasks_api_endpoint_replays_alias_history_targets_when_sparse(tmp_path: Path):
    project_dir = tmp_path / "projects" / "app.example.com"
    tagged_dir = project_dir / "tagged_urls"
    current_api_file = tagged_dir / "20260413_target_tagged_api_endpoint.jsonl"
    history_api_candidate_file = tagged_dir / "20260412_target_tagged_api_candidate.jsonl"

    _write_jsonl(
        current_api_file,
        [
            {"url": "https://app.example.com/api/v1/profile", "method": "GET", "forms": []},
        ],
    )
    _write_jsonl(
        history_api_candidate_file,
        [
            {"url": "https://app.example.com/api/v2/orders?status=open", "method": "GET", "forms": []},
            {"url": "https://external.example.net/api/v2/orders?status=open", "method": "GET", "forms": []},
            {"url": "https://app.example.com/static/js/app.js?v=1", "method": "GET", "forms": []},
        ],
    )

    recon_results = {
        "tagged_api_endpoint": {
            "file": str(current_api_file),
            "count": 1,
            "description": "Tagged URLs (api_endpoint)",
            "tags": ["api_endpoint"],
        },
    }

    mc = _new_mc(required_vuln_families=["api", "injection"])
    mc.project_manager = SimpleNamespace(project_dir=project_dir)
    mc.workspace = SimpleNamespace(user_sessions={}, root=tmp_path)
    mc.context.target_info["target"] = "https://app.example.com/"

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    api_tasks = [
        task
        for task in tasks
        if task.params.get("category") == "api_endpoint" and task.params.get("source_category") == "tagged_api_endpoint"
    ]
    task_targets = {str(task.params.get("target", "") or "") for task in api_tasks}
    # SGK-2026-0367: per-URL evidence lookup
    replay_url_task = next(
        (t for t in api_tasks if t.params.get("target") == "https://app.example.com/api/v2/orders?status=open"),
        None,
    )
    replay_evidence = (
        (replay_url_task.params.get("_context", {}) or {}).get("url_evidence_by_url", {})
        if replay_url_task else {}
    )

    assert api_tasks
    assert "https://app.example.com/api/v1/profile" in task_targets
    assert "https://app.example.com/api/v2/orders?status=open" in task_targets
    assert "https://external.example.net/api/v2/orders?status=open" not in task_targets
    assert "https://app.example.com/static/js/app.js?v=1" not in task_targets
    assert replay_evidence.get("https://app.example.com/api/v2/orders?status=open", {}).get("source") == "mc_history_replay"


def test_create_attack_tasks_admin_replays_auth_history_targets_when_sparse(tmp_path: Path):
    project_dir = tmp_path / "projects" / "app.example.com"
    tagged_dir = project_dir / "tagged_urls"
    current_admin_file = tagged_dir / "20260413_target_tagged_admin.jsonl"
    history_auth_file = tagged_dir / "20260412_target_tagged_auth.jsonl"

    _write_jsonl(
        current_admin_file,
        [
            {"url": "https://app.example.com/admin/dashboard", "method": "GET", "forms": []},
        ],
    )
    _write_jsonl(
        history_auth_file,
        [
            {"url": "https://app.example.com/admin/users", "method": "GET", "forms": []},
            {"url": "https://app.example.com/account/security", "method": "GET", "forms": []},
            {"url": "https://external.example.net/admin/users", "method": "GET", "forms": []},
        ],
    )

    recon_results = {
        "tagged_admin": {
            "file": str(current_admin_file),
            "count": 1,
            "description": "Tagged URLs (admin)",
            "tags": ["admin_panel"],
        },
    }

    mc = _new_mc(required_vuln_families=["access_control"])
    mc.project_manager = SimpleNamespace(project_dir=project_dir)
    mc.workspace = SimpleNamespace(user_sessions={}, root=tmp_path)
    mc.context.target_info["target"] = "https://app.example.com/"

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    admin_tasks = [
        task
        for task in tasks
        if task.params.get("category") == "admin" and task.params.get("source_category") == "tagged_admin"
    ]
    task_targets = {str(task.params.get("target", "") or "") for task in admin_tasks}
    # SGK-2026-0367: per-URL evidence
    admin_users_task = next(
        (t for t in admin_tasks if t.params.get("target") == "https://app.example.com/admin/users"),
        None,
    )
    admin_users_evidence = (
        (admin_users_task.params.get("_context", {}) or {}).get("url_evidence_by_url", {})
        if admin_users_task else {}
    )

    assert admin_tasks
    assert "https://app.example.com/admin/dashboard" in task_targets
    assert "https://app.example.com/admin/users" in task_targets
    assert "https://external.example.net/admin/users" not in task_targets
    assert admin_users_evidence.get("https://app.example.com/admin/users", {}).get("source") == "mc_history_replay"


def test_resolve_in_scope_hosts_includes_target_and_scope_domains():
    mc = _new_mc(required_vuln_families=["auth"])
    mc.context.target_info["target"] = "http://127.0.0.1:8888/"
    mc.context.target_info["in_scope_domains"] = ["api.localtest.me", "127.0.0.1"]
    mc.target = "http://fallback.example.local"

    hosts = mc._resolve_in_scope_hosts()

    assert "127.0.0.1" in hosts
    assert "api.localtest.me" in hosts


def test_is_target_url_in_scope_accepts_subdomain():
    mc = _new_mc(required_vuln_families=["auth"])

    assert mc._is_target_url_in_scope(
        "https://sub.app.example.com/api",
        ["app.example.com"],
    )
    assert not mc._is_target_url_in_scope(
        "https://other.example.net/api",
        ["app.example.com"],
    )
