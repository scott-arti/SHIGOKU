"""SGK-2026-0460: dispatch 時 _context マージ化の単体テスト。

build 時（SGK-2026-0458, master_conductor.py:14742-14749）に注入された
discovery 契約キー（save_endpoints / forms_by_url / url_evidence_by_url）が、
dispatch 前処理（accumulated_context 非空時のマージ）後も保持されること、
および overlap キーは accumulated（新しい recon 要約）が優先されることを検証する。
"""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from src.core.domain.model.task import Task
from src.core.engine.master_conductor import MasterConductor
from src.core.engine.task_queue import TaskContext


BUILD_SAVE_ENDPOINTS = [
    {
        "url": "https://example.invalid/products/1/reviews",
        "method": "POST",
        "form_action": "/products/1/reviews",
    }
]
BUILD_FORMS_BY_URL = {"https://example.invalid/products/1": ["review_text"]}
BUILD_URL_EVIDENCE = {"https://example.invalid/products/1/reviews": {"seen_in": ["recon"]}}


def _make_mc(accumulated: TaskContext) -> MasterConductor:
    mc = MasterConductor.__new__(MasterConductor)
    mc.accumulated_context = accumulated
    return mc


def _make_build_time_task() -> Task:
    """recon build (master_conductor.py:14622-14749) 相当の _context を持つタスク。"""
    return Task(
        id="xss_scan_ctx_merge",
        name="XSS Scan (3 targets)",
        agent_type="InjectionManager",
        action="scan",
        params={
            "target": "https://example.invalid/",
            "_context": {
                "discovered_endpoints": ["https://example.invalid/old/a"],
                "auth_tokens": {},
                "discovered_params": [],
                "tech_stack": ["Node.js"],
                "waf_info": {},
                "critical_findings": [],
                "save_endpoints": BUILD_SAVE_ENDPOINTS,
                "forms_by_url": BUILD_FORMS_BY_URL,
                "url_evidence_by_url": BUILD_URL_EVIDENCE,
            },
        },
    )


# ---------------------------------------------------------------------------
# 1. _merge_accumulated_context 単体: build 時 discovery 契約キーの保持
# ---------------------------------------------------------------------------


def test_dispatch_merge_preserves_build_time_keys_and_accumulated_wins():
    """accumulated 非空時にマージ後も save_endpoints/forms_by_url/url_evidence_by_url が残り、
    overlap キー（discovered_endpoints）は accumulated 値で上書きされる。"""
    mc = _make_mc(
        TaskContext(
            discovered_endpoints=["https://example.invalid/new/b"],
            auth_tokens={"bearer": "tok123"},
            tech_stack=["React"],
        )
    )
    task = _make_build_time_task()

    mc._merge_accumulated_context(task)

    merged = task.params["_context"]
    # build 時のみ入る discovery 契約キーは生存
    assert merged["save_endpoints"] == BUILD_SAVE_ENDPOINTS
    assert merged["forms_by_url"] == BUILD_FORMS_BY_URL
    assert merged["url_evidence_by_url"] == BUILD_URL_EVIDENCE
    # overlap キーは accumulated（新しい recon 要約）優先
    assert merged["discovered_endpoints"] == ["https://example.invalid/new/b"]
    # accumulated のみが持つキーは追加される
    assert merged["auth_tokens"] == {"bearer": "tok123"}
    # build 時のみの非 overlap キーも保持（overlap キー tech_stack は accumulated 優先）
    assert merged["tech_stack"] == ["React"]


def test_dispatch_merge_sets_accumulated_when_context_absent():
    """_context が存在しないタスクは accumulated の要約がそのまま設定される。"""
    mc = _make_mc(TaskContext(discovered_endpoints=["https://example.invalid/new/b"]))
    task = Task(id="t_absent", name="no-ctx", params={"target": "https://example.invalid/"})

    mc._merge_accumulated_context(task)

    assert task.params["_context"] == {
        "discovered_endpoints": ["https://example.invalid/new/b"],
        "auth_tokens": {},
        "discovered_params": [],
        "tech_stack": [],
        "waf_info": {},
        "critical_findings": [],
    }


def test_dispatch_merge_replaces_non_dict_context():
    """_context が dict でない（異常値）場合は accumulated で置換しクラッシュしない。"""
    mc = _make_mc(TaskContext(tech_stack=["PHP"]))
    task = Task(id="t_bad", name="bad-ctx", params={"_context": "corrupted"})

    mc._merge_accumulated_context(task)

    assert isinstance(task.params["_context"], dict)
    assert task.params["_context"]["tech_stack"] == ["PHP"]


# ---------------------------------------------------------------------------
# 2. 配線テスト: 実 _execute_single_task_full_flow 経由でマージが効くこと
# ---------------------------------------------------------------------------


def _make_full_flow_mc(task: Task) -> MasterConductor:
    import threading

    mc = MasterConductor.__new__(MasterConductor)
    mc._state_lock = threading.RLock()
    mc.accumulated_context = TaskContext(
        discovered_endpoints=["https://example.invalid/new/b"],
        auth_tokens={"bearer": "tok123"},
    )
    mc.context = MagicMock()
    mc.context.target_info = {"correlation": {}}
    mc.context.update_success_rate.return_value = None
    mc.context_designer = MagicMock()
    mc.context_designer.enrich_task.side_effect = lambda *a, **k: a[0]
    mc.workspace = None
    mc.risk_predictor = MagicMock()
    mc.risk_predictor.assess.return_value = SimpleNamespace(
        should_proceed=True, recommended_delay=0.0, risk_level="low", risk_score=0.0
    )
    # 下流の実体（本テスト対象外）をスタブ
    mc._reject_invalid_task_snapshot_at_start = MagicMock(return_value=None)
    mc._evaluate_phase7_state_assertion_before_start = MagicMock(return_value=None)
    mc._run_intervention_precheck = MagicMock(return_value=None)
    mc._dispatch_with_timeout_retry = MagicMock(
        return_value={
            "success": True,
            "message": "ok",
            "output": "",
            "data": {},
            "findings": [],
            "context": {},
        }
    )
    mc._drain_vdp_pending_follow_up_injections = MagicMock()
    mc.execution_log = MagicMock()
    mc._emit_task_state_event = MagicMock()
    mc._update_flaky_quarantine = MagicMock()
    mc.check_hitl_required = MagicMock(return_value=None)
    mc._mark_pending_hitl_done = MagicMock()
    mc._record_task_prioritizer_outcome = MagicMock()
    return mc


def test_full_flow_dispatch_merge_keeps_save_endpoints_reachable():
    """実 dispatch フロー（accumulated 非空時）を通しても save_endpoints が到達可能。

    SGK-2026-0460 の回帰防止: 置換だと build 時注入キーが消える（旧 7717 挙動）。
    マージ後、injection 側 (smart_xss/injection manager) が読む
    task.params["_context"]["save_endpoints"] が生存していることを保証する。
    """
    task = _make_build_time_task()
    mc = _make_full_flow_mc(task)

    with (
        patch("src.core.engine.master_conductor.get_event_bus"),
        patch("src.core.engine.master_conductor.get_notifier"),
    ):
        result = mc._execute_single_task_full_flow(task)

    assert result["success"] is True
    merged = task.params["_context"]
    assert merged["save_endpoints"] == BUILD_SAVE_ENDPOINTS
    assert merged["forms_by_url"] == BUILD_FORMS_BY_URL
    assert merged["url_evidence_by_url"] == BUILD_URL_EVIDENCE
    assert merged["discovered_endpoints"] == ["https://example.invalid/new/b"]
    assert merged["auth_tokens"] == {"bearer": "tok123"}
