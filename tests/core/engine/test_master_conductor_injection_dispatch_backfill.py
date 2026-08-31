"""SGK-2026-0462: dispatch 時 save_endpoints 補填の単体テスト。

canonical VDP / coverage backfill 等、recon-category builder
（master_conductor.py:14758-14760）を通らない経路で build された
injection タスクにも、dispatch 時に _context へ save_endpoints
（+ forms_by_url / url_evidence_by_url）が確実に載ることを検証する。

保証対象:
- injection タスクのみ補填（非 injection は byte-identical 不変）。
- sidecar 不在時は no-op（byte-identical）。
- accumulated_context が空でも補填が効く（is_empty() スキップ経路）。
- 既存キーは尊重（上書きしない）。
"""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from src.core.domain.model.task import Task
from src.core.engine.master_conductor import MasterConductor
from src.core.engine.task_queue import TaskContext

# 製品非依存の汎用パス片のみ（固有製品のパス片は使わない）。
SIDECAR_SAVE_ENDPOINTS = [
    {
        "url": "https://example.invalid/app/api/reviews",
        "method": "POST",
        "fields": ["review_text"],
        "marker": "sgkdeadbeef",
        "source_page": "https://example.invalid/app/",
        "revisit_urls": ["https://example.invalid/app/", "https://example.invalid/app/account"],
    }
]


def _make_mc(*, sidecar: list | None = SIDECAR_SAVE_ENDPOINTS) -> MasterConductor:
    mc = MasterConductor.__new__(MasterConductor)
    mc.accumulated_context = TaskContext()
    if sidecar is not None:
        mc._load_run_save_endpoints = MagicMock(return_value=sidecar)
    else:
        mc._load_run_save_endpoints = MagicMock(return_value=[])
    return mc


def _make_injection_task(*, agent_type: str = "InjectionSwarm") -> Task:
    return Task(
        id="xss_seed_abc12345",
        name="XSS Minimal Security Check (2 targets)",
        agent_type=agent_type,
        action="scan",
        params={
            "target": "https://example.invalid/app/reviews",
            "targets": ["https://example.invalid/app/reviews", "https://example.invalid/app/api/reviews"],
            "category": "xss_candidate",
            "_context": {
                "discovered_endpoints": [],
                "auth_tokens": {},
                "discovered_params": [],
                "tech_stack": [],
                "waf_info": {},
                "critical_findings": [],
            },
        },
    )


def _make_non_injection_task() -> Task:
    return Task(
        id="scope_parse_abc",
        name="Scope Parser",
        agent_type="scope_parser",
        action="verify_scope",
        params={"target": "https://example.invalid/"},
    )


# ---------------------------------------------------------------------------
# 1. injection タスクへの補填（単体）
# ---------------------------------------------------------------------------


def test_backfill_fills_save_endpoints_for_injection_task():
    """injection タスクの dispatch 時、_context に save_endpoints が補填される。"""
    mc = _make_mc()
    task = _make_injection_task()

    mc._ensure_injection_dispatch_discovery_context(task)

    ctx = task.params["_context"]
    assert ctx["save_endpoints"] == SIDECAR_SAVE_ENDPOINTS
    # forms_by_url / url_evidence_by_url も sidecar 由来で補填
    assert ctx["forms_by_url"] == {
        "https://example.invalid/app/api/reviews": [
            {
                "action": "https://example.invalid/app/api/reviews",
                "method": "POST",
                "fields": ["review_text"],
            }
        ]
    }
    assert ctx["url_evidence_by_url"] == {
        "https://example.invalid/app/api/reviews": {
            "method": "POST",
            "source": "save_endpoints_sidecar",
            "has_form_tag": True,
        }
    }


def test_backfill_respects_existing_keys():
    """既存の save_endpoints / forms_by_url / url_evidence_by_url は上書きしない。"""
    mc = _make_mc()
    task = _make_injection_task()
    task.params["_context"]["save_endpoints"] = [{"url": "https://existing.invalid/app/", "method": "POST"}]
    task.params["_context"]["forms_by_url"] = {"https://existing.invalid/app/": ["legacy_form"]}
    task.params["_context"]["url_evidence_by_url"] = {"https://existing.invalid/app/": {"method": "GET"}}

    mc._ensure_injection_dispatch_discovery_context(task)

    ctx = task.params["_context"]
    assert ctx["save_endpoints"] == [{"url": "https://existing.invalid/app/", "method": "POST"}]
    assert ctx["forms_by_url"] == {"https://existing.invalid/app/": ["legacy_form"]}
    assert ctx["url_evidence_by_url"] == {"https://existing.invalid/app/": {"method": "GET"}}


def test_backfill_noop_when_sidecar_absent():
    """sidecar 不在時は no-op（byte-identical）。"""
    mc = _make_mc(sidecar=None)
    task = _make_injection_task()
    before = dict(task.params)

    mc._ensure_injection_dispatch_discovery_context(task)

    assert task.params == before
    assert "save_endpoints" not in task.params["_context"]


def test_backfill_skips_non_injection_task():
    """非 injection タスクには補填しない（byte-identical）。"""
    mc = _make_mc()
    task = _make_non_injection_task()
    before = dict(task.params)

    mc._ensure_injection_dispatch_discovery_context(task)

    assert task.params == before
    assert "_context" not in task.params


def test_backfill_creates_context_when_absent_with_sidecar():
    """_context が存在しない injection タスクでも sidecar があれば新設して補填。"""
    mc = _make_mc()
    task = _make_injection_task()
    del task.params["_context"]

    mc._ensure_injection_dispatch_discovery_context(task)

    assert task.params["_context"]["save_endpoints"] == SIDECAR_SAVE_ENDPOINTS


def test_backfill_does_not_create_context_when_sidecar_absent():
    """sidecar 不在で _context も無い場合は新設しない（byte-identical）。"""
    mc = _make_mc(sidecar=None)
    task = _make_non_injection_task()

    mc._ensure_injection_dispatch_discovery_context(task)

    assert "_context" not in task.params


# ---------------------------------------------------------------------------
# 2. 配線テスト: 実 _execute_single_task_full_flow 経由
# ---------------------------------------------------------------------------


def _make_full_flow_mc(task: Task, *, sidecar: list | None) -> MasterConductor:
    import threading

    mc = MasterConductor.__new__(MasterConductor)
    mc._state_lock = threading.RLock()
    # accumulated_context は空 → :7716 is_empty() スキップ経路を踏ませる
    mc.accumulated_context = TaskContext()
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
    if sidecar is not None:
        mc._load_run_save_endpoints = MagicMock(return_value=sidecar)
    else:
        mc._load_run_save_endpoints = MagicMock(return_value=[])
    return mc


def test_full_flow_backfill_reaches_context_even_with_empty_accumulated():
    """accumulated_context 空（is_empty() スキップ経路）でも dispatch で補填される。

    SGK-2026-0462 の回帰防止: :7716 の is_empty() ガードを迂回して
    injection タスクには save_endpoints が必ず載ることを保証する。
    """
    task = _make_injection_task()
    mc = _make_full_flow_mc(task, sidecar=SIDECAR_SAVE_ENDPOINTS)

    with (
        patch("src.core.engine.master_conductor.get_event_bus"),
        patch("src.core.engine.master_conductor.get_notifier"),
    ):
        result = mc._execute_single_task_full_flow(task)

    assert result["success"] is True
    merged = task.params["_context"]
    assert merged["save_endpoints"] == SIDECAR_SAVE_ENDPOINTS
    assert "forms_by_url" in merged
    assert "url_evidence_by_url" in merged


def test_full_flow_noop_when_sidecar_absent():
    """sidecar 不在のフル走行フローでは _context に何も足されない（byte-identical）。"""
    task = _make_injection_task()
    before = dict(task.params)
    mc = _make_full_flow_mc(task, sidecar=None)

    with (
        patch("src.core.engine.master_conductor.get_event_bus"),
        patch("src.core.engine.master_conductor.get_notifier"),
    ):
        result = mc._execute_single_task_full_flow(task)

    assert result["success"] is True
    assert task.params == before
