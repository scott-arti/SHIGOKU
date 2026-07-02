---
task_id: SGK-2026-0051
doc_type: plan
status: backlog
parent_task_id: null
related_docs: []
created_at: '2026-05-13'
updated_at: '2026-07-02'
---

# Raw Confirmed Stability + IDOR/Endpoint Class Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make gate decisions stably reflect raw session evidence and lift raw confirmed coverage so `confirmed>=3` with required classes no longer blocked by `idor_bola`/`endpoint_bfla` gaps.

**Architecture:** Keep the current raw-summary gate direction, but extend required-class evaluation to use session-native `detection_class` counts (fallback to report parsing when session info is unavailable). In parallel, make API object A/B comparison emit an explicit IDOR companion finding with strong metadata so raw confirmed count and class coverage increase without heuristic backfill dependence.

**Tech Stack:** Python 3.11, pytest, SHIGOKU core agents/reporting, shigoku-ops CLI, benchmark scripts.

---

### Task 1: Gate Required-Class Decision Uses Session Detection-Class Counts

**Files:**
- Modify: `src/reporting/initial_release_gate.py`
- Modify: `tests/unit/reporting/test_initial_release_gate.py`
- Validate: `tests/unit/reporting/test_initial_release_gate.py`

- [ ] **Step 1: Add failing test for required-class decision source (session detection class preferred)**

```python
# tests/unit/reporting/test_initial_release_gate.py
# Add new test that creates:
# - report findings row: broken_access_control only
# - session completed_tasks findings with additional_info.detection_class="endpoint_bfla"
# Expect:
# verdict["report_metrics"]["required_detection_class_evaluation"]["decision_source"] == "session_detection_class_summary"
# endpoint_bfla count uses session value and passes when min=1
```

- [ ] **Step 2: Run the targeted test and confirm failure first**

Run: `/.venv/bin/pytest -q tests/unit/reporting/test_initial_release_gate.py::test_initial_release_gate_uses_session_detection_class_for_required_class_decision`
Expected: FAIL (feature not implemented yet)

- [ ] **Step 3: Implement session detection-class summary helper and wire into gate decision**

```python
# src/reporting/initial_release_gate.py
# Add helper (same pattern as _build_session_findings_summary):
# def _build_session_detection_class_summary(session_path: Path | None) -> dict[str, Any]
# - use inspect_session_findings(session_path)
# - count by finding["detection_class"] (normalized)
# - return {"available", "confirmed_by_detection_class", "source": "session_detection_class_summary"}

# In evaluate_initial_release_gate:
# - build session_detection_class_summary near session_findings_summary
# - required_detection_class evaluation source priority:
#   1) session_detection_class_summary when available
#   2) detection_class_summary_raw (current fallback)
# - emit decision source + class counts in report_metrics.required_detection_class_evaluation
# - add report_metrics.session_detection_class_summary for traceability
```

- [ ] **Step 4: Re-run targeted gate tests**

Run: `/.venv/bin/pytest -q tests/unit/reporting/test_initial_release_gate.py`
Expected: PASS

- [ ] **Step 5: No commit in this session**

Per current repository/agent guardrails: do not create commits unless explicitly requested.

---

### Task 2: Emit Explicit IDOR Companion Finding from Object A/B API Comparison

**Files:**
- Modify: `src/core/agents/swarm/injection/manager.py`
- Modify: `tests/core/agents/swarm/test_injection_manager.py`
- Validate: `tests/core/agents/swarm/test_injection_manager.py`

- [ ] **Step 1: Add failing test for IDOR companion finding creation**

```python
# tests/core/agents/swarm/test_injection_manager.py
# Add/extend object_ab test scenario to assert:
# - at least one finding has vuln_type == "idor"
# - that finding.additional_info["detection_class"] == "idor_bola"
# - finding.additional_info includes object_ab_comparison.performed == True
# - overall findings_count increases accordingly in API minimal flow
```

- [ ] **Step 2: Run targeted test and confirm failure first**

Run: `/.venv/bin/pytest -q tests/core/agents/swarm/test_injection_manager.py::test_api_minimal_check_emits_idor_companion_finding_on_object_ab_success`
Expected: FAIL (no companion finding yet)

- [ ] **Step 3: Implement minimal IDOR companion finding emission**

```python
# src/core/agents/swarm/injection/manager.py
# In _run_api_minimal_check after object_ab_comparison is populated and API unauth finding is generated:
# - if object_ab_comparison.performed and status_a/status_b in {200,201,202,204}:
#   append new Finding(
#       vuln_type=VulnType.IDOR,
#       severity=Severity.MEDIUM,
#       title="Potential IDOR/BOLA via Object Parameter Mutation",
#       target_url=object_ab_comparison["url_b"] or url,
#       evidence=Evidence(request_method="GET", request_url=url_b, ...),
#       confidence ~= 0.7,
#       tags=["idor", "auth_context"],
#       additional_info={
#          "detection_class": "idor_bola",
#          "object_ab_comparison": object_ab_comparison,
#          "comparison_checks": comparison_checks,
#          "single_request_validation": False,
#          "authz_differential": _build_authz_differential(... scenario="object_ab_idor_probe" ...)
#       }
#   )
# - increment findings_count consistently with existing return path
# - keep existing unauth API finding unchanged (no refactor)
```

- [ ] **Step 4: Re-run targeted injection tests**

Run:
- `/.venv/bin/pytest -q tests/core/agents/swarm/test_injection_manager.py::test_api_minimal_check_records_auth_three_way_and_object_ab_comparison`
- `/.venv/bin/pytest -q tests/core/agents/swarm/test_injection_manager.py::test_api_minimal_check_emits_idor_companion_finding_on_object_ab_success`
Expected: PASS

- [ ] **Step 5: No commit in this session**

Per current repository/agent guardrails: do not create commits unless explicitly requested.

---

### Task 3: Focused Regression + Real Artifact + 3-Run Benchmark Validation

**Files:**
- Modify (if needed from failures): `src/reporting/initial_release_gate.py`, `src/core/agents/swarm/injection/manager.py`
- Validate artifacts under: `tmp/bench_fast_parallel5_rawgate_<timestamp>/...`

- [ ] **Step 1: Run focused test suites**

Run:
- `/.venv/bin/pytest -q tests/unit/reporting/test_initial_release_gate.py`
- `/.venv/bin/pytest -q tests/core/agents/swarm/test_injection_manager.py`
- `/.venv/bin/pytest -q tests/unit/reporting/test_haddix_formatter_kpi.py`

Expected: PASS

- [ ] **Step 2: Run real report consistency check via shigoku-ops**

Run:
- `/.venv/bin/shigoku-ops --json report consistency --report <absolute-haddix-report-path>`

Expected: `status=consistent`

- [ ] **Step 3: Run 3-run benchmark (parallel + raw gate conditions)**

Run command block:

```bash
cd /home/bbb/Documents/App/Shigoku
RUN_TAG=$(date +%Y%m%d_%H%M%S)
RT="/home/bbb/Documents/App/Shigoku/tmp/bench_fast_parallel5_rawgate_${RUN_TAG}"
ART="${RT}/workspace/projects/127.0.0.1:8888/reports/benchmark_scn01_07_P0"

SHIGOKU_MODEL=deepseek/deepseek-v4-flash \
SHIGOKU_MODEL_OUTPUT=deepseek/deepseek-v4-pro \
SHIGOKU_MODEL_LIGHTWEIGHT=deepseek/deepseek-v4-flash \
SHIGOKU_DEEPSEEK_THINKING_ENABLED_FOR_OUTPUT=true \
SHIGOKU_DEEPSEEK_THINKING_ENABLED_FOR_LIGHTWEIGHT=false \
SHIGOKU_RISK_PREDICTOR_DELAY_DISABLE=1 \
SHIGOKU_PHASE1_TIMEOUT_RETRY_SAME_CAUSE_GUARD=1 \
SHIGOKU_PHASE1_TIMEOUT_RETRY_GUARD_MIN_PRIORITY=55 \
SHIGOKU_INJECTION_FULL_PARALLEL_DISPATCH=1 \
SHIGOKU_MAX_DERIVED_TASKS_PER_SESSION=40 \
SHIGOKU_MAX_SESSION_TASKS=300 \
RUNTIME_CWD="${RT}" PROFILE_ID=P0 SEED_SET_ID=scn01-07_seed_v2 AUTO_APPLY_SEED=1 \
BENCH_FAST=1 BENCH_ULTRA=0 RUN_COUNT=3 RUN_TIMEOUT_SEC=900 RUN_TIMEOUT_KILL_AFTER_SEC=30 \
bash scripts/bench/run_scn01_07_p0_5runs.sh
```

Expected:
- consistency: 3/3 consistent
- gate: stable reason-codes
- improvement target: `confirmed_count >= 3` and `idor_bola/endpoint_bfla` gaps reduced

- [ ] **Step 4: Post-run gate/consistency inspection for each report**

Run:

```bash
for report in "$ART"/../haddix_report_*.md; do
  .venv/bin/shigoku-ops --json report consistency --report "$report" | jq '{report:.report.path,status,reason_codes}'
  .venv/bin/shigoku-ops --json report gate \
    --report "$report" \
    --allowed-missing scn_08_oob_external_channel_flow,scn_10_semantic_business_logic,scn_12_advanced_ssrf_internal_topology \
    --required-confirmed-classes access_control,idor_bola,mass_assignment,endpoint_bfla \
    --required-class-confirmed-min 1 \
  | jq '{report:.consistency.report.path,status,reason_codes,findings_summary:.report_metrics.findings_summary,required_eval:.report_metrics.required_detection_class_evaluation}'
done
```

- [ ] **Step 5: Document residual risk and next action**

If gate still fails, include exact dominant reason codes and choose one minimal next lever (single-variable change) for follow-up run.

