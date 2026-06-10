---
task_id: SGK-2026-0279
doc_type: work_log
status: done
parent_task_id: SGK-2026-0265
related_docs:
  - docs/shigoku/subtasks/2026-06-09_injectionmanager-additional-split-plan_subtask_plan.md
  - docs/shigoku/reports/2026-06-09_sgk-2026-0279_injectionmanager-additional-split_work_report.md
created_at: '2026-06-09'
updated_at: '2026-06-11'
---

# Work Log: SGK-2026-0279

## 2026-06-09

### Baseline (Steps 1-4)
- manager.py: 2382 lines
- dispatch: 664 lines (L812-L1475), _process_single_url: 251 lines (L1477-L1727)
- run_*_hunter 群: ~517 lines total
- Baseline pytest: 470 pass, 2 fail (pre-existing: blind_correlation shape mismatch), 18 errors (live tests)
- Character tests: 63/65 pass (same 2 pre-existing)
- timeout/circuit/lane2: 5/5 pass

### run_*_hunter extraction (Steps 7-10)
- Added `HunterRunnerDependencies` TypedDict (7 fields) to models.py
- Created runner functions in tool_runners.py:
  - Blind-correlation: `run_sqli_hunter_runner`, `run_xss_hunter_runner`, `run_cmd_ssrf_hunter_runner`
  - Simple retry: `run_lfi_check_runner`, `run_open_redirect_check_runner`
  - Custom: `run_ssti_hunter_runner`, `run_cors_hunter_runner`, `run_crlf_hunter_runner`, `run_graphql_hunter_runner`, `run_ssrf_hunter_runner`
  - Common helpers: `_ensure_context_defaults`, `_extract_blind_correlation`, `_extract_tested_params_or_fallback`, `_make_auth_dict`
- Replaced 10 run_*_hunter methods in manager.py with thin wrappers (5-7 lines each)
- manager.py: 2382 → 2029 lines (-353)
- tool_runners.py: 135 → 621 lines (+486)
- Fix: `build_hunter_task` None-safe current_context handling (GraphQL guard test failure)
- Fix: CRLF/GraphQL/CORS wrapper context guard (preserve self.current_context mutation)
- Tests: 63/65 pass (2 pre-existing), 428/472 pass (wide, excluding live tests)
- tool_runners.py exceeds 500-line threshold → deferred as SGK-2026-0279-D05

### specialist factory + tool registration extraction (Steps 15-16)
- Created `specialist_factory.py` (78 lines): `create_specialists(config)`
- Created `tool_registration.py` (131 lines): `register_manager_tool_scans()`, `register_initial_tools()`
- Replaced `_initialize_specialists` (73 lines) with 1-line delegation
- Replaced `_register_manager_tools` (59 lines) + `_register_initial_tools` (43 lines) with thin delegations
- manager.py: 2029 → 1887 lines (-142)
- Tests: same pass/fail pattern, no regressions

### _process_single_url extraction (Steps 11-14)
- Added `dispatch_vuln_type_branch()` to process_url_dispatcher.py (173 lines added)
- Handles all 13 vuln_type branches (sqli, xss, lfi, ssti, cors, crlf, redirect, cmd_ssrf, ssrf, csrf, api, admin, unknown)
- Unknown branch inline computes `unknown_classification_only` boolean
- Manager wrapper retains: cache key/write, exception handler, return dict assembly
- manager.py: 1887 → 1758 lines (-129)
- process_url_dispatcher.py: 49 → 222 lines
- Tests: same 2 pre-existing failures, 0 new

### unknown_scan_runner extraction (Step 20)
- Created `unknown_scan_runner.py` (98 lines): `run_unknown_hypothesis_scans()`
- Specialist loop (sqli/xss/lfi/ssti/cors/crlf/cmd_ssrf/ssrf/graphql) via callables dict
- Manager wrapper passes bound methods as callables
- Fix: test_graphql_pipeline.py patch target updated to `unknown_scan_runner.build_unknown_hypotheses`
- manager.py: 1758 → 1710 lines (-48)
- Tests: 470/472 pass, 2 pre-existing, 0 new

### Static boundary checks
- `tool_runners.py`: no `self.`, `InjectionManagerAgent`, `AsyncNetworkClient(`, `.close(`, `dispatch(` (rg: 0 matches)
- `specialist_factory.py`: clean
- `tool_registration.py`: clean

### Verification
- SHIGOKU validate: MD_FILES=356, BROKEN_LINKS=0, REGISTRY_ISSUES=0

## Next Actions
- deferred_tasks D01-D06 を後続 subtask として起票
- graphify update . の実行（別途）
