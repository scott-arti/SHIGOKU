---
task_id: SGK-2026-0259
doc_type: work_log
status: done
parent_task_id: SGK-2026-0221
related_docs:
  - docs/shigoku/subtasks/done/2026-06-03_sgk-2026-0259_recipe-auth-jwt-oauth_subtask_plan.md
  - docs/shigoku/reports/2026-07-20_sgk-2026-0259_auth-jwt-oauth-recipe_work_report.md
title: "作業ログ: Auth/JWT/OAuth Recipe 固定契約化 (SGK-2026-0259)"
created_at: '2026-07-20'
updated_at: '2026-07-21'
---

# 作業ログ

## 2026-07-20: Auth/JWT/OAuth Recipe 固定契約化

### 実施

- `recipes/auth/` に新規 Recipe 4件を作成:
  - `oauth_binding_drift.yaml`: OAuth state/nonce/redirect_uri binding 不備検出。required_signals=[auth_endpoint, bearer_token]、3-stage DAG (auth_attack→analyze→report)
  - `session_invariant.yaml`: セッション token/capability/role 不整合検出。required_signals=[auth_endpoint, session_cookie]、3-stage DAG
  - `jwt_claim_enforcement.yaml`: JWT claim 検証漏れ検出。required_signals=[auth_endpoint, bearer_token, jwt]、3-stage DAG
  - `refresh_rotation.yaml`: refresh token rotation 不備検出。required_signals=[auth_endpoint, refresh, bearer_token]、3-stage DAG

- `recipes/auth/` の既存 Recipe 3件を SGK-2026-0260 固定契約へ移行:
  - `jwt_alg_none.yaml`: 旧 tool/action 直指定 (alg_none, rs256_hs256) → trigger+allowlist アクション (auth_attack, analyze, report)
  - `oauth_token_leak.yaml`: 旧 reconbot/check_token_leak → trigger+recon (token_leak), analyze, report
  - `oauth_redirect_bypass.yaml`: 旧 oauth_dancer/redirect_bypass, pkce_downgrade → trigger+auth_attack×2, analyze, report

- 全 Recipe の step action を `ALLOWED_RECIPE_STEP_ACTIONS` (auth_attack / recon / analyze / report) に収め、新規 action 追加は行わなかった。

- `tests/unit/engine/test_recipe_contracts.py` に schema validation テスト追加 (5 tests):
  - `test_validate_auth_recipe_schema_passes_for_valid_step_actions`
  - `test_validate_auth_recipe_schema_rejects_unsupported_actions`
  - `test_validate_auth_recipe_schema_rejects_redirect_bypass_action`
  - `test_validate_auth_recipe_rejects_zero_steps`
  - `test_validate_all_auth_recipe_names_schema_pass`

- `tests/unit/engine/test_recipe_selector.py` に auth signal-based selection テスト追加 (8 tests):
  - `test_auth_recipe_matches_with_bearer_token_and_endpoint_signal`
  - `test_auth_recipe_does_not_match_without_required_signals`
  - `test_auth_recipe_does_not_match_without_auth_signals`
  - `test_multiple_auth_recipes_match_same_signal`
  - `test_oauth_recipe_matches_when_oauth_label_present`
  - `test_jwt_recipe_matches_when_jwt_label_present`
  - `test_non_auth_recipe_does_not_match_auth_only_signals`
  - `test_auth_recipe_candidate_has_success_and_stop_conditions`

- `tests/unit/engine/test_optimized_runner.py` に auth recipe DAG execution テスト追加 (3 tests):
  - `test_auth_recipe_probe_confirm_evidence_dag_execution`
  - `test_auth_recipe_stops_at_confirm_failure`
  - `test_auth_recipe_unsupported_action_fails_fast`

- `tests/core/engine/test_master_conductor_signal_recipe_routing.py` に auth MC routing テスト追加 (3 tests):
  - `test_auth_surface_signal_routes_to_auth_recipe_not_direct_swarm`
  - `test_auth_recipe_produces_follow_up_decision_on_success`
  - `test_weak_auth_signal_confidence_routes_to_direct_swarm`

### 検証

```text
.venv/bin/pytest tests/unit/engine/test_recipe_selector.py -q (45 passed)
.venv/bin/pytest tests/core/engine/test_master_conductor_signal_recipe_routing.py -q (15 passed)
.venv/bin/pytest tests/unit/engine/test_recipe_contracts.py -q (17 passed)
.venv/bin/pytest tests/core/engine/test_master_conductor_recipe_contracts.py -q (2 passed)
.venv/bin/pytest tests/unit/engine/test_optimized_runner.py -q (6 passed)
.venv/bin/pytest tests/unit/engine/test_recipe_loader.py -q (11 passed)
.venv/bin/pytest tests/core/engine/test_master_conductor_api_candidate_routing.py -q (26 passed)
.venv/bin/pytest tests/core/engine/test_master_conductor_scenario_probes.py -q (23 passed)

Total: 147 passed, 0 failed
```

- SGK-2026-0260 共通層 (recipe_contracts.py, recipe_loader.py, optimized_runner.py, master_conductor.py) は一切変更していない。

### 次アクション

- technique 個別の specialist tool binding 実装
- auth surface signal の正規化精度向上
- 実 target での接続テスト
