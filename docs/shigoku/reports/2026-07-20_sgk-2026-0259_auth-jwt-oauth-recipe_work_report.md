---
task_id: SGK-2026-0259
doc_type: work_report
status: done
parent_task_id: SGK-2026-0221
related_docs:
  - docs/shigoku/subtasks/done/2026-06-03_sgk-2026-0259_recipe-auth-jwt-oauth_subtask_plan.md
  - docs/shigoku/subtasks/2026-06-03_sgk-2026-0260_recipe-recon-swarm_subtask_plan.md
  - docs/shigoku/reports/2026-07-18_sgk-2026-0260_signal-recipe-selector-bridge_work_report.md
  - docs/shigoku/worklogs/2026-07-20_sgk-2026-0259_auth-jwt-oauth-recipe_work_log.md
title: "Auth/JWT/OAuth Recipe 群の固定契約化 (SGK-2026-0259)"
created_at: '2026-07-20'
updated_at: '2026-07-21'
---

# SGK-2026-0259 作業報告書: Auth/JWT/OAuth Recipe の固定契約化

## この回の実装内容

### 1. 新規 Recipe YAML (4件)
`recipes/auth/` 配下に、`SGK-2026-0260` で凍結した共通 selector / runner 契約の上に載せる Auth/JWT/OAuth 特化 Recipe を追加した:

- **`oauth_binding_drift.yaml`**: OAuth state/nonce/redirect_uri binding 不備を単一セッションで検出。required_signals: `auth_endpoint`, `bearer_token`。3-stage DAG (auth_attack → analyze → report)。
- **`session_invariant.yaml`**: login/refresh/profile change 前後の token/capability/role 不整合を検出。required_signals: `auth_endpoint`, `session_cookie`。3-stage DAG。
- **`jwt_claim_enforcement.yaml`**: aud, iss, nbf, typ, kid 周辺の JWT claim 検証漏れを応答差分として評価。required_signals: `auth_endpoint`, `bearer_token`, `jwt`。3-stage DAG。
- **`refresh_rotation.yaml`**: refresh 後の旧 token 再利用、scope drift、revocation 不備を検出。required_signals: `auth_endpoint`, `refresh`, `bearer_token`。3-stage DAG。

### 2. 既存 Recipe の固定契約移行 (3件)
旧形式 (tool/action 直指定、trigger なし) の auth YAML を 0260 固定契約へ移行した:

- **`jwt_alg_none.yaml`**: 旧 `alg_none`/`rs256_hs256` アクション → `auth_attack` (jwt_algorithm), `analyze`, `report`。trigger に `required_signals: [auth_endpoint, bearer_token, jwt]` を追加。
- **`oauth_token_leak.yaml`**: 旧 `reconbot`/`check_token_leak` → `recon` (token_leak), `analyze`, `report`。trigger 追加。
- **`oauth_redirect_bypass.yaml`**: 旧 `oauth_dancer`/`redirect_bypass`/`pkce_downgrade` → `auth_attack` (redirect_bypass + pkce_downgrade), `analyze`, `report`。trigger 追加。

全 Recipe が以下を遵守:
- step action は全て `ALLOWED_RECIPE_STEP_ACTIONS` (auth_attack / recon / analyze / report) 内
- `trigger.type: signal` で deterministic trigger
- `success_condition` / `stop_condition` を構造化
- 3-stage probe → confirm → evidence DAG

### 3. テスト (16 追加)
- **`tests/unit/engine/test_recipe_contracts.py`** (+5 tests): auth recipe schema 検証。7 Recipe 全件 schema pass、unsupported action reject、zero steps reject。
- **`tests/unit/engine/test_recipe_selector.py`** (+8 tests): auth surface signal に応じた Recipe 選抜。bearer_token 前提、oauth/jwt ラベル一致、unrelated recipe 非混入、success/stop condition 付与。
- **`tests/unit/engine/test_optimized_runner.py`** (+3 tests): auth recipe DAG 実行 (3-stage success)、failure 停止、unsupported action fast-fail。
- **`tests/core/engine/test_master_conductor_signal_recipe_routing.py`** (+3 tests): auth surface → run_recipe task 化、follow-up decision (all-success → no_follow_up_needed)、weak signal → direct swarm fallback。

## 判断理由

- 0260 の共通層 (selector / runner / vocabulary / allowlist / suppression key / follow-up decision) を一切変更せず、0259 の Auth/JWT/OAuth Recipe 群を載せた。
- 全 Recipe が signal + KG 基準の deterministic trigger を持ち、LLM 単独判定では発火しない。
- step action は既存 allowlist に完全準拠。新規 action 追加なし。
- probe → confirm → evidence の 3-stage 構造で、weak signal のみの confirmed 誤昇格を防止。

## 検証

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

## 残課題

- 各 Recipe step の `params.probe_type` / `params.techniques` に対応する specialist tool binding の実装。現在は step が allowlisted action で実行可能だが、technique 個別の専門エグゼキュータは未実装。
- 各 technique (alg_none, state_replay, redirect_uri_open 等) の具体的な HTTP request 生成・応答差分評価ロジック。
- auth surface signal の正規化精度向上 (primary_label の正確な分類)。

```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0259-D01
    title: "継続実装: auth recipe step technique 個別の specialist tool binding"
    reason: "step action は allowlist 準拠だが、probe_type/technique ごとの専門実装が未完了"
    impact: high
    tracking_task_id: SGK-2026-0259-D01
    recommended_next_action: "各 probe_type に対応する StepExecutor 内分岐を実装し、technique ごとの HTTP request 生成・応答評価を追加する"
```

## 次アクション

- technique 個別の specialist tool binding 実装 (SGK-2026-0259-D01)
- auth surface signal の正規化精度向上 (Recon 側)
- 実 target での接続テスト
