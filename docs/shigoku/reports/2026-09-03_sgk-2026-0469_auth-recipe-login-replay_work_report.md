---
task_id: SGK-2026-0469
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-03_sgk-2026-0469_authenticated-scan-token-refresh.md
- docs/shigoku/worklogs/2026-09-03_sgk-2026-0469_auth-recipe-login-replay_work_log.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/plans/done/2026-09-02_sgk-2026-0468_unauth-probe-custom-header-scheme.md
created_at: '2026-09-03'
updated_at: '2026-09-03'
tags:
- shigoku
- vdp
- auth
- reauth
- secrets
---

# SGK-2026-0469 作業報告書 — 設定式ログインレシピ → 既存 reauth パイプライン注入

## 実装内容（What）

既存の自動再認証パイプライン（SGK-2026-0280）を再利用し、設定式ログインレシピ
（`settings.auth_recipe`）から `login_request` を構築して
`accumulated_context.auth_tokens["login_request"]` に注入する。新規再認証機構は作らない。

変更ファイル（すべて追加のみ・`auth_recipe.enabled` 既定 OFF gate）:

| ファイル | 変更 |
|---|---|
| `src/core/config/settings.py` | `AuthRecipeSettings`（enabled/login_url/method/content_type/body/headers/token_path/token_header/token_format、content_type validator）+ `Settings.auth_recipe`。env: `SHIGOKU_AUTH_RECIPE__ENABLED` 等（nested `__`） |
| `src/core/engine/master_conductor.py` | additive helpers: `_auth_recipe_settings`（lazily get_settings フォールバック・`__new__` テスト経路 guard）, `_resolve_auth_recipe_env_value`（`$NAME`/`${NAME}` 全体一致・未設定変数は該当キー drop＋警告 値非出力）, `_auth_recipe_base_url`（失効リクエスト URL の origin を基点）, `_absolutize_auth_recipe_login_url`（urljoin）, `_build_auth_recipe_login_request`（json→`json.dumps` + `Content-Type: application/json`、form→dict + urlencoded、`setdefault` でユーザーヘッダ不崩し）, `_maybe_seed_auth_recipe_login_request`（idempotent・narrow fail-safe）。`_handle_session_expired` の reauth dispatch 直前（:1125）で呼び出し |
| `src/core/engine/master_conductor_session_service.py` | `redact_reauth_params_for_persistence`（flag ON 時のみ `login_request`/`auth_tokens` に正本 `redact_secrets_deep` + recipe 資格キー `user/username/email/login/pass/passwd/password` の深さ再帰マスク、JSON 文字列 body 内も辿る）+ `_persistence_params`。`build_async_session_payload` / `build_checkpoint_session_state` / `serialize_legacy_session_task_queue`（deepcopy 上で redact・メモリ Task 不変）に配線。flag OFF → はバイト完全一致 |
| `src/core/logging/log_redactor.py` | `_EXTRA_SECRET_KEYS`（既定空）+ `register_auth_recipe_secret_keys()`（idempotent、`user/username/email/login/pass` 追加）。seed 経路のみ呼ばれ、OFF 時は赤線挙動不変 |
| `src/core/agents/swarm/auth/reauth_specialist.py` | `_try_parse_json` + `_extract_token_path`（dot-path・dict キー/リスト index）。`_try_login_replay`: `token_path` 指定時は JSON dot-path 抽出を優先、失敗時は既存正規表現経路にフォールバック（正規表現経路不変）。`token_header`/`token_format` 付属時は `new_tokens[token_header] = token_format.format(token=...)` と `new_tokens["bearer"] = raw` を additive 発火 |
| `tests/fixtures/vdp_authz_multiuser_app/app.py` | `POST /login`（汎用 `{user, pass}`、fixture 内 demo 定数、`{"auth":{"token":"..."}}` 返却）を additive 追加。既存 route 無改変 |
| `tests/core/engine/test_auth_recipe_login_replay.py` | 新規 20 テスト |

## _try_login_replay 期待スキーマへの一致方法

精読（reauth_specialist.py:409-412）で確定した期待形に厳密一致させた:
`{method?, url!, headers?, body | data}`。実行は `data=` 経路（`json=` 不使用）のため、
JSON ログインは **body を JSON 文字列** + `Content-Type: application/json` ヘッダで構築
（dict を渡すと aiohttp が form-encode し Content-Type と不整合になるため）。
form は dict + `application/x-www-form-urlencoded`。`token_path`/`token_header`/`token_format`
は login_request の追加キーとして渡す（specialist は未知キーを無視・確認済み）。

## 逸脱と判断理由

- **逸脱1**: 仕様どおり `new_tokens[token_header]`（既定 Authorization）に加え、`new_tokens["bearer"] = 生トークン` をも発火。理由: 既存の名前付きキー消費者は `context_designer.enrich_task`（auth_tokens["bearer"]/["jwt"] → Authorization ヘッダ）であり、素の `"Authorization"` キーは消費されない。recipe 経路限定（login_request に token_header 付属時のみ）で additive、これが実配線を成立させる。
- **逸脱2**: 正本 `redact_secrets_deep` ワンウェイ赤線に加え `_mask_recipe_credential_values` を重ねた。理由: 正本キーセットは汎用キー（user/email/login/pass 等）を除外するため form-body の深度 ≥2 平文残存が残り、完了条件 4 を満たさないため。flag gate 済。

## 検証（全て .venv/bin/pytest・観測結果）

| コマンド | 結果 |
|---|---|
| `pytest tests/core/engine/test_auth_recipe_login_replay.py -q` | **20 passed**（実行者: fixer・orchestrator 両方） |
| `pytest tests/core/agents/swarm/auth/ -q` | **59 passed** |
| `pytest tests/core/engine/test_master_conductor_reauth.py tests/core/engine/test_master_conductor_session_service.py -q` | 39 passed / **1 failed（既存・本タスク非起因）** |
| `pytest tests/core/test_settings.py tests/unit/config tests/unit/test_log_redactor.py -q` | **109 passed** |

必須テスト対応: ①レシピ→login_request 生成＋注入 ②login_replay 実動作・token_path 抽出 ③flag OFF no-op（`_handle_session_expired` dispatch 経由含む）→新規 20 件で網羅。④秘密マスク（深度 ≥2・セッション+ログ赤線）・⑤既存 reauth スイート回帰なし（下記既存 failure 除く）。

### 既存 failure の立証（非回帰）

`test_master_conductor_reauth.py::TestReauthHappyPath::test_reauth_success_updates_context_and_releases_tasks`
は clean HEAD（ed8f1ce, 本タスク差分なしの detached worktree）でも同様に失敗することを確認済み
（Phase 6 M2 の `_pending_event_follow_ups` 遅延化に対しテストが `_add_tasks` 1 回を期待、ТЕст側未追随）。
→ 完了条件「回帰なし」は満たす（本タスク起因の新規失敗 0）。

### 完了条件ゲート

- **確定バー5ファイル**: `git diff --quiet HEAD -- src/core/agents/swarm/injection/payout_grade.py src/core/validation/sealed_reproduction_checker.py src/prompts/roles/poc_judge.md src/core/validation/finding_validator.py src/core/engine/task_queue.py` → **exit 0（BAR_OK・orchestrator 独立再実行）**
- **denylist**: `scripts/check_vdp_product_independence.py`（manifest+denylist+changed-files）→ 追加行 grep **0 件**。※whole-file スキャンは `log_redactor.py:43` の**既存コメント**（Cookie 例 "security=low"）で fail するが、先行タスク規約（追加行・新規ファイル grep）では 0 件。新規テスト/fixture 全文 grep も **0 件**
- **secret-scan**: 追加行・新規ファイルへの JWT/API-key/秘密鍵パターン grep **0 件**。テストは dummy env (`SHIGOKU_TEST_LOGIN_*`)・fixture 定数のみ、製品トークン 0。セッション永続化面は flag ON で `redact_secrets_deep`+資格キーマスク（テスト④緑）、OFF でバイト不変。

## リスク / 判断

- 再ログインは 401 発火元 URL の origin を基点に絶対化する（target と login ホストが異なる SSO 構成は非対応・絶対 URL を `login_url` に直書きで回避可）。
- `redact_secrets_deep` を新規 persistence 面（将来追加）へ手動配線する必要がある（本タスク配下の 3 面＋legacy serialize は網羅）。
- フォーム＋CSRF 対象では既存の preflight/CSRF フローがそのまま働く（変更なし）。

## deferred_tasks

- SGK-2026-0470: 実走行（本物対象・`SHIGOKU_AUTH_RECIPE__ENABLED=1`）でトークン失効をまたぐ再ログインと認可系確定到達を E2E 実証する。0470 の高速化と併検が効率的（単独の新規追跡タスクは非起票・0470 実走行時に統合検証）。

## 参照ルールファイル（AGENTS.md §17 報告義務）

`rules/lessons.md`・`rules/codingrules.md`・`rules/python-tests.md`・`rules/task-ledger.md`・`rules/shigoku-docs.md`・`rules/cli-ops-routing.md`
