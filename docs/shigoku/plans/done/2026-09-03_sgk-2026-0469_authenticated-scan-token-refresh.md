---
task_id: SGK-2026-0469
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-02_sgk-2026-0468_unauth-probe-custom-header-scheme.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-03_sgk-2026-0469_auth-recipe-login-replay_work_report.md
- docs/shigoku/worklogs/2026-09-03_sgk-2026-0469_auth-recipe-login-replay_work_log.md
created_at: '2026-09-03'
updated_at: '2026-09-03'
tags:
- shigoku
- vdp
- auth
- session
- robustness
---

# SGK-2026-0469 計画 — 認証付き走査の自動再ログイン／トークン更新

## 目的（何を・なぜ）

SGK-2026-0468 part-2 の実走行検証で判明した実戦上の弱点: 認証が必要な対象を長時間の自律走行にかけると、
セッショントークン（例: Juice Shop の JWT・既定約1時間）が**走行途中で失効**し、以降の認証リクエストが
壊れて確定に到達できない。SHIGOKU には現状**自動再ログイン／トークン更新の仕組みが無い**。
これは認証付きバグバウンティ（IDOR/BOLA・認可欠陥）を実戦で自律実行する上での核心的なギャップ。

## 事実（精読確定・2026-09-03 更新）

- 既存の自動再認証パイプライン（SGK-2026-0280）が完成・稼働済み:
  - `src/core/infra/network_client.py:636` が 401 検知 → `SESSION_EXPIRED` を EventBus に発火。
  - `AutoReauthSpecialist`（`src/core/agents/swarm/auth/reauth_specialist.py`）が Strategy 2: Login Replay
    （`_try_login_replay`, :400-522）で `login_request` を再送し新トークン取得 → `REAUTH_SUCCESS` 発火。
    重複排除の期待スキーマ（テスト実証済み）: `{method?, url!, headers?, body|data}` — 実行は `data=` 経路
    （`json=` 不使用）のため JSON ログインは body を JSON 文字列 + `Content-Type: application/json` で構築する。
    トークン抽出は `response.text` に対する正規表現のみ（`_ACCESS_TOKEN_PATTERNS`, :39-44）。
  - `MasterConductor._handle_reauth_success`（master_conductor.py:808-856）がトークン更新＋隔離タスク再開。
- 本番コードで `accumulated_context.auth_tokens["login_request"]` を書く箇所は**存在しない**。唯一の読込は
  reauth dispatch 直前（master_conductor.py:944）。観測トラフィック由来でしか埋まらないのが欠点。
- 漏洩ベクトル: reauth タスク params はセッション永続化に素通りする
  （`master_conductor_session_service.py:101/117/222`。metadata のみ `_sanitize_metadata_for_session_payload` 経由）。
  パーシステンス赤線の正本は `redact_secrets_deep`（同 :259-332 で使用実績）。

## 事実（0468 実走行での観測）

- 狙い撃ちの高速確定（数秒）はトークン失効の影響を受けず、本物の Juice Shop で cross-account BOLA を
  確定まで実証済み（SGK-2026-0467/0468 part-2）。
- 一方、フル自律走行は AI 逐次判断で低速（~1時間で LLM 呼び出し186回・思考42ターン規模）。
  トークン失効（~1時間）と競合し、認証依存の確定に届く前に失効する公算が大きい。

## 対象（in scope・2026-09-03 確定）

1. 設定式ログインレシピ（`AuthRecipeSettings`, `settings.auth_recipe`）を追加し、`auth_recipe.enabled`
   （既定 OFF / env `SHIGOKU_AUTH_RECIPE__ENABLED`）で gate。値は env 参照（`$VAR`）とし YAML/env に生値を置かない。
2. `auth_recipe.enabled` かつ `login_request` 未設定のとき、レシピから `login_request` を構築し
   `accumulated_context.auth_tokens["login_request"]` に注入（既存 reauth dispatch 直前・lazy・1 回限り）。
   既存再認証機構は**新規に作らず再利用**する。
3. `_try_login_replay` に `token_path`（dot-path JSON 抽出）を additive 追加（正規表現経路は不変・指定時のみ優先）。
4. 秘密規律: 資格情報値は env 参照解決＋失効時 fail-safe スキップ。セッション永続化・ログでマスク
   （`redact_secrets_deep` / `pii_masker` / `log_redactor` 正本、credentials キーは additively 保護）。

## 完了条件（確定・2026-09-03）

- 必須テスト（製品トークン 0・fixture は product 非依存）全緑:
  1. レシピ → login_request 生成 + `auth_tokens["login_request"]` 注入（env `$VAR` 解決）
  2. 構築 login_request による `_try_login_replay` が新トークン取得・`token_path` 抽出成功
  3. `auth_recipe.enabled=False`（既定）で no-op・既存挙動不変
  4. 資格情報値が redactor/pii_masker 通過後、深さ 2 以上でも平文残存 0
  5 既存 auth/reauth スイート回帰なし
- 確定バー 5 ファイル無改変: `git diff --quiet HEAD -- src/core/agents/swarm/injection/payout_grade.py
  src/core/validation/sealed_reproduction_checker.py src/prompts/roles/poc_judge.md
  src/core/validation/finding_validator.py src/core/engine/task_queue.py` → exit 0。
- 追加行互換 denylist 0（`scripts/check_vdp_product_independence.py`）・secret-scan（saved artifacts）0。
- 変更は additive・フラグ既定 OFF で既存挙動 byte-identical・製品トークン 0。

## NOT in scope

- 確定バー5ファイルの改変。
- 破壊的リクエストの追加。
- 高速化そのもの（AI往復削減）は SGK-2026-0470 で扱う。

## 備考

高速化（SGK-2026-0470）と組み合わせると、認証付き自律走査の実戦性が大きく向上する見込み。
