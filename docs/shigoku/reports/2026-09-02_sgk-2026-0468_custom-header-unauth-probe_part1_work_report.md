---
task_id: SGK-2026-0468
doc_type: work_report
status: active
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/2026-09-02_sgk-2026-0468_unauth-probe-custom-header-scheme.md
- docs/shigoku/worklogs/2026-09-02_sgk-2026-0468_custom-header-unauth-probe_part1_work_log.md
- docs/shigoku/plans/done/2026-09-01_sgk-2026-0467_idor-bola-confirmation-fact-first.md
- docs/shigoku/reports/2026-09-02_sgk-2026-0467_idor-bola-confirmation-fact-first_work_report.md
created_at: '2026-09-02'
updated_at: '2026-09-03'
tags:
- shigoku
- vdp
- detection
- confirmation
- idor
- bola
- authz
---

# SGK-2026-0468 作業完了報告（part-1）— 未認証プローブのカスタムヘッダ対応（cross-account 確定を独自ヘッダ認証でも発火）

## 何をしたか / なぜ

SGK-2026-0467 で実装した cross-account BOLA 確定は、共有の未認証プローブ（`manager.py` `_run_api_minimal_check` の `unauth_headers`、authorization/cookie のみ剥離）に依存するため、X-Auth-Token 等の独自ヘッダ認証スキームでは未認証プローブに認証ヘッダが残り `auth_boundary_observed` が立たず、確定が fail-closed で静かに不発火（誤検知なし・機会損失のみ）だった。part-1 ではこれを解消する:

- **STEP 1**: モジュール定数 `_UNAUTH_STRIP_HEADER_KEYS`（汎用認証ヘッダ名の frozenset。既存 idor.py / proxy_log_analyzer.py / vdp_observation_adapter.py の先例に倣い製品固有名なし）を `manager.py` 上部に追加。
- **STEP 2**: cross-account ブロック（`if _idor_cross_account_enabled and auth_b_headers:` 内・`_matrix_signals` の直後）で境界（保護されているか）を独自算出する形に変更。マトリクスが既に `auth_boundary_observed` を示していればそのまま使い（追加リクエスト無し）、示していない時だけ・`auth_status` が 2xx の時に、広域剥離（`_UNAUTH_STRIP_HEADER_KEYS` で全剥離）した真の未認証 GET を **1 回だけ** 送り、非 2xx なら境界確立とする。広域剥離結果が narrow と等しい場合は追加検証しない。

制約は 0467 と同一で厳守: 確定バー 5 ファイル無改変／製品トークン 0／GET-only／共有 `unauth_headers`・`auth_context_matrix`・既存「Potential Unauthenticated API Access」ブロック無改変（追加のみ・後方互換）／新挙動は既存フラグ `idor_cross_account_confirm_enabled`（既定 False）配下のみ。

## 結果（確定）

- 独自ヘッダ（X-Auth-Token）認証の authA でも cross-account 確定が発火するようになった。マトリクス signals は `authA_success / unauth_success / authB_success / authA_authB_both_success`（境界はマトリクス外）のまま、広域剥離プローブの非 2xx で境界を確立し finding を発火。
- finding 構築ブロックは無改変（共有 unauth の `status` 値・reproduction_steps の文言はそのまま。判定は広域剥離プローブのみが担う）。
- 広域剥離プローブは、`_broad_unauth_headers != unauth_headers`（広域が narrow より多く剥がす＝独自ヘッダ認証）の場合のみ・フラグ配下でのみ発行。Authorization: Bearer 等の既存スキームでは一切発行されない（リクエスト数不変）。

## 検証（実行したコマンドと観測結果）

- 新規テスト 3 件（`tests/core/agents/swarm/injection/test_cross_account_bola.py` に追加）:
  - `test_cross_account_bola_custom_header_confirmed_vuln`（独自ヘッダ authA で確定・広域剥離プローブ 1 本の発行をリクエスト記録で確認・payout_grade 検証）
  - `test_cross_account_bola_custom_header_secure_negative_control`（SECURE fake で 0 件・広域プローブ不発行）
  - `test_cross_account_bola_bearer_no_extra_broad_probe`（既存 Bearer 経路の非回帰＋広域プローブ不発行を空ヘッダ GET 数で確認）
- `.venv/bin/pytest tests/core/agents/swarm/injection/test_cross_account_bola.py -q` → **9 passed**（既存 6＋新規 3）。
- 回帰: `.venv/bin/pytest tests/core/agents/swarm/injection -q` → **634 passed**（非回帰）。
- 独自ヘッダ authA での cross_account finding の判定（独立実行で観測）: `evaluate_payout_grade(finding_payload(f))` → **payout_grade=True / reason=payout_grade_satisfied / marker=authz_diff**（cross_findings=1）。
- 確定バー 5 ファイル（`src/core/agents/swarm/injection/payout_grade.py` / `poc_judge.md` / `src/core/engine/task_queue.py` / `src/core/validation/finding_validator.py` / `src/core/agents/swarm/injection/sealed_reproduction_checker.py`）: `git diff --quiet HEAD -- <5ファイル>` → **exit 0**。
- denylist（juice / dvwa / /vulnerabilities/ / localhost:3000 等）: `manager.py` 差分の追加行＋テストファイル全体を case-insensitive grep → **0 件**。
- 広域プローブが Authorization ケースで走らないこと: `test_cross_account_bola_bearer_no_extra_broad_probe` で空ヘッダ GET が共有 unauth プローブの 1 本のみであることをリクエスト記録で確認（走っていれば 2 本になる）。
- ドキュメント: `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` 0 エラー（本報告時点で実施）。

## リスク

- 低。新挙動は全てフラグ配下・cross-account ブロック内のみで、共有 unauth プローブ／マトリクス／既存未認証判定は無改変。追加リクエストは独自ヘッダ認証かつマトリクスに境界が無い場合の GET 1 本のみ（read-only・30s timeout・失敗時は fail-closed で現行同挙動）。
- 独自ヘッダ認証サイトでは共有ブロックの既存挙動（unauth プローブが token を保持したまま 200 になる）は不変（本タスクの対象外・既存経路変更禁止）。

## 次の一手

- part-2: 実走行 E2E 再確認（`multi_session.enabled`＋authA/authB 登録＋`SHIGOKU_IDOR_CROSS_ACCOUNT_CONFIRM_ENABLED=1` で cross-account finding の payout_grade=True を実物で確認）は本タスク内の残作業（下記 deferred）。

## deferred_tasks

```yaml
deferred_tasks:
  - summary: "part-2: 実走行 E2E 再確認 — multi_session.enabled＋authA/authB 登録＋SHIGOKU_IDOR_CROSS_ACCOUNT_CONFIRM_ENABLED=1 の実走行で cross-account finding の payout_grade=True 到達を実物で確認（本 part-1 はモックベース unit で発火経路を実証）。"
    tracking_task_id: SGK-2026-0468
    blocking: false
```
