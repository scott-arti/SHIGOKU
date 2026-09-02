---
task_id: SGK-2026-0468
doc_type: work_log
status: active
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/2026-09-02_sgk-2026-0468_unauth-probe-custom-header-scheme.md
- docs/shigoku/reports/2026-09-02_sgk-2026-0468_custom-header-unauth-probe_part1_work_report.md
- docs/shigoku/plans/done/2026-09-01_sgk-2026-0467_idor-bola-confirmation-fact-first.md
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

# SGK-2026-0468 作業ログ（part-1）— 2026-09-02

## 変更要約

- `src/core/agents/swarm/injection/manager.py`:
  - モジュール上部に `_UNAUTH_STRIP_HEADER_KEYS` 定数追加（汎用認証ヘッダ名の frozenset。authorization / proxy-authorization / cookie / x-api-key / api-key / apikey / x-auth-token / auth-token / x-access-token / access-token / x-session-token / session-token / session / token / bearer / jwt / x-csrf-token / x-xsrf-token。製品固有名なし）。
  - `_run_api_minimal_check` の cross-account ブロック（SGK-2026-0467 追加分）内で境界を独自算出: マトリクスに `auth_boundary_observed` が無く authA が 2xx のときのみ、広域剥離した真の未認証 GET を 1 回送り非 2xx なら境界確立。`_broad_unauth_headers != unauth_headers`（広域剥離が narrow より多く剥がす）時だけ追加検証。失敗時は fail-closed。
- `tests/core/agents/swarm/injection/test_cross_account_bola.py`: 新規 3 テスト追加（独自ヘッダ authA で確定＋payout_grade 検証／独自ヘッダ SECURE 負コントロール／Bearer 非回帰＋広域プローブ不発行）。

## 判断理由

- 共有 `unauth_headers`（manager.py:1750）・`finalize_auth_context_matrix`・既存未認証アクセス判定ブロックは「既存経路の挙動変更禁止」のため無改変。追加検証は cross-account ブロック内・フラグ配下でのみ動作させる design とした。
- 広域剥離の実施条件を「`_broad_unauth_headers != unauth_headers`」とし、Authorization/Cookie のみの既存スキームではリクエスト数が一切増えないことを保証（非回帰をリクエスト記録で assert）。
- finding 構築ブロック（`unauth_status`・reproduction_steps の文言）は無改変とし、広域プローブの status は判定のみに使用（指示どおり）。
- 参照: `rules/codingrules.md`、`rules/python-tests.md`、`rules/task-ledger.md`、`rules/shigoku-docs.md`、`rules/lessons.md`。

## 検証

- `.venv/bin/pytest tests/core/agents/swarm/injection/test_cross_account_bola.py -q` → 9 passed（既存 6＋新規 3）。
- `.venv/bin/pytest tests/core/agents/swarm/injection -q` → 634 passed（非回帰）。
- 独自ヘッダ authA の cross_account finding: `evaluate_payout_grade` → payout_grade=True / reason=payout_grade_satisfied / marker=authz_diff。
- 確定バー 5 ファイル `git diff --quiet HEAD` → exit 0。
- denylist grep（manager.py 追加行＋テストファイル全体）→ 0 件。
- `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` → 0 エラー。

## 次アクション

- SGK-2026-0468 は part-1（カスタムヘッダ対応）完了により引き続き `active`。part-2（実走行 E2E 再確認）を残作業として追跡。
