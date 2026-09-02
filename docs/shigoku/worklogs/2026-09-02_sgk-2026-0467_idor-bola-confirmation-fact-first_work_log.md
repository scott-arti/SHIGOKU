---
task_id: SGK-2026-0467
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-01_sgk-2026-0467_idor-bola-confirmation-fact-first.md
- docs/shigoku/reports/2026-09-02_sgk-2026-0467_idor-bola-confirmation-fact-first_work_report.md
- docs/shigoku/plans/2026-09-02_sgk-2026-0468_unauth-probe-custom-header-scheme.md
created_at: '2026-09-02'
updated_at: '2026-09-03'
tags:
- shigoku
- vdp
- detection
- confirmation
- idor
- bola
---

# SGK-2026-0467 作業ログ — 2026-09-02

## 変更要約

- `src/core/config/settings.py`: `idor_cross_account_confirm_enabled: bool = False` 追加（SGK-2026-0467 コメント付き・env `SHIGOKU_IDOR_CROSS_ACCOUNT_CONFIRM_ENABLED`）。
- `src/core/agents/swarm/injection/manager.py`: (a) `ResponseComparator`/`ComparisonInput` import 追加、(b) `_run_api_minimal_check` 内に cross-account BOLA 確定発火ブロックを新設（auth マトリクス `authA_authB_both_success`+`auth_boundary_observed`＋`ResponseComparator` 構造相関でのみ発火。`detection_class="cross_account_bola"` の IDOR/HIGH finding を impact/reproduction_steps 付きで発火し `second_account_compared`/`cross_account_compared` VDP marker を格納。`_funnel_finding_created` 踏襲）、(c) base_params `_auth` builder に `auth_b_headers`/`auth_b_role` 透過を追加。
- `src/core/engine/master_conductor.py`: `_resolve_second_account_auth()` ヘルパ新設（`user_sessions` 2 件以上で非プライマリ 1 件を返す・単一セッションは no-op）＋API/Injection backfill タスク生成箇所への `auth_b_headers`/`auth_b_role` additive 設定（typing import に `Tuple, Dict` 追加）。
- `tests/core/agents/swarm/injection/test_cross_account_bola.py`: 新規 6 テスト（VULN 確定+payout_grade 検証／SECURE 負コントロール／authB 不在 no-op／フラグ OFF no-op／authB 配線透過／settings 既定 OFF）。

## 判断理由

- 確定バー無改変の制約下で cross-account 確定を通すため、既存の `authz_diff` firing marker 語彙（`auth_success`+`unauth_success`）と `_VDP_IMPACT_MARKERS`（`second_account_compared`）をそのまま使う設計とした。impact/reproduction_steps は cross-account の実挙動を正直に記述し、捏造となる「未認証アクセス許可」ヘルパ（`build_authz_impact_and_reproduction_steps`）は呼ばない。
- 新ブロックは既存 object_ab ブロック（未認証成功の入れ子内でのみ発火）とは独立の top-level 配置とし、protected 資源でも cross-account を試行できるようにした。
- 参照: `rules/codingrules.md`、`rules/python-tests.md`、`rules/task-ledger.md`、`rules/shigoku-docs.md`、`rules/lessons.md`。

## 検証

- `.venv/bin/pytest tests/core/agents/swarm/injection/test_cross_account_bola.py -q` → 6 passed（payout_grade=True/marker=authz_diff を観測）。
- `.venv/bin/pytest tests/core/agents/swarm/test_injection_manager.py tests/core/agents/swarm/injection/ -q` → 683 passed（非回帰）。
- 確定バー 5 ファイル `git diff --quiet HEAD` → exit 0（task_queue.py は実パス `src/core/engine/task_queue.py`）。
- denylist grep（追加行＋新規テストファイル）→ 0 件。
- `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` → 0 エラー。

## 次アクション

- 親タスク SGK-2026-0467 は実装スコープ完了により `done`。継続監視（カスタムヘッダスキーム対応・実走行 E2E 再確認）は `SGK-2026-0468`（active）に分離追跡。
