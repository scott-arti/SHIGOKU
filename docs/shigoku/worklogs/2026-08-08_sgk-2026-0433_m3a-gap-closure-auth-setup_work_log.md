---
task_id: SGK-2026-0433
doc_type: work_log
status: active
parent_task_id: SGK-2026-0432
related_docs:
- docs/shigoku/plans/done/2026-08-08_sgk-2026-0433_m3a-gap-closure-capability_plan.md
- docs/shigoku/reports/2026-08-08_sgk-2026-0433_m3a-gap-closure-auth-setup_work_report.md
created_at: '2026-08-08'
updated_at: '2026-08-08'
tags:
- shigoku
target: tests/fixtures/vdp_juiceshop_sealed
---

# 作業ログ: SGK-2026-0433（auth-setup 実装 slice）

## 実施経過

1. 台帳確認: SGK-2026-0433 は active（plan 済・承認済み認可エンベロープ）。本ターンは auth-setup 能力 slice。
2. 事前ロード: `rules/lessons.md` / `rules/codingrules.md` / `rules/python-tests.md` / `rules/shigoku-docs.md` / `rules/task-ledger.md` + learnings（redaction 境界・write 経路の教訓）。
3. 実装:
   - `auth_setup_config.json`: 製品固有 provisioning config（register/login 仕様・token path・id_factory）。
   - `auth_setup.py`: `AuthSetupGuard`（config のみから構築した allowlist・deviation は transport 前に `AuthSetupRejected`）・provisioning フロー（env 提供 → login→register fallback／無し → generate→register→login・already-exists 許容）・0600 session env・sha256 digest redaction。
   - `run_m5_audit.sh`: phase 6d（auth-setup, pre-run・失敗時 die）＋ main runner に session_env.txt の `--env-file` 追記（不在時 WARN）。
   - `tests/unit/engine/test_vdp_auth_setup_guard.py`: fake transport 方式（test_vdp_cross_account.py の _AuthNet パターンを同期版に適用）で 30 テスト。
4. テスト失敗 2 件を修正: provision_accounts は A/B 両アカウントを provisioning するため、login-only 系テストに B の env 提供を追加。
5. 検証: 新テスト 30 passed・sealed cases 56 passed/1 skipped（無回帰）・bash -n OK・git diff --check clean・src/ 無改変確認。
6. docs: work_report/work_log 作成・sync → validate 0 issue。
7. レビュー・フォローアップ（追記）: redirect 非追従（_NoRedirectHandler + geturl 検証）・harness WARN→die・partial credential fail-closed・error body 完全除去・session env atomic write・timeout 180 を適用。テスト 38 件（+8）・sealed cases 無回帰・docs validator 0 issue。

## 主要決定

- guard の allowlist は config のみから構築（register A/B・login A/B の 4 spec）。register 禁止 config（`register.allowed: false`）では login のみに縮退。
- SECRET は login 応答の session token（Bearer）。account password は env ファイルに書かない。
- 値の write 境界は 0600 session env ファイルのみ（atomic replace）。stdout/stderr は digest のみ・エラーは body 完全除去（レビュー追記: 旧 redact/truncate 方式から strict 化。redirect 非追従・partial credential fail-closed・harness WARN→die・timeout 180 も追記適用）。
- 実コンテナには非接触（テストは全て fake transport）。封印実測は D01 で追跡。
