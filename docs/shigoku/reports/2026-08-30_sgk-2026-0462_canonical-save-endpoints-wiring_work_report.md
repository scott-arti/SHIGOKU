---
task_id: SGK-2026-0462
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-30_sgk-2026-0462_canonical-save-endpoints-wiring.md
- docs/shigoku/worklogs/2026-08-30_sgk-2026-0462_canonical-save-endpoints-wiring_work_log.md
- docs/shigoku/plans/2026-08-30_sgk-2026-0463_stored-stage2-redirect-marker-fix.md
created_at: '2026-08-30'
updated_at: '2026-09-01'
tags:
- shigoku
- vdp
- detection
- xss
- stored
- orchestration
---

# SGK-2026-0462 作業完了報告 — canonical VDP 経路で save_endpoints を injection タスクへ配線

## 実施内容

`src/core/engine/master_conductor.py`（+72行・全て加算）:

1. **`_INJECTION_DISPATCH_AGENT_TYPES`** モジュール定数を追加（InjectionManagerAgent の AgentRegistry 登録名と一致: InjectionManager / InjectionManagerAgent / injection_manager / InjectionSwarm）。
2. **`_ensure_injection_dispatch_discovery_context(task)`** を新規追加:
   - injection 系 agent_type のタスクのみ対象（それ以外は byte-identical no-op）。
   - `_context` の `save_endpoints` が無い/空なら `_load_run_save_endpoints()` で補填（sidecar 不在時は no-op・`_context` を新設しない）。
   - `forms_by_url` / `url_evidence_by_url` も既存キー尊重で補填（sidecar 由来の汎用構造のみ・上書き禁止）。
3. **`_execute_single_task_full_flow` の RUNNING 遷移（:7714-7719）** に呼び出しを追加 — `accumulated_context.is_empty()` によるスキップ経路（:7716）でも補填が効く。
4. 既存 `:14758-14760`（recon-category builder の注入）は無変更・idempotent 温存。

## 検証（実出力）

### 単体
- `tests/core/engine/test_master_conductor_injection_dispatch_backfill.py`（新規7件）+ `test_master_conductor_context_merge.py`（既存5件）
- 出力: `12 passed in 1.85s`
- カバー: injection 補填 / 非injection不変 / sidecar不在no-op（byte-identical）/ accumulated空でも補填 / 既存キー尊重 / `_context` 新設条件 / 実 `_execute_single_task_full_flow` 経由配線。
- 広域: `tests/core/agents/swarm/injection/` = `622 passed in 12.03s`。エンジン広域の失敗14件は HEAD と完全同一（stash 比較で本変更起因ゼロを確認）。

### 実走行（CB-B 部分達成）
- コマンド: `SHIGOKU_RECON_ACTIVE_POST_ENABLED=true .venv/bin/python -m src.main --target http://127.0.0.1:5008 --mode vulntest`（Caido 8081・練習台5008 起動下）。
- セッション: `workspace/projects/127.0.0.1:5008/sessions/session_20260830_050641.json` / レポート `haddix_report_20260830_050643.md`。
- **CB-A 実証**: `xss_seed_d821ddcb` の `_context` に `save_endpoints`（`/comment` POST・fields=["comment"]・revisit_urls 6件）+ `forms_by_url` + `url_evidence_by_url` が実在（旧 session_20260830_002046 では不在）。全 id_param 系 injection タスクも se=True。
- **method=POST 解決 実証**: マネージャログ `classified as 'xss' (…signals=category:xss_candidate,method:POST,form_surface)` + `ExecutionSafeguard: HITL APPROVED method=POST url=http://127.0.0.1:5008/comment`。
- **第2段階起動 実証（旧0件→今回発生）**: 04:36:39 に marker POST（`POST /comment` 303）→ `GET /` → `GET /account` `/account/profile` `/account/settings` `/dashboard` `/profile` の**全6 revisit URL スイープ**を練習台アクセスログで観測。
- **結果**: Confirmed 0 / Candidate 129（全件 real_http・browser_execution_missing・reason=insufficient_validation）。dialog は未観測。
- **残ギャップ真因（実データ確定）**: 練習台5008 の `POST /comment` は `redirect("/", code=303)` → smart_client が follow → 実効レスポンス本文（`GET /`）に保存済み marker が描画 → `_attempt_stored_revisit_validation`（smart_xss.py:821-824）の marker 反射チェックが **by-design 早期リターン**（既存反射/同一URL保存経路へ委譲）→ 委譲先は variant="generic"（/comment は xss_s 非含有）として `_validate_reflected_runtime_xss` → `GET /comment`=405 → dialog 不可。これは**検出側 smart_xss ロジック**に属し、本計画の NOT in scope（検出側変更禁止）に該当 → **SGK-2026-0463 へ deferred**（ユーザー判断・別タスク起票済み）。

### DVWA / バー / token0（CB-C）
- `python3 scripts/check_initial_release_gate.py --report workspace/projects/localhost:4280/reports/haddix_report_20260727_095226.md` → `status: fail` / `reason_codes: ["candidate_above_maximum"]` / **candidate_count: 5**（既知安全保留・不変）。
- `python3 scripts/verify_report_session_consistency.py --report …095226.md` → `status: consistent`。新セッション `haddix_report_20260830_050643.md` も `consistent`。
- `git diff --quiet HEAD -- src/core/agents/swarm/injection/payout_grade.py src/prompts/roles/poc_judge.md src/core/engine/task_queue.py src/core/validation/finding_validator.py src/core/validation/sealed_reproduction_checker.py` → **BAR_UNCHANGED**。
- `python3 scripts/check_vdp_product_independence.py --manifest config/diagnostics/product_independence_manifest_v1.json --denylist config/diagnostics/sealed_product_denylist.txt --changed-files <変更2ファイル>` → `verdict: pass` / **total_token_hits: 0**。

## 完了契約との対応

- **CB-A（dispatch 時 save_endpoints 確実配線）: PASS**（単体7件 + 実走行で save_endpoints/forms_by_url/url_evidence_by_url 実在を実証・sidecar 不在 no-op・非injection不変）。
- **CB-B（formal confirmed=1）: 部分達成** — method=POST 解決・第2段階起動（marker POST + 全6 revisit URL スイープ）までは達成・実証。**dialog 観測は未達** — 練習台5008 の 303-redirect × smart_xss marker チェック（検出側・計画 NOT in scope）による。→ SGK-2026-0463 で追跡。
- **CB-C（DVWA 5候補不変・バー5無改変・token0・ユニット緑）: PASS**。

## deferred_tasks

```yaml
deferred_tasks:
  - description: "保存型XSS第2段階の303-redirect誤早期リターン修正（検出側 smart_xss）: 練習台5008 の POST /comment が 303 redirect→client follow→GET / が保存済みmarkerを描画→smart_xss.py:821-824 の marker 反射チェックが by-design 早期リターン→既存反射経路（variant=generic）が GET /comment=405 で dialog 不可。3xx 応答を「POST応答自体の反射」として扱わない等の最小修正で、練習台5008 フル走行の formal confirmed=1（variant=stored・dialog_observed=True）を目指す。判定緩和・バー変更・0461 B 変更は禁止。"
    tracking_task_id: SGK-2026-0463
    tracking_doc: docs/shigoku/plans/2026-08-30_sgk-2026-0463_stored-stage2-redirect-marker-fix.md
```

## 参考ルール

rules/lessons.md、rules/codingrules.md、rules/task-ledger.md、rules/shigoku-docs.md、rules/python-tests.md、rules/report-session-consistency.md、rules/reporting.md
