---
task_id: SGK-2026-0462
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-30_sgk-2026-0462_canonical-save-endpoints-wiring.md
- docs/shigoku/reports/2026-08-30_sgk-2026-0462_canonical-save-endpoints-wiring_work_report.md
- docs/shigoku/plans/2026-08-30_sgk-2026-0463_stored-stage2-redirect-marker-fix.md
created_at: '2026-08-30'
updated_at: '2026-09-01'
tags:
- shigoku
- vdp
- detection
- xss
- stored
---

# SGK-2026-0462 作業ログ — canonical VDP 経路で save_endpoints を injection タスクへ配線

## 日時

2026-08-30（実装・単体・実走行・回帰・docs を一貫して実施）

## 作業内容

### 1. 実装（`src/core/engine/master_conductor.py`）

- `_INJECTION_DISPATCH_AGENT_TYPES` 定数追加（injection 系 agent_type の正規名集合）。
- `_ensure_injection_dispatch_discovery_context(task)` 新規:
  - injection タスク限定。`_context` の save_endpoints が無い/空なら `_load_run_save_endpoints()` で補填。
  - forms_by_url / url_evidence_by_url は sidecar 由来の汎用構造を既存尊重で補填。
  - sidecar 不在・非injection は byte-identical no-op。`_context` は sidecar 非空時のみ新設。
- `_execute_single_task_full_flow` RUNNING 遷移で本メソッドを呼び出し（`is_empty()` スキップ経路でも有効）。
- 既存 `:14758-14760` は温存。

### 2. テスト（新規7件）

`tests/core/engine/test_master_conductor_injection_dispatch_backfill.py`:
- injection 補填（save_endpoints/forms_by_url/url_evidence_by_url）
- 既存キー尊重（上書きなし）
- sidecar 不在 no-op（byte-identical・`_context` 新設なし）
- 非injection 不変
- `_context` 不在 + sidecar 有 → 新設補填 / sidecar 無 → 新設なし
- 実 `_execute_single_task_full_flow` 経由（accumulated 空 = is_empty スキップ経路）で補填到達
- フルフロー sidecar 不在 no-op

### 3. 検証コマンド（実出力）

```
$ .venv/bin/pytest tests/core/engine/test_master_conductor_injection_dispatch_backfill.py tests/core/engine/test_master_conductor_context_merge.py -q
12 passed in 1.85s

$ .venv/bin/pytest tests/core/agents/swarm/injection/ -q
622 passed in 12.03s

$ git diff --quiet HEAD -- src/core/agents/swarm/injection/payout_grade.py src/prompts/roles/poc_judge.md src/core/engine/task_queue.py src/core/validation/finding_validator.py src/core/validation/sealed_reproduction_checker.py && echo BAR_UNCHANGED
BAR_UNCHANGED

$ python3 scripts/check_initial_release_gate.py --report workspace/projects/localhost:4280/reports/haddix_report_20260727_095226.md
status: fail / reason_codes: ["candidate_above_maximum"] / candidate_count: 5（既知安全保留・不変）

$ python3 scripts/verify_report_session_consistency.py --report workspace/projects/localhost:4280/reports/haddix_report_20260727_095226.md
status: consistent

$ python3 scripts/check_vdp_product_independence.py --manifest config/diagnostics/product_independence_manifest_v1.json --denylist config/diagnostics/sealed_product_denylist.txt --changed-files <master_conductor.py + 新テスト>
verdict: pass / total_token_hits: 0
```

### 4. 実走行（CB-B）

```
$ SHIGOKU_RECON_ACTIVE_POST_ENABLED=true .venv/bin/python -m src.main --target http://127.0.0.1:5008 --mode vulntest
```
- session_20260830_050641 / haddix_report_20260830_050643（consistency=consistent）
- xss_seed タスク `_context` に save_endpoints 実在（旧002046 では不在）→ method=POST 解決 → 第2段階起動（marker POST + 全6 revisit URL スイープ）
- 結果: Confirmed 0 / Candidate 129（real_http・browser_execution_missing）→ dialog 未観測
- 真因（検出側・計画 NOT in scope）: 練習台5008 の 303-redirect × smart_xss marker チェック → **SGK-2026-0463 へ deferred**

### 5. docs

- `docs/shigoku/registry/task_registry.yaml`: 0462 を done 化 + 0463 を active で登録（DOC-0532）
- `docs/shigoku/registry/task_ledger.md`: 0462 done / 0463 active 行を更新
- `docs/shigoku/plans/2026-08-30_sgk-2026-0463_stored-stage2-redirect-marker-fix.md` 新規
- `docs/shigoku/reports/2026-08-30_sgk-2026-0462_..._work_report.md` 新規（deferred_tasks → SGK-2026-0463）
- 本 work_log 新規

## 残課題

- dialog 観測（検出側 smart_xss の 303-redirect 誤早期リターン修正）→ SGK-2026-0463（active）で追跡。

## 参考ルール

rules/lessons.md、rules/codingrules.md、rules/task-ledger.md、rules/shigoku-docs.md、rules/python-tests.md、rules/report-session-consistency.md、rules/reporting.md
