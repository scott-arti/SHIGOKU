---
task_id: SGK-2026-0425
doc_type: work_log
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/subtasks/done/2026-08-05_sgk-2026-0425_vdp-causal-attack-funnel-diagnosis_subtask_plan.md
- docs/shigoku/reports/2026-08-06_sgk-2026-0425_vdp-causal-attack-funnel-diagnosis_work_report.md
title: VDP causal attack-funnel diagnosis 作業ログ（M0〜M5コードゲート）
created_at: '2026-08-06'
updated_at: '2026-08-07'
tags:
- shigoku
target: src/core/engine,src/reporting,scripts,config/diagnostics,tests
---

# 作業ログ: SGK-2026-0425（M0〜M5 コードゲート）

## 実施内容

1. **M0 契約凍結**: `config/diagnostics/taxonomy_v1.json`（stage S00〜S12/U00、cause C01〜C13、mechanism codes、判定規則、threshold floor、boundary map、content hash付き）、`config/diagnostics/product_independence_manifest_v1.json`（既存製品固有contentの棚卸し25件、VDP runtime closureはclean by construction）、`config/diagnostics/sealed_product_denylist.txt`。characterization testでflag off時の既存出力をbit単位で凍結（4個のgolden hash）。`config/shigoku.yaml`/example に `diagnostics` ブロック（enabled=false/required=false/上限値）をadditive追加。`DiagnosticsSettings` を settings.py に追加（fail-closed）。`vdp_diagnostic_trace.py` にschema語彙＋`validate_diagnostic_section()`（fail-closed gate）。
2. **M1 telemetry**: `DiagnosticCollector`（bounded queue、max_events上限、決定論的event ID、dedupe、deep redaction、atomic checkpoint/resume、from_section）。master_conductor に S00〜S06 の境界hook＋required kill switch（送信前停止）＋`vdp_diagnostics_v1` section注入と保存時fail-closed gate。executor/validator に collector 注入（S07〜S11の事実event）。
3. **M2 analyzer/CLI**: `vdp_diagnostic.py`（analyze_observed_lineages / first_failure_for_case / evaluate_expected_paths / DAG検証）、`vdp_report_projection.py` の `vdp_diagnostic_index_v1` embed/extract、`report_session_consistency.py` のsibling比較（additive absent互換）、`shigoku-ops vdp diagnose`（label引数なし、report指定時は公式consistency checker先行、上書き拒否、coverage note）。
4. **M3 counterfactual**: `vdp_counterfactual.py`（freeze_input_bundle / validate_experiment / compute_stage_delta / attribution_verdict。2変数変更・input hash不一致・repeat不足・threshold後付け・safety悪化を拒否）。
5. **M4 fixture/hidden eval**: `tests/fixtures/vdp_diagnostic_env/`（fixture-target / runtime / evaluator、`docker compose` v2、evaluator network 0、runtimeからlabels/tests/repo全体がENOENT）。`config/diagnostics/thresholds_v1.json`（§9の12メトリクスをdirection付きで凍結）。fault matrix 39 runs（3 seeds × S00〜S12）→ accuracy 1.0、unattributable 0.0、trace_coverage 1.0。`config/diagnostics/diagnostic_eval_v1.json`。
6. **M5 sealed audit（offline）**: 公式consistency checkerでconsistentなJS/DVWA各1 pairをoffline診断 → 期待どおり U00 baseline（producer_trace_missing/stage_event_missing）。`config/diagnostics/external_audit_v1.json`。active rerunは未実行（ユーザー明示承認待ち）。

## 検証コマンド（代表）

- `.venv/bin/pytest`（VDP回帰＋新規診断テスト一式）: **1291 passed**（最終統合run、exit 0）
- `.venv/bin/shigoku-ops --json validate pytest --suite ops_cli --quiet`: **106 passed**（exit 0、新規diagnoseテスト登録済み）
- `bash tests/fixtures/vdp_diagnostic_env/run_diagnostic_eval.sh`（3 seeds × 13 stages = 39 runs）: 全run exit 0、`diagnostic_eval_done:1`
- `python3 scripts/sync_shigoku_updated_at.py` / `python3 scripts/validate_shigoku_docs.py`: 本ログ更新後に実行
- `git diff --check`: 0件

## 残タスク（コードゲート後のクローズフェーズ）

- 最終完了監査表（§14×§11）の確定と報告
- M5 active rerun（ユーザー明示承認後、隔離network、1回）
- ドキュメントクローズ（status遷移はSGK-2026-0426引き渡し後）
