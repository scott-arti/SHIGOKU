---
task_id: SGK-2026-0309
doc_type: plan
status: done
parent_task_id: SGK-2026-0305
related_docs:
  - docs/shigoku/plans/2026-06-17_cli-entrypoint-followup_plan.md
  - docs/shigoku/reports/2026-06-18_SGK-2026-0305_work_report.md
title: '二段分割: report_haddix.py evidence/coverage cluster 抽出'
created_at: '2026-06-18'
updated_at: '2026-06-18'
tags:
  - shigoku
  - refactor
  - cli
target: >
  report_haddix.py: 1514→400-500
---

# 二段分割計画: report_haddix.py evidence/coverage cluster 抽出

## 背景
SGK-2026-0305 (CLI Entrypoint 追加分割) で `src/main.py` から report/haddix cluster を
`src/cli/handlers/report_haddix.py` へ抽出した。しかし抽出先は 1,514 行 / 17 関数となり、
計画書 §3 の目安 (500-900 行) を超過。計画書 §5 で「後続で evidence helper と coverage helper に
二段分割する」と明記されているため、本タスクで対応する。

### 現状の関数分布 (1,514 行 / 17 関数)

| Cluster | 関数群 | 合計行数 |
|---------|--------|----------|
| **Evidence (artifact合成)** | `coerce_finding_dict`, `first_non_empty_string`, `clip_http_text`, `synthesize_request_raw_from_evidence`, `synthesize_response_raw_from_evidence`, `build_replay_command_for_finding`, `build_detector_signals`, `materialize_haddix_evidence_artifacts` | ~330 行 |
| **Coverage (scenario/findings)** | `enable_debug_mode`, `extract_scn_number`, `normalize_scenario_id_for_report`, `resolve_scn_catalog_for_report`, `build_scenario_coverage_for_report`, `build_heuristic_findings_from_execution_notes`, `finding_signature_for_merge`, `merge_heuristic_candidates_into_findings` | ~769 行 |
| **Orchestration (残留 facade)** | `run_haddix_report_generation` | ~390 行 |

## 完了条件
- [x] `report_haddix.py` (facade) が 500 行以下に縮小される
- [x] `report_haddix_evidence.py` が新規作成され、evidence cluster (~330 行) を保持する
- [x] `report_haddix_coverage.py` が新規作成され、coverage cluster (~769 行) を保持する
- [x] 公開 import path (`from src.cli.handlers.report_haddix import run_haddix_report_generation`) 維持
- [x] `src/main.py` に差分なし（facade 経由で呼び出しが維持されるため）
- [x] targeted pytest: `tests/unit/main/test_main_report_haddix.py` の既存 pass 件数が維持される
- [x] `.venv/bin/python -m compileall src/cli/handlers` 正常

## 実装ステップ

### Step 1: Evidence cluster 抽出 (`report_haddix_evidence.py`)
- [x] 以下の関数を `src/cli/handlers/report_haddix_evidence.py` へ移動:
  - `coerce_finding_dict` (14 行)
  - `first_non_empty_string` (8 行)
  - `clip_http_text` (7 行)
  - `synthesize_request_raw_from_evidence` (50 行)
  - `synthesize_response_raw_from_evidence` (33 行)
  - `build_replay_command_for_finding` (47 行)
  - `build_detector_signals` (37 行)
   - `materialize_haddix_evidence_artifacts` (134 行)
- [x] `report_haddix.py` から上記を削除し、import で参照する
- [x] 想定行数: evidence ファイル ~350 行

### Step 2: Coverage cluster 抽出 (`report_haddix_coverage.py`)
- [x] 以下の関数を `src/cli/handlers/report_haddix_coverage.py` へ移動:
  - `enable_debug_mode` (10 行)
  - `extract_scn_number` (13 行)
  - `normalize_scenario_id_for_report` (136 行)
  - `resolve_scn_catalog_for_report` (85 行)
  - `build_scenario_coverage_for_report` (130 行)
  - `build_heuristic_findings_from_execution_notes` (321 行)
  - `finding_signature_for_merge` (11 行)
   - `merge_heuristic_candidates_into_findings` (63 行)
- [x] `report_haddix.py` から上記を削除し、import で参照する
- [x] 想定行数: coverage ファイル ~790 行
- [x] ⚠️ `build_heuristic_findings_from_execution_notes` 単体で 321 行。
       本タスクでは移動のみとし、内部分割が必要なら後続タスクとする。

### Step 3: Facade 薄化と import 整理
- [x] `report_haddix.py` に残るのは `run_haddix_report_generation` (~390 行) + import のみ
- [x] `report_haddix.py` の先頭で evidence / coverage モジュールから必要な関数を import
- [x] 外部から `from src.cli.handlers.report_haddix import run_haddix_report_generation` が維持されることを確認

### Step 4: 検証
- [x] `.venv/bin/python -m compileall src/cli/handlers`
- [x] `.venv/bin/pytest tests/unit/main/test_main_report_haddix.py -q`
- [x] `wc -l src/cli/handlers/report_haddix*.py` で行数確認:
  - `report_haddix.py` ≤ 500 行
  - `report_haddix_evidence.py` ≤ 400 行
  - `report_haddix_coverage.py` ≤ 850 行

### Step 5: ドキュメント更新
- [x] work_report 作成 (SGK-2026-0309)
- [x] 台帳ステータス更新: SGK-2026-0309 → done, SGK-2026-0305 → done
- [x] `validate_shigoku_docs.py` 実行

## 推奨検証コマンド
```bash
.venv/bin/python -m compileall src/cli/handlers
.venv/bin/pytest tests/unit/main/test_main_report_haddix.py -q
wc -l src/cli/handlers/report_haddix*.py
```

## 既知のリスクと申し送り
- [x] [重要度:中] `build_heuristic_findings_from_execution_notes` が 321 行と大きい。
       本タスクでは coverage モジュールへの移動のみとし、内部リファクタは別途検討。
- [x] [重要度:低] `run_haddix_report_generation` (390 行) 自体も将来的に
       report 生成フェーズごとの分割候補だが、現時点では orchestrator として残す。
