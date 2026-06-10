---
task_id: SGK-2026-0281
doc_type: work_report
status: done
parent_task_id: SGK-2026-0264
related_docs:
  - docs/shigoku/subtasks/2026-06-10_masterconductor-next-high-impact-split_subtask_plan.md
  - docs/shigoku/plans/2026-06-05_master-conductor-split-plan_plan.md
  - docs/shigoku/reports/2026-06-09_master-conductor-split_work_report.md
  - docs/shigoku/worklogs/2026-06-10_sgk-2026-0281_masterconductor-next-split_work_log.md
created_at: '2026-06-10'
updated_at: '2026-06-11'
---

# Work Report: SGK-2026-0281 MasterConductor scenario/global guard 抽出

## 実装内容

### 修正ファイル
- `src/core/engine/master_conductor.py`
  - 7406行 → **6603行 (-803行, -10.8%)**
  - scenario coverage 評価チェーン、global guard task 生成の実装本体を service へ移設
  - 全 11 method を thin wrapper 化。public/private method 名を維持

### 抽出 method 一覧

| method | 抽出先 | 削減行数 |
|---|---|---|
| `_create_missing_core_scenario_probe_tasks` | scenario_coverage_service | 242 |
| `_task_matches_scenario` | scenario_coverage_service | 26 |
| `_has_scenario_in_queue_or_history` | scenario_coverage_service | 31 |
| `_normalize_scenario_id_for_coverage` | scenario_coverage_service | 126 |
| `_resolve_intervention_scenario_catalog` | scenario_coverage_service | 57 |
| `_evaluate_intervention_scenario_coverage` | scenario_coverage_service | 93 |
| `_resolve_global_oob_guard_target` | global_guard_task_service | 53 |
| `_resolve_global_csrf_guard_target` | global_guard_task_service | 19 |
| `_ensure_global_csrf_guard_task` | global_guard_task_service | 63 |
| `_ensure_global_xss_guard_task` | global_guard_task_service | 61 |
| `_ensure_global_oob_guard_task` | global_guard_task_service | 42 |
| **dead code removal** | — | -10 |
| **合計** | | **803** |

### 新規ファイル
- `src/core/engine/master_conductor_scenario_coverage_service.py` (312行)
  - `task_matches_scenario`, `has_scenario_in_queue_or_history`, `normalize_scenario_id_for_coverage`
  - `resolve_intervention_scenario_catalog`, `evaluate_intervention_scenario_coverage`
  - `create_missing_core_scenario_probe_tasks`
- `src/core/engine/master_conductor_global_guard_task_service.py` (456行)
  - `resolve_global_oob_guard_target`, `resolve_global_csrf_guard_target`
  - `build_csrf_guard_payload`, `build_xss_guard_payload`, `build_oob_guard_payload`
  - `ensure_global_csrf_guard_decision`, `ensure_global_xss_guard_decision`, `ensure_global_oob_guard_decision`

## テスト結果

| テスト群 | 結果 |
|---|---|
| targeted (4 files) | 76/76 pass |
| related (5 files) | 26/26 pass |
| **合計** | **102/102 pass** |

## 未達領域と停止理由

計画書の目標削減は 1,000 行。実績は 803 行（達成率 80.3%）。
残り 197 行の内訳:

- `_get_intervention_decision` (30行): `InterventionPolicy.decide()` を呼び出し state mutation あり、深層依存
- `TaskState` enum 依存: coverage evaluator と密結合、service 分離にコスト大
- service ファイルのインフラ増分（定数・import）: 約 -40 行相殺

これらは `dispatch` / `execution loop` と同様に高リスク領域に隣接しており、
行数削減よりも回帰リスクが大きいため、**リスク制御により 803 行で停止**。

## 後続候補（deferred_tasks）

```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0281-D01
    title: "execution/replan ループ (1,270行) の service 化"
    reason: "最大削減効果だが、execute_with_replan / _dispatch / _execute_single_task_full_flow は並列実行、checkpoint、HITL precheck が絡む高リスク領域"
    impact: high
    tracking_task_id: SGK-2026-0264

  - deferred_id: SGK-2026-0281-D02
    title: "_get_intervention_decision と残存 coverage helper の抽出"
    reason: "803行で停止した残り197行。InterventionPolicy state 依存が深く単独抽出は非効率"
    impact: medium
    tracking_task_id: SGK-2026-0264

  - deferred_id: SGK-2026-0281-D03
    title: "active probe / degradation / HITL 抽出 (962行)"
    reason: "public 寄り method が多く wrapper 維持前提。policy evaluation と state mutation の分離が必要"
    impact: medium
    tracking_task_id: SGK-2026-0264
```
