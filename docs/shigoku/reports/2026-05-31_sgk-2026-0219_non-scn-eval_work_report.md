---
task_id: SGK-2026-0219
doc_type: work_report
status: done
parent_task_id: null
related_docs:
- docs/shigoku/plans/2026-05-19_non-scn-vulnerability-discovery-evaluation-plan-juice-shop-dvwa-crapi_plan.md
- docs/shigoku/subtasks/2026-05-31_sgk-2026-0219-non-scn_subtask_plan.md
- docs/shigoku/specs/2026-05-31_sgk-2026-0219_non-scn-evaluation-spec.md
- docs/shigoku/worklogs/sgk-2026-0219_baseline_manifest_20260531_0121.md
- docs/shigoku/worklogs/2026-05-31_sgk-2026-0219_non-scn-eval_work_log.md
created_at: '2026-05-31'
updated_at: '2026-05-31'
---

# Work Report: SGK-2026-0219 Step1-7

## Summary
- Step1-7 を baseline 6 sessions で実行。
- 実測で再現性判定（許容差: max(2件,10%)）は3target全て pass。

## KPI Results
| target | run1 unique | run2 unique | diff | reproducibility |
|---|---:|---:|---:|---|
| Juice Shop | 9 | 9 | 0 | pass |
| DVWA | 0 | 0 | 0 | pass |
| CRAPI | 5 | 5 | 0 | pass |

Global aggregates:
- total findings: 40
- unique findings: 17
- severity distribution: medium 40 / 40
- evidence quality rate: 100%

## Follow-up Execution (Requested 3 Tasks)

### Task 1: 追加run実行（3run化）
- Juice Shop run3: `session_20260518_134951.json`
- DVWA run3: `session_20260518_085428.json`
- CRAPI run3: `session_20260517_050945.json`

### Task 2: KPI-4 層化監査（target x severity）
- Juice Shop: audited=5, fp_rate=0.0%
- DVWA: audited=0（finding 0件のため監査対象なし）
- CRAPI: audited=5, fp_rate=0.0%

### Task 3: KPI-5 3-run MA
- Juice Shop: 44.23%
- DVWA: 0.00%
- CRAPI: 33.33%
- 判定閾値: `>=5%`

## Step7 Decision
- SCN layer: reference baseline gate pass (existing records)
- Non-SCN layer:
  - evidence quality >= 90%: pass
  - reproducibility: pass
  - false positive: 未監査（KPI-4 sampling audit pending）
  - new discovery rate: baseline onlyのため暫定

再判定: `Conditional`（出荷不可、継続）
- reason1: DVWA の KPI-5 が 0.00% で閾値未達
- reason2: DVWA は finding 0件のため KPI-4 監査サンプルが不足（追加runでの観測継続が必要）

## Risks
- DVWA findings 0 のため、検出ゼロが環境起因か仕様起因かの切り分けが追加で必要。
- KPI-4/KPI-5確定には追加runと監査が必要。

## Next Action
1. DVWA の追加runを最低2回実施し、監査サンプル0件状態の解消を試行
2. DVWA で finding 発生時に KPI-4 層化監査を再実施
3. KPI-5 再計算後に Step7 を最終判定（Go/Hold/No-Go）

## deferred_tasks
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0219-D01
    title: "DVWA 継続監視（KPI-4/KPI-5 再評価）"
    reason: "親計画の実装スコープは完了したが、Conditional 判定解消には追加観測が必要"
    impact: medium
    tracking_task_id: SGK-2026-0249
    recommended_next_action: "SGK-2026-0249 で DVWA 追加runと層化監査を実施し、再判定を更新する"
```
