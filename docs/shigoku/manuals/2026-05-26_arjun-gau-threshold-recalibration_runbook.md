---
task_id: SGK-2026-0245
doc_type: manual
status: active
parent_task_id: SGK-2026-0239
related_docs:
  - docs/shigoku/plans/2026-05-26_arjun-gau-kpi_plan.md
created_at: '2026-05-26'
updated_at: '2026-05-26'
---

# Arjun/GAU 閾値再校正 Runbook

## 目的
- 初期閾値を実測データで再校正し、誤警報と見逃しを低減する。

## 実施条件
- 連続14日以上の本番相当データが存在すること。
- 欠損率（メトリクス未送信率）が 1% 未満であること。

## 対象KPI
- `arjun_failure_rate`
- `native_fallback_rate`
- `arjun_empty_success_rate`
- `confirmed_rate`
- `fp_rate`
- `reproducibility_rate`

## 再校正手順
1. 直近14日の日次分布（p50/p90/p95/p99）を抽出する。
2. 現行 Warning/Critical 閾値に対する発報件数を確認する。
3. 誤警報率が 20% 超なら Warning閾値を +0.02 調整候補にする。
4. 見逃し（重大障害未検知）が1件でもあれば Critical閾値を -0.02 調整候補にする。
5. `confirmed_rate/fp_rate/reproducibility_rate` への副作用を確認する。
6. 調整内容を承認し、計画書とゲート設定に反映する。

## 承認フロー
- Responsible: Platform On-call
- Accountable: Security Engineering Manager
- Consulted: AppSec Lead / SRE Lead
- Informed: CTO

## 記録テンプレート
- 実施日:
- 対象期間:
- 変更前閾値:
- 変更後閾値:
- 根拠（分布/発報件数/副作用評価）:
- 承認者:
- 次回レビュー予定日:

### work_report の deferred_tasks 記載例（未完了項目がある場合）
```yaml
deferred_tasks:
  - deferred_id: SGK-YYYY-NNNN-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
