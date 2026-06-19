---
task_id: SGK-2026-0245
doc_type: manual
doc_usage: reference_manual
status: active
parent_task_id: SGK-2026-0239
related_docs:
  - docs/shigoku/plans/2026-05-26_arjun-gau-kpi_plan.md
created_at: '2026-05-26'
updated_at: '2026-05-26'
---

# Arjun/GAU 障害演習 Runbook

## 目的
- 障害時の検知・一次対応・復旧判定が実運用で成立することを証明する。

## 必須演習シナリオ
1. `timeout急増`
2. `provider_error連発`
3. `監視基盤停止（heartbeat欠損）`

## 共通実施手順
1. 演習開始時刻と担当者を記録する。
2. 監視画面で異常が閾値を超えることを確認する。
3. 一次対応（隔離/切替/通知）を実施する。
4. 復旧条件を満たしたことを確認する。
5. 事後レビューで改善点を記録する。

## 復旧判定
- 監視基盤停止時:
  - 再送成功率 `>= 99%`
  - 未送信残量 `<= 100 events`
- Arjun系異常時:
  - `arjun_failure_rate <= 0.08`（5分窓）
  - `native_fallback_rate <= 0.20`（5分窓）

## 証跡テンプレート
- シナリオ名:
- 実施日:
- 参加者:
- 検知時刻:
- 一次対応内容:
- 復旧判定時刻:
- 復旧判定値:
- 影響範囲:
- 改善アクション:
- 承認者:

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
