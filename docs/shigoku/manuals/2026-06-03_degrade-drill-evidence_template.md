---
task_id: SGK-2026-0255
doc_type: manual
status: active
parent_task_id: SGK-2026-0251
related_docs:
  - docs/shigoku/subtasks/2026-06-02_sgk-2026-0255_degrade-runbook_subtask_plan.md
  - docs/shigoku/plans/2026-06-01_sgk-2026-0251_task_plan.md
created_at: '2026-06-03'
updated_at: '2026-07-02'
---

# Degrade Drill 証跡テンプレート

## 目的
- Step 7 の tabletop / drill 実施時に、復旧判断と submit block の証跡を同じ形式で残す。
- `AuditLogger` / `DecisionTracer` / Runbook / `work_report` の記録粒度をそろえる。

## 使い方
1. drill 実施前に「シナリオ定義」を埋める。
2. drill 中に「実行ログ要約」と「判定結果」を追記する。
3. drill 終了後に「差分レビュー」と「次アクション」を記録する。
4. 結果は `work_report` へ転記するか、Runbook の付録として保存する。

## 最低限残すべき証跡
- `scenario_id`
- `triggered_component`
- `expected_state`
- `observed_state`
- `submit_blocked`
- `replay_verdict`
- `followup_action`

## シナリオ定義テンプレート
```yaml
scenario_id: DRILL-YYYYMMDD-01
scenario_title: "<例: report_adapter degraded with dependency failure>"
triggered_component: "<program_memory|audit_logger|report_adapter|unknown_component>"
failure_mode: "<dependency_failure|waf_repeat|scope_violation|ttl_expired|manual_rollback>"
signal_source: "<alert name / audit event / tracer event>"
evaluation_window: "<例: 5m>"
expected_state: "<continue|defer|blocked>"
expected_fallback: "<in_memory_only|buffered_events|canonical_payload_only|best_effort>"
submit_blocked: true
replay_required: true
preconditions:
  - "<例: canonical_report_payload が生成済み>"
  - "<例: dependency failure を模擬できる>"
```

## 実行ログ要約テンプレート
```yaml
started_at: "2026-06-03T10:00:00+09:00"
ended_at: "2026-06-03T10:12:00+09:00"
operator: "<name or role>"
runbook_ref: "docs/shigoku/manuals/<runbook-file>.md"
correlation_id: "<uuid or trace id>"
policy_version: "<git sha / rule version>"
component_before: "<healthy|degraded|error>"
component_after: "<healthy|degraded|error>"
selected_fallback: "<fallback name>"
decision_reason: "<why continue/defer/blocked was selected>"
recovery_reason: "<why recovery or rollback was allowed>"
recovery_outcome: "<recovered|rolled_back|deferred>"
observed_state: "<continue|defer|blocked>"
observed_submit_behavior: "<blocked|not_applicable|unexpected_submit>"
replay_verdict: "<required|completed|not_required|failed>"
```

## 判定結果テンプレート
| 項目 | 期待値 | 実測 | 判定 | メモ |
| --- | --- | --- | --- | --- |
| state transition | `expected_state` |  | PASS / FAIL |  |
| fallback | `expected_fallback` |  | PASS / FAIL |  |
| submit blocked | `true` |  | PASS / FAIL |  |
| replay verdict | `required` or `completed` |  | PASS / FAIL |  |
| audit trace completeness | required fields present |  | PASS / FAIL |  |

## 差分レビュー
- `expected_state` と `observed_state` の差分:
- submit が block されなかった場合の原因:
- replay が失敗または不要になった理由:
- Runbook / code / test のどこに差分があったか:

## 次アクション
```yaml
followup_action:
  - type: "<doc_fix|test_fix|code_fix|monitoring_followup>"
    description: "<next action>"
    owner_role: "<role only>"
    due_hint: "<optional date or next review>"
deferred_tasks:
  - deferred_id: SGK-2026-0255-D01
    title: "継続監視: [監視対象]"
    reason: "drill で差分が見つかり継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```

## `work_report` 転記用の最小サマリ
```md
### Drill Evidence Summary
- scenario_id: DRILL-YYYYMMDD-01
- triggered_component: report_adapter
- expected_state / observed_state: defer / defer
- submit_blocked: true
- replay_verdict: required
- followup_action: Runbook に replay 手順の補足を追加
```
