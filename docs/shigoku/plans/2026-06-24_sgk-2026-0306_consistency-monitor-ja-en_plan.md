---
task_id: SGK-2026-0306
doc_type: plan
status: active
parent_task_id: SGK-2026-0301
related_docs:
  - docs/shigoku/reports/2026-06-24_haddix-ja-en-paired-report_work_report.md
  - docs/shigoku/subtasks/2026-06-24_sgk-2026-0301_haddix-ja-en-paired-report_subtask_plan.md
created_at: '2026-06-24'
updated_at: '2026-06-30'
---

# 継続監視: haddix-ja-en consistency checker 互換性

SGK-2026-0301 の deferred task D02。実運用データでの ja-en レポート consistency checker 通過を継続確認する。

## スコープ
- 実 session_*.json から haddix-ja-en レポートを生成
- `verify_report_session_consistency.py` による整合性チェックを定期実行
- ja-en 出力の scenario_coverage / session 解決が正しく機能することを確認
