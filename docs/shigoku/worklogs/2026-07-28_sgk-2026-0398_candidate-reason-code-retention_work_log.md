---
task_id: SGK-2026-0398
doc_type: work_log
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/subtasks/done/2026-07-28_reason-code_subtask_plan.md
- docs/shigoku/reports/2026-07-28_sgk-2026-0398_candidate-reason-code-retention_work_report.md
created_at: '2026-07-28'
updated_at: '2026-07-28'
---

# SGK-2026-0398 作業ログ

## 2026-07-28

- 共通 `FindingDeduplicator` が、似た候補を統合すると強い候補以外の `additional_info` の reason code を失うことを、先行テストで再現した。
- 共通統合で全 reason code を canonical `reason_codes` へ統合し、evidence-quality の由来も保持した。
- レポート統合で未知のドメイン固有 reason code が正規化時に落ちることを確認し、明示的な reason-code 欄を保持するようにした。
- 対象テスト 90 件と、High report/session 整合性チェックを実行した。

次アクション: 次回のレポート生成で保持規則が反映される。保存済み session に元から無い reason code を新規に発生させる検出分類は別課題として扱う。
