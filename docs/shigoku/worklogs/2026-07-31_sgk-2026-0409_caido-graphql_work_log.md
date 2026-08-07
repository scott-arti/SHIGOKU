---
task_id: SGK-2026-0409
doc_type: work_log
status: done
parent_task_id: SGK-2026-0408
related_docs:
- docs/shigoku/subtasks/done/2026-07-31_caido-graphql_subtask_plan.md
- docs/shigoku/reports/2026-07-31_sgk-2026-0409_caido-graphql_work_report.md
created_at: '2026-07-31'
updated_at: '2026-08-07'
---

# 作業ログ：Caido GraphQL 転送対応と事前チェック接続先表示修正

## 2026-07-31

- Docker 内で Caido URL と token が設定済みであることを確認した。
- Caido の `/graphql` が `/graphql/` へ HTTP 307 で転送することを確認した。
- Caido 事前チェックに明示的な転送追従を追加し、誤った固定ポート表示を修正した。
- 対象の回帰テスト 53 件を実行した。

次アクション: 新しい Caido token を設定して Docker 実行を再試行する。
