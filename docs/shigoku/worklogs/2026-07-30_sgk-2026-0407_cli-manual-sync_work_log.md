---
task_id: SGK-2026-0407
doc_type: work_log
status: active
parent_task_id: SGK-2026-0001
related_docs:
- docs/shigoku/plans/2026-07-30_cli_plan.md
- docs/shigoku/reports/2026-07-30_sgk-2026-0407_cli-manual-sync_work_report.md
created_at: '2026-07-30'
updated_at: '2026-08-07'
---

# 作業ログ：CLIマニュアルと実装の同期

## 2026-07-30

- `src/main.py` と `scripts/shigoku_ops_cli.py` の引数定義、実際の `--help` 出力、既存マニュアルを照合した。
- 現行 CLI にないオプションを利用者向けの説明から除去し、未記載の運用コマンドを詳細一覧へ追加した。
- マニュアル起点のリンク切れを修正し、リンク検証を0件まで解消した。
- 計画書を完了済みディレクトリへ移動し、台帳を `done` に更新した。

次アクション: 台帳の過去参照切れ2件を解消後に文書検証を再実行し、その後CLIを変更するタスクで、同じ詳細リファレンスとの同期確認を行う。
