## 16) Mandatory Task Ledger Workflow (Enforced)
- 実装/機能追加時は、必ず次の順序で実施する:
  1. 台帳確認 (`docs/shigoku/registry/task_registry.yaml`, `task_ledger.md`)
  2. 新タスクなら新しい `SGK-YYYY-NNNN` を採番し台帳へ追加（既存ID再利用禁止）
  3. `status` を記入（開始時 `active`、完了時 `done` など）
  4. タスク計画書 (`plan` or `subtask_plan`) を作成/更新
  5. 作業完了報告書 (`work_report`) を作成/更新
  6. 作業ログ (`work_log`) を作成/更新
- 実装スコープが完了している場合、継続監視項目が残っていても親タスクは `done` 化してよい。
- 継続監視は別タスク（`plan` / `subtask_plan`）として起票し、`active` で追跡する。
- `work_report` の `deferred_tasks` に記載した残課題は、対応する追跡タスクID（`SGK-YYYY-NNNN`）を必須で紐付ける。
- 主要ドキュメントは `parent_task_id` と `related_docs` を必須で設定する。
- 変更後は必ず `python3 scripts/validate_shigoku_docs.py` を実行し、0エラーであることを確認する。
- 変更後は必ず `python3 scripts/sync_shigoku_updated_at.py` を先に実行し、変更した Markdown の `updated_at` を当日付に揃えてから `python3 scripts/validate_shigoku_docs.py` を実行する。
