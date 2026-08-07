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

## Completion Contract and Final Audit

- 実装開始時点で承認された計画書の対象、完了条件、必須テスト、NOT in scopeを「完了契約」として固定する。
- 最終監査は、各指摘を `in_scope_blocker`、`deferred_followup`、`non_blocking_observation` のいずれかに分類する。
- `in_scope_blocker`にできるのは、完了契約の未達、必須テスト失敗、当該変更による回帰、現在有効な機能の安全境界違反だけとする。必ず違反する計画書項目と再現可能な証拠を併記する。
- scope逸脱、secret漏洩、未承認状態変更、回復不能なデータ損失、通常経路の利用不能、完了根拠の偽装・無効化は、計画外でも例外的blockerにできる。
- 将来段階のhardening、現在無効な機能の運用課題、計画外の設計改善は`deferred_followup`とし、追跡タスクの実装手順、必須テスト、完了条件へ組み込む。
- 監査中に新しい完了条件を暗黙追加しない。完了契約を変更する必要がある場合は、先にユーザーの明示承認を得て計画書を更新する。
- 完了契約がすべてPASSし、`in_scope_blocker`が0件なら、追跡可能な`deferred_followup`が残っていても元タスクを`done`にする。
- 同じ差分に対する最終監査後、新しいコード差分または新しい具体的証拠がない限り、新規blockerを追加しない。
