# SHIGOKU Documentation Rules

Use this file for SHIGOKU-related documentation changes.

## Canonical location

The canonical location for SHIGOKU documentation is:

```text
docs/shigoku/
```

Create new documentation under this tree unless the task explicitly requires another location.

Directory usage

Use the appropriate directory:

specs/
roadmaps/
plans/
subtasks/
reports/
worklogs/
manuals/
registry/

- Active `plan` documents live in `docs/shigoku/plans/`.
- Done `plan` documents live in `docs/shigoku/plans/done/`.
- Active `subtask_plan` documents live in `docs/shigoku/subtasks/`.
- Done `subtask_plan` documents live in `docs/shigoku/subtasks/done/`.
- Plan and subtask filenames should follow `YYYY-MM-DD_<task_id lowercase>_<slug>.md`.
- Express status through directory placement, not by adding `active` or `done` to filenames.

Do not create new operational documents under archive/ or misc/ unless the task is migration or cleanup.

Front matter

`scripts/validate_shigoku_docs.py` は `docs/shigoku/` 配下の全 Markdown を検査する。
plan / subtask / report だけでなく、manual や一時的な learnings ドキュメントも含め、次の Front Matter を必須とする:

task_id:
doc_type:
status:
parent_task_id:
related_docs:
created_at:
updated_at:

Allowed doc_type values:

spec
roadmap
plan
subtask_plan
work_report
work_log
manual

Use YYYY-MM-DD for dates.

- 親タスクがない standalone doc は `parent_task_id: null` を明示する。
- 関連文書がない場合でも `related_docs: []` を明示する。

Deferred tasks

If a work report leaves unfinished items, record them in a structured deferred_tasks block.
Each deferred task must reference an existing tracking task ID (`SGK-YYYY-NNNN` or `SGK-YYYY-NNNN-SNN`) in the task registry.
Never use placeholder values such as `TBD`.

Done with ongoing monitoring

- Mark the implementation task `done` when its committed scope is complete.
- Track ongoing monitoring/review as a separate `plan` or `subtask_plan` task with `status: active`.
- Link parent/child documents via `related_docs` and keep traceability from `deferred_tasks`.
- When moving a `plan` or `subtask_plan` into `done/`, update the moved file, `task_registry.yaml`, `task_ledger.*`, and every `related_docs` / body link that still points at the old path.
