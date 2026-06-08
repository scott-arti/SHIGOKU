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

Do not create new operational documents under archive/ or misc/ unless the task is migration or cleanup.

Front matter

Task-related Markdown documents must include:

task_id:
doc_type:
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

Deferred tasks

If a work report leaves unfinished items, record them in a structured deferred_tasks block.
Each deferred task must reference an existing tracking task ID (`SGK-YYYY-NNNN`) in the task registry.

Done with ongoing monitoring

- Mark the implementation task `done` when its committed scope is complete.
- Track ongoing monitoring/review as a separate `plan` or `subtask_plan` task with `status: active`.
- Link parent/child documents via `related_docs` and keep traceability from `deferred_tasks`.
