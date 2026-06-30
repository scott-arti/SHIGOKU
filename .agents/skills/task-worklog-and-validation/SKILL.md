---
name: task-worklog-and-validation
description: Use when older instructions or cached references mention this legacy closeout alias for task completion work.
---

# Task Worklog and Validation

このスキルは [`task-work-reporting`](../task-work-reporting/SKILL.md) に統合済み。

## Current Rule
1. `task-work-reporting` を正本として使う。
2. `work_report` 作成、`work_log` 作成、台帳反映、`sync_shigoku_updated_at.py`、`validate_shigoku_docs.py` はすべて `task-work-reporting` の手順に従う。
3. このファイルには重複手順を再定義しない。
