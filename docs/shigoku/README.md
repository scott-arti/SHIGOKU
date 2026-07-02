---
task_id: SGK-2026-0001
doc_type: manual
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# SHIGOKU Documentation Hub

このディレクトリは SHIGOKU ドキュメントの正本です。新規作成・更新は原則ここで行います。

## Current Operator References
- ユーザーマニュアル現行版: [`manuals/2026-07-02_sgk-2026-0338_operator-user-manual.md`](manuals/2026-07-02_sgk-2026-0338_operator-user-manual.md)
- 内部仕様書現行版: [`specs/2026-07-02_sgk-2026-0338_internal-architecture-and-dataflow-spec.md`](specs/2026-07-02_sgk-2026-0338_internal-architecture-and-dataflow-spec.md)
- 詳細コマンドリファレンス: [`manuals/2026-07-02_sgk-2026-0337_detailed-command-reference.md`](manuals/2026-07-02_sgk-2026-0337_detailed-command-reference.md)

## Structure
- `specs/`: 全体仕様・機能仕様
- `roadmaps/`: 全体ロードマップ
- `plans/`: 機能計画書
- `subtasks/`: サブタスク計画書
- `reports/`: 実装作業報告書
- `worklogs/`: 横断作業ログ
- `manuals/`: マニュアル・運用手順
- `registry/`: タスクID台帳
  - `task_registry.yaml`: 機械可読台帳（正本）
  - `task_ledger.md` / `task_ledger.csv`: 人間向け一覧台帳

`archive/` と `misc/` は移行作業用としてのみ許容し、通常運用では新規格納しません。

## Mandatory Front Matter
```yaml
---
doc_type: spec|roadmap|plan|subtask_plan|work_report|work_log|manual
task_id: SGK-YYYY-NNNN
parent_task_id: null
title: ""
status_value: draft|active|done|deferred|archived
tags: [shigoku]
target: ""
created_at: YYYY-MM-DD
updated_at: YYYY-MM-DD
related_docs: []
---
```

## Deferred Task Recording (for AI re-extraction)
作業報告書には次の構造を残します。

```yaml
deferred_tasks:
  - deferred_id: SGK-YYYY-NNNN-D01
    title: ""
    reason: ""
    impact: low|medium|high
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: ""
```

## ID Rules
- Core Task: `SGK-YYYY-NNNN`
- Subtask: `SGK-YYYY-NNNN-SNN`
- Deferred: `SGK-YYYY-NNNN-DNN`

## Mandatory Flow (Implementation Tasks)
1. 台帳確認（`registry/task_registry.yaml` と `registry/task_ledger.md`）
2. 新タスクなら必ず新しい `SGK-YYYY-NNNN` を採番
3. `status` を更新（開始時 `active`、完了時 `done`）
4. 計画書 (`plan`/`subtask_plan`) → 報告書 (`work_report`) → ログ (`work_log`) の順で記録
5. 新規/更新後に `python3 scripts/sync_shigoku_updated_at.py` を実行して、変更した Markdown の `updated_at` を当日付に揃える
6. 仕上げに `python3 scripts/validate_shigoku_docs.py` で整合性チェック

## Done と継続監視の扱い
- 実装スコープが完了したタスクは `done` にしてよい。
- 継続監視・定期レビュー・長期観測は同一タスクに混在させず、別タスク（`plan` または `subtask_plan`）として起票し、`active` で追跡する。
- 親タスクの `work_report` に `deferred_tasks` を記載する場合、各項目は対応する追跡タスクID（例: `SGK-YYYY-NNNN`）と関連付ける。
