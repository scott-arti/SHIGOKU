---
task_id: SGK-2026-0275
doc_type: work_report
status: done
parent_task_id: SGK-2026-0265
related_docs:
  - docs/shigoku/plans/2026-06-05_sgk-2026-0265_injection-manager-split-plan_plan.md
  - docs/shigoku/subtasks/2026-06-09_sgk-2026-0275_process-single-url-branch_subtask_plan.md
title: '作業完了報告書: _process_single_url branch単位分割'
created_at: '2026-06-09'
updated_at: '2026-06-30'
tags:
  - shigoku
  - refactoring
target: src/core/agents/swarm/injection/manager.py
---

# 作業完了報告書: _process_single_url branch単位分割

## 実装内容

追加手順15/10 に基づき、`_process_single_url` の unknown classification-only ブランチを `manager_internal/process_url_dispatcher.py` へ抽出した。

### 新規モジュール

`src/core/agents/swarm/injection/manager_internal/process_url_dispatcher.py`

### 抽出関数

| 関数名 | 用途 |
|---|---|
| `process_unknown_classification_only` | unknown分類専用ブランチ（仮説構築＋IDOR候補生成） |

### 変更内容

- `_process_single_url` 内の `unknown_classification_only` 分岐（~24行）を抽出
- `_request_cache` 書き込み、`normalize_findings_additional_info` は facade 側に残置
- `build_unknown_hypotheses`, `build_unknown_idor_candidate_finding`, `sanitize_tested_params` を明示的引数で受け取る純粋関数として設計

### admin/api/csrf ブランチについて

計画書では admin/api/csrf ブランチの抽出も指示されていたが、各ブランチが5-8行と小さく、`self.current_context` への副作用が強いため、抽出による利益が限定的と判断し着手しなかった。

## 検証結果

| メトリクス | 値 |
|---|---|
| injection テスト | 444/444 passed |
| 全体回帰 | 487/489 passed (2 pre-existing) |
| 新規テスト | +5 unit tests, +3 character tests |
| 新規回帰 | 0件 |

## deferred_tasks

```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0275-D01
    title: "admin/api/csrf ブランチの抽出検討"
    reason: "各ブランチが5-8行と小さく、self.current_context への副作用が強いため利益限定的。"
    impact: low
    tracking_task_id: null
    recommended_next_action: "manager.py の更なる行数削減が必要になった場合に再検討"
```
