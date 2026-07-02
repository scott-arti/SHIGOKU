---
task_id: SGK-2026-0274
doc_type: work_report
status: done
parent_task_id: SGK-2026-0265
related_docs:
  - docs/shigoku/plans/2026-06-05_sgk-2026-0265_injection-manager-split-plan_plan.md
  - docs/shigoku/subtasks/2026-06-09_sgk-2026-0274_tool-runner-manager-internal_subtask_plan.md
title: '作業完了報告書: tool runner 結果整形の manager_internal 抽出'
created_at: '2026-06-09'
updated_at: '2026-07-02'
tags:
  - shigoku
  - refactoring
target: src/core/agents/swarm/injection/manager.py
---

# 作業完了報告書: tool runner 結果整形の抽出

## 実装内容

追加手順14/10 に基づき、`run_lfi_check`、`run_open_redirect_check`、`run_cors_hunter` の結果整形ロジックを `manager_internal/tool_runners.py` へ抽出した。

### 抽出関数

| 関数名 | 用途 | 適用先 |
|---|---|---|
| `format_simple_hunter_result` | 汎用 hunter 結果整形 | `run_lfi_check`, `run_open_redirect_check` |
| `format_cors_hunter_result` | CORS 特化結果整形 | `run_cors_hunter` |
| `_extract_tested_params_from_finding` | finding から tested_params 抽出 | 内部ヘルパー |
| `_extract_payloads_used_from_finding` | finding から payloads_used 抽出 | 内部ヘルパー |
| `_fallback_tested_params_from_url` | URL からの fallback params | 内部ヘルパー |

### 変更内容

- `manager.py` 内の3メソッドの結果整形ブロック（if/else + return dict）を抽出関数呼び出しに置換
- public method シグネチャは `manager.py` に facade として維持
- specialist 実行、`current_context["findings"]` への追加は facade 側に残置

## 検証結果

| メトリクス | 値 |
|---|---|
| injection テスト | 444/444 passed |
| 全体回帰 | 479/481 passed (2 pre-existing) |
| 新規回帰 | 0件 |

## deferred_tasks

```yaml
deferred_tasks: []
```
