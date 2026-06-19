---
task_id: SGK-2026-0288
doc_type: plan
status: done
parent_task_id: SGK-2026-0264
created_at: '2026-06-16'
updated_at: '2026-06-18'
related_docs:
  - docs/shigoku/plans/2026-06-05_master-conductor-split-plan_plan.md
  - docs/shigoku/subtasks/2026-06-13_masterconductor-execution-loop-deep-extraction_subtask_plan.md
  - docs/shigoku/reports/2026-06-16_sgk-2026-0287_phase1-2_work_report.md
tags:
  - shigoku
  - master-conductor
  - recon-pipeline
title: 'ReconPipeline adapter 設計: master_conductor=self 依存の解消'
---

# ReconPipeline adapter 設計: master_conductor=self 依存の解消

## 背景

`MasterConductor._dispatch` 内の ReconPipeline 初期化 (`L5118-L5132`) で `ReconPipeline(master_conductor=self)` を渡しており、
これが `_dispatch` の facade からの抽出をブロックしている。

SGK-2026-0286 (D01) および SGK-2026-0287 (D05) で見送られた recon branch 完全抽出の前提条件。

## 現状

```python
# master_conductor_facade.py L5118-L5132
pipeline = ReconPipeline(
    config=settings.model_dump() if hasattr(settings, "model_dump") else settings.dict(),
    workspace_root=self.project_manager.project_dir if self.project_manager else workspace_root,
    project_manager=self.project_manager,
    master_conductor=self  # ← この依存を解消したい
)
```

`ReconPipeline` が `master_conductor` に依存する操作:
- `mc._add_tasks(attack_tasks, source="recon_result")`
- `mc.phase_gate` へのアクセス
- `mc.context` の cookie/auth 情報
- `mc.llm_client` の利用

## 目標

1. `ReconPipeline` が `MasterConductor` instance を直接保持しないようにする
2. 必要な依存を `ReconExecutionDependencies` (既存) 経由で注入する
3. `_dispatch` 内の recon branch (~85 lines) を `dispatch_router` へ抽出可能にする

## アプローチ案

1. **ReconPipelineProtocol**: `MasterConductor` のうち ReconPipeline が必要とする interface を Protocol 化
2. **ReconPipelineAdapter**: `ReconPipeline` のラッパーで `master_conductor` の代わりに `ReconExecutionDependencies` を受け取る
3. **ReconPipeline 本体改修**: `ReconPipeline.__init__` の `master_conductor` パラメータを deprecated にし、代わりに `deps: ReconExecutionDependencies` を受け取る

推奨: アプローチ 1 + 3 (Protocol 化 + 本体改修)。adapter を挟まずに直接プロトコル化するのが最もシンプル。

## 完了条件

- [x] `ReconPipeline(master_conductor=self)` が不要になり、`ReconPipeline(deps=...)` で初期化できる
- [x] ReconPipeline / ParallelTasks 内の `self.mc._add_tasks` → `self._add_tasks_via_deps` に移行
- [x] ReconPipeline / ParallelTasks 内の `self.mc.context.target_info` → `self._get_target_info()` に移行
- [x] facade `_dispatch` recon branch が `deps=build_recon_dependencies_from_mc(self)` を使用
- [ ] `_dispatch` 内の recon branch が `dispatch_router` に抽出可能になる（前提整備完了、抽出は0287 D02へ）
- [ ] recon 関連の tests がすべて通過する（pre-existing 5 failures あり、本タスク起因の退行なし）
- [x] `master_conductor_facade.py` の recon branch から `master_conductor=self` 依存を除去

## 参照

- SGK-2026-0286 D01 (ReconPipeline adapter 見送り)
- SGK-2026-0287 D05 (tracking_task_id: null → 本タスクに紐付け)
- `src/core/engine/master_conductor_dependencies.py` `ReconExecutionDependencies`
