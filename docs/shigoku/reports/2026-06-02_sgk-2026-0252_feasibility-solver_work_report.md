---
task_id: SGK-2026-0252
doc_type: work_report
status: done
parent_task_id: SGK-2026-0251
related_docs:
- docs/shigoku/subtasks/2026-06-02_sgk-2026-0252_feasibility-solver_subtask_plan.md
- docs/shigoku/plans/2026-06-01_sgk-2026-0251_task_plan.md
- docs/shigoku/worklogs/2026-06-02_sgk-2026-0252_feasibility-solver_work_log.md
title: SGK-2026-0252 feasibility solver 実装完了報告
created_at: '2026-06-02'
updated_at: '2026-07-02'
---

# SGK-2026-0252 feasibility solver 実装完了報告

## 実装内容
- `src/core/intelligence/chain_builder.py` に shared feasibility evaluator を追加し、heuristic 候補・AI 候補の両方へ同一の制約判定を適用した。
- feasibility trace と canonical material、constraint schema version、decision trace version、structured `failed_constraints` を実装した。
- `analyze_with_budget()` に fallback reason と solver metrics を追加し、予算超過時のフォールバックを可視化した。
- `promotion:*` namespace を追加し、promotion 失敗理由と feasibility 失敗理由を分離した。
- `src/core/intelligence/phase2_benchmark.py` に feasibility solver benchmark profile を追加し、通常ケース・予算超過ケース・infeasible corpus を固定入力で評価できるようにした。
- `src/core/engine/master_conductor.py` に shadow feasibility diff 集計を追加し、shadow verdict と公開 state の差分をレポートできるようにした。
- `tests/scripts/verify_chaining_flow.py` の固定 sleep を condition-based wait へ置換し、主検証を補助する E2E スクリプトの不安定性を下げた。

## 主な変更ファイル
- `src/core/intelligence/chain_builder.py`
- `src/core/intelligence/phase2_benchmark.py`
- `src/core/engine/master_conductor.py`
- `tests/scripts/verify_chaining_flow.py`
- `tests/core/intelligence/test_feasibility_solver_tdd.py`
- `tests/core/intelligence/test_chain_builder.py`
- `tests/core/intelligence/test_phase2_benchmark.py`
- `tests/core/engine/test_master_conductor_phase25_shadow.py`
- `docs/shigoku/subtasks/2026-06-02_sgk-2026-0252_feasibility-solver_subtask_plan.md`

## 判断理由
- feasibility 判定は rule 候補と AI 候補で別実装にすると差分事故が起きやすいため、`evaluate_feasibility()` に集約した。
- unknown / 欠損 / unsupported constraint は silent pass せず、trace と state に反映することで診断可能性を優先した。
- shadow mode は公開 state を変えずに差分だけ観測し、enforcement 前に explainable diff を確認できる形を優先した。

## 検証
- `.venv/bin/pytest tests/core/intelligence/test_feasibility_solver_tdd.py`
  - 結果: `13 passed`
- `.venv/bin/pytest tests/core/intelligence/test_chain_builder.py tests/core/intelligence/test_feasibility_solver_tdd.py tests/core/intelligence/test_phase2_benchmark.py tests/core/engine/test_master_conductor_phase25_shadow.py`
  - 結果: `27 passed`
- `.venv/bin/pytest tests/core/intelligence/test_chain_builder.py tests/core/intelligence/test_chain_proposal.py tests/core/intelligence/test_phase0_risk_clearance_checklist.py tests/core/intelligence/test_phase1_risk_clearance_checklist.py tests/core/intelligence/test_phase2_benchmark.py tests/core/intelligence/test_phase2_risk_clearance_checklist.py tests/core/intelligence/test_phase3_benchmark.py tests/core/engine/test_master_conductor_phase25_shadow.py tests/core/engine/test_mc_intelligence_integration.py`
  - 結果: `78 passed`
- `.venv/bin/python tests/scripts/verify_chaining_flow.py`
  - 結果: exit code `0`

## リスク
- 現在の constraint 実装は `auth` / `same_origin` / `primitive` / `asset_scope` / `token_lifetime` / `session_generation` の最小スキーマ中心で、より高度な temporal relation の追加は今後の拡張余地がある。
- feasibility solver の budget 制御は lightweight 実装であり、大規模 graph 探索アルゴリズムの最適化は別タスクで深掘り余地がある。

## deferred_tasks
```yaml
deferred_tasks: []
```
