---
task_id: SGK-2026-0364
doc_type: plan
status: done
parent_task_id: null
related_docs:
- docs/shigoku/reports/2026-07-15_sgk-2026-0364_work_report.md
- docs/shigoku/worklogs/2026-07-15_sgk-2026-0364_work_log.md
- docs/shigoku/plans/done/2026-07-14_sgk-2026-0359_dvwa-low-session-report-bundle-fix_plan.md
- docs/shigoku/plans/done/2026-07-14_sgk-2026-0360_scn06-meta-observability-coverage-task-promotion-fix_plan.md
title: Derived Task Admission Policy Cleanup and Coverage-Critical Consolidation
created_at: '2026-07-15'
updated_at: '2026-07-21'
tags:
- shigoku
target: src/core/engine/master_conductor.py, src/core/engine/task_queue.py, src/core/engine/strategy_optimizer.py, src/core/engine/task_pruning_policy.py
---

# 実装計画書：Derived Task Admission Policy Cleanup and Coverage-Critical Consolidation

## 1. 達成したいゴール（ユーザー視点）
- [x] `recon_result` 由来の正当な attack fan-out が、loop 防止用の derived task cap で不自然に落ちないこと。
- [x] `SCN06` などの coverage-critical task を、derived cap の個別 exempt で救済する構造を解消すること。
- [x] coverage-critical 判定を queue / pruning / prioritization で共有し、重複定義を減らすこと。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: derived task cap の source-aware 化、recon enqueue ログの正規化、coverage-critical priority 判定の共通化。
  - `src/core/engine/task_queue.py`: asset pruning 保護判定の共通化。
  - `src/core/engine/strategy_optimizer.py`: low-value pruning 保護判定の共通化。
  - `src/core/engine/task_pruning_policy.py`: pruning protection 判定の共通化。
  - `src/core/engine/task_criticality.py`: coverage-critical task / derived-cap source の共有判定。
  - `tests/core/engine/*`: derived cap / pruning / coverage priority の回帰テスト更新。
- **データの流れ / 依存関係:**
  - Recon result -> `_create_attack_tasks_from_recon()` -> `TaskExpander` -> `_add_tasks(source="recon_result")` -> queue / optimizer / pruning policy。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `max_derived_tasks_per_session` 到達済み状態、`recon_result` 由来タスク、coverage-critical task params。
- **出力/結果 (Output):** loop-prone source だけに derived cap が効き、recon fan-out と coverage-critical 判定は共有ロジックで扱われる。
- **制約・ルール:**
  - `react` / `replan` などの暴走防止は維持する。
  - SCN06専用の blanket exempt を増やさず、source-aware admission に寄せる。
  - 既存の unrelated local changes は戻さない。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: derived cap と coverage-critical 判定の重複箇所を整理し、共通化方針を確定する。
- [x] ステップ2: source-aware derived cap と shared helper を実装する。
- [x] ステップ3: queue / optimizer / pruning policy / master conductor の重複条件を shared helper に寄せる。
- [x] ステップ4: targeted tests を更新・追加し、既存の SCN06 rescue regression を新方針へ置き換える。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:中] unified settings 側の `max_derived_tasks_per_session=100` と legacy settings 側 `20` の不一致は今回の committed scope に含めていない。必要なら別タスクで統一する。
- [ ] [重要度:低] derived task source policy の粒度（`dynamic_recipe` や `pending_fuzz` をどこまで uncapped にするか）は、実run telemetry で見直す余地がある。
