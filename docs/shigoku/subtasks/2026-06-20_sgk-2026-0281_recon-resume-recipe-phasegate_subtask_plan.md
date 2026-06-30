---
task_id: SGK-2026-0281
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0278
related_docs:
- docs/shigoku/plans/2026-06-20_sgk-2026-0278_ver-2-planning-bundle-dev-mode-recon_plan.md
- docs/shigoku/roadmaps/future_functions1.md
title: 'Recon運用再設計: Resume・再利用・Recipe/PhaseGate連携計画'
created_at: '2026-06-20'
updated_at: '2026-06-30'
tags:
- shigoku
target: src/recon/, src/core/engine/recipe_loader.py, src/core/engine/phase_gate.py,
  src/core/engine/master_conductor.py
---

# 実装計画書：Recon運用再設計: Resume・再利用・Recipe/PhaseGate連携計画

## 1. 達成したいゴール（ユーザー視点）
- 長い Recon が中断しても、途中成果を活かして再開できる。
- 既知ターゲットでは過去 Recon 成果物を再利用し、無駄な再走査を減らせる。
- Recon 結果が `RecipeLoader` と `PhaseGate` に賢く渡り、Attack 開始が「全部解放」ではなく「必要なものから解放」になる。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/recon/`: Step 単位 resume / artifact reuse の中心
  - `src/core/engine/master_conductor.py`: Recon 完了後の task 生成と gate 制御
  - `src/core/engine/recipe_loader.py`: context から recipe を選ぶ
  - `src/core/engine/phase_gate.py`: Phase unlock と phase data 蓄積
- **データの流れ / 依存関係:**
  - Recon state / prior artifacts -> ReconPipeline -> normalized results
  - normalized results -> `PhaseGate` / `_create_attack_tasks_from_recon()`
  - target_info / tech_stack / signals -> `RecipeLoader.match_recipes_to_context()`

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - Recon step range, intermediate state, prior project artifacts, tech stack, classified results
- **出力/結果 (Output):**
  - Step 単位 resume 可能な Recon 実行
  - `--import-recon` 相当の artifact reuse
  - score-based recipe selection
  - 粒度の細かい `PhaseGate` 制御案
- **制約・ルール:**
  - `タグベース動的Agent選択` は次期バージョン送りとし、本計画では扱わない
  - `RecipeLoader` は全面作り直しではなく、現行接続を生かした選抜改善を優先する
  - `PhaseGate` は MC 代替ではなく、MC の判断材料を細かくする部品として扱う

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: Recon step state と prior artifact の棚卸しを行い、`resume` と `import-recon` の責務境界を定義する
- [ ] ステップ2: `RecipeLoader.match_recipes_to_context()` を全件返しから score-based 選抜へ変える設計を作る
- [ ] ステップ3: `PhaseGate` の unlock 条件を finding / auth_required / scope / budget で細粒度化する設計をまとめる

## 4.1 フェーズ分割
- Phase A: Recon step 単位 resume
- Phase B: 過去 Recon 成果物の再利用
- Phase C: Recipe 選抜改善
- Phase D: PhaseGate 細粒度化

## 4.2 いま不足していること
- `--resume` は MC session 復元中心で、ReconPipeline の step resume ではない
- `RecipeLoader.match_recipes_to_context()` は loaded recipe 全件を返す
- `PhaseGate` は Recon 成果があれば Attack をほぼ一括解放する

## 4.3 細粒度 PhaseGate の価値
- scope 逸脱や予算超過で Attack 全体を止めやすくなる
- auth 必須 endpoint と public endpoint を同じ熱量で解放しなくてよくなる
- critical finding 発生後に Report/HITL 優先へ寄せる判断を実装しやすくなる

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] artifact reuse を急ぐと古い成果物の混入で誤判定しやすい - freshness 判定と provenance を先に設計する
- [ ] [重要度:中] recipe score を粗く入れると全件返しと大差ない - required/optional signal と top-N 制限を必須にする

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0281-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
