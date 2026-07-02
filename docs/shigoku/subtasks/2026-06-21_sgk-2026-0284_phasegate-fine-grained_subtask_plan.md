---
task_id: SGK-2026-0284
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0278
related_docs:
- docs/shigoku/plans/2026-06-20_sgk-2026-0278_ver-2-planning-bundle-dev-mode-recon_plan.md
- docs/shigoku/subtasks/2026-06-20_sgk-2026-0281_recon-resume-recipe-phasegate_subtask_plan.md
- docs/shigoku/roadmaps/future_functions1.md
title: PhaseGate細粒度化計画
created_at: '2026-06-21'
updated_at: '2026-07-02'
tags:
- shigoku
target: src/core/engine/phase_gate.py, src/core/engine/master_conductor.py, src/core/security/ethics_guard.py
---

# 実装計画書：PhaseGate細粒度化計画

## 1. 達成したいゴール（ユーザー視点）
- Recon が終わった瞬間に Attack をまとめて開放するのではなく、得られた情報に応じて必要なタスクだけ順に開放できる。
- Scope 逸脱、budget 超過、critical finding 発生などの条件で、MC が攻撃を一時停止したり report 側へ寄せたりできる。
- MC中心設計を維持しつつ、PhaseGate を「判断を細かくする部品」として使える。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/phase_gate.py`: 現在は `INIT / RECON / ATTACK / REPORT` の unlock 判定と phase data 保持のみ
  - `src/core/engine/master_conductor.py`: Recon 結果を `PhaseGate` に追加し、条件が満たされると `ATTACK` を unlock
  - `src/core/security/ethics_guard.py`: scope / rate limit 由来の停止理由を gate 条件へ渡す候補
  - `src/core/engine/recipe_loader.py`: 将来的に recipe 選抜と gate 解放条件を接続する対象
- **データの流れ / 依存関係:**
  - Recon 結果 (`assets`, `tech_stack`, `classified_files`) -> `PhaseGate`
  - `PhaseGate verdict` + scope / budget / auth情報 -> `MasterConductor` の task create / defer / skip
  - critical finding / operator override -> `PhaseGate` state transition -> report / HITL / attack queue

## 3. 具体的な仕様と制約条件
- **現状整理:**
  - `PhaseGate.can_create_task()` は実質 `phase が unlocked か` しか見ていない。
  - `MasterConductor` は Recon 成果が1つでもあれば `Phase.ATTACK` を unlock し、攻撃タスクを生成し得る。
  - 現在の gate は大まかな開始可否で、task 単位の policy までは見ていない。
- **入力情報 (Input):**
  - phase state
  - recon の分類結果 / tech / assets
  - task attributes (`requires_auth`, `attack_class`, `host`, `risk`)
  - runtime signals (`scope_violation`, `budget`, `critical finding`, `HITL pending`)
- **出力/結果 (Output):**
  - `allow`, `defer`, `lock_phase`, `unlock_subset`, `route_to_report`
  - gate reason と trace
  - attack queue への投入可否
- **制約・ルール:**
  - MC中心設計を維持し、Swarm 間で勝手に unlock / lock を決めない
  - `PhaseGate` は司令塔の代替ではなく、司令塔の判断材料と停止機構
  - phase を増やしすぎず、まずは `ATTACK` 内サブレベルまたは capability gate で表現する
  - scope / budget / HITL の signal は gate reason として保存可能にする

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: 現行 `PhaseGate` の unlock 条件と `MasterConductor._create_attack_tasks_from_recon()` の依存関係を棚卸しする
- [ ] ステップ2: `Attack 全開放` をやめ、`public_attack`, `auth_attack`, `high_risk_attack`, `report_priority` などの細粒度 gate 案を定義する
- [ ] ステップ3: gate 入力として必要な task metadata と runtime signal のスキーマを定義する
- [ ] ステップ4: `scope_violation`, `budget_exceeded`, `critical finding`, `pending_hitl` 発生時の状態遷移表を作る
- [ ] ステップ5: Recon / Recipe / Scope policy と矛盾しない接続順を決め、最小実装順を整理する

## 4.1 細粒度化の意味
- `phase` を単に増やす話ではない
- 例:
  - public endpoint への軽量検証は許可
  - 認証必須の攻撃は auth signal が揃うまで defer
  - post exploit 系は scope policy 次第で lock
  - critical finding が出たら report / HITL を優先

## 4.2 これで何ができるようになるか
- いまは Recon 後に「全部 attack」寄りだが、将来は発見済みシグナルに応じて段階的に攻撃を進められる
- 危険なタスクだけ止めて安全な調査は継続できる
- MC が一連の攻撃意図を保ったまま、次に何を解放するかを状態として持ちやすくなる

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] gate の粒度を上げても task metadata が不足すると判定不能が増える - task schema 整理とセットで進める
- [ ] [重要度:中] PhaseGate と Scope policy の責務が曖昧だと二重判定になる - `scopeは可否`, `gateは進行制御` の線引きを明文化する
- [ ] [重要度:中] 細かくしすぎると operator 視点で状態が見えづらい - summary / reason code / dashboard 表示も合わせて設計する

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0284-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
