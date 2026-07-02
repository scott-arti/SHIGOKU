---
task_id: SGK-2026-0278
doc_type: plan
status: active
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
- docs/shigoku/roadmaps/future_functions1.md
- docs/shigoku/roadmaps/bug_bounty_enhancements_2026.md
title: 'Ver.2 planning bundle: DEV_MODE整理・自律再認証強化・Recon再設計'
created_at: '2026-06-20'
updated_at: '2026-07-02'
tags:
- shigoku
target: src/recon/, src/core/agents/swarm/auth/, src/core/engine/
---

# 実装計画書：Ver.2 planning bundle: DEV_MODE整理・自律再認証強化・Recon再設計

## 1. 達成したいゴール（ユーザー視点）
- Ver.2 で優先実施する設計変更を、実装着手可能な粒度で分離する。
- 今回の会話で「現行維持」「次期送り」「今回計画化」の境界を固定し、判断の揺れを減らす。
- 次の3本を独立して進められる状態にする。
  - `SGK-2026-0279`: DEV_MODE デモ経路分離 + BurpIntegration 削除
  - `SGK-2026-0280`: 自律再認証強化 + EventBus 運用明確化
  - `SGK-2026-0281`: Recon 運用再設計

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/recon/`: デモ/実運用の分離対象
  - `src/core/adapters/proxy_integration.py`: Caido 単独前提へ整理
  - `src/core/agents/swarm/auth/`: 自律再認証の改善対象
  - `src/core/infra/event_bus.py`: イベント駆動連携の中核
  - `src/core/engine/master_conductor.py`: EventBus 購読、Recon 後段、Recipe/PhaseGate 接続点
  - `src/core/engine/recipe_loader.py`: Recipe 選抜ロジックの改善対象
  - `src/core/engine/phase_gate.py`: 粒度改善対象
- **データの流れ / 依存関係:**
  - `NetworkClient` の 401 / findings / log イベント -> `EventBus` -> `MasterConductor` / UI / Notification
  - Recon 成果物 -> `MasterConductor` -> `PhaseGate` / attack task 生成 / `RecipeLoader`
  - デモモード設定 -> Recon 実行経路 -> 実 subprocess またはデモ用 fixture/provider

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - 現行コードの実装状況
  - 今回の会話で合意した「次期送り/今回計画化/現状維持」の判断
- **出力/結果 (Output):**
  - Ver.2 実装計画の親子構造
  - 個別計画ごとのスコープ、非スコープ、実装順、検証方針
- **制約・ルール:**
  - `InternalToolProvider` は Ver.2 で統合設計予定のため、今回の計画では触らない
  - `VisualRecon`, `CloudMisconfigChecker の本格化`, `MultiSessionManager`, `Agentic RAG の深掘り`, `タグベース動的Agent選択` は次期バージョン送りとして扱う
  - 既存の用語混線を避けるため、各計画書で「現状できていること / 不足 / 追加後にできること」を明示する

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: 3つの個別計画へ責務を分割し、重複しないスコープを定義する
- [ ] ステップ2: BurpIntegration を実コードから削除し、計画と現行実装の差分を縮める
- [ ] ステップ3: 会話要約と次期バージョン項目整理をユーザー向けにまとめる

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] `RecipeLoader` が loaded recipe 全件返しのため、Recon/Signal 起点の賢い選抜がまだ働かない - `SGK-2026-0281` で扱う
- [ ] [重要度:中] EventBus は導入済みだが、Swarm 間の完全なリアルタイム協調モデルには至っていない - `SGK-2026-0280` で整理する
- [ ] [重要度:低] LearningRepository の Recipe 自動化はバイアス設計検討が未了 - 次期バージョンへ送る

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0278-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
