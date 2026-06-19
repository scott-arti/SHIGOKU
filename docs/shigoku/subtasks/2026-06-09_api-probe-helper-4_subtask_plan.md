---
task_id: SGK-2026-0273
doc_type: subtask_plan
doc_usage: execution_plan
status: done
parent_task_id: SGK-2026-0265
related_docs:
- docs/shigoku/plans/2026-06-05_injection-manager-split-plan_plan.md
title: API probe 純粋 helper の追加抽出 (4関数)
created_at: '2026-06-09'
updated_at: '2026-06-09'
tags:
- shigoku
target: src/core/agents/swarm/injection/manager.py
---

# 実装計画書：API probe 純粋 helper の追加抽出 (4関数)

## 1. 達成したいゴール（ユーザー視点）
- [ ] [ユーザー操作]を行うと、[期待する結果]が実現されること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `[path/to/file]`: （新規/修正）[役割]
- **データの流れ / 依存関係:**
  - [入力元] -> [処理] -> [保存/表示先]

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** [name] ([type]), [name] ([type])
- **出力/結果 (Output):** [成功時の結果], [失敗時の挙動]
- **制約・ルール:**
  - [必須ルール1]
  - [必須ルール2]
  - [品質/型/セキュリティ制約]

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: [変更対象と作業内容]
- [ ] ステップ2: [単体確認・テスト観点]
- [ ] ステップ3: [統合・接続・最終確認]

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:低/中/高] [懸念内容] - [次回対応方針]

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0273-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
