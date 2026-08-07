---
task_id: SGK-2026-0402
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0401
related_docs:
- docs/shigoku/plans/done/2026-07-29_llm-provider-endpoint-explicit-configuration-and-legacy-routing-removal_plan.md
title: LLM thinking effort pass-through configuration
created_at: '2026-07-29'
updated_at: '2026-08-07'
tags:
- shigoku
target: src/core/models/llm.py and config/shigoku.yaml
---

# 実装計画書：LLM thinking effort pass-through configuration

## 1. 達成したいゴール（ユーザー視点）

- [x] profile の Thinking 設定をそのままプロバイダーへ渡し、SHIGOKU 独自の強さ変換を行わない。

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
- [x] ステップ1: `extra.thinking` の enabled/disabled と effort を定義。
- [x] ステップ2: 同期・非同期呼出しでその値を送信。
- [x] ステップ3: LLM の単体テストを実行。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:低/中/高] [懸念内容] - [次回対応方針]

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0402-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
