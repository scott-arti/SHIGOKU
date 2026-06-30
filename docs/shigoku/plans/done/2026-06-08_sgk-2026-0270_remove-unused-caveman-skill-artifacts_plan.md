---
task_id: SGK-2026-0270
doc_type: plan
status: done
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
title: Remove unused Caveman skill artifacts
created_at: '2026-06-08'
updated_at: '2026-06-24'
tags:
- shigoku
target: .agents/skills
---

# 実装計画書：Remove unused Caveman skill artifacts

## 1. 達成したいゴール（ユーザー視点）
- [ ] SHIGOKU リポジトリから未使用の Caveman 系スキル資産が除去され、今後の運用提案が Caveman 依存なしで整理されること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `.agents/skills/caveman*`: 削除。未使用の Caveman 系スキル実体。
  - `.agents/skills/cavecrew`: 削除。Caveman 派生の補助スキル実体。
  - `skills-lock.json`: 修正。削除したスキルの lock 情報を除去する。
  - `AGENTS.md`: 修正。Caveman 思考スタイル指示を除去する。
  - `docs/shigoku/registry/*`, `docs/shigoku/reports/*`, `docs/shigoku/worklogs/*`: 更新。タスク記録と結果報告。
- **データの流れ / 依存関係:**
  - ユーザー判断 -> Caveman 関連実体/参照の除去 -> ドキュメント整合チェック -> Git SKILL 方針の再提案

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** 現在リポジトリ内に残る Caveman 系スキルディレクトリ、lock 情報、AGENTS の Caveman 指示
- **出力/結果 (Output):** Caveman 依存のない作業環境と、それを前提にした新しい Git SKILL 設計提案
- **制約・ルール:**
  - 削除対象は Caveman 系に限定し、無関係な skill は残す。
  - 参照切れを避けるため、ディレクトリ削除と参照更新を同時に行う。
  - SHIGOKU 台帳・計画書・報告書・作業ログを必ず同期する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: Caveman 関連ディレクトリと参照箇所を特定し、新規タスクを起票
- [x] ステップ2: Caveman 実体と project 内参照を最小差分で削除
- [x] ステップ3: 報告書/作業ログ更新、`sync_shigoku_updated_at.py` と `validate_shigoku_docs.py` による確認

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] グローバル環境側に残る Caveman plugin/skill 本体はこの repo の削除だけでは消えない - 必要なら別途ローカル環境を整理する

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0270-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
