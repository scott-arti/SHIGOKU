---
task_id: SGK-2026-0269
doc_type: plan
status: done
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
title: Git ignore cleanup for fresh GitHub repository
created_at: '2026-06-08'
updated_at: '2026-06-08'
tags:
- shigoku
target: .gitignore
---

# 実装計画書：Git ignore cleanup for fresh GitHub repository

## 1. 達成したいゴール（ユーザー視点）
- [ ] 新しい GitHub リポジトリを初期化するとき、ローカル生成物・個人用出力・依存物がコミット対象に混ざらないこと。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `.gitignore`: 修正。新規リポジトリ向けの追跡除外ルールを定義する。
  - `docs/shigoku/registry/task_registry.yaml`: 更新。今回作業のタスクIDと状態を記録する。
  - `docs/shigoku/reports/`: 追加。実施内容と判断理由を記録する。
  - `docs/shigoku/worklogs/`: 追加。作業ログと次アクションを記録する。
- **データの流れ / 依存関係:**
  - ユーザー合意 -> `.gitignore` 更新 -> Git の追跡候補整理 -> SHIGOKU 台帳/報告へ反映

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** ユーザーが合意した ignore 対象（`workspace/`, `graphify-out/`, `md/`, ローカル環境ファイル、依存物、ログ/一時ファイル）
- **出力/結果 (Output):** 新しい GitHub リポジトリへ不要物を載せない `.gitignore`。必要ファイルは引き続き追跡対象に残す。
- **制約・ルール:**
  - 既存スタイルを維持し、`.gitignore` は最小差分で更新する。
  - `.env.example` は共有用サンプルとして除外しない。
  - `DVWA/` は誤って除外しない。今回の前提では ignore 対象から外す。
  - SHIGOKU 台帳、計画書、報告書、作業ログを整合させる。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: 台帳確認、新規タスク採番、計画書ひな形の生成
- [x] ステップ2: `.gitignore` に合意済みの ignore ルールを反映
- [x] ステップ3: 報告書/作業ログ更新、`sync_shigoku_updated_at.py` と `validate_shigoku_docs.py` による確認

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] すでに追跡済みの `workspace/` や `node_modules/` は `.gitignore` 追加だけでは追跡停止しない - 新規 GitHub 初期化時にインデックス整理が必要

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0269-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
