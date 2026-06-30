---
task_id: SGK-2026-0271
doc_type: plan
status: done
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
title: Remove secret-like test fixtures blocking GitHub push
created_at: '2026-06-08'
updated_at: '2026-06-24'
tags:
- shigoku
target: tests
---

# 実装計画書：Remove secret-like test fixtures blocking GitHub push

## 1. 達成したいゴール（ユーザー視点）
- [ ] GitHub push protection に止められずに、現在の変更を新規 GitHub リポジトリへ push できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `tests/unit/engine/test_context_propagator.py`: 修正。secret-like な API key fixture を安全なダミー値へ置換する。
  - `tests/test_pii_masker.py`: 修正。Stripe secret-like fixture を push protection に引っかからないテスト値へ置換する。
  - `docs/shigoku/registry/*`, `docs/shigoku/reports/*`, `docs/shigoku/worklogs/*`: 更新。今回の修正内容と検証結果を記録する。
- **データの流れ / 依存関係:**
  - GitHub push error -> 検出対象 fixture の修正 -> 対象テスト実行 -> Git 履歴上の対処方針整理

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** GitHub push protection が指摘した commit / path / line 情報と、現在のテスト fixture 値
- **出力/結果 (Output):** secret-like でない fixture に置換されたテストコードと、push を通すための履歴上の次アクション
- **制約・ルール:**
  - 本物の秘密情報は使わず、テスト意図を維持したダミー値へ置換する。
  - 変更範囲は GitHub が指摘した fixture と記録ドキュメントに限定する。
  - Python テストは `.venv/bin/pytest` で対象を絞って確認する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: GitHub が指摘した commit / fixture / 履歴位置を確認し、新規タスクを起票
- [x] ステップ2: secret-like な fixture を安全なダミー値へ置換し、対象テストを実行
- [x] ステップ3: 報告書/作業ログ更新、`sync_shigoku_updated_at.py` と `validate_shigoku_docs.py` による確認

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] GitHub がブロックした commit `065caae` は履歴上の commit 単位で再 push されるため、修正後は commit の作り直しまたは history の付け替えが必要

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0271-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
