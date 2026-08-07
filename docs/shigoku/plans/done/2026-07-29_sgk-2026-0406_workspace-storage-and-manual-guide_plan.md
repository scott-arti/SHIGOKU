---
task_id: SGK-2026-0406
doc_type: plan
status: done
parent_task_id: null
related_docs:
  - docs/shigoku/manuals/WORKSPACE_STORAGE_AND_MANUAL_GUIDE.md
  - docs/shigoku/reports/2026-07-29_sgk-2026-0406_workspace-storage-and-manual-guide_work_report.md
  - docs/shigoku/worklogs/2026-07-29_sgk-2026-0406_workspace-storage-and-manual-guide_work_log.md
title: ワークスペース保存構造とマニュアル案内の整備
created_at: '2026-07-29'
updated_at: '2026-08-07'
tags:
- shigoku
target: docs/shigoku/manuals
---

# 実装計画書：ワークスペース保存構造とマニュアル案内の整備

## 1. 達成したいゴール（ユーザー視点）
- [x] `workspace/` 直下と対象別プロジェクト内の保存先について、役割と保持判断を後から確認できること。
- [x] `docs/shigoku/manuals/` の文書を、目的別に選べること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `docs/shigoku/manuals/WORKSPACE_STORAGE_AND_MANUAL_GUIDE.md`: （新規）保存構造とマニュアルの案内。
  - `src/core/project/project_manager.py`: 保存構造のコード上の正本（参照のみ）。
- **データの流れ / 依存関係:**
  - SHIGOKU 実行 -> `workspace/projects/<対象>/` -> セッション・レポート・検出結果を保存
  - 利用者 -> 本案内 -> 目的別のマニュアルを選択

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** 実行時に生成される保存物、既存マニュアル一覧
- **出力/結果 (Output):** 保存場所の説明とマニュアル分類を含む案内文書
- **制約・ルール:**
  - 現行の標準保存先と、互換・履歴用途の保存物を区別する。
  - 認証情報を含み得るCookieの中身は文書に記載しない。
  - 既存マニュアルは削除・改名せず、案内文書から役割を示す。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: コードと保存物から現行の標準構造を確認する。
- [x] ステップ2: 保存構造とマニュアル分類の案内を追加する。
- [x] ステップ3: 文書台帳とリンクを検証する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:低] `workspace/projects_old/`、`workspace/target_site/`、旧 `vulnerabilities/` は root 所有のため、この作業では削除できない。必要時は所有者権限で削除する。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0406-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
