---
task_id: SGK-2026-0408
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0407
related_docs:
- docs/shigoku/manuals/manual_legacy/2026-07-02_sgk-2026-0338_operator-user-manual.md
title: Caido 接続ポート設定の運用マニュアル追記
created_at: '2026-07-31'
updated_at: '2026-08-07'
tags:
- shigoku
target: Caido connection configuration
---

# 実装計画書：Caido 接続ポート設定の運用マニュアル追記

## 1. 達成したいゴール（ユーザー視点）
- [x] Caido の接続先が未設定の場合はポート `8080` を使うこと、別ポートを使う場合の設定方法が運用マニュアルから分かること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `docs/shigoku/manuals/manual_legacy/2026-07-02_sgk-2026-0338_operator-user-manual.md`: （修正）Caido 接続 URL とポートの設定案内。
- **データの流れ / 依存関係:**
  - `SHIGOKU_CAIDO__URL` -> `settings.caido.url` -> Caido の GraphQL 接続先。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `SHIGOKU_CAIDO__URL`（URL文字列）、`SHIGOKU_CAIDO__TOKEN`（Caido token）。
- **出力/結果 (Output):** 未設定時は `http://127.0.0.1:8080`、設定時は指定した URL を接続先として使用する。
- **制約・ルール:**
  - トークンの実値や例示用の秘密情報はマニュアルに記載しない。
  - URL とポートの変更手順を、非開発者にも分かる言葉で説明する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: Caido URL の設定元と、現行運用マニュアルの該当節を確認する。
- [x] ステップ2: 既定ポート `8080` と `SHIGOKU_CAIDO__URL` による変更手順を追記する。
- [x] ステップ3: 文書台帳を完了記録へ更新し、文書検証を実行する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- 現時点で未対応事項はない。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0408-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
