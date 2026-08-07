---
task_id: SGK-2026-0409
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0408
related_docs:
- src/core/preflight/caido_check.py
- tests/unit/preflight/test_caido_check.py
title: Caido GraphQL 転送対応と事前チェック接続先表示修正
created_at: '2026-07-31'
updated_at: '2026-08-07'
tags:
- shigoku
target: Caido preflight GraphQL endpoint
---

# 実装計画書：Caido GraphQL 転送対応と事前チェック接続先表示修正

## 1. 達成したいゴール（ユーザー視点）
- [x] Caido が `/graphql/` へ転送する構成でも、事前チェックが転送先を確認できること。
- [x] 接続確認に失敗した場合、設定された実際のポート番号がエラーに表示されること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/preflight/caido_check.py`: （修正）GraphQL と identity 確認時の転送追従、エラー文のポート表示。
  - `tests/unit/preflight/test_caido_check.py`: （修正）転送追従と実ポート表示の回帰テスト。
- **データの流れ / 依存関係:**
  - `SHIGOKU_CAIDO__URL` -> `PreflightContext.caido_url` -> `CaidoCheck` の HTTP/GraphQL 確認。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** Caido の URL と token。
- **出力/結果 (Output):** HTTP 307 の転送先を追従して GraphQL 応答を判定し、失敗時は設定済み URL のポートを表示する。
- **制約・ルール:**
  - token の生値をログ、テスト、文書に出力しない。
  - 既存の timeout、proxy 無効化、理由コードを変更しない。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: Caido の HTTP 転送応答、設定伝播、既存の事前チェック処理を確認する。
- [x] ステップ2: `follow_redirects=True` と実ポート表示を追加し、回帰テストを作成する。
- [x] ステップ3: 対象テストを実行し、文書台帳を完了記録へ更新する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- 実 Caido への再接続は token 再発行後に利用者が行う。ネットワーク接続を伴うため、本タスクでは実施しない。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0409-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
