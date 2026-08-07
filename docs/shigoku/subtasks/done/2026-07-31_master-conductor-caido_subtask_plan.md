---
task_id: SGK-2026-0410
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0409
related_docs:
- src/core/engine/master_conductor.py
- tests/core/engine/test_master_conductor_caido_preflight.py
- workspace/projects/localhost:3000/reports/haddix_report_20260731_141807.md
title: Master Conductor 内部事前チェックへの Caido 設定伝播修正
created_at: '2026-07-31'
updated_at: '2026-08-07'
tags:
- shigoku
target: Master Conductor Caido preflight configuration propagation
---

# 実装計画書：Master Conductor 内部事前チェックへの Caido 設定伝播修正

## 1. 達成したいゴール（ユーザー視点）
- [x] 外側の事前チェックと Master Conductor 内部の事前チェックが、同じ Caido URL と token を使うこと。
- [x] 通常実行とresumeの両方で、設定済みの `8081` が既定値 `8080` に戻らないこと。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: （修正）内部事前チェックの共通コンテキスト生成とCaido設定伝播。
  - `tests/core/engine/test_master_conductor_caido_preflight.py`: （新規）通常実行・resume・実行ループの回帰テスト。
- **データの流れ / 依存関係:**
  - `SHIGOKU_CAIDO__URL` / `SHIGOKU_CAIDO__TOKEN` -> `settings.caido` -> `MasterConductor._build_preflight_context()` -> `EntryGateFacade`。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** 設定済みのCaido URLとtoken、実行対象、認証コンテキスト。
- **出力/結果 (Output):** 内部事前チェックでも設定済みCaidoへ接続し、設定欠落によるfail-closeを起こさない。
- **制約・ルール:**
  - tokenを `target_info` やsessionへ保存しない。
  - 通常実行とresumeで同じ生成処理を使う。
  - 既存のgate policy、対象認証情報、理由コードを変更しない。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: 中断レポートとsessionの整合性を確認し、内部事前チェックだけが既定値へ戻ることを特定する。
- [x] ステップ2: 設定伝播の回帰テストを先に追加し、修正前に2件失敗することを確認する。
- [x] ステップ3: 通常実行とresumeを共通helperへ接続し、関連テストと文書検証を実行する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- 修正後の実Caidoを使った再実行は、利用者側で新しいtokenを使って確認する。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0410-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
