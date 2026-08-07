---
task_id: SGK-2026-0414
doc_type: plan
status: done
parent_task_id: null
related_docs:
- src/core/engine/master_conductor.py
- src/recon/pipeline.py
- src/core/config/settings.py
- tests/core/engine/test_master_conductor_phase5_parallelism.py
- tests/recon/test_recon_pipeline_proxy_gate.py
- docs/shigoku/reports/2026-07-31_sgk-2026-0414_recon-settings-and-task-result-runtime-contract_work_report.md
- docs/shigoku/worklogs/2026-07-31_sgk-2026-0414_recon-settings-and-task-result-runtime-contract_work_log.md
title: Recon設定型と並列結果正規化の実行時例外修正
created_at: '2026-07-31'
updated_at: '2026-08-07'
tags:
- shigoku
target: MasterConductor recon execution and post-batch feedback
---

# 実装計画書：Recon設定型と並列結果正規化の実行時例外修正

## 1. 達成したいゴール（ユーザー視点）
- [x] ローカルターゲットへの偵察を実行すると、Pydantic の `ScanSettings` を辞書として扱ったことによる例外で停止しないこと。
- [x] 並列実行されたタスクの後処理を行うと、`TaskResult` を辞書として扱ったことによる例外で停止せず、保留された後処理を反映できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/recon/pipeline.py`: 偵察開始時のプロキシ解決。設定の正本である `Settings.get_proxy_url()` を利用する。
  - `src/core/engine/master_conductor.py`: 並列オーケストレーターの `TaskResult.result` と従来の辞書結果を、後処理前に同じ辞書形式へ正規化する。
  - `tests/recon/`: プロキシ解決の設定型契約を確認する回帰テスト。
  - `tests/core/engine/test_master_conductor_phase5_parallelism.py`: 実際の `TaskResult` を使う後処理の回帰テスト。
- **データの流れ / 依存関係:**
  - `Settings` -> `get_proxy_url()` -> 偵察プロキシ到達性確認
  - `ParallelOrchestrator.TaskResult.result` または従来の辞書 -> 後処理用辞書 -> `_post_batch_feedback` の反映

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `Settings.scan` (`ScanSettings`)、並列実行結果 (`TaskResult` または `dict`)
- **出力/結果 (Output):** 既存のプロキシ優先順位を維持して偵察を継続し、対応するタスクの保留後処理だけを反映する。
- **制約・ルール:**
  - Juice Shop や URL 形式に依存した分岐は追加しない。
  - `Settings.get_proxy_url()` をプロキシ解決の正本として利用し、既存のプロキシ必須・到達性確認の安全性を下げない。
  - 従来の辞書結果と `TaskResult.result` の両方を受け入れ、無関係な結果形式を推測で変換しない。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: 二つの例外経路を再現する最小の回帰テストを追加し、修正前に失敗することを確認する。
- [x] ステップ2: プロキシ解決と並列結果の正規化を最小限に修正する。
- [x] ステップ3: 対象・関連テスト、構文検査、知識グラフ更新、ドキュメント検証を実行する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- 実ターゲットの再実行は、実装前の実行で今回の二つの例外が確認済みである。本タスクでは外部サービスを動かさず、同じ型契約を単体テストで恒久的に固定する。
- 関連テストでは、今回と無関係な既存失敗が2件確認された。偵察の同時数設定キーの不一致と、バンドル未設定テストの事前検査失敗であり、本タスクでは変更しない。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0414-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
