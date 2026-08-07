---
task_id: SGK-2026-0411
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0410
related_docs:
- src/core/swarm/worker/recon_workers.py
- docker-compose.yml
- tests/core/swarm/worker/test_recon_workers.py
- docs/shigoku/manuals/manual_legacy/2026-07-02_sgk-2026-0338_operator-user-manual.md
- docs/shigoku/reports/2026-07-31_sgk-2026-0411_caido-proxy-recon-routing_work_report.md
- docs/shigoku/worklogs/2026-07-31_sgk-2026-0411_caido-proxy-recon-routing_work_log.md
title: Caidoプロキシへの初回偵察通信伝播修正
created_at: '2026-07-31'
updated_at: '2026-08-07'
tags:
- shigoku
target: initial recon Caido proxy routing
---

# 実装計画書：Caidoプロキシへの初回偵察通信伝播修正

## 1. 達成したいゴール（ユーザー視点）
- [x] `SHIGOKU_SCAN__PROXY` に Caido のプロキシリスナーを設定して
  Docker 実行すると、初回偵察の HTTP 通信が Caido の履歴に残ること。
- [x] Caido API の URL と通信記録用プロキシの違いをマニュアルで確認できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/swarm/worker/recon_workers.py`: 初回偵察の Katana/HTTPX へプロキシを渡す。
  - `docker-compose.yml`: ホストの `SHIGOKU_SCAN__PROXY` をコンテナへ渡す。
  - `tests/core/swarm/worker/test_recon_workers.py`: プロキシ伝播の回帰テスト。
  - `docs/shigoku/manuals/manual_legacy/2026-07-02_sgk-2026-0338_operator-user-manual.md`: API とプロキシの設定を区別して説明する。
- **データの流れ / 依存関係:**
  - `SHIGOKU_SCAN__PROXY` -> `settings.scan.proxy` -> Recon Worker -> Katana/HTTPX のプロキシ引数 -> Caido Proxy 履歴。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `SHIGOKU_SCAN__PROXY`（URL文字列）。
- **出力/結果 (Output):** 設定ありの場合のみ Katana/HTTPX がプロキシを利用する。未設定時は従来どおり直接接続する。
- **制約・ルール:**
  - `SHIGOKU_CAIDO__URL` は Caido API 接続先であり、プロキシ設定に流用しない。
  - Naabu の TCP ポート探索は HTTP プロキシ対象外とする。
  - token や認証情報をログ・テストへ記録しない。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: Katana/HTTPX Worker が設定済みプロキシを渡す失敗テストを追加する。
- [x] ステップ2: Worker と Docker Compose に最小限のプロキシ伝播を実装する。
- [x] ステップ3: 対象・関連テストと文書検証を行い、マニュアルとタスク記録を更新する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [x] [重要度:低] Caido 側のリスナーポートは利用者の設定に依存するため、自動推測せず明示設定を必須とした。
