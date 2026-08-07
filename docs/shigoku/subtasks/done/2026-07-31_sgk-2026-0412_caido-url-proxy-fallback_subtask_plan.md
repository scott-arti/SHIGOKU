---
task_id: SGK-2026-0412
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0411
related_docs:
- src/core/config/settings.py
- src/core/intel/caido_crawler.py
- tests/unit/config/test_caido_proxy_resolution.py
- docs/shigoku/manuals/manual_legacy/2026-07-02_sgk-2026-0338_operator-user-manual.md
- docs/shigoku/reports/2026-07-31_sgk-2026-0412_caido-url-proxy-fallback_work_report.md
- docs/shigoku/worklogs/2026-07-31_sgk-2026-0412_caido-url-proxy-fallback_work_log.md
title: Caido明示URLの実通信プロキシ適用修正
created_at: '2026-07-31'
updated_at: '2026-08-07'
tags:
- shigoku
target: Caido URL and scan proxy resolution
---

# 実装計画書：Caido明示URLの実通信プロキシ適用修正

## 1. 達成したいゴール（ユーザー視点）
- [x] `SHIGOKU_CAIDO__URL=http://127.0.0.1:8081` を明示すると、
  Preflightだけでなく実際のHTTP通信も同じ8081のCaido Proxyを通ること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/config/settings.py`: 実通信プロキシURLの解決規則を修正する。
  - `tests/unit/config/test_caido_proxy_resolution.py`: URL解決の回帰テストを追加する。
  - `docs/shigoku/manuals/manual_legacy/2026-07-02_sgk-2026-0338_operator-user-manual.md`: 単一設定での動作を説明する。
- **データの流れ / 依存関係:**
  - `SHIGOKU_CAIDO__URL` -> `settings.caido.url` -> `get_proxy_url()` -> Katana/HTTPX/共有NetworkClient -> Caido HTTP History。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `SHIGOKU_SCAN__PROXY`、`SHIGOKU_CAIDO__URL`。
- **出力/結果 (Output):** 明示的なscan proxyを最優先し、未指定なら明示設定されたCaido URLを使用する。
- **制約・ルール:**
  - `SHIGOKU_SCAN__PROXY` がある場合は必ず優先する。
  - Caido URLが明示されていない通常実行は、従来どおり強制プロキシなしとする。
  - URLやtokenを新たにログへ出力しない。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: 優先順位とCaido URLフォールバックの失敗テストを追加する。
- [x] ステップ2: `get_proxy_url()` を最小変更し、対象・関連テストを実行する。
- [x] ステップ3: マニュアル、作業報告、台帳を更新して文書検証する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [x] [重要度:低] Caido以外のプロキシを使う場合は `SHIGOKU_SCAN__PROXY` で上書きする。
