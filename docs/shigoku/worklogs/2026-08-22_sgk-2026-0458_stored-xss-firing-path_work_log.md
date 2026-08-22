---
task_id: SGK-2026-0458
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-22_sgk-2026-0458_stored-xss-firing-path.md
- docs/shigoku/reports/2026-08-22_sgk-2026-0458_stored-xss-firing-path_work_report.md
- docs/shigoku/plans/2026-08-22_sgk-2026-0459_active-save-sink-discovery.md
title: 保存型(Stored)XSSの検出側発火経路を製品非依存に拡張 作業ログ
created_at: '2026-08-22'
updated_at: '2026-08-22'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- xss
- stored
- browser
- firing-path
---

# SGK-2026-0458 作業ログ（フェーズ0診断・設計・実装・独立検証・実走行）

## 2026-08-22

### フェーズ0（診断・Claude 引用確認）

- 保存型が confirmed に至らない真因を実コードで引用特定。`_validate_stored_runtime_xss`（`smart_xss.py:701`）を呼ぶ入口は3つとも Juice Shop で塞がっている: ①決定的プリチェック（`variant=="stored"` 限定・`_detect_xss_variant` は DVWA 目印 `xss_s` のみ stored）②act の同一URL反射（保存APIはJSON応答で同一URL反射しない）③act の `stored_probe`＋`reflection_url`（本来正しい流れだが `reflection_url` を書き込む箇所がリポジトリ全体に無く構造的に死んでいた）。
- 付随発見: `_check_dom_xss`（`:1867`）は製品名ハードコード有だが呼び出し元ゼロの死にコード（token0 に無影響・今回スコープ外）。

### 設計（Claude・製品非依存で詰め）

- 再訪「表示URL」候補を構造だけから導出（フォーム発見元=`target`／保存EPの GET 読み戻し／マネージャ在庫 `url_results` の同一オリジンURL）。良性マーカー保存 → 巡回で反射先発見 → `reflection_url` 算出 → 既存 `_validate_stored_runtime_xss` でブラウザ発火確認（発火時のみ付与＝偽陽性ゼロ）。
- 安全境界: 保存POSTは `AsyncNetworkClient` 経由で既存 `sealed_run_get_only`（`network_client.py:456-469`）が強制。良性・最小・ローカル練習台限定。

### 実装（DeepSeek）と独立検証（Claude・額面で信用しない）

- 差分実在確認: `smart_xss.py` `_derive_revisit_candidates`（:736）・marker（:799）・巡回（:820-832）・`reflection_url` セット（:866）・発火確認（:867）・POST ゲート（:1238-1240）。`manager.py` `_same_origin_revisit_candidates`（:4241）・受け渡し（:4281-4282）。追加のみ・置換なし。
- ユニット: `test_smart_xss_stored_revisit.py`＋`test_smart_xss.py`＋`test_smart_xss_logic.py` **23 passed（exit0）**。
- バー diff: 5 ファイル exit0。製品非依存: 変更差分に製品トークン追加 0 件（diff 直接スキャン）。

### 実走行（Caido 8081・SHIGOKU_T3_HYBRID_ENABLED=1・GET_ONLY 無し）

- 正本: `session_20260822_102243.json` / `haddix_report_20260822_102244.md` → 整合チェッカ **consistent / rerun_required=false**（Claude 実行）。
- session 直読: `variant="stored"` 0 件（`browser_execution` 20 件すべて `variant="dom"`）・confirmed=0・`revisit_candidates` 痕跡 0・POST の XSS タスク node 0。発見 URL 105 件（api/rest 7 件）にレビュー保存 API（`/api/ProductReviews`・`products/N/reviews`）は 0 件。`/reviews` は `feedback_review`／`unknown`。
- 真因（root of root）: 動的偵察（Playwright/XHR 傍受・痕跡あり）は走ったが、保存 API は「実際に投稿した瞬間」にしか XHR に現れず受け身の傍受では発見不能。検出側 stored 経路（完成済み）は住所を受け取れず発火機会なし。上流の発見・dispatch ギャップ＝スコープ外。

### 分離と ledger 遷移（ユーザー承認 2026-08-22）

- C1（stored 経由 confirmed=1）は上流発見の欠落で未達。**ユーザー承認のもと SGK-2026-0458 を done で閉じ、C1 を SGK-2026-0459（能動的な保存 sink 発見・active plan）へ deferred**。計画書の完了契約に承認 defer を明記し done/ へ移動。
- 台帳: task_registry.yaml（0458 plan→done・work_report/work_log 追加・0459 plan 追加）・task_ledger.md（0458→done・0459 追加）。

## 参考ルール

rules/lessons.md（一ファイルの挙動を仕様と断定しない・sealed run の REAL target 到達検証・スコープ固定）、rules/codingrules.md（局所変更・偽陽性防止・シークレット非露出）、rules/task-ledger.md、rules/shigoku-docs.md、rules/python-tests.md。
