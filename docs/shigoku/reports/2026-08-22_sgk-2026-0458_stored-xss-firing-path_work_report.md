---
task_id: SGK-2026-0458
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-22_sgk-2026-0458_stored-xss-firing-path.md
- docs/shigoku/worklogs/2026-08-22_sgk-2026-0458_stored-xss-firing-path_work_log.md
- docs/shigoku/plans/2026-08-22_sgk-2026-0459_active-save-sink-discovery.md
- docs/shigoku/plans/done/2026-08-22_sgk-2026-0457_stored-xss-confirmation.md
title: 保存型(Stored)XSSの検出側発火経路を製品非依存に拡張 作業完了報告
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
target: src/core/agents/swarm/injection/smart_xss.py,src/core/agents/swarm/injection/manager.py,tests/core/agents/swarm/injection/test_smart_xss_stored_revisit.py
---

# SGK-2026-0458 作業完了報告 — 検出側の stored 発火経路を製品非依存に拡張

## What（何をしたか）

保存型 XSS の検出側発火経路を製品非依存・挙動ベースで拡張した。実装は DeepSeek、Claude が実物で独立検証した。

- `src/core/agents/swarm/injection/smart_xss.py`（+166）:
  - `_derive_revisit_candidates()`（保存後の再訪「表示URL」候補を構造だけから導出：フォーム発見元ページ=`target`／保存エンドポイントの GET 読み戻し／マネージャ走査済み同一オリジン在庫 `revisit_candidates` 先頭20件）。
  - 良性ランダムマーカー（`sgk<hex>`・`secrets.token_hex`）を保存 → 候補を GET 巡回してマーカー反射先を発見 → `reflection_url` を算出 → 既存 `_validate_stored_runtime_xss(reflection_url)` でブラウザ実 dialog 発火を確認（発火時のみ `variant="stored"`・`dialog_observed=true`・`test_url=reflection_url`）。
  - 起動ゲート: `method=="POST"` かつ `revisit_candidates` あり かつ明示 `reflection_url` 無し のときのみ（反射型/DOM 型の既存経路は無改変・追加のみ）。`revisit_candidates` を META_KEYS へ追加し payload param への混入を防止。
- `src/core/agents/swarm/injection/manager.py`（+37）: `_same_origin_revisit_candidates()` で同一オリジン URL 在庫（`current_context["url_results"]`）を XSS タスク params へ受け渡し（追加のみ）。
- テスト `tests/core/agents/swarm/injection/test_smart_xss_stored_revisit.py`（新規・T1/T2）。

## Why（なぜ）

SGK-2026-0457 で確定ゲート（reproduction stored 分岐）は完成したが、検出側が実走行で `variant="stored"` finding を 1 件も生成しなかった。真因（0457 実走行・引用特定）は「保存 sink への POST → 別の再訪 GET レンダーで発火」を挙動ベース・製品非依存で発見する経路が検出側に無く、`reflection_url`（再訪表示URL）を書き込む箇所がリポジトリ全体に存在しなかったこと。本タスクは `reflection_url` を構造から動的算出して死んでいた stored 経路を生かす。

## Validation（検証・独立実施・DeepSeek 報告は額面で信用しない）

- **ユニット（C3/C5）**: `test_smart_xss_stored_revisit.py`＋`test_smart_xss.py`＋`test_smart_xss_logic.py` = **23 passed（exit0・228s）**。既存回帰なし。
- **バー無改変（C4）**: `payout_grade.py`/`poc_judge.md`(roles)/`task_queue.py`/`finding_validator.py`/`sealed_reproduction_checker.py` 各 `git diff --quiet HEAD` **exit0**。
- **製品非依存（C2）**: 変更差分（manager.py・smart_xss.py・新規テスト）に製品トークン（juice/localhost:3000/reviews/ProductReviews/rest/products/dvwa/xss_s）の追加 **0 件**（Claude が diff を直接スキャン）。
- **実走行（Caido 8081・`SHIGOKU_T3_HYBRID_ENABLED=1`・GET_ONLY 無し・Juice Shop）**: 正本 `session_20260822_102243.json` / `haddix_report_20260822_102244.md`。整合チェッカ **consistent / rerun_required=false**（Claude 実行）。

## Risks / 未達（正直な開示）

- **C1（stored 経由 confirmed=1）は未達**。session 直読で `variant="stored"` finding **0 件**（全 `browser_execution` 20 件が `variant="dom"`）・confirmed=0・`revisit_candidates` 痕跡 0 件。POST の XSS タスク node 数 0（保存 sink が XSS へ一度も dispatch されず）。`/reviews` は `feedback_review`／`unknown` 扱いで XSS へ渡らず、レビュー保存 API（`/api/ProductReviews` 等）は発見 URL 一覧 105 件（api/rest 7 件）に**一度も現れない**。
- **真因（root of root）**: 動的偵察（Playwright で XHR/Fetch 傍受）は走ったが、**保存 API は「実際にレビューを投稿した瞬間」にしか XHR に現れない**ため、受け身の傍受・HTML フォーム解析では発見できない。検出側 stored 経路（本タスク完成済み）は保存 sink の住所を受け取れず発火機会を得られなかった。**上流の発見・dispatch のギャップ**であり本タスクのスコープ「検出側のみ」の外。
- 偽陽性ゼロ規律は維持: マーカー反射だけでは stored finding を作らず、Playwright の実 dialog 観測時のみ付与。

## Next step

- **SGK-2026-0459**（active）で「能動的な保存 sink 発見」（入力欄へ良性マーカーを投稿して書き込み API と再訪表示URLを炙り出し、XSS の stored 経路へ受け渡す）を製品非依存に実装し、Juice Shop 実走行で `variant="stored"` finding 生成 → 0457/0458 経路で confirmed=1 を実証する。
- commit は検証後の成果物（smart_xss.py・manager.py・新規テスト・docs）をステージングし実施、push はユーザー。

## deferred_tasks

```yaml
deferred_tasks:
  - description: 能動的な保存 sink 発見（入力欄へ良性マーカーを投稿して書き込み API・項目・再訪表示URLを炙り出す発見能力）と XSS stored 経路への受け渡し。Juice Shop 実走行で variant=stored の finding を生成し 0457/0458 経路で confirmed=1 を実証（製品非依存・書き込みガード遵守）。
    tracking_task_id: SGK-2026-0459
    tracking_doc: docs/shigoku/plans/2026-08-22_sgk-2026-0459_active-save-sink-discovery.md
```
