---
task_id: SGK-2026-0458
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-22_sgk-2026-0457_stored-xss-confirmation.md
- docs/shigoku/plans/done/2026-08-21_sgk-2026-0456_xss-dom-fragment-firing-path.md
- docs/shigoku/plans/2026-08-22_sgk-2026-0459_active-save-sink-discovery.md
- docs/shigoku/reports/2026-08-22_sgk-2026-0458_stored-xss-firing-path_work_report.md
- docs/shigoku/worklogs/2026-08-22_sgk-2026-0458_stored-xss-firing-path_work_log.md
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

# SGK-2026-0458 計画書 — 保存型(Stored)XSS の発火経路を汎用ターゲットへ拡張

## 目的（Objective）

SGK-2026-0457 で reproduction gate の stored 分岐（`variant="stored"` の finding を再訪 URL の browser 再ロードで dialog 再観測 → `matched`/`mismatched`/`not_run`・fail-closed）は実装・ユニット検証済み（T1/T2 pass・バー無改変・整合 consistent・製品非依存 pass/token0）。しかし実走行で検出側が Juice Shop に対し `variant="stored"` の finding を **1 件も生成しなかった**（全 browser_execution が `variant="dom"`）。確定経路（0457）は完成しているのに「本物の発火証拠」を持つ stored finding が流れないため C1（confirmed>=1）に到達しない。本タスクは **検出側の発火経路**を製品非依存に拡張し、stored finding を実発火で生成して 0457 の確定経路で confirmed に到達させる。

## 背景・根拠（SGK-2026-0457 実走行で判明・2026-08-22）

- 0457 実走行（Caido 8081・`SHIGOKU_T3_HYBRID_ENABLED=1`・GET_ONLY 無し＝保存 POST 許可・Juice Shop・`--mode vulntest`）:
  - 正本 `workspace/projects/localhost:3000/sessions/session_20260822_014604.json` / `reports/haddix_report_20260822_014606.md`（consistent・製品非依存 pass/token0）。
  - `browser_execution` 24 件すべて `variant="dom"`（param `q` のフラグメント DOM 発火・0456 経路）。`variant="stored"` は **0 件**。confirmed=1（XSS in parameter 'q'）は DOM 経路。
  - ハンターは `/reviews`・`/rest/products/1/reviews` へ fuzzing タスクを発射したが、XSS ハンターの stored 経路は発火せず。
- 真因（引用特定・lessons: 一ファイルの挙動を仕様と断定しない）:
  - `smart_xss.py:238-246 _detect_xss_variant()` は path に `xss_s`（DVWA 目印）を含む場合のみ `"stored"` を返す。Juice Shop の path は `"generic"` に分類。
  - `smart_xss.py:1120-1127`: deterministic precheck の反射観測時、`variant=="stored"` のみ `_validate_stored_runtime_xss` へ（generic/reflected は反射型検証）。
  - `smart_xss.py:1355-1428`: ThoughtLoop の `stored_probe` アクション（LLM 主導）が唯一の汎用 stored 経路だが実行されず、また `stored_probe` フローは保存先 URL とは別の `reflection_url`（再訪反射確認先）を context に要求する。
  - すなわち「**保存 sink への POST → 再訪 GET レンダーで反射/発火を確認**」を挙動ベース・製品非依存で発見・実行する経路が検出側に存在しない。
- 0457 の確定経路（reproduction stored 分岐）は完成済み。本タスクでは触らない（バー無改変）。

## フェーズ0（診断・実装前の必須ゲート）

1. stored 発火経路の所有箇所・呼び出し元を引用特定（上記）。lessons: 一ファイルの挙動を仕様と断定しない。
2. 保存 sink の発見・保存・再訪検証を**製品非依存**の設計にする（例: POST 可能なフォーム/API の挙動ベース検出 → 良性 payload をローカル練習台へ保存 → 再訪 URL で反射/発火を browser 確認 → `variant="stored"`・`dialog_observed=true`・`test_url=<再訪 URL>` を記録。特定ルート・製品名を焼き込まない）。
3. 反射型・DOM 型の既存検出経路を退行させない（追加であって置換ではない）。
→ フェーズ0を提出・レビュー承認後に実装。

## 完了契約（Fixed completion criteria）

- C1: Juice Shop の保存型 XSS が、Caido(8081) 経由の実走行で `variant="stored"`・`dialog_observed=true` の finding として生成され、SGK-2026-0457 の reproduction stored 分岐（再訪 browser 再ロードで dialog 再観測）を通って **confirmed=1件以上**。正本 session/report を残し、`verify_report_session_consistency` = `consistent`/`rerun_required=false`。**（ユーザー承認 2026-08-22: 検出側 stored 経路は実装・検証完了だが、実走行で保存 sink（レビュー保存 API）が発見・dispatch されず stored 経路が発火機会を得られなかった。真因は上流の発見・dispatch にあり本タスクのスコープ「検出側のみ」の外。C1 の end-to-end 到達は SGK-2026-0459 へ deferred・本タスクは検出側実装完了で done）**
- C2: 保存 sink 発見は**製品非依存**（`check_vdp_product_independence.py` verdict=pass・token0・特定 sink/route 焼き込み禁止）。発火しない候補に `dialog_observed` を付けない（偽陽性なし）。
- C3: 反射型・DOM 型の既存検出経路は退行なし（既存テスト緑・結果不変）。
- C4: 確定バー無改変（`payout_grade.py`/`poc_judge.md`/`task_queue.py`/`finding_validator.py` の判定ルール本体、および `sealed_reproduction_checker.py` の 0457 実装を変えない）。本タスクは検出側のみ。
- C5: 新規/変更ユニット全 pass。HEAD 既知失敗以外の新規失敗なし。

## 必須テスト（Required tests）

- T1: 保存 sink の発見（POST 保存 → 再訪反射/発火）が、製品非依存の任意ターゲットで stored 経路へ進むこと（ユニット・stub）。
- T2: `_validate_stored_runtime_xss` が実発火時 `variant="stored"`・`dialog_observed=true`・`test_url=<再訪 URL>` を finding に付与し、非発火時は付与しない（ユニット・playwright stub 注入・偽陽性回帰）。
- T3: e2e で Juice Shop の保存型 XSS が `variant="stored"`・`dialog_observed=true` finding として生成され、0457 経路で confirmed=1・整合 consistent（Caido 8081・実走行）。

## NOT in scope

- SGK-2026-0457 の reproduction gate（完成済み・done）。確定バーの変更。
- 反射型/DOM 型 XSS の再設計（SGK-2026-0454/0455/0456 で完了）。GET-only 強制環境での保存型（設計上ブロックが正しい）。破壊的/機微データ書換の書き込み。

## 実装・実走行判定（2026-08-22・Claude 独立検証）

検出側（A/B/C/D）は DeepSeek 実装、Claude が実物で独立検証した。

- **実装は実在し承認設計どおり**: `smart_xss.py` に良性マーカー保存 → 在庫URL巡回で反射先発見（`_derive_revisit_candidates`）→ `reflection_url` 算出 → 既存 `_validate_stored_runtime_xss` でブラウザ発火確認、の POST ゲート付き経路を追加（+166行）。`manager.py` に `_same_origin_revisit_candidates`（同一オリジン在庫を XSS タスクへ受け渡し・+37行）。**追加のみ・置換なし**。
- **ユニット**: 新規 `tests/core/agents/swarm/injection/test_smart_xss_stored_revisit.py` を含む `test_smart_xss_stored_revisit.py`＋`test_smart_xss.py`＋`test_smart_xss_logic.py` = **23 passed（exit0）**。既存回帰なし（C3/C5）。
- **バー無改変（C4）**: `payout_grade.py`/`poc_judge.md`(roles)/`task_queue.py`/`finding_validator.py`/`sealed_reproduction_checker.py` 各 `git diff --quiet HEAD` **exit0**。
- **製品非依存（C2）**: 変更差分に製品トークン（juice/localhost:3000/reviews/ProductReviews/rest/products/dvwa/xss_s）の追加は **0 件**（Claude が diff を直接スキャン）。
- **実走行（Caido 8081・`SHIGOKU_T3_HYBRID_ENABLED=1`・GET_ONLY 無し・Juice Shop）**: 正本 `workspace/projects/localhost:3000/sessions/session_20260822_102243.json` / `reports/haddix_report_20260822_102244.md`。整合 **consistent / rerun_required=false**（Claude 実行）。
- **C1 未達（正直な開示）**: session 直読で `variant="stored"` の finding **0 件**（全 `browser_execution` 20 件が `variant="dom"`）・confirmed=0・`revisit_candidates` 痕跡 0 件。**保存 sink が XSS タスクとして一度も dispatch されなかった**（POST の XSS タスク node 数 0）。`/reviews` は `feedback_review`／`unknown` 扱いで XSS へ渡らず、レビュー保存 API（`/api/ProductReviews` 等）は**発見 URL 一覧 105 件（api/rest 7 件）に一度も現れない**。
- **真因（root of root・引用特定）**: 動的偵察（Playwright で XHR/Fetch 傍受）は走ったが、**保存 API は「実際にレビューを投稿した瞬間」にしか XHR に現れない**ため受け身の傍受・HTML フォーム解析では発見できない（Juice Shop のレビュー投稿は Angular の XHR で、生 GET の `/reviews` は SPA シェルのみ）。検出側 stored 経路（本タスク完成済み）は保存 sink の住所を受け取れず発火機会を得られなかった。これは**上流の発見・dispatch のギャップ**であり、本タスクのスコープ「検出側のみ」の外。
- → 検出側の実装・ユニット・バー無改変・製品非依存・整合まで完了。**C1 の end-to-end 到達は「能動的な保存 sink 発見」を SGK-2026-0459 として分離し追跡する**（ユーザー承認済み・2026-08-22）。

## 実装計画（承認後・実装は DeepSeek / 独立検証は Claude）

- 実装: `smart_xss.py` の stored 発火経路を汎用化（保存 sink の挙動ベース発見・`stored_probe` 到達性・再訪検証の配線）。製品非依存・特定 sink 焼き込み禁止。
- 独立検証（Claude）: フェーズ0引用確認 → T1/T2/T3 ユニット → 実走行（Caido 8081・`SHIGOKU_T3_HYBRID_ENABLED=1`・GET_ONLY 無し）で `variant="stored"` confirmed=1 → 整合 consistent → 製品非依存 pass/token0 → ledger 遷移。DeepSeek 報告は額面で信用せず実 session/report と ledger を直接確認。

## ガードレール

- カーブフィッティング禁止・確定基準を下げない・製品非依存維持。書き込みは良性・最小・ローカル練習台限定。機微データ抽出/書換・破壊操作禁止。秘密の生値を成果物に残さない。
- Caido = 127.0.0.1:8081（8080 は SearXNG）。Juice Shop = http://localhost:3000。
- commit は検証後、push はユーザー。
