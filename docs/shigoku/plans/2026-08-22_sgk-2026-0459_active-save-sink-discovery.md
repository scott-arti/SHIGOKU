---
task_id: SGK-2026-0459
doc_type: plan
status: active
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-22_sgk-2026-0458_stored-xss-firing-path.md
- docs/shigoku/plans/done/2026-08-22_sgk-2026-0457_stored-xss-confirmation.md
created_at: '2026-08-22'
updated_at: '2026-08-22'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- discovery
- xss
- stored
- recon
- browser
---

# SGK-2026-0459 計画書 — 能動的な保存 sink 発見（保存型 XSS を実際に確定まで到達）

## 目的（Objective）

保存型 XSS を **実際に confirmed=1件以上** まで到達させる。SGK-2026-0457（確定ゲートの stored 分岐）と SGK-2026-0458（検出側の stored 発火経路・`reflection_url` 動的算出）はいずれも完成・検証済みだが、実走行で **保存 sink（例: レビュー保存 API）がそもそも発見・dispatch されず**、完成済みの stored 経路が発火機会を得られなかった。真因は上流の「発見」段階：**保存 API は実際に投稿した瞬間にしか XHR に現れない**ため、受け身の偵察（XHR 傍受・HTML フォーム解析）では見つからない。本タスクは **能動的な保存 sink 発見**（入力欄へ良性マーカーを投稿して書き込み API・項目・再訪表示URLを炙り出す）を製品非依存に実装し、0458/0457 の完成経路へ受け渡して confirmed=1 を実証する。

## 背景・根拠（SGK-2026-0458 実走行で判明・2026-08-22・引用特定）

- 0458 実走行（Caido 8081・`SHIGOKU_T3_HYBRID_ENABLED=1`・GET_ONLY 無し・Juice Shop）: 正本 `session_20260822_102243.json` / `haddix_report_20260822_102244.md`（consistent）。
  - 動的偵察（Playwright で XHR/Fetch 傍受）は走り、URL 105 件（api/rest 7 件）を発見。しかし **レビュー保存 API（`/api/ProductReviews`・`/rest/products/N/reviews`）は 0 件**。
  - `/reviews`（表示ページ）は `feedback_review`／`unknown` 扱いで XSS へ dispatch されず。POST の XSS タスク node 数 0・`variant="stored"` 0・confirmed=0。
- 真因（root of root）: 保存 API は状態変更（POST/PUT）で、**ユーザーが実際に入力を送信した瞬間にしか XHR に現れない**。受け身の傍受・生 GET の HTML フォーム解析（Angular SPA では GET は空シェル）では発見できない。
- 完成済みで本タスクでは触らない: 0457 確定ゲート（`sealed_reproduction_checker.py`）、0458 検出側 stored 経路（`smart_xss.py` の `_derive_revisit_candidates`／`reflection_url` 算出／マーカー→巡回→ブラウザ発火）。本タスクは **発見側（recon/discovery）と受け渡し** のみ。

## フェーズ0（診断・実装前の必須ゲート）

1. 発見サブシステムの所有箇所・呼び出し元を引用特定（`src/core/agents/swarm/discovery/manager.py`＝Playwright XHR/Fetch 傍受・フォーム抽出、`src/core/intel/cartographer.py`＝sitemap、injection manager への受け渡し）。lessons: 一ファイルの挙動を仕様と断定しない。
2. 能動的入力の安全境界を設計で担保: 状態変更 POST は既存 `sealed_run_get_only`（`network_client.py:456-469`）で GET-only 時にブロックされる。GET-only 無しの実走行でのみ良性マーカーを投稿。良性・最小・ローカル練習台限定・冪等寄り。機微データ書換・破壊操作・大量書込み禁止。
3. 発見は **製品非依存・挙動ベース**: 「入力欄（フォーム/SPA レンダー後の入力）を検出 → 良性マーカーを送信 → 発生した書き込み API（URL・メソッド・項目）を捕捉 → マーカーが再訪表示されるページを探索」。特定ルート・製品名・ホスト名の焼き込み禁止。
→ フェーズ0を提出・レビュー承認後に実装。

## 完了契約（Fixed completion criteria）

- C1: Juice Shop の保存型 XSS が、Caido(8081) 経由の実走行で **能動的に発見された保存 sink** から `variant="stored"`・`dialog_observed=true` の finding として生成され、0458 の検出側 stored 経路と 0457 の reproduction stored 分岐を通って **confirmed=1件以上**。正本 session/report を残し `verify_report_session_consistency` = `consistent`/`rerun_required=false`。
- C2: 保存 sink 発見は **製品非依存**（`check_vdp_product_independence.py` verdict=pass・token0・特定 sink/route/製品名の焼き込み禁止）。発火しない候補に `dialog_observed` を付けない（偽陽性なし）。
- C3: 既存の発見・検出（反射型/DOM 型 XSS、他 vuln の recon/dispatch）に退行なし（既存テスト緑・結果不変）。
- C4: 確定バー無改変（`payout_grade.py`/`poc_judge.md`/`task_queue.py`/`finding_validator.py` の判定ルール本体、`sealed_reproduction_checker.py` の 0457 実装、`smart_xss.py` の 0458 検出側 stored 経路を判定として壊さない）。本タスクは発見側と受け渡しが主。
- C5: 新規/変更ユニット全 pass。HEAD 既知失敗以外の新規失敗なし。
- C6: 能動的入力の安全境界を満たす（良性・最小・ローカル練習台限定、GET-only 時はブロック尊重、機微データ書換/破壊なし、秘密の生値を成果物に残さない）。

## 必須テスト（Required tests）

- T1: 能動的入力の発見（入力欄検出 → 良性マーカー送信 → 書き込み API・項目・再訪表示URLの捕捉）が製品非依存の任意 stub ターゲットで機能する（ユニット・stub・特定ルート非依存）。
- T2: 捕捉した保存 sink が XSS の stored 経路（0458）へ `revisit_candidates`／保存 EP・項目として受け渡され、発火時のみ `variant="stored"`・`dialog_observed=true` を生成する（ユニット・playwright stub・偽陽性回帰）。
- T3: 能動的入力の安全境界（GET-only 時ブロック・良性マーカーのみ・ローカル練習台限定）をユニットで固定。
- T4: e2e で Juice Shop の保存型 XSS が能動発見 → `variant="stored"`・`dialog_observed=true` → 0457 経路で confirmed=1・整合 consistent（Caido 8081・実走行）。

## NOT in scope

- SGK-2026-0457 の reproduction gate・SGK-2026-0458 の検出側 stored 経路（完成済み）。確定バーの変更。
- 反射型/DOM 型 XSS の再設計（0454/0455/0456 で完了）。GET-only 強制環境での保存型（設計上ブロックが正しい）。破壊的/機微データ書換の書き込み。死にコード `_check_dom_xss` の掃除（別件）。

## 実装計画（承認後・実装は DeepSeek / 独立検証は Claude）

- 実装: 発見サブシステム（`discovery/manager.py` 等）に能動的な保存 sink 発見（良性マーカー投稿 → 書き込み API・項目・再訪表示URLの捕捉）を追加し、injection manager 経由で XSS の stored 経路（0458）へ受け渡す。製品非依存・焼き込み禁止・書き込みガード遵守。
- 独立検証（Claude）: フェーズ0引用確認 → T1/T2/T3/T4 ユニット → 実走行（Caido 8081・`SHIGOKU_T3_HYBRID_ENABLED=1`・GET_ONLY 無し）で能動発見 → `variant="stored"` confirmed=1 → 整合 consistent → 製品非依存 pass/token0 → ledger 遷移。DeepSeek 報告は額面で信用せず実 session/report と ledger を直接確認。

## ガードレール

- カーブフィッティング禁止・確定基準を下げない・製品非依存維持・能力の過小化をしない。書き込みは良性・最小・ローカル練習台限定。機微データ抽出/書換・破壊操作禁止。秘密の生値を成果物に残さない。
- Caido = 127.0.0.1:8081（8080 は SearXNG）。Juice Shop = http://localhost:3000。
- commit は検証後、push はユーザー。
