---
task_id: SGK-2026-0457
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-20_sgk-2026-0455_dom-xss-confirmation-routing.md
- docs/shigoku/plans/done/2026-08-21_sgk-2026-0456_xss-dom-fragment-firing-path.md
- docs/shigoku/plans/done/2026-08-22_sgk-2026-0458_stored-xss-firing-path.md
- docs/shigoku/reports/2026-08-22_sgk-2026-0457_stored-xss-confirmation_work_report.md
- docs/shigoku/worklogs/2026-08-22_sgk-2026-0457_stored-xss-confirmation_work_log.md
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
- confirmation
---

# SGK-2026-0457 計画書 — 保存型(Stored)XSS を確定まで運ぶ

## 目的（Objective）

保存型 XSS（payload を保存 sink へ書き込み → 別の GET レンダーで発火）を、確定バーを緩めずに **confirmed** まで運ぶ。既存の保存型検出（`_validate_stored_runtime_xss`：保存後に再訪 GET でブラウザ実行を確認し `variant="stored"`・`dialog_observed=true` を記録）は存在するが、確定側の reproduction gate が `variant=="stored"` を扱えず確定に至らない。DOM 型で SGK-2026-0455 が解いたのと同型の穴を stored 向けに是正する。

## 背景・既存下地（読み取り調査済み・2026-08-22）

- 検出側: `smart_xss.py:701 _validate_stored_runtime_xss` は、保存(POST)後の**再訪 URL を browser で GET 再ロードして dialog 発火を確認**し、`browser_execution = {variant:"stored", event:"stored_revisit_browser_execution", dialog_observed:true, test_url:<revisit_url>}` と `_stored_xss_revisit_evidence`（save/revisit request id）を記録する。保存(POST)自体は ThoughtLoop の攻撃ステップが実施（`self._last_poc_request`）。
- 確定側の穴: `sealed_reproduction_checker.py:241-245` のブラウザ再実行分岐は `variant=="dom"` **限定**。`variant=="stored"` は反射型 HTTP 再送経路へ落ち、保存 payload は単純 GET 再送では再現できず `mismatched/not_run`＝確定不可（SGK-2026-0455 の DOM 穴と同型）。
- 既に効くもの（0455 実装）: `_build_user_payload` は `variant`/`event`/`dialog_observed`/`test_url` を poc_judge へ可視化済み。`_t3_browser_evidence_trigger` は `dialog_observed` で発火するため resurrection も stored 証拠で作動する見込み。
- 書き込み境界: `settings.sealed_run_get_only` 既定 **False**＝非GET(保存POST)は既定許可。本タスクはローカル練習台(Juice Shop)への**良性 payload（例 `<img src=x onerror=alert(1)>`）書き込み**を、保存型 XSS 確定に不可欠な行為として前提化する（機微データ書換・破壊操作はしない・冪等/最小限）。GET-only 強制環境では対象外（`readonly_get_only_enforced` で正しくブロックされる）。

## フェーズ0（診断・実装前の必須ゲート）

1. 確定側の穴（`variant=="stored"` 未対応）を引用特定済み（上記）。reproduction gate の stored 分岐は **再訪 URL の browser 再ロード（GET・読み取り）で dialog 再観測**＝反射型 HTTP 経路も DOM 経路も無改変で追加のみ、を確認。
2. **検出側の実発火確認（live・0456 の教訓）**: Juice Shop の保存 sink で、ハンターの stored 経路が実際に `variant="stored"`・`dialog_observed=true` の finding を生成できるかを実走行で確認する（生成できない＝発火経路側の追加課題を分離）。カーブフィッティング禁止・特定 sink 焼き込み禁止。
3. 書き込みは良性・最小・ローカル練習台限定であることを設計で担保。
→ フェーズ0提出・レビュー承認後に実装。

## 完了契約（Fixed completion criteria）

- C1: Juice Shop の保存型 XSS が、Caido(8081) 経由の実走行で `variant="stored"`・`dialog_observed=true` の finding として生成され、reproduction gate の stored 分岐（再訪 browser 再ロードで dialog 再観測）を通って **confirmed=1件以上**。正本 session/report を残し、`verify_report_session_consistency` = `consistent`/`rerun_required=false`。**（ユーザー承認 2026-08-22: 検出側が Juice Shop で stored finding を生成しなかったため C1 は SGK-2026-0458 へ deferred・本タスクは gate 側実装完了で done）**
- C2: 確定は**本物のブラウザ実行証拠**（再訪レンダーでの実 dialog 発火）に基づく。保存されていない／発火しない候補は `mismatched`/`not_run` で confirmed に至らない（偽陽性なし）。
- C3: reproduction gate は **stored 分岐の追加のみ**許可（`sealed_reproduction_checker.py` に `variant=="stored"` で再訪 URL を browser 再ロードし dialog 再観測→`matched`/`mismatched`/`not_run`）。DOM 経路・反射型 HTTP 経路は無改変。残る凍結バー `payout_grade.py`/`poc_judge.md`/`task_queue.py`/`finding_validator.py` の判定ルール本体は無改変（各 `git diff --quiet HEAD` = exit0、finding_validator は 0455 既存差分のみ）。
- C4: 製品非依存（`check_vdp_product_independence.py` verdict=pass・token0、特定 sink/route 焼き込み禁止）。
- C5: 新規/変更ユニット全 pass。HEAD 既知失敗以外の新規失敗なし。

## フェーズ0・実走行判定（2026-08-22・Claude 独立検証）

実走行（Caido 8081・`SHIGOKU_T3_HYBRID_ENABLED=1`・GET_ONLY 無し＝保存 POST 許可・Juice Shop・`--mode vulntest`）を実施し、正本 `workspace/projects/localhost:3000/sessions/session_20260822_014604.json` / `reports/haddix_report_20260822_014606.md` を直接確認した。

- 整合: `verify_report_session_consistency` = **consistent / rerun_required=false**。製品非依存: **verdict=pass / token_hits=0**。
- **検出側の stored 発火は実走行で確認できず**: session 内の `browser_execution` は 24 件すべて `variant="dom"`（param `q` のフラグメント DOM 発火・0456 経路）。`variant="stored"` の finding は **0 件**。confirmed=1（XSS in parameter 'q'）は DOM 経路。
- ハンターは `/reviews`・`/rest/products/1/reviews` へ fuzzing タスクを発射したが、XSS ハンターの stored 経路は発火しなかった。真因（引用特定）: `smart_xss.py:238-246 _detect_xss_variant()` は path の `xss_s`（DVWA 目印）のみ "stored" を返し、Juice Shop は "generic" に分類。deterministic precheck の反射観測（:1120-1127）は `variant=="stored"` のみ stored 検証へ、ThoughtLoop の `stored_probe`（:1384・LLM 主導・`reflection_url` 必要）は選択されず。**「保存 sink への POST → 再訪 GET レンダーで発火」を挙動ベース・製品非依存で発見する経路が検出側に存在しない**。
- → 本タスク（reproduction gate 側）は実装・ユニット検証・バー無改変・整合・製品非依存まで完了。**C1 の end-to-end 到達は検出側の発火経路を SGK-2026-0458 として分離し追跡する**（ユーザー承認済み・2026-08-22）。

## 必須テスト（Required tests）

- T1: reproduction gate の stored 分岐が、`variant=="stored"`・`test_url`（再訪 URL）を持つ finding に対し、browser 再ロードで dialog 再観測時 `matched`、非発火 `mismatched`、不能 `not_run`（fail-closed）を返す（ユニット・playwright stub 注入）。
- T2: DOM 経路（`variant=="dom"`）・反射型 HTTP 経路が byte-identical で不変（回帰）。
- T3: e2e で Juice Shop の保存型 XSS が `variant="stored"`・`dialog_observed=true` で生成され confirmed=1・整合 consistent（Caido 8081・実走行）。

## NOT in scope

- 反射型/DOM 型 XSS（SGK-2026-0455/0456 で完了）。確定バーの変更。
- GET-only 強制環境での保存型（設計上ブロックが正しい）。破壊的/機微データ書換の書き込み。

## 実装計画（承認後・実装は DeepSeek / 独立検証は Claude）

- 実装: `sealed_reproduction_checker.py` に `variant=="stored"` 分岐を追加（再訪 `test_url` を browser 再ロード＝GET 読み取りで dialog 再観測）。DOM 分岐（案A）と同じ fail-closed 規律・scope 再検証・budget 消費。
- 独立検証（Claude）: フェーズ0引用確認 → T1/T2/T3 → 実走行で `variant="stored"` confirmed=1 → 整合 consistent → 製品非依存 pass/token0 → ledger 遷移。DeepSeek 報告は額面で信用せず実 session/report と ledger を直接確認。

## ガードレール

- カーブフィッティング禁止・確定基準を下げない・製品非依存維持。書き込みは良性・最小・ローカル練習台限定。機微データ抽出/書換・破壊操作禁止。秘密の生値を成果物に残さない。
- Caido = 127.0.0.1:8081（8080 は SearXNG）。Juice Shop = http://localhost:3000。
- commit は検証後、push はユーザー。
