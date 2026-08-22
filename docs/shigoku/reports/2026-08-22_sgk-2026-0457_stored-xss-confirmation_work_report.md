---
task_id: SGK-2026-0457
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-22_sgk-2026-0457_stored-xss-confirmation.md
- docs/shigoku/worklogs/2026-08-22_sgk-2026-0457_stored-xss-confirmation_work_log.md
- docs/shigoku/plans/done/2026-08-22_sgk-2026-0458_stored-xss-firing-path.md
- docs/shigoku/plans/done/2026-08-20_sgk-2026-0455_dom-xss-confirmation-routing.md
- docs/shigoku/plans/done/2026-08-21_sgk-2026-0456_xss-dom-fragment-firing-path.md
title: 保存型(Stored)XSSのreproduction gateにstored分岐を追加 作業完了報告
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
target: src/core/validation/sealed_reproduction_checker.py,tests/core/validation/test_sealed_reproduction_checker.py
---

# SGK-2026-0457 作業完了報告 — reproduction gate に variant==stored 分岐を追加

## What（何をしたか）

`sealed_reproduction_checker.py` のブラウザ再実行分岐を `variant=="dom"` 限定から `variant in {"dom","stored"}` に拡張した。stored finding は保存(POST)後の**再訪 URL**（`browser_execution.test_url`）を browser で GET 再ロード＝読み取りのみで dialog 再観測し、`matched`（再発火）/`mismatched`（非発火・唯一の mismatch 経路）/`not_run`（ブラウザ不能・例外・スコープ外・状態変更・予算超過・fail-closed）を返す。分岐条件の拡張のみで、既存 `_check_dom_via_browser` への委譲、DOM 経路・反射型 HTTP 再送経路のコードは**無改変**（コメント/docstring の更新のみ）。

- `src/core/validation/sealed_reproduction_checker.py`（+13/-9・すべて分岐条件拡張とコメント）:
  - L241-245: `variant=="dom"` → `variant in {"dom","stored"}`（test_url 条件は従来どおり）。
  - コメント/docstring を DOM/stored 共用経路として更新（判定ロジック無変更）。
- 検出側 `smart_xss.py` は**本タスクで無変更**（`git diff --quiet HEAD` exit0）。確定バー `payout_grade.py`/`poc_judge.md`/`task_queue.py`/`finding_validator.py` も無改変（各 exit0）。

## Why（なぜ）

保存型 XSS の検出は既存（`smart_xss.py:701 _validate_stored_runtime_xss` が保存後の再訪 GET でブラウザ発火を確認し `variant="stored"`・`dialog_observed=true`・`test_url=<revisit_url>` を記録）だが、確定側の reproduction gate が `variant=="dom"` 限定で stored を反射型 HTTP 経路に落とし、保存 payload は単純 GET 再送では再現できず確定不可だった（SGK-2026-0455 の DOM 穴と同型）。stored は DOM と同じく「保存済みページの GET レンダーでの実 dialog 再発火」が唯一の本物の再現証拠であるため、DOM と同じ browser 再ロード分岐へ委譲するのが正しい確定経路。

## Validation（検証・独立実施）

- **T1（stored 分岐・playwright stub 注入）**: `tests/core/validation/test_sealed_reproduction_checker.py` に `TestStoredBrowserPath`（10 件）追加。`variant="stored"`・`test_url`（再訪 URL）を持つ finding に対し、dialog 再観測→`matched`（`reproduction_browser_dialog_observed`・再訪 test_url が reload される）、非発火→`mismatched`（`reproduction_marker_mismatch`）、`is_available()==False`→`not_run`（`reproduction_browser_unavailable`）、例外→`not_run`（`reproduction_transport_error`）、スコープ外/scope None/state-changing→`not_run`、run-wide budget 消費、検出時 dialog 非観測候補は確定時も matched にならない（偽陽性回帰）、test_url 無しは browser 不使用（HTTP 経路・fingerprint 不一致 not_run）。
- **T2（回帰・byte-identical）**: 既存 `TestDomBrowserPath`（variant=="dom"）と反射型 HTTP 経路のテストは**未変更のまま全通過**。`test_sealed_reproduction_checker.py` **48 passed**。配線系 `test_t3_hybrid_wiring.py` + `test_poc_judge_browser_evidence.py` **45 passed**、`test_smart_xss_logic.py` **11 passed**（HEAD 既知失敗以外に新規失敗ゼロ）。
- **バー diff**: `payout_grade.py`/`poc_judge.md`/`task_queue.py`/`finding_validator.py` 各 `git diff --quiet HEAD` **exit0**。`smart_xss.py`（検出側）も exit0。
- **製品非依存**: `scripts/check_vdp_product_independence.py` **verdict=pass**・total_token_hits=0（6チェック全て ok・denylist 14 token・changed files 2）。
- **T3 実走行**（Caido 8081・`SHIGOKU_T3_HYBRID_ENABLED=1`・GET_ONLY 無し＝保存 POST 許可・Juice Shop 3000・`--mode vulntest`・診断/ツールコーリング/dedup 有効）:
  - 正本: `workspace/projects/localhost:3000/sessions/session_20260822_014604.json` / `reports/haddix_report_20260822_014606.md`。整合チェッカ **consistent / rerun_required=false**。Coverage Gate PASS・成功率 91.3%。
  - **REAL target 到達**: Caido 8081 経由で `/api/Challenges/` 等が実データを返すことを session/report で確認（スタブではない）。
  - **検出側の stored 発火は確認できず**: session 内 `browser_execution` 24 件すべて `variant="dom"`（param `q` のフラグメント DOM 発火・0456 経路）。`variant="stored"` の finding は **0 件**。confirmed=1（XSS in parameter 'q'）は DOM 経路。
  - 真因（引用特定）: `smart_xss.py:238-246 _detect_xss_variant()` は path の `xss_s`（DVWA 目印）のみ "stored" を返し Juice Shop は "generic"。deterministic precheck の反射観測（:1120-1127）は `variant=="stored"` のみ stored 検証へ。ThoughtLoop の `stored_probe`（:1384・LLM 主導・`reflection_url` 必要）は選択されず。「保存 sink への POST → 再訪 GET レンダーで発火」を挙動ベース・製品非依存で発見する経路が検出側に存在しない。

## Risks / 未達（正直な開示）

- **C1（stored 分岐経由 confirmed=1）は未達**。reproduction gate の stored 分岐自体は T1/T2・バー無改変・整合・製品非依存で完了検証済みだが、検出側が Juice Shop で `variant="stored"` finding を生成しないため end-to-end 確定に至らない。**ユーザー承認（2026-08-22）のもと C1 は SGK-2026-0458（検出側 stored 発火経路）へ deferred**。
- 偽陽性を作らない設計は維持: stored 確定は再訪 browser 再ロードでの**実 dialog 再観測**のみ `matched`。非発火候補は `mismatched`/`not_run` で confirmed に至らない（C2 担保・ユニットで回帰固定）。
- DOM 経路・反射型 HTTP 経路は byte-identical（分岐条件の拡張のみ）。検出側は無変更。

## Next step

- **SGK-2026-0458**（active）で検出側の stored 発火経路を製品非依存に汎用化し、Juice Shop 実走行で `variant="stored"` finding 生成 → 0457 の stored 分岐で confirmed=1 を実証する。
- commit は検証後の成果物（sealed_reproduction_checker.py・テスト・docs）をステージングし実施、push はユーザー。

## deferred_tasks

```yaml
deferred_tasks:
  - description: 検出側の stored 発火経路を製品非依存に拡張（保存 sink の挙動ベース発見 → 再訪 GET レンダーで variant=stored/dialog_observed=true の finding 生成 → 0457 の reproduction stored 分岐で confirmed=1）
    tracking_task_id: SGK-2026-0458
    tracking_doc: docs/shigoku/plans/done/2026-08-22_sgk-2026-0458_stored-xss-firing-path.md
```
