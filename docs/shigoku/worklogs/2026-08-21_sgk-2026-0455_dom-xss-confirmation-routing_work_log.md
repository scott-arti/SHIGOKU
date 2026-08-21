---
task_id: SGK-2026-0455
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-20_sgk-2026-0455_dom-xss-confirmation-routing.md
- docs/shigoku/plans/done/2026-08-18_sgk-2026-0454_xss-dom-runtime-firing-path.md
title: DOM XSSのブラウザ実行証拠を確定まで運ぶ（confirmation routing是正）作業ログ
created_at: '2026-08-21'
updated_at: '2026-08-22'
tags:
- shigoku
- vdp
- xss
- dom
- confirmation
---

# SGK-2026-0455 作業ログ（実装フェーズ）

## 2026-08-21（実装・DeepSeek）

計画書（案A・2026-08-20 ユーザー承認）に基づき、確定バー4点（`payout_grade.py` / `poc_judge.md` / `finding_validator.py` / `task_queue.py`）を無改変のまま実装した。独立検証（実走行 C1）は Claude が実施するため、本ログは実装フェーズの記録に留める（タスクは `active` 維持）。

### 実装1: reproduction gate に DOM 経路（案A: 確定時ブラウザ再実行）

- `src/core/validation/sealed_reproduction_checker.py`:
  - `check()` 冒頭の run-wide budget チェックは共通のまま、その直後に DOM 分岐を追加。`additional_info.browser_execution` が dict で `variant=="dom"` かつ `test_url` 保持の finding のみ `_check_dom_via_browser()` へ。反射型 HTTP GET 再送経路（L223-312 相当）は分岐外で byte-identical（git diff で確認）。
  - `_check_dom_via_browser()`: masked URL 復元（0439）→ GET-only probe → read-only/state-changing ガード → 封印スコープ再検証（target host[:port] のみ）→ `PlaywrightValidator.is_available` が False なら not_run（`reproduction_browser_unavailable`・fail-closed）→ `validate_xss_sync` で PoC URL を 1 回再ロード。dialog 再観測→ matched（`reproduction_browser_dialog_observed`）、応答あり非発火→ mismatched（`reproduction_marker_mismatch`・唯一の DOM mismatch 経路）、例外/timeout→ not_run（`reproduction_transport_error`・fail-closed）。送信試行時に `_replays_used += 1`。
  - 新 reason は checker 内定数追加のみ（funnel REASON_CODES は不変）。
- `src/tools/browser/playwright_validator.py`: `validate_xss_sync()` 同期ラッパ追加（既存 `validate_xss` 挙動不変）。running loop 無し→ `asyncio.run`、running loop あり→ ワーカースレッドの新規ループで完走（デッドロック防止）。ブラウザ起動は 1 finding 最大 1 回、`time_budget_seconds=600` 内。

### 実装2: resurrection 配線（manager.py `_t3_run_hybrid_pass`）

- 問題: parked record は `_t3_apply_hybrid_verdict` の判定スキップ（state != needs_more）で再評価されず、`CandidateLifecycleManager.revisit`（resurrect_matching 相当）は実装済みながら caller 0 件だった。
- `src/core/agents/swarm/injection/manager.py`:
  - `_t3_browser_evidence_trigger(finding)`: `browser_execution.dialog_observed==true` の finding に `("evidence","browser_execution")` トークンを付与（語彙追加のみ・基準不変）。
  - `_t3_resurrection_information(findings, lifecycle)`: ブラウザ証拠 finding の標準 trigger 語彙（vuln_type/endpoint/capability）＋ browser-evidence トークンで new_information を構築（order-preserving dedup）。
  - `_t3_apply_hybrid_verdict`: `apply_verdict(..., extra_triggers=self._t3_browser_evidence_trigger(finding))` で _park 側の revisit_triggers にも同トークンを載せる。
  - `_t3_run_hybrid_pass`: ledger open 後・判定ループ前に、parked records を `lifecycle.revisit(parked, new_information)` で needs_more(budget_used=0, resurrection_count+1) の復活コピーへ → 既存ループで再判定 → 実装1で matched → confirmed。`resurrection_history` 消費で無限復活を防止。初回 record なし（needs_more 未満）の finding は挙動不変。

### 必須テスト

- T1（checker DOM 経路・stub 注入）: `variant=="dom"` + dialog_observed finding → matched / 非発火 stub → mismatched / `is_available()==False` → not_run / 例外 → not_run。反射型 finding は既存 HTTP 経路（回帰 green）。scope 外・state-changing・budget 消費も追加。
- T2（偽陽性回帰）: ブラウザ証拠無し（dialog_observed 無し / browser_execution 無し）DOM 候補は matched にならない。
- T2b（resurrection 回帰）: parked record + ブラウザ証拠 finding → `revisit` 経由 needs_more(budget_used=0) 復活 → DOM 再実行 matched → CONFIRMED（`resurrection_count==1`）。トリガー非一致 parked は復活しない。`resurrection_history` 消費済みは再復活しない。_park 側 trigger に browser-evidence トークンが載ること。
- `validate_xss_sync` 単体（running loop 無し/あり）も追加。

### 検証結果（実装フェーズ）

- 対象スイート: `test_sealed_reproduction_checker.py` + `test_t3_hybrid_wiring.py` + `test_candidate_lifecycle.py` + `test_candidate_ledger.py` + `test_poc_judge_browser_evidence.py` + `test_hybrid_verdict_selfcheck.py` + `test_playwright.py` + `test_browser_pool_verification.py` + `test_xss_dom_routing.py` + `test_playwright_unit.py` + `test_playwright_proxy_availability.py` → **216 passed / 2 failed**。失敗 2 件は HEAD 既知（`test_validate_xss_success`・`test_pool_exhaustion_handling`）のみで、本変更由来の新規失敗ゼロ。
- バー3点 `git diff --quiet HEAD` exit=0（payout_grade / poc_judge / task_queue）。`finding_validator.py` は `_build_user_payload` のみ変更（判定ルール L200-233 無改変を diff で確認）。
- 製品非依存 `check_vdp_product_independence.py`（production スコープ）: verdict=pass・token_hits=0。
- 参考ルール: `rules/lessons.md` / `rules/codingrules.md` / `rules/python-tests.md` / `rules/task-ledger.md`。

## 2026-08-21（追加修正・実走行診断を受けて）

実走行で「単独では confirmed=0」と判明。真因は承認範囲の外（poc_judge が実発火証拠を見ていない）＋ resurrection のフィールド食い違いバグ。C3 を (b) で拡張（承認済み・計画書反映済み）。基準は下げない・カーブフィッティング禁止・偽陽性の最終防波堤は reproduction gate。

### 変更1（C3(b)・真因）: poc_judge に実発火証拠を可視化

- `src/core/validation/finding_validator.py` の `PoCJudge._build_user_payload`（L425-448）に `browser_execution` キーを 1 つ追加。事実サブフィールドのみ写像: executor / event / variant / dom_mutation_observed / dialog_observed / test_url（dict でなければ None・証拠なしを捏造しない）。判定ルール(200-233)・閾値・poc_judge.md プロンプト本文は無改変（diff で確認）。期待答え・製品名・「本物」等のヒント文言は入れない。
- T5（新規 `tests/core/validation/test_poc_judge_browser_evidence.py`）: `_build_user_payload` の出力 JSON に browser_execution 事実サブフィールド、dict でない場合は None、stub judge での入力受領検証、ブラウザ証拠無し・反射なし候補は従来どおり賞金級にならない（偽陽性回帰）。

### 変更2（スキーマ食い違いバグ）: resurrection の browser-evidence 判定

- `src/core/agents/swarm/injection/manager.py` の `_t3_browser_evidence_trigger` を実スキーマに拡張: `dialog_observed` truthy **または** `dom_mutation_observed` truthy **または** `event == "dom_sink_reflection"` のいずれかで browser 実行証拠あり → `[("evidence","browser_execution")]`。それ以外は `[]`。従来は `dialog_observed` のみ判定で、実 finding（dom_mutation_observed:true・event:"dom_sink_reflection"・dialog_observed キー無し）で常に空振りしていた。`_t3_resurrection_information` は本 helper を利用するため追加変更なし。
- T2b改（`tests/core/agents/swarm/injection/test_t3_hybrid_wiring.py`）: dom_mutation_observed:true（dialog_observed 無し）finding で trigger 非空 → parked XSS record が revisit 経由 needs_more(budget_used=0) 復活・再判定 → DOM 再実行 matched → CONFIRMED。トリガー非一致 parked は復活しない。event="dom_sink_reflection" 単独でも証拠あり。

### 追加修正後の検証

- T5・T2b改 を含む対象スイート: **216 passed / 2 failed（HEAD 既知のみ）**。
- バー3点 exit=0、finding_validator は `_build_user_payload` のみ変更。
- 製品非依存（production スコープ）: verdict=pass / token_hits=0。

### 次アクション

- Claude 独立検証: バー diff（3点 exit0・finding_validator は _build_user_payload のみ）→ ユニット T1/T2/T2b改/T5 + 回帰 → 再走行（Caido 8081・SHIGOKU_T3_HYBRID_ENABLED=1）で DOM XSS が poc_judge を通過し reproduction に到達 → 実ページで dialog が出れば confirmed / 出なければ REFUTED（どちらも正しい・偽陽性を作らない）。正本 session/report で verify_report_session_consistency consistent/rerun=false → 製品非依存 pass/token0 → ledger 遷移確認。確認後に commit（検証後）・push（ユーザー）。
- C1 確認後に本タスクを `done` 化し、work_report を作成する。
