---
task_id: SGK-2026-0477
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/reports/2026-09-09_sgk-2026-0477_xss-browser-execution-confirmation_work_report.md
- docs/shigoku/worklogs/2026-09-09_sgk-2026-0477_xss-browser-execution-confirmation_work_log.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/plans/done/2026-09-09_sgk-2026-0476_jwt-alg-none-forgery-confirmation.md
tags:
- shigoku
- detection
- xss
- dom-xss
- confirmation-bar
created_at: '2026-09-09'
updated_at: '2026-09-09'
---

# SGK-2026-0477 計画 — 反射型/DOM型XSS を実ブラウザ発火で「本物確定（◎）」まで到達させる

## 目的（何を・なぜ）

検出能力マップ [[sgk-2026-0465]] で反射型/DOM型XSS は「○ 配線済み・発火経路は保存型と共通」。
実対象 Juice Shop で本物確定（◎）へ引き上げる。保存型XSS は既に ◎。

## 事実（実測・実コードで確定・2026-09-09）

- **実 Juice Shop に発火する DOM XSS が実在**（GET ナビゲーションで実測・実ブラウザで alert 発火）:
  `#/search?q=<iframe src="javascript:alert(...)">` / `?q=<img src=x onerror=alert(1)>` で search の
  innerHTML sink が発火し、実 Playwright で dialog を観測。
- **再現チェッカーは DOM/stored のブラウザ再実行を既に持つ**（SGK-2026-0455/0457・sealed_reproduction_checker.py:333-352）:
  `additional_info.browser_execution` の variant が dom/stored かつ test_url があれば、マーカー種別に関係なく
  PoC/revisit URL を実ブラウザで再ロードし alert 再観測で matched。→ **A②（再現）は改変不要**。
- **エンジン smart_xss は browser_execution/impact/reproduction_steps を Finding に設定済み**
  （smart_xss.py: `_build_xss_impact`/`_build_xss_reproduction_steps`・958-984 で browser 実行検証時
  `evidence.response_status=200`・additional_info に browser_execution）。→ **B（エンジン）は改変不要**。
- **唯一の壁（実測で確定）**: `payout_grade._match_firing_marker` の xss 分岐（payout_grade.py:459-467）は
  「本文に `_XSS_MARKERS` 出現」または `info.get("reflection_observed")` のときだけ `reflected_payload` を返し、
  **実ブラウザ発火（`browser_execution.dialog_observed`）を一切考慮しない**（payout_grade に browser 参照 0）。
  DOM XSS はペイロードが URL フラグメント由来で HTTP 本文に出ないため発火せず、`payout_grade=False /
  no_firing_marker` で止まる（ハンドメイドの browser-fired DOM finding で実測確定）。

## 対象（このタスクで触るファイル）

- **A（凍結・ユーザー明示承認済み・2026-09-09）** `src/core/agents/swarm/injection/payout_grade.py`
  - `_match_firing_marker` の xss 分岐に、**`additional_info.browser_execution` が dict で
    `dialog_observed` が真（＝実際にスクリプトが実行された）**のとき `reflected_payload` を返す条件を追加する
    （マーカーは既存 xss 語彙 `reflected_payload` を流用＝再現側は既存 DOM 経路でそのまま動く）。
  - 既存の本文反映（`_XSS_MARKERS`）／`reflection_observed` 経路は不変。`browser_execution` 不在 /
    `dialog_observed` 非真は従来どおり（本文反映が無ければ None＝fail-closed）。
  - **実ブラウザ発火は本文反映より強い証拠**であり、これは能力追加であって敷居低下ではない。

## 確定バー（凍結・本タスクでは無改変）

- `sealed_reproduction_checker.py`（DOM 再実行を既に具備）・`poc_judge.md` / `task_queue.py` /
  `finding_validator.py` は無改変（`git diff --quiet HEAD` exit 0）。
- エンジン `smart_xss.py` も無改変（browser_execution/impact/repro/status を既に設定）。

## 完了条件（完了契約）

1. A: browser-fired XSS finding（`additional_info.browser_execution.dialog_observed` 真・本文反映なし）に対し
   `evaluate_payout_grade` が `payout_grade=True / marker=reflected_payload` を返す。逆に `dialog_observed`
   非真かつ本文反映なしでは `payout_grade=False`（fail-closed）。本文反映あり/`reflection_observed` は従来どおり発火。
2. `finding_validator.validate_finding` に browser-fired DOM XSS finding＋AI賞金級＋再現 matched
   （DOM ブラウザ再実行・既存）を与えると `CONFIRMED / hybrid_confirmed` に到達する。
3. 凍結: 改変は `payout_grade.py` のみ。`sealed_reproduction_checker.py` / `poc_judge.md` /
   `task_queue.py` / `finding_validator.py` と `smart_xss.py` は `git diff --quiet HEAD` exit 0。
4. 製品非依存 token 0（denylist）。テスト fixture は target.example 等・汎用 XSS ペイロードのみ。
5. **実対象での ◎ 実証**: 認可対象 **Juice Shop** の search DOM XSS（innerHTML sink）に対し、実エンジンの
   browser 実行検証→dialog 発火→`payout_grade=True/reflected_payload`→再現 DOM ブラウザ再実行 matched→
   `CONFIRMED`（GET-only・証拠は合言葉マスク）。
6. **非回帰**: 既存の本文反映 reflected XSS・保存型XSS（reflected_payload 本文経路）の ◎ が維持される。

## 必須テスト

- `payout_grade` 単体: (a) browser_execution.dialog_observed 真＋本文反映なし→True/marker=reflected_payload、
  (b) dialog_observed 非真＋本文反映なし→False、(c) 本文に `_XSS_MARKERS`→従来どおり True（非回帰）、
  (d) reflection_observed→従来どおり True（非回帰）、(e) browser_execution が dict でない/空→False。
- 統合: `validate_finding` が browser-fired DOM XSS 本物証拠＋AI賞金級＋再現matched で CONFIRMED。
- injection + validation スイート非回帰（保存型XSS の既存テスト緑維持）。
- 変更後 `python3 scripts/sync_shigoku_updated_at.py` → `python3 scripts/validate_shigoku_docs.py` が 0 エラー。

## NOT in scope

- 確定バーの敷居低下・見かけだけ通す curve-fitting。
- `smart_xss.py` / `sealed_reproduction_checker.py` / `poc_judge.md` / `task_queue.py` /
  `finding_validator.py` の改変（すでに DOM を支えており不要）。
- XSS 以外の種別。dialog 非観測（DOM mutation のみ等）の弱い証拠での ◎ 昇格。

## リスク

- 凍結 `payout_grade.py` の xss 語彙拡張＝実ブラウザ発火を発火信号に加える。**能力追加であり敷居低下ではない**
  （本文反映より強い証拠）ことを、dialog 非観測＋本文反映なしの fail-closed テスト（完了条件1b/e）で担保する。
- 既存 reflected_payload 本文経路・保存型XSS の ◎ を壊さないことを非回帰テストで担保する。

## 実装・検証の分担

- 実装は DeepSeek/opencode に**テキストで**指示（ドキュメント化しない）。opencode は fixer サブエージェントの
  makora フォールバック対策として repo opencode.json に一時 agent→deepseek 上書きを入れて起動し完了後復元
  （[[opencode-fixer-subagent-makora-fallback]]）。
- 完了報告は額面通り信用せず、Claude が独立検証（テスト実出力・diff・凍結残り4＋smart_xss 無改変・実 Juice Shop
  DOM XSS E2E・fail-closed 否定側）。
