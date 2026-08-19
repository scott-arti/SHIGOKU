---
task_id: SGK-2026-0455
doc_type: plan
status: active
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-18_sgk-2026-0454_xss-dom-runtime-firing-path.md
created_at: '2026-08-20'
updated_at: '2026-08-20'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- confirmation
- xss
- dom
- browser
---

# SGK-2026-0455 計画書 — DOM XSS のブラウザ実行証拠を確定まで運ぶ（confirmation routing 是正）

## 目的（Objective）

SGK-2026-0454 で XSS の発火経路は是正され、Juice Shop の看板DOM XSS は **本物のブラウザで実際に alert が発火**する（`browser_execution.dialog_observed=true`）ところまで到達した。しかしその finding は **confirmed にならず**（confirmed=0）、確定判定に到達する前に脱落している。本タスクは、この「本物のブラウザ実行証拠を持つ DOM XSS」を、**確定バーを1バイトも緩めず**に confirmed まで運ぶ経路是正を行う。

XSS 確定の厳しさ（本物のブラウザ実行証拠を要求する現行の基準）は維持する。緩めるのではなく、既に得られている強い証拠（実ブラウザでの dialog 発火）を、正当に確定判定へ届かせる。

## 現状の根拠（実測・SGK-2026-0454 で確定）

- 正本 session: `workspace/projects/localhost:3000/sessions/session_20260820_023313.json` / report: `haddix_report_20260820_023315.md`（整合 consistent）。
- 当該 XSS finding（id `512d98c4bde8`）の実際の脱落地点（`finding_funnel_v1` 実測）:
  - `first_failure_stage: F3`、`first_failure_reason: phase2_skipped_early_return`
  - `block_reasons: [no_tool_error, risk_not_met, phase2_on_empty_disabled]`
  - `max_stage_reached: F4`、F5/F6（確定判定）へ**未到達**（by_stage F5=0, F6=0）。
- finding は `additional_info.browser_execution` に `dialog_observed=true`（executor=playwright, parameter=q, payload=`<img src=x onerror=alert(1)>`, observation_logs に dialog=alert message=1）を保持。`impact`/`reproduction_steps` も実測に基づき供給済み。
- **未確認（hypothesis）**：確定できない一次原因が F3(phase2) 昇格ロジックの `risk_not_met` / `phase2_on_empty_disabled` にあるのか、あるいは仮に F5/F6 に到達しても poc_judge/finding_validator がブラウザ実行証拠を受け付けないのか、は**未診断**。SGK-2026-0454 で DeepSeek が挙げた「判定予算枯渇/poc_judge形式拒否」は funnel 実データと矛盾し否定済み。まず正確な診断から始める。

## フェーズ0（診断・実装前の必須ゲート）

コードを書く前に、実データとコードで以下を確定して提出する（lessons 2026-08：一部挙動を仕様と断定しない・根拠を引用・未確認は hypothesis 明示）。

1. F3(phase2) の昇格判定の所有モジュールと、`risk_not_met` / `phase2_on_empty_disabled` / `phase2_skipped_early_return` を出している実コード箇所（ファイル:行）を引用で特定。
2. browser_execution（dialog 発火）を持つ finding が「risk 未達」と判定される理由を、実データ（当該 finding の risk 関連フィールド）で説明。
3. 確定判定（F5/F6, poc_judge, finding_validator）が、ブラウザ実行証拠をそもそも受理し得るのか／し得ないのかを、コードで確認（受理不可なら、それはバー5点の変更を要するのか、バー外の入力構築の問題かを切り分け）。
4. 是正案：バー5点（`payout_grade.py`/`sealed_reproduction_checker.py`/`poc_judge.md`/`finding_validator.py`/`task_queue.py`）を**変更せずに**確定まで運べる経路（phase2 昇格でブラウザ実行証拠を risk 充足として扱う等）を第一候補として提示。もしバー5点の変更が不可避と判明した場合は、**基準を下げない形の設計**（本物のブラウザ発火＝強い確定根拠として正当に受理する、偽陽性ループを作らない）を明示し、**ユーザーの明示承認を得てから**着手する。

→ フェーズ0を提出しレビュー承認後に実装へ。

## 完了契約（Fixed completion criteria）

- C1: Juice Shop の看板DOM XSS（`/#/search?q=` 系）が、Caido(8081)経由の実走行で **confirmed=1件以上** になる。正本 session/report を残し、`verify_report_session_consistency`（または shigoku-ops）が `consistent` / `rerun_required=false`。
- C2: 確定は**本物のブラウザ実行証拠**（実 dialog 発火／DOM 危険挿入の実観測）に基づく。反射なしの JSON 反射等を XSS と誤確定しない（偽陽性を作らない）。
- C3: **確定バー無改変を第一目標**。バー5点 `payout_grade.py`/`sealed_reproduction_checker.py`/`poc_judge.md`/`finding_validator.py`/`task_queue.py(PCR-P1)` が個別に `git diff --quiet HEAD` = exit0。やむを得ずバー変更が必要な場合は、フェーズ0でユーザー承認を得て本契約を更新してからのみ許可。
- C4: **製品非依存**：`check_vdp_product_independence.py` verdict=pass・token0。Juice Shop への焼き込み禁止。
- C5: 新規/変更のユニットテストが全 pass。既存の HEAD 既知失敗（`test_validate_xss_success`・`test_pool_exhaustion_handling`）以外に本変更由来の新規失敗が無い。

## 必須テスト（Required tests）

- T1: browser_execution（dialog 発火）を持つ XSS finding が phase2 昇格を通過し、確定判定段階（F5/F6）へ到達する（funnel 実データまたはユニットで確認）。
- T2: ブラウザ実行証拠の無い（反射なし・発火なし）候補は従来どおり confirmed にならない（偽陽性防止の回帰）。
- T3: e2e で Juice Shop の DOM XSS が confirmed=1、整合 consistent。

## NOT in scope

- Stored/POST XSS の網羅、他種検出の追加、SGK-2026-0454 で完了済みの発火経路是正。
- 基準を下げる形の確定緩和（本物のブラウザ実行証拠の要求は維持）。カーブフィッティング（製品固有の焼き込み）。

## ガードレール

- カーブフィッティング禁止・確定基準を下げない・製品非依存を維持。
- GET 中心の境界、機微データ抽出禁止、秘密の生値を成果物に残さない。
- Caido は 127.0.0.1:8081（8080 は SearXNG）。Juice Shop は http://localhost:3000。
- 実装は DeepSeek、独立検証は Claude（実 session/report＋整合チェッカ）。commit は検証後、push はユーザー。
