---
task_id: SGK-2026-0455
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-18_sgk-2026-0454_xss-dom-runtime-firing-path.md
- docs/shigoku/plans/2026-08-21_sgk-2026-0456_xss-dom-fragment-firing-path.md
created_at: '2026-08-20'
updated_at: '2026-08-22'
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

## フェーズ0 診断結果（2026-08-20 完了・承認済み）

実データ（正本 session `session_20260820_023313.json` / `candidate_ledger.json`）とコードで確定。参照ルール: `rules/lessons.md`（一ファイルの挙動を仕様と断定しない・sealed run の REAL target 到達検証）。

### 結論：真因は「F3 昇格ロジック(risk_not_met)」ではない

- funnel（`finding_funnel_trace.py:5-16`, `manager.py:399-402`）は**測定専用で検出・確定を一切変えない**。計画書の当初 hypothesis「risk_not_met が原因」は funnel の見かけであり否定。early-return path は finding を捨てず `return SwarmResult(findings=phase1_findings,...)`（`manager.py:3431`）で返している。
- 真因は **2段のブロック**。

### ① 【バー外・配線漏れ】parked 済み record が再評価されない
- 当該 DOM XSS `512d98c4bde8` は**過去 run(02:07)の貧弱証拠**で `inconclusive_parked`（terminal）。ledger evidence に「本文に反射・実行痕跡なし / impact 空欄 / reproduction_steps 空配列」が残存、`promise_score=0.333`（3条件中1）。
- SGK-2026-0454 で発火経路が修正され、今の finding は `browser_execution.dialog_observed=true`・impact・実行痕跡を保持。しかし terminal record は再判定スキップ（`manager.py:1181`「already terminal/parked: skip judgement entirely」）。
- 復活機構 `resurrect_matching`（`candidate_lifecycle.py:283`）は**実装済みだが呼び出し元ゼロ＝未配線**（src/tests/scripts 全走査で caller 0件）→ parked record は永久に復活しない。今回 run(02:33) は ledger 未更新（mtime 02:07）・session に hybrid 判定痕跡ゼロ。
- 未確定(hypothesis)：今回 run で hybrid が完全 off だったか parked-skip だったかは session 痕跡のみでは断定不可（過去 run で SQLi confirmed=1 = 有効化経路は存在）。

### ② 【バー内・原理的非互換】reproduction gate が DOM XSS を却下する
- `sealed_reproduction_checker.check()`（`sealed_reproduction_checker.py:215-312`）は PoC を **HTTP GET で1回再送し、サーバー応答本文**の firing marker で判定。
- DOM XSS payload は `.../#/search?q=<img ... onerror=alert(1)>` で **`#`以降はサーバーに送信されない**（ledger request_url も `/?q=...` とハッシュ落ち）→ 本文に反射せず marker 非検出。`reflected_payload` は `_NON_BODY_MARKERS`(=`authz_diff`のみ) に含まれず body 検査対象 → `mismatched` → `finding_validator.py:227-228` で **REFUTED（却下）**。
- `browser_execution.dialog_observed` は reproduction checker から**一切参照されていない**（grep 0件）。
- 一方 payout_grade(floor) は今の finding なら通る見込み（`reflection_observed=true`→`reflected_payload`、impact 充足 — `payout_grade.py:294-301`）。

### 是正方針（2026-08-20 ユーザー承認・案A）
本物のブラウザで発火する DOM XSS は現行バーでは（証拠がどれだけ強くても）confirmed 到達不可の構造。基準を下げない形で reproduction gate を拡張することをユーザーが承認（案A: 確定時にブラウザ再実行）。

## フェーズ0 実走行診断追記（2026-08-21・案A実装後の実走行で判明）

案A実装（reproduction DOM経路＋resurrection配線）を Caido 8081・`SHIGOKU_T3_HYBRID_ENABLED=1` で実走行検証した結果、**単独では C1 未達（XSS confirmed=0）**。正本は整合 `consistent`/`rerun_required=false` の `sessions/session_20260821_012307.json` / `reports/haddix_report_20260821_012308.md`。真因は3点:

1. **poc_judge が実発火証拠を見ていない（真の詰まり所・reproduction より上流）**: `finding_validator.py` の判定順は フロア→poc_judge→reproduction。DOM XSS finding `41b277a8e626` は rule6 `ai_no_prize_grade` で停止し reproduction に未到達。`_build_user_payload` が poc_judge へ渡す証拠に `browser_execution` が含まれず、HTTP側証拠も弱い（`response_status=0`・本文101字）ため賞金級と判定されない。→ C3(b) で是正。
2. **resurrection のフィールド食い違いバグ**: 実 finding の証拠は `{variant:dom, test_url:…, dom_mutation_observed:true, event:dom_sink_reflection}` で `dialog_observed` キーが無い。しかし `manager._t3_browser_evidence_trigger` は `dialog_observed` を見るため常に空振り→ parked XSS が復活しない（`resurrection_count=0`）。→ 実スキーマ（`dom_mutation_observed`/`event` も許容）に合わせて修正。
3. **証拠種別の区別（偽陽性防止の観点）**: 今回の finding は `dom_mutation_observed`（DOM書換）であって `dialog_observed`（alert 実発火）ではない。①②修正後も、実ページが alert を出さなければ reproduction は正しく `mismatched`→REFUTED（confirmed にならない）＝正常動作。C1到達は「実ページで本当に dialog が出るか」に依存し、出なければ REFUTED が正しい結論。

## 完了契約（Fixed completion criteria）

- C1: Juice Shop の看板DOM XSS（`/#/search?q=` 系）が、Caido(8081)経由の実走行で **confirmed=1件以上** になる。正本 session/report を残し、`verify_report_session_consistency`（または shigoku-ops）が `consistent` / `rerun_required=false`。
- C2: 確定は**本物のブラウザ実行証拠**（実 dialog 発火／DOM 危険挿入の実観測）に基づく。反射なしの JSON 反射等を XSS と誤確定しない（偽陽性を作らない）。
- C3: **確定バーの拡張は「(a) reproduction gate のブラウザ再実行（案A・2026-08-20承認）」＋「(b) poc_judge へ渡す証拠に実発火証拠を可視化（2026-08-21・実走行診断を受けユーザー承認）」の2点のみ許可**。
  - (a) `sealed_reproduction_checker.py`: DOM XSS 用のブラウザ再実行経路（PoC URL 再ロードで dialog 再観測→`matched`／非発火→`mismatched`／送信・観測不能→`not_run`）。反射型 XSS の HTTP GET 再送経路は**無改変**。
  - (b) `finding_validator.py` の `_build_user_payload`（poc_judge へ渡す証拠の組み立て）に `additional_info.browser_execution`（`variant`/`executor`/`event`/`dom_mutation_observed`/`dialog_observed`/`test_url` 等の**事実のみ**・マスク経由）を追加してよい。**判定ルール(rule 200-233)・閾値・`poc_judge.md` プロンプト本文は無改変**。期待答え・製品名・「本物」ヒントは渡さない（カーブフィッティング禁止）。基準は下げない＝審査側に本物の強い証拠を見せるだけ。偽陽性の最終防波堤は reproduction gate（実 dialog 再観測で `matched` のみ確定）。
  - **完全無改変を維持**: `payout_grade.py` / `poc_judge.md`(プロンプト本文) / `task_queue.py(PCR-P1)`（各 `git diff --quiet HEAD` = exit0）。`finding_validator.py` は `_build_user_payload` の証拠追加**のみ**（判定ルール 200-233 が無改変であることを diff で個別確認）。
- C4: **製品非依存**：`check_vdp_product_independence.py` verdict=pass・token0。Juice Shop への焼き込み禁止。
- C5: 新規/変更のユニットテストが全 pass。既存の HEAD 既知失敗（`test_validate_xss_success`・`test_pool_exhaustion_handling`）以外に本変更由来の新規失敗が無い。

## 必須テスト（Required tests）

- T1: `sealed_reproduction_checker` の DOM 経路が、`browser_execution.dialog_observed=true` を持つ DOM XSS finding に対し確定時ブラウザ再実行で `matched` を返す（ユニット）。dialog 非発火なら `mismatched`、送信/観測不能なら `not_run`（fail-closed）。反射型 XSS の HTTP 再送経路は byte-identical で不変（既存テスト維持）。
- T2: ブラウザ実行証拠の無い（反射なし・発火なし）DOM 候補は再実行で dialog 非観測→`mismatched`/`not_run`となり confirmed にならない（偽陽性防止の回帰）。
- T2b: parked(terminal) record が、ブラウザ実行証拠の獲得を復活トリガーとして `resurrect_matching` 経由で `needs_more`(budget_used=0) に復活し再判定される（ユニット。未配線 caller の是正）。
- T3: e2e で Juice Shop の DOM XSS が confirmed=1、整合 consistent（Caido 8081 経由・実走行）。
- T2b（改）: resurrection の browser-evidence 判定を**実スキーマ**（`dialog_observed` **または** `dom_mutation_observed`／`event==dom_sink_reflection`）で発火させ、parked XSS record が `needs_more`(budget_used=0) に復活・再判定される（フィールド食い違いバグの回帰）。トリガー非一致の parked は復活しない。
- T5: `finding_validator._build_user_payload` が `browser_execution`（事実のみ・マスク経由）を含み、poc_judge が実発火証拠を見て賞金級判定に至れること（ユニット、stub judge で入力受領を検証）。**判定ルール 200-233・閾値・プロンプトは無改変**。ブラウザ証拠の無い反射なし候補は従来どおり賞金級にならない（偽陽性回帰）。

## NOT in scope

- Stored/POST XSS の網羅、他種検出の追加、SGK-2026-0454 で完了済みの発火経路是正。
- 基準を下げる形の確定緩和（本物のブラウザ実行証拠の要求は維持）。カーブフィッティング（製品固有の焼き込み）。

## 実装計画（承認後・実装は DeepSeek / 独立検証は Claude）

- 実装1（reproduction gate 拡張・案A）: `sealed_reproduction_checker.py` に DOM variant 分岐を追加。`additional_info.browser_execution.variant=="dom"` の finding は、反射型の HTTP GET 再送をスキップし、**確定時に playwright で `test_url` を再ロードして dialog 発火を再観測**する。dialog 観測→`matched`、応答したが dialog 非発火→`mismatched`、送信/ブラウザ不能・budget切れ→`not_run`（fail-closed）。反射型経路（既存の HTTP GET＋本文マーカー）は分岐外で**無改変**。scope/read-only/GET-only の既存ガードは DOM 経路でも同等に適用。
- 実装2（resurrection 配線）: `resurrect_matching` を実際に呼び出す。ブラウザ実行証拠の獲得（`dialog_observed=true` の付与）を復活トリガー（new_information トークン）として parked record を `needs_more`(budget_used=0) に復活させ、改善証拠で再判定させる。blind-retry 防止（`resurrection_history` の消費）は維持。
- 検証（Claude 独立）: T1/T2/T2b ユニット → 実走行（Caido 8081, Juice Shop 3000）で C1(confirmed>=1) → `verify_report_session_consistency`（または shigoku-ops）で consistent/rerun_required=false → `check_vdp_product_independence.py`(C4)。DeepSeek 報告は額面で信用せず、実 session/report と ledger を私が直接確認する（過去2回の誤診断を踏まえ）。

## ガードレール

- カーブフィッティング禁止・確定基準を下げない・製品非依存を維持。
- GET 中心の境界、機微データ抽出禁止、秘密の生値を成果物に残さない。
- Caido は 127.0.0.1:8081（8080 は SearXNG）。Juice Shop は http://localhost:3000。
- 実装は DeepSeek、独立検証は Claude（実 session/report＋整合チェッカ）。commit は検証後、push はユーザー。
