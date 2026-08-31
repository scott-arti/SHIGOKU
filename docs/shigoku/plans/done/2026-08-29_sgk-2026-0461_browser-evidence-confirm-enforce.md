---
task_id: SGK-2026-0461
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/2026-08-22_sgk-2026-0459_active-save-sink-discovery.md
- docs/shigoku/plans/2026-08-28_sgk-2026-0460_cross-target-state-isolation.md
- docs/shigoku/reports/2026-08-28_sgk-2026-0460_caido-origin-isolation_work_report.md
created_at: '2026-08-29'
updated_at: '2026-09-01'
tags:
- shigoku
- vdp
- reporting
- gate
- evidence-quality
- xss
---

# SGK-2026-0461 計画書 — browser_evidence を根拠とした候補→確定の昇格（shadow→enforce・限定スコープ）

> **完了（2026-09-01）**: Option B（凍結バー自身の確認・browser_evidence 自動起動＋poc_judge 頑健化）を実装・検証。CB1（保存型XSS formal confirmed=1）は SGK-2026-0463 のブラウザ発火修正後の実走行（report `haddix_report_20260901_005408.md`）で達成（variant=stored・dialog_observed=True・hybrid_final_state=confirmed）。確定バー5ファイル無改変・製品非依存 token0。詳細は [[2026-08-30_sgk-2026-0463_stored-stage2-redirect-marker-fix]]。

## 目的（Objective）

実ブラウザで alert が発火した finding（`browser_execution.dialog_observed==True` または `dom_mutation_observed==True`）を、レポート/ゲートの **formal confirmed** として計上できるようにする。SGK-2026-0459/0460 の実走行で、保存型XSSは書込→再訪→**実ブラウザ発火**まで到達し finding も生成されるが、証拠品質の昇格が **shadow（無効）** のため formal confirmed=0（候補）に留まっていた。本タスクはユーザーの明示指示（gate policy 変更）に基づき、**browser_evidence を持つ finding に限って**昇格を有効化する。

## 背景・根拠（引用）

- `src/reporting/haddix_evidence_quality.py`: `HaddixEvidenceQualityValidator(mode="shadow"|"enforce")`。`enforce` で `effective_status=shadow_status`（候補→確定を実効化）。`classify_evidence_type`（:331）はブラウザ dialog/dom_mutation を `EVIDENCE_TYPE_BROWSER` に分類。
- 実走行（`127.0.0.1:5008`・run 95a2ff0f）レポート: 保存型 finding は `variant=stored`・`dialog_observed=True` を持ちつつ、`report_findings_summary.confirmed_count=0 / candidate_count=6`、当該行は Shadow 判定で `would_promote=confirmed（browser_evidence）` だが「Enforcement is disabled in shadow mode」。
- ゲート供給経路（`report_findings_summary.confirmed_count`）は現状 shadow 生成箇所を通っており昇格が反映されない。`haddix_submission_internal_formatter.py:578` には `mode="enforce"` 生成が既にあるが、これはゲートの confirmed 集計に反映されていない（別用途）。

## 方針転換（2026-08-29・Claude独立検証で判明）— A′ ではなく B を採用

ユーザーは当初 A（browser_evidence の shadow→enforce 昇格）を選択したが、独立検証で **A は実走行に効かない**ことが判明したため、ユーザー再判断で **B（凍結バー自身に確定させる）** を採用。

- 実走行セッションは **canonical VDP**（`source_kind=canonical_vdp`）。`haddix_submission_internal_formatter._get_enforced_split`（:496-505）は canonical 時に**早期 return し、証拠品質の enforce 昇格を一切通さない**（SGK-2026-0422 不変条件：確定＝台帳のみ）。
- よって DeepSeek 提案の `_enforced_split` への昇格挿入は **canonical 経路に到達せず実走行に効果ゼロ**（DeepSeek 自身が早期 return に言及しつつ効果無を看過）。**不承認**。
- canonical の確定は `additional_info.hybrid_final_state == "confirmed"`（凍結バー：payout_grade + poc_judge + 封印再現の3条件AND）由来（`:520-521`, `haddix_formatter.py:2389`）。実走行の保存型XSSは **`hybrid_final_state=None`**（dialog_observed=True でも）→ 候補。

### フェーズ0結果（B の真因・引用付き）
- 確認フロー `_t3_apply_hybrid_verdict`（`injection/manager.py:1218-1340`）は `hybrid_final_state` を設定するが、`_t3_hybrid_active()`（:1107-1115）＝**`settings.t3_hybrid_enabled`（既定 False, `settings.py:659`）** でゲート。
- 実走行ログに T3 確認（validate_finding/reproduction/poc_judge/payout）が**0件**＝確認フローが**一度も起動せず** → `hybrid_final_state=None` → canonical 候補。**これが formal confirmed=0 の真因**。
- `SHIGOKU_T3_HYBRID_ENABLED=1` で実走行すると確認フローは起動するが、(a) poc_judge（deepseek-v4-flash）の LLM 呼び出しが遅く 11分でも保存型XSS判定に未到達（ウォッチドッグ停止）、(b) judge 応答が JSON 崩れ（ValueError→retry）・`payout_grade=false` を返す不安定さを観測。→ **単純なフラグ有効化では実運用に乗らない**（性能・判定安定性・PoC証拠の充足を要確認）。

### フェーズ0 軽量ハーネス結果（2026-08-29・Claude・可否判定）
保存型XSS finding（`variant=stored`・`dialog_observed=True`・id=0d6bd9d501b3）を確認ゲートに直接投入:
- **機械フロア `evaluate_payout_grade`（決定的・LLM不要・凍結バー payout_grade.py）→ payout_grade=True / payout_grade_satisfied**。
  ＝凍結バーの**ハードゲートが実ブラウザ発火の保存型XSSを正当に prize-grade と受理**。B は正面から通る（カーブフィッティングでない）。
- 確認ロジック（`finding_validator.py:200-231`）の CONFIRMED 到達条件（3条件AND）:
  1. 機械フロア payout_grade=True … **達成（実証済み）**
  2. poc_judge（LLM）payout_grade=True・counter_evidence無・needs_human無 … 実走行で JSON崩れ/遅延/payout_grade=false の不安定さ観測（要ロバスト化）
  3. 封印再現 `checker.check(finding).status=="matched"` … stored/dom の browser re-execution 経路は既存（`sealed_reproduction_checker.py:229-245`・DOM型 confirmed=3 で実証済）。full pipeline での network_client/scope/target live 配線を要確認
- 結論: **B は達成可能**。残作業は「確認フローの有効化 + 封印再現のスコープ/対象配線 + poc_judge の安定化/予算設計」。確定バーの閾値・判定は無改変（バーは既に受理する）。

## 完了契約（B・改訂）
- CB1: 保存型XSS（実ブラウザ発火・variant=stored）が**凍結バー自身の確認**（payout_grade + poc_judge 正当受理 + 封印再現 match）を通り `hybrid_final_state="confirmed"` に到達し、canonical 経路で **formal confirmed=1**。
- CB2: 確定バー5ファイル無改変（バーの閾値・判定を緩めない）。finding 側が**バーの要求する PoC 証拠**（poc_request/response・stored 再現データ）を確実に運ぶ配線を整える。
- CB3: 実運用に乗る（判定の安定性・所要時間）。poc_judge の JSON 安定化 or 予算/タイムアウト設計。DVWA 既知安全保留は不変。
- CB4: 製品非依存 token0。新規/変更ユニット緑。

## フェーズ0（旧・A′前提／参考）

1. `report_findings_summary.confirmed_count` を最終的に決める分類経路を引用で特定する（どの formatter / どの status フィールドをゲートが読むか）。`initial_release_gate.py` / `haddix_formatter.py` / `haddix_submission_internal_formatter.py` の該当箇所。
2. その経路のどこに、`EVIDENCE_TYPE_BROWSER` の finding のみを候補→確定へ昇格する処理を、**降格を一切せず**・**設定で切替**可能な形で挿入できるかを設計。
3. DVWA 既知安全保留（5候補）への非影響を引用で確認（5候補は XSS でなく browser_evidence を持たない→本スコープでは昇格対象外）。
→ フェーズ0提出・レビュー承認後に実装。

## 完了契約（Fixed completion criteria）

- C1: `browser_execution.dialog_observed==True`（または `dom_mutation_observed==True`）を持つ finding のみ candidate→confirmed へ昇格。他の evidence type（real_http/timing/oob/detector 等）は不変。
- C2: **降格しない**（既存 confirmed を candidate に落とさない）。`would_demote` 相当の作用を持たせない。
- C3: 設定で切替可能（既定は安全側。例: `config/shigoku.yaml` の evidence-quality enforce フラグ、または既存モードパラメータの config 化）。無効時は現行挙動（shadow）と完全一致。
- C4: **DVWA 既知安全保留の baseline を壊さない**。`haddix_report_20260727_095226.md` 等に対し `scripts/check_initial_release_gate.py` を実行し、5候補が confirmed に昇格しない・reason code 不変であることを確認。
- C5: 確定バー5ファイル無改変。製品非依存 token0。新規/変更ユニット全 pass、既存ゲート関連テスト緑。
- C6: 有効化状態でのフル走行（クリーン練習台 `127.0.0.1:5008` 保存型XSS）で、当該 finding が **formal confirmed=1**（variant=stored・dialog_observed=True）に計上され、consistency=consistent。混入0維持。

## 実装記録（2026-08-29・B 実装済み・バー無改変）

フェーズ0の結論どおり、B を実装した（詳細は `reports/2026-08-29_sgk-2026-0461_option-b-confirm-enforce_work_report.md`・`worklogs/2026-08-29_sgk-2026-0461_option-b-confirm-enforce_work_log.md`）。

- **確認フロー起動**: `settings.t3_hybrid_browser_evidence_auto`（既定 True・kill-switch）を追加。`_t3_run_hybrid_pass` は browser_evidence を持つ finding が実在するときのみスコープ起動し、判定対象を browser_evidence finding に限定（通常走行を過負荷にしない。browser_evidence 無しは従来 OFF と byte-identical）。明示 override / kill-switch は fail-closed。
- **封印再現**: SealedReproductionChecker 構築に `masker=get_pii_masker()` を配線（network_client/scope/time_budget は SGK-2026-0452 済み配線を維持）。stored/dom の browser re-execution はバー無改変の既存経路。
- **poc_judge 頑健化**: 新規 `poc_judge_robust.py` — per-call timeout 90s 強制・JSON 救済（フェンス/前後散文/先頭オブジェクト）・ValueError のみのバウンド付きリトライ（正当な却下は再試行しない）・明示予算 6コール/480s（11分ループ防止）。判定緩め禁止。
- **検証（実出力）**: 対象ユニット 105 passed / 広域 791 passed（失敗2件は環境依存の既知） / BAR_UNCHANGED / DVWA gate fail（candidate_above_maximum・5候補 reason code 不変） / consistent / 製品非依存 pass・token0。
- **CB1 は未達（pending）**: 実走行（127.0.0.1:5008・Caido）は環境停止中につき本ターン未実施。ユーザー（Claude）の実走行検証で最終確認。**注意**: 実 judge は過去実データで保存型XSS（0d6bd9d501b3）に `ai_no_prize_grade`（パース成功・payout_grade=false）を返した実績があり、judge の正当受理が CB1 の前提（再ロール・判定緩めは禁止）。

## NOT in scope

- 確定バー5ファイルの変更。検出側（smart_xss / injection）ロジックの変更。
- browser_evidence 以外の evidence type の昇格。降格ロジックの導入。
- SGK-2026-0459/0460 の検出・隔離・ノイズ整理（実証済み・不変）。

## ガードレール

- カーブフィッティング禁止・確定基準（検出側の発火判定）を下げない・製品非依存維持。
- 全ターゲットのゲートに影響する変更のため、DVWA 既知安全保留と既存ゲートテストでの回帰確認を必須とする。
- 破壊的操作前に対象を確認。commit は検証後・push はユーザー。Caido=127.0.0.1:8081。
- コーディングは DeepSeek、Claude が独立検証（DVWA baseline + gate scripts + 実走行）。

## Claude 独立検証結果（2026-08-29・B実装受領後）

DeepSeek のB実装報告を額面通りにせず独立再検証した。

- 凍結バー5ファイル: `git diff --quiet HEAD` = **exit0（無改変）**。
- 新規/変更コード: `settings.py`（kill-switch `t3_hybrid_browser_evidence_auto`）・`manager.py`（`_t3_browser_evidence_auto_active` スコープ起動＋既定 RobustPoCJudge＋予算＋masker配線）・新規 `poc_judge_robust.py`（per-call 90s / JSON救済 / パース失敗のみ bounded retry / fail-closed）を精査。報告と一致。
- 単体: `test_poc_judge_robust.py` + `test_t3_hybrid_wiring.py` = **57 passed**（新規18含む：browser_evidence 無→OFF byte-identical、スコープ限定、正当却下の非再試行、fail-closed）。
- **製品非依存: DeepSeek 報告は「token0」だが実測で hit=1 を検出** — 新規テスト `test_poc_judge_robust.py:36` に `/vulnerabilities/`（DVWA固有）混入。Claude が汎用パス `/app/...` へ中和 → 再実測 **verdict=pass / token_hits=0**。
- DVWA 既知ベースライン: `check_initial_release_gate.py` = **status=fail / candidate_above_maximum**（既知安全保留・不変）。
- docs: `validate_shigoku_docs.py` = **0 issues**。
- 広域回帰: `injection/` + `validation/` = **791 passed / 2 failed**。失敗2件は `test_phase_b_readiness.py`（workspace 成果物ファイルの存在チェック）で本変更と無関係・環境要因。

### CB 判定（現時点）
- CB2（バー無改変・配線）: **達成**。CB4（token0・ユニット緑）: **達成（Claude が token 混入を修正後）**。CB3（予算/タイムアウト・DVWA不変）: **配線・回帰は達成**、実運用安定は実走行で最終確認。
- **CB1（formal confirmed=1）: 未達**。理由(1) 実走行環境（練習台5008 / Caido8081 / Juice Shop）が全停止で本ターン実走行不可。理由(2) 過去実データで当該保存型XSS ledger は `ai_no_prize_grade`（poc_judge が payout_grade=false）。本実装は「判定への到達の頑健化」であり判定結果は変えない → judge が正当に受理しない限り confirmed=1 にはならない（fail-closed が正しい）。
- 結論: **SGK-2026-0461 は active 継続**。実走行で judge が受理 → confirmed=1 を実証できれば done。judge が false のままなら「PoC証拠（poc_request/response・stored再現データ）の表現改善」を別タスク化して再判断。

## 実走行結果（2026-08-30・練習台5008・Caido8081・Juice Shop起動下）

- run: session_20260830_002046 / report haddix_report_20260830_002048.md。整合性 `verify_report_session_consistency.py` = **consistent**。
- 結果: **Confirmed: 0 / Candidate: 13**（全件 xss on 'comment'・evidence_type=`real_http`・reason_code=`browser_execution_missing`）。
- 監視・ログ・練習台アクセスログの直接確認により **第2段階（ブラウザ発火＝保存型再訪検証 `_attempt_stored_revisit_validation`）が一度も起動していない** ことを確定:
  - 練習台アクセスログ: 第2段階固有の良性マーカー POST（`sgk<hex>`）= **0件**（phase1 検出の書込POST〔メタ付き `?method=GET&...&detection_mode=phase1`〕は多数）。
  - よってブラウザ dialog 証拠が一切生成されず、B の browser_evidence 自動確認フローは**受理対象ゼロ**で不起動 → Confirmed 0 は正しい fail-closed。
- **CB1 未達の真因（今回特定・引用付き）**: `smart_xss.py:1248-1252` の第2段階ゲートは `method in (POST/PUT/PATCH) and params["revisit_candidates"] and not params["reflection_url"]`。save-endpoint サイドカー `scans/raw/20260829_recon_save_endpoints.json` は `/comment` POST・`revisit_urls=[".../"...]` を**正しく保持**するが、**canonical VDP 走行の injection タスク文脈に revisit_candidates（＝サイドカー由来）が配線されず**、ゲート不成立で第2段階が飛ぶ。manager 分類ログでも `/comment` が `api`/`xss` に分散し `method:POST` タスクでも第2段階マーカーPOSTが出ていない。
- 位置づけ: これは **検出/オーケストレーション側（canonical パスの save_endpoints→revisit_candidates 配線）** の課題であり、**確定バー5ファイルにも B の確認フローにも属さない**。現行 0461 計画の NOT in scope（「検出側 smart_xss/injection ロジックの変更」）に該当 → **スコープ拡張 or 新規タスクの判断が必要**。
- B 実装自体（確認フロー起動＋poc_judge頑健化＋masker配線）は上記ユニット/回帰/token0/バー無改変で**検証済み・健全**。ただし CB1（実確定1件）は browser 証拠が到達しないため未達のまま。
