---
task_id: SGK-2026-0470
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-02_sgk-2026-0468_unauth-probe-custom-header-scheme.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-07_sgk-2026-0470_llm-in-loop-latency-reduction_work_report.md
- docs/shigoku/worklogs/2026-09-07_sgk-2026-0470_llm-in-loop-latency-reduction_work_log.md
created_at: '2026-09-03'
updated_at: '2026-09-07'
tags:
- shigoku
- performance
- llm
- robustness
---

# SGK-2026-0470 計画 — AI 逐次判断の遅延削減（フル走行の高速化）

## 目的（何を・なぜ）

フル自律走行が低速（数時間規模）で、実戦の使い勝手と認証トークン失効 [[SGK-2026-0469]] との競合を
悪化させている。当初は「一手ごとの decide ループ」を主因と仮説したが、既存テレメトリの測定で
**主因は poc_judge（候補妥当性判定 AI）の大量呼び出し（全 AI 往復の 68〜80%）**であることが判明した（下記「事実」）。
本タスクは凍結バー・AI 判定基準を一切変えず、呼び出し側で「無駄な AI 判定を減らす」ことで高速化する。

## 事実（測定で確定・当初仮説の訂正）

**測定方法**: 既存テレメトリ（RunLedger の `llm_called` イベント）を run_id 単位で集計（新規計装なし・
実走行台帳2本）。当初計画は「一手ごとの decide ループが遅さの主因」と仮説していたが、実データで覆った。

- **AI 往復の主因は poc_judge（候補妥当性判定 AI）の大量呼び出し**:
  - run 36f88cad（09-01・~2h50m）: llm_called 合計 272 回中 **poc_judge 217 回（80%）**。他: xss 18・swarm_manager 14・planner 14・sqli 9。
  - run 04f64975（08-31・~3h20m）: llm_called 合計 398 回中 **poc_judge 269 回（68%）**。他: sqli 90・planner 17・swarm_manager 13・xss 9。
- **候補の氾濫が poc_judge を押し上げる**（candidate_ledger.json 190 件）:
  - 内訳 cors 150（79%）・sqli 30・xss 8・broken_access_control 2。状態 confirmed 28・refuted 8・needs_more 139・parked 15。
  - CORS は「機微データ漏えい未証明は確定に上げない」既知の safe-hold（CLAUDE.md）。確定不能な候補が大量生成され、
    パスごとに再 AI 判定される（needs_more は毎パス無条件で再判定・budget_used cap は max 3）。
- **重複排除はレポート時のみ**（`haddix_formatter._candidate_dedup_key`・SGK-2026-0464）＝全候補を判定した後に集約。
  判定コスト（poc_judge 往復）は氾濫したまま消費されている。
- 副次: sqli の decide 往復（片方の走行で 90 回）は既存の決定論発火フラグ `sqli_firing_path_enabled`（既定OFF）で低減余地。

## 対象（in scope・確定）

呼び出し側（`manager.py` / `candidate_lifecycle.py`・いずれも非凍結）のみを変更。凍結 5 ファイル
（`payout_grade.py` / `poc_judge.md` / `task_queue.py` / `finding_validator.py` / `sealed_reproduction_checker.py`）
と AI 判定基準は一切変更しない。共通の「判定用証拠フィンガープリント」（poc_judge が実際に見る証拠
= vuln_type・evidence(method/url/status/body)・poc_request/response・impact・reproduction_steps・browser_execution）を鍵に:

1. **Lever 1 — 判定重複排除（confirm-gated・intra-pass）**: SGK-2026-0464 と同型の root-cause 署名
   （vuln_class・エンドポイント(クエリ/fragment除去)・method・parameter、authz/cors は scenario/class 変種）で候補をまとめ、
   各署名グループの最強代表（severity/has_poc/confidence）を先に AI 判定する。**代表が confirmed になったグループのみ、
   同署名の残りをスキップ（同一 root-cause は 1 件確定で十分）**。代表が confirmed にならなければ同署名の残りも従来どおり判定する
   （＝確定するはずの候補を判定前に捨てない）。制御 A/B（下記）で「代表のみ判定」の素朴版は confirmed を落とすと実証されたため
   confirm-gated に是正した。
2. **Lever 2 — 再判定抑制（cross-pass）**: `_t3_apply_hybrid_verdict` で、needs_more 記録の証拠フィンガープリントが
   前回判定時と同一（新証拠なし）なら再 AI 判定をスキップ（記録は据え置き）。証拠が変われば従来どおり再判定する。
   同一証拠で AI を振り直して却下を覆すのは既存の no-gaming 方針と一致（識別子: line 1277-1278）。

両レバーとも**新規 settings フラグで既定 OFF**（ON 明示時のみ発火・OFF 時は byte-identical）。

## 完了条件（確定）

- 両フラグ OFF で既存走行が byte-identical（回帰なし）。
- 制御 A/B（実走行 04f64975 の本物の候補110件＋台帳の実判定結果を固定入力・実コード直接呼び出し・新規LLM呼び出しゼロ）で
  **poc_judge 往復回数が有意に減少**（実測 246→82・66.7%減）し、かつ **confirmed 件数・分類が非回帰**（confirmed 消失 0）、
  candidate は「同一 root-cause の重複排除による正当な減少」以外の欠落がない（＝真の脆弱性クラスを 1 件も落とさない）。
  素朴版 Lever 1（代表のみ判定）は同条件で confirmed を1件落としたため不採用、confirm-gated 版で消失 0 を再実証済み（2026-09-07・制御A/B）。
- 確定バー 5 ファイル `git diff --quiet HEAD` exit 0・製品非依存 token 0・`validate_shigoku_docs.py` 0 エラー。
- 追加ユニットテスト（フィンガープリント一致でスキップ／不一致で判定／署名重複排除で最強代表選択・非回帰）緑。

## NOT in scope

- 確定バー 5 ファイルの改変・AI 判定基準の変更。
- root-cause 署名を超えた積極的な候補間引き（別パラメータ/別 method を潰す等）＝検出網羅性の犠牲（カーブフィッティング禁止）。
- decide ループ本体の再設計・キャッシュ層の新設（今回は poc_judge 主因に集中）。
- 認証寿命管理そのもの（[[SGK-2026-0469]]）。
