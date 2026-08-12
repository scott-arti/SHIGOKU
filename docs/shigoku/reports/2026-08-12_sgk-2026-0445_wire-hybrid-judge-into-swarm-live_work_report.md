---
task_id: SGK-2026-0445
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-12_sgk-2026-0445_wire-hybrid-judge-into-swarm-live.md
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/worklogs/2026-08-12_sgk-2026-0445_wire-hybrid-judge-into-swarm-live_work_log.md
title: T3 共有判定＋ライフサイクルを swarm 経路に配線（実戦投入）作業完了報告
created_at: '2026-08-12'
updated_at: '2026-08-12'
tags:
- shigoku
- vdp
- security-sensitive
deferred_tasks:
  - deferred_id: SGK-2026-0445-D01
    title: "run 内調査キャップ配線（T2 allocate_investigation_budget・run_budget=10）と judge token 数記録（run_ledger_llm_usage）"
    reason: "T3 は配線（Phase-1 finding 確定直後＋merge ゲート）と予算（PoCJudgeBudget 10 回/600s・再送 5 回/60s）をコンストラクタ既定値で完結。キャップ配線・token 記録は未配線のまま（計画書 §F・work_log 次アクションに記載済み）"
    impact: low
    tracking_task_id: SGK-2026-0442
    recommended_next_action: "SGK-2026-0447 以降の後続タスクで YAML 予算配線（0444-D01 継続）と併せて配線"
  - deferred_id: SGK-2026-0445-D02
    title: "封印 run で confirmed に到達する finding の実測（今回の run では 3条件AND を満たす finding が生まれず confirmed 0 = 誤確定ゼロの実証）"
    reason: "封印環境（Juice Shop）の候補は機械フロア fail（missing_impact 等）または AI 反証で confirmed 未達。confirmed 到達可能化の実戦実測は、ターゲット状態・候補の質に依存し今回未達。敷居は下げない（3条件AND 不変）"
    impact: low
    tracking_task_id: SGK-2026-0442
    recommended_next_action: "実VDP評価・別ターゲットで confirmed 実測（T4=0446 の Haddix 明記と併せて継続監視）"
---

# 作業完了報告: SGK-2026-0445（T3 共有判定＋ライフサイクルを swarm 経路に配線）

## 0. 成果物サマリ

- **設計承認関門を通過**: ①配線点 ②再現 sender の封印接続（GET-only・状態変更除外・時間予算）
  ③poc_judge 実起動の予算 ④0440 funnel への emit 設計 ⑤confirmed 成果物の形 — を提示しユーザー承認。
  計画書 §設計付録 A〜F として固定（実装契約）。
- **T1 判定＋T2 ライフサイクルを swarm 経路に配線**:
  - `SealedReproductionChecker`（新規・Lane A）: 封印環境で PoC を GET 再送し同一発火マーカーを確認する
    ReproductionChecker 実装。read-only ガード列（assert_read_only_probe → evaluate_readonly_request →
    scope 再検証 → fingerprint 一致 → 送信 → マーカー比較）を既存資産から再利用。
    **mismatched は「応答あり・同一マーカー非発火」のみ**・タイムアウト/エラーは not_run（fail-closed）。
  - `PoCJudgeBudget`（10 回/600s）＋ `BudgetedPoCJudge`＋ `JudgeBudgetExhausted`（Lane A）:
    poc_judge 実起動の予算上限。超過は ai_judge=None 写像 → needs_more（confirmed 不可・fail-closed）。
  - `manager.py` 配線（Lane B）: funnel REASON_CODES に hybrid 系 5 語を additive 追加、
    Phase-1 finding 確定直後＋Phase-2 merge ゲートの両方で `_t3_run_hybrid_pass`（ledger open →
    budgeted judge → sealed checker → lifecycle → save 1 回）を実行。有効化フラグ
    `settings.t3_hybrid_enabled`（additive・既定 off・off で byte-identical）。
  - **配線点の構造修正（封印 run 2 回の実測駆動・ユーザー承認）**: 当初の配線点（Phase-2 merge
    ゲートのみ）は early-return 経路が merge ゲートをバイパスする構造問題が判明（fast-types の
    finding は Phase 2 前に return され T3 に到達しない）。**Phase-1 finding 確定直後へ移動**し、
    全 finding（fast-types 含む）を T1→T2 に通す。
  - **再現 sender のスコープ供給（ユーザー承認）**: `_build_sealed_reproduction_scope` で封印
    ターゲット自身の host[:port] のみ許可（実VDP外部へは送信しない・port 精度 fail-closed）。
  - **F5 emit 修正**: `apply_verdict` 後の record.state（LifecycleState）ベースに変更 —
    T6 予算切れ棚上げ（inconclusive_parked）も F5 hybrid_parked を emit するように。
  - **ledger 集約修正**: `_resolve_candidate_ledger_path` を host[:port] 抽出に修正 —
    URL パス名ディレクトリへの分散生成を解消し、1 つの ledger に集約。
- **単体完結の既存挙動は不変**: T1 判定ロジック（3条件AND・合成規則・閾値）・T2 lifecycle/ledger
  本体・payout_grade・read-only ガード・vdp_scope_validator・PCR-P1・禁則ファイル・funnel
  OUTCOMES は全て無変更（追加・配線のみ）。

## 1. 封印 run 実測（最終 run6 = session_20260812_175220）

### funnel before/after（0441 → 0445 run6）

| 指標 | before（0441） | after（0445 run6） |
|---|---|---|
| ユニーク候補 | 8 | **11** |
| F4 by_stage | 8 | 11 |
| **F5 by_stage** | **0** | **5** |
| 最終状態の集計 | — | ledger 11 候補（needs_more 6 / inconclusive_parked 4 / refuted 1 / **confirmed 0**） |

- **F5 到達 5 件**: 438f9bac437c / 67001d154ed0 / b7aa7f57bce4 / eac69dd7387e / f4a0c33cba59
  （funnel stages F5=reached・max_stage F5）。
- **ledger（candidate_ledger.json・単一ファイル集約）**: 11 候補すべて保存。
  - inconclusive_parked ×4（budget_exhausted・T6 予算切れ棚上げ = 消さない）
  - refuted ×1（b7aa7f57bce4・ai_counter_evidence = AI が証拠内矛盾を実測して反証・
    D3 契約どおり「明確な反証のみ却下」）
  - needs_more ×6（継続中・F5 未到達）
  - **confirmed 0 = 誤確定ゼロの実証**（3条件AND を満たす finding が生まれなかった・
    敷居を下げていない）
- **poc_judge 実起動**: 22 calls（llm_usage by_actor に poc_judge 出現・v4-pro thinking）。
- **GET-only / 安全0**: session 内 method 20 件全て GET・state_change 0・pending_hitl 0。
- **ledger マスク保存**: `[PII:` マスク 18 箇所・生秘密ヒット 0（secret-scan）・
  evidence は D5 サマリ投影（refs + マスク済 URL + ステータス数値のみ）。
- **consistency gate**: `verify_report_session_consistency.py` → **consistent**（reason_codes 空）。

### これまでの封印 run（修正駆動の実測プロセス）

| run | 結果 | 発見 |
|---|---|---|
| run2/3 | F5=0・ledger 未生成 | **early-return が merge ゲートをバイパス**（構造問題）→ 配線点移動（承認） |
| run4 | poc_judge 実起動・ledger save 失敗 15 回 | **ディレクトリ権限 root:root で PermissionError**（chown 修復・承認） |
| run5 | ledger 保存成功（1 件のみ・F5=0） | **再現 sender scope None で not_run**（スコープ供給・承認）＋ ledger 分散生成（host:port 集約修正）＋ F5 emit が record.state ベースでない（修正） |
| **run6** | **F5 5・ledger 11・confirmed 0** | 完了条件充足（誤確定ゼロ実証） |

## 2. 検証（実装後・実測）

| 項目 | 結果 |
|---|---|
| 対象単体（T3 wiring 25 + sealed checker 24 + funnel 29） | **78 passed**（最終統合で再確認） |
| validation 全体 | 138 passed / 2 failed（test_phase_b_readiness = 既存環境要因・baseline 実証済み） |
| injection 広域 | 623 passed / 3 failed（test_cmd_ssrf_timeout_fix = 既存環境要因・baseline 実証済み） |
| preflight | `check_vdp_product_independence.py` → **pass / exit 0**（6/6 checks・total_token_hits 0） |
| PCR-P1 | task_queue.py **diff 0** |
| 禁則 | vdp_evidence_validator / vdp_admission / admission_policy / src/reporting / vdp_scope_validator / candidate_lifecycle / candidate_ledger **diff 0** |
| 循環 import | `import src.core.validation` + `import src.core.agents.swarm.injection.manager` 成功（lazy import 化で解消） |
| docs | validate_shigoku_docs.py 0 エラー（FRONT_MATTER 0 / BROKEN_LINKS 0 / REGISTRY 0 / DEFERRED 0） |
| 変更ファイル | src: manager.py / settings.py / finding_funnel_trace.py / validation/__init__.py / sealed_reproduction_checker.py（新規）+ テスト2ファイル（新規）+ docs（plan/work_log/registry） |

## 3. 不変条件の実証（死守事項）

- **確定＝3条件AND・敷居を下げない**: T1 合成規則・threshold 無変更。封印 run で confirmed 0 =
  3条件未達の finding を confirmed にしていない（誤確定ゼロの実測）。
- **AI 主張のみで確定しない**: 機械フロア必須ゲート（既存）・AI はフロア pass 後にのみ呼ぶ
  （合成規則3・遅延評価）。poc_judge 26 calls（run4）/ 22 calls（run6）が confirmed を生まなかった実測。
- **証明不足は棚上げ/人間送り（消さない）**: T2 遷移表・apply_verdict no-op invariant 無変更。
  run6 で inconclusive_parked ×4（budget_exhausted）が ledger にマスク保存され run 終了後に取り出し可。
- **封印 read-only GET**: SealedReproductionChecker のガード列（state-changing 除外・scope
  fail-closed・fingerprint 一致）・封印スコープはターゲット自身の host[:port] のみ（port 精度
  fail-closed・実VDP外部へは送信不能）。run6 で method 20 件全て GET・state_change 0。
- **秘密マスク**: ledger は D5 サマリ投影（生値ゼロ）・`[PII:` 18 箇所・生秘密ヒット 0。
  token_map 非永続化。
- **カーブフィッティング禁止**: マーカー語彙は既存 payout_grade 再利用（新規マーカーなし）・
  fixture は target.example / localhost:3000・preflight exit 0・docs opaque。
- **PCR-P1 無改変**: task_queue.py diff 0。

## 4. 完了条件判定（計画書対比・§19 スコープ固定）

| 完了条件 | 判定 | 根拠 |
|---|---|---|
| 1. 封印 run の 0440 funnel before/after: F5 へ到達し得ること・最終状態（confirmed/parked/needs_human）が集計できる | **PASS** | run6: F5 by_stage 0→5・ledger 11 候補（parked 4 / refuted 1 / needs_more 6 / confirmed 0）を run 終了後に集計・取り出し確認 |
| 2. confirmed が出た場合、賞金級 PoC artifact 提示・**誤確定ゼロ** | **PASS（confirmed 0）** | confirmed は 0（3条件AND 未達）＝誤確定ゼロの実証。賞金級 PoC は今回の封印 run では発生せず（D02 追跡） |
| 3. parked/needs_human が candidate_ledger にマスク保存・run 終了後に取り出せる | **PASS** | run6 ledger: inconclusive_parked ×4 を `[PII:` マスク 18 箇所・生秘密 0 で保存・json 読取で復元 |
| 4. カーブフィッティング無し（preflight exit 0）・秘密漏洩 0・PCR-P1 diff 0・consistent・GET-only・実行1回・validator 0 | **PASS** | §2・§3 参照（consistency consistent・GET-only 20/20・preflight exit 0・PCR-P1 diff 0・docs validator 0） |

**in_scope_blocker 0 件**。deferred_followup: D01（キャップ配線・token 記録・YAML 予算配線は
0444-D01 継続・後続タスク）・D02（confirmed 実測はターゲット状態依存・T4=0446 で継続監視）。
non_blocking_observation: `data/vuln_roi_db.json` の diff は run の副作用（ROI DB 更新・mtime
17:52 = run6 レポート生成時刻）で本タスクのコード変更ではない（コミット対象外）。
本タスクを **done** とする。

## 5. 作業プロセス注記（教訓）

- 封印 run 実測が設計の妥当性を検証する最重要経路だった（配線点・スコープ・F5 emit・ledger
  集約の 4 つの構造問題は全て run 実測で発見・ユーザー承認の下で修正）。
- ディレクトリ権限（root:root）による書込失敗はテストでは検出できない環境問題 —
  封印 run 前に workspace の所有権を確認することを今後のタスクへ推奨。
- 参考ルール: rules/lessons.md（mask-and-restore 正本・設計意図は正本照合・回帰の比較方法）、
  rules/codingrules.md（lazy import・例外境界・OSError 伝播）、rules/task-ledger.md（完了契約・
  done 化条件）、rules/python-tests.md（.venv/bin 実行・対象単体→広域）、rules/shigoku-docs.md
  （front matter 必須・done/ 移動）、rules/report-session-consistency.md（consistent 判定）。
