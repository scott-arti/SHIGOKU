---
task_id: SGK-2026-0441
doc_type: work_report
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/plans/done/2026-08-11_sgk-2026-0441_validation-loop-modernization-payout-grade.md
- docs/shigoku/reports/2026-08-11_sgk-2026-0440_finding-pipeline-instrumentation_work_report.md
- docs/shigoku/worklogs/2026-08-11_sgk-2026-0441_validation-loop-modernization-payout-grade_work_log.md
title: 検証ループの近代化 — 見つけた候補を「賞金級 PoC」で確定させる 作業完了報告
created_at: '2026-08-12'
updated_at: '2026-08-12'
tags:
- shigoku
- vdp
- security-sensitive
target: src/core/agents/swarm/thought_loop.py,src/core/agents/swarm/base_manager.py,src/core/agents/swarm/injection/manager.py,src/core/agents/swarm/injection/payout_grade.py,src/core/agents/swarm/injection/manager_internal/execution_policy.py,config/shigoku.yaml,src/prompts/roles/poc_judge.md
deferred_tasks:
  - deferred_id: SGK-2026-0441-D01
    title: "F0 抑制キーの family 交差による別ベクトル衝突の可能性（実害は未観測）"
    reason: "0440 の3件の suppressed は真の重複と診断（同一 finding id を生成する同一経路）だが、dedup キー (url, family, ep) は family 集合が交差する別ベクトル（例: 後続 id_param タスク）も抑制し得る設計ギャップ。今回の封印 run では実害なし（suppressed_tasks=3・同一 finding id）"
    impact: low
    tracking_task_id: SGK-2026-0418
    recommended_next_action: "多段攻撃計画タスク（⑥）で suppression キーの精緻化（specialist/route 次元の追加）を検討"
  - deferred_id: SGK-2026-0441-D02
    title: "再送ループ（Phase-2 payout-grade 再検証）は未実装・assert_read_only_probe はガード関数のみ"
    reason: "承認設計のエンベロープ（検証送信 GET-only）は、新規送信経路を追加しない方針（既存 specialist 送信を再利用・時間予算と早期停止のみ追加）により構造的に充足。封印 run で GET-only を実測（session 内 method 全 GET）。再送ループが必要になった際は assert_read_only_probe を配線"
    impact: low
    tracking_task_id: SGK-2026-0418
    recommended_next_action: "⑥ で Phase-2 再検証ループを実装する場合に assert_read_only_probe を送信境界へ配線"
---

# 作業完了報告: SGK-2026-0441（検証ループの近代化・賞金級 PoC）

## 0. 成果物サマリ

- **診断（一次証拠）**: 0440 funnel で確定した F3 全滅の機構を解明。
  ThoughtLoop は Phase 2 の本体ではなく `BaseManagerAgent.dispatch`（max_turns=5）が実体。
  swarm 経路には**確定機構が存在しない**（FindingValidator ゲートはデッドコード・
  F5 エミッタはゼロ・read-only ギャップあり）。
- **実装（承認設計 ①〜⑤）**: 賞金級 PoC 判定器（fail-closed・決定的マーカー）+
  early-return 門番修正（payout-grade 済みのみ早期 return・全面 OFF にしない）+
  時間予算・payout-grade 即終了 + `poc_judge` role + should_stop 接続。
- **封印 run 実測**: funnel **F4 3 → 8**（全候補が検証段の証拠評価を受ける）+
  **Phase 2 実動**（sqli/xss の ThoughtLoop が Turn 進行・新規 sqli finding が
  poc_request/response 完備で出現）。confirmed は 0 のまま =
  impact 欠如で **fail-closed 判定により候補のまま**（敷居据え置きの実証）。

## 1. 診断結果（exp-3/exp-4・一次証拠）

| 項目 | 根拠（file:line） | 内容 |
|---|---|---|
| Phase 2 の実体 | base_manager.py:218（max_turns=5）・manager.py:2997 | ThoughtLoop ではなく BaseManagerAgent.dispatch。時間予算は wait_for のみ |
| early-return 機構 | execution_policy.py:96-128・manager.py:2761-2766 | fast_types {lfi, redirect, csrf, api} は phase1 finding ありで Phase2 打ち切り |
| swarm に確定機構なし | manager.py:3915/3960（デッドコード）・F5 エミッタ 0 | FindingValidator は呼び出しなし。confirmed は VDP 経路のみ |
| read-only ギャップ | vdp_readonly_guard.py:111-204 vs swarm 経路 | swarm thought_loop は m3a GET-only 制約の対象外（safeguard のみ） |
| F0 診断 | master_conductor.py:1677-1687（dedup キー） | 3件の suppressed は**真の重複**（同一 finding id 生成経路）。キーは family 交差で別ベクトル衝突の余地あり（実害なし） |
| role 基盤 | config/shigoku.yaml llm ブロック | reasoning_api（thinking enabled）が xss_final/final_judgement で使用済み → ①は既存パターンに乗る |

## 2. 統合設計（承認済み・死守事項の実装対応）

| 設計 | 実装 |
|---|---|
| ① 熟考・強モデル化 | `poc_judge` role 新設（profile reasoning_api = thinking enabled・reasoning_effort high・SGK-2026-0292 準拠）+ `src/prompts/roles/poc_judge.md`（製品非依存・LLM 主張のみでの確定禁止・JSON 出力） |
| ② 止め方の近代化 | base_manager.py:276-284 時間予算チェック（`phase2_time_budget_seconds`・None → legacy）+ :358-365 payout-grade 即終了（`stop_reason=payout_grade_obtained`）。thought_loop.py:59-63 時間予算・:93-98 payout-grade 即終了（additive `time_budget_exhausted` ステータス）。max_turns は安全上限として温存 |
| ③ 賞金級 PoC 判定器（新規） | `payout_grade.py`: 再現性（構造化 Evidence または poc_request/response 完備）→ 発火（カテゴリ別決定的マーカー: sql_error / reflected_payload / file_content_leak / command_execution / ssrf_callback / authz_diff）→ impact（reproduction_steps + impact 非空 または VDP マーカー）。**fail-closed**（missing_evidence / not_reproducible / no_firing_marker / unknown_category / missing_impact）・LLM 呼び出しなし・例外を投げない |
| ④ 門番修正 | `should_auto_early_return(..., payout_grade_hold)` — hold=True（未確定候補あり）で Phase 2 を回す。**全面 OFF にしない**（全 finding が payout-grade なら従来どおり速度優先） |
| ⑤ should_stop 接続 | smart_sqli:694 / smart_xss:1208 / smart_lfi:436 / smart_cmd_ssrf:1020 / actor_critic:292 に `_payout_grade_obtained()` を追加（既存停止条件は温存・攻撃本体無変更）。open_redirect は決定論的のため対象外 |
| F4/F5 emit | early-return 判定時 F4（reached / skipped evidence_insufficient）・Phase-2 merge 後 F4 reached + F5 confirmed `payout_grade_poc`（additional_info に payout_grade/reason/markers）・明示 refute 信号時のみ F5 refuted |

## 3. 封印 run 実測（session_20260811_223709・修正後）

### funnel before/after（0440 → 0441）

| 指標 | 0440（before） | 0441（after） |
|---|---|---|
| F4 by_stage | 3（auto_reverified のみ） | **8（全候補が検証段の証拠評価）** |
| max_stage_reached | F3/F4 混在 | **全エントリ F4** |
| first_failure | F3×5 / F0×3 | F3×5 / F0×3（first-failure 規約: 最も早い停止点・後の進行を上書きしない） |
| **Phase 2 実動** | なし | **sqli/xss ThoughtLoop が Turn 進行**（run_stdout で確認） |
| **新規 finding** | — | **sqli 1件**（poc_request/poc_response・sql_error_observed・blind_time_based_confirmed 完備） |
| confirmed | 0 | 0（sqli finding は impact/reproduction_steps 欠如で **fail-closed 判定により候補のまま** = 敷居据え置き・PoC 無しは確定しないの実証） |

### 不変条件の実証

- **GET-only / 安全0**: session 内 method 38 件全て GET・state_change marker 0。
- **秘密**: マスク＆復元維持（0440 funnel 機構をそのまま利用・[PII:] トークンのみ）・
  session_env 0600・ログにトークン/元値 0。
- **consistency gate**: **consistent**（reason_codes 空）。
- **preflight**: `check_vdp_product_independence.py` → **pass / exit 0**
  （11 files scanned・total_token_hits 0）。**manifest に pre-existing 2件を正規登録**
  （`/vulnerabilities/` トークンは HEAD に存在する既存コード・`git show HEAD` で検証・
  0441 の + 行ではない。smart_xss.py と同型の deferred_classified 機構・SGK-2026-0426 委譲）。
- **PCR-P1 / 禁則**: task_queue.py diff 0・vdp_evidence_validator /
  vdp_admission / admission_policy / src/reporting/ diff 0。
- **実行1回**: single-run marker・config byte-identical・runtime surface byte-identical。
- **所有権**: session 644・report 600・session_env 0600（全て bbb）。

## 4. 検証（実装後）

- 単体: payout_grade 41 passed・Lane B stop criteria + poc_judge role 18 passed・
  llm_config 46 passed・funnel 系 49 passed・主要統合 160 passed。
- 回帰: injection 全体 517 passed・swarm 全体 696 passed・広域
  tests/core/agents/swarm + tests/core/engine **38 failed / 1438 passed** は
  **0440 の失敗セットと IDENTICAL**（新規失敗ゼロ・worktree 比較で確定済みの pre-existing のみ）。
- カーブフィッティング無し: 判定器は決定的マーカー（既存専門家ヘルパー・ExploitVerifier regex 再利用）
  + 製品 token 遮断（preflight exit 0）・docs opaque。

## 5. 完了条件判定（計画書対比）

| 完了条件 | 判定 | 根拠 |
|---|---|---|
| 1. F3 全滅候補が検証段（F4/F5）へ進む実測 | PASS | funnel F4 3→8・max_stage 全 F4・Phase 2 実動（sqli/xss ThoughtLoop・新規 sqli finding 出現） |
| 2. confirmed は賞金級 PoC を伴う・PoC 無しは確定しない | PASS | confirmed 0・sqli finding は実証を持つが impact 欠如で fail-closed（候補のまま）= 敷居据え置きの実証 |
| 3. カーブフィッティング無し | PASS | 決定的判定器・preflight exit 0・docs opaque |
| 4. F0 は診断に基づき最小限（真の重複なら緩めない） | PASS | 3件は真の重複と診断 → **緩和せず**（suppressed_tasks=3 のまま・重複攻撃を乱発しない） |
| 5. マスク＆復元維持・PCR-P1 diff 0・安全0・consistent・validator 0・実行1回 | PASS | §3 参照（validator 0 は docs フェーズで確認） |

**in_scope_blocker 0 件**。deferred_followup: D01（F0 キー精緻化は ⑥ で）・
D02（再送ループは ⑥ で・GET-only は本 run で実測済み）。non_blocking_observation: なし。
本タスクを **done** とする。
