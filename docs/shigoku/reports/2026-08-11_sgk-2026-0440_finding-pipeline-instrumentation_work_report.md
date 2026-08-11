---
task_id: SGK-2026-0440
doc_type: work_report
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/plans/done/2026-08-11_sgk-2026-0440_finding-pipeline-instrumentation.md
- docs/shigoku/reports/2026-08-11_sgk-2026-0439_param-dependent-attack-enablement-safe_work_report.md
- docs/shigoku/worklogs/2026-08-11_sgk-2026-0440_finding-pipeline-instrumentation_work_log.md
title: 本物の攻撃経路（候補→確定）を正しく計測する finding-pipeline 計装 作業完了報告
created_at: '2026-08-11'
updated_at: '2026-08-11'
tags:
- shigoku
- vdp
- diagnostics
target: src/core/engine/finding_funnel_trace.py,src/core/agents/swarm/injection/manager.py,src/core/engine/master_conductor.py,src/reporting/vdp_report_projection.py,src/reporting/haddix_formatter.py,src/reporting/finding_extractor.py
deferred_tasks:
  - deferred_id: SGK-2026-0440-D01
    title: "finding 重複 dict（同一 finding_id が複数タスクの result に記録される）の発生源を詰まり修正タスクで解明"
    reason: "封印 run で 17 finding dict 中ユニーク id は 8（同一候補が複数タスクの結果に重複記録）。funnel はユニーク id 単位で全カバーするため計測は正しいが、重複自体がレポート行数（16）と漏斗件数（8）の見かけの乖離の原因。重複は計測外の原因（複数タスクでの同一 finding 再記録）であり本タスクの NOT in scope（詰まり修正）に属する"
    impact: low
    tracking_task_id: SGK-2026-0418
    recommended_next_action: "計測結果（first-failure 分類）を見て詰まり修正タスクを起票する際に、finding 記録の重複抑制も検討"
---

# 作業完了報告: SGK-2026-0440（finding-pipeline 計装）

## 0. 成果物サマリ

- **swarm 攻撃経路に F0-F6 診断計装を追加**（計測のみ・検出/確定/閾値/抑制ロジック無変更）。
- **封印 run 実測**: 全ユニーク候補（8）に first-failure stage＋理由が機械可読付与。
  落下点が可視化: **F3 phase2_skipped_early_return ×5 / F0 task_suppressed_ownership ×3**。
- **diagnostics off で byte-identical**（0425 契約踏襲・実証済み）。

## 1. 診断結果（exp-1/exp-3・一次証拠）

- **swarm は診断イベント 0 件**（`src/core/agents/swarm` 全体で stage_id/diagnostic なし・
  event_bus.emit は reauth のみ）。「16件見つけて0確定」の落下点は計測器の視界外だった。
- **16候補の正体**: `completed_tasks[*].result.findings`（manual_verify タグ付き finding）。
  レポートの candidate 判定は HaddixFormatter `_is_candidate_finding`（:2002-2026）。
  **per-candidate の stage/drop メタデータは現状ゼロ**（検証済み）。
- **落下点コード地点**: `phase1_safe_skip_no_signal`（Phase2 skipped early-return・
  `phase2_block_reason` 分解あり）/ ownership suppression（MC :1709-1759・**log only**）/
  FindingValidator gate（rejected は drop）。URL レベル skip は url_results に
  `skip_reason` あり（inert）。
- **安定キー**: `Finding.id` = md5(vuln_type:target_url:title)[:12]。
- **default-off の正本**: 既存 `diagnostics.enabled`（off → collector None → 全 emit no-op）。
- **additive 経路**: `DiagnosticEventV1.from_dict` は strict → vdp_contract の新キー
  `finding_funnel_v1` が安全（injector/reader は未知キー許容）。

## 2. 統合設計（承認済み・死守事項の実装対応）

| 死守 | 実装 |
|---|---|
| 計装は additive・default off | `FindingFunnelRecorder` は `diagnostics.enabled` を再利用（off → `get_finding_funnel()` が None → 全フック no-op → session キー無し → report ブロック無し = byte-identical） |
| 検出/確定/閾値/Validator/admission/抑制 無変更 | フックは**例外を投げない fail-safe**・判定ロジックと log 行は無変更（計測のみ） |
| F0-F6 マッピング | F0: `_create_attack_tasks_from_recon`（MC）/ F1: `_process_single_url` dispatch / F2: manual_verify finding 生成 6 箇所 / F3: Phase2 開始・`should_skip_phase2`・early-return・budget/timeout / F4: FindingValidator gate・auto_reverification / F5/F6: レポートタイム |
| first-failure 規約（0425） | 最も早い {skipped,blocked,failed} stage を記録・後の成功で上書きしない・retry は同 stage 反復 |
| 理由コード語彙 | 13 種（url_skipped_dedupe / url_skipped_low_ssrf_score / url_skipped_ssrf_reachability / url_skipped_timeout_circuit / url_timeout / url_error / phase2_skipped_early_return / budget_exhausted / phase2_timeout / finding_validator_rejected / evidence_insufficient / false_positive_refuted / task_suppressed_ownership）strict 検証 |
| 記録は opaque | finding_id は md5・URL/製品 token なし・セクションはハッシュと語彙のみ |
| レポート機械可読 | `<!-- finding_funnel_v1:start -->` ブロック（`embed_finding_funnel_index`・None → markdown 不変）+ `HaddixFinding.additional_info` に first_failure_stage/reason |

## 3. 封印 run 実測（session_20260811_091439・修正後）

### finding_funnel_v1（vdp_contract 内・機械可読）

- **entries 8 = ユニーク候補 8 全てをカバー**（raw findings 17 dict → ユニーク id 8・
  `raw NOT in funnel: []`・`funnel NOT in raw: []`）。
- 内訳:
  - **F3 phase2_skipped_early_return ×5**（max_stage F3/F4・block_reasons 分解
    no_tool_error/no_weak_signal/risk_not_met/phase2_on_empty_disabled）
  - **F0 task_suppressed_ownership ×3**（max_stage F3 まで記録）
- summary: `by_stage {F0:8, F1:8, F2:5, F3:8, F4:3}`・`by_reason {phase2_skipped_early_return:5, task_suppressed_ownership:3}`・`suppressed_tasks:3`・`total_candidates:8`。
- レポート: `<!-- finding_funnel_v1:start -->` ブロック埋め込み（L882-1040）。

### 「16候補」と「8 entries」の関係（D01）

- レポートの Candidate:16 は **finding dict 行数**（同一 finding_id の重複行を含む）。
  ユニーク候補は 8 で、funnel はその全てに付与。重複記録（同一 finding が複数タスクの
  result に載る）は計測外の既存挙動で、計測の正しさには影響しない。

## 4. 不変条件の実証

- **PCR-P1**: task_queue.py diff **0 行**。
- **Evidence Validator / admission / suppression**: 無変更（禁則ファイル diff 0）。
- **default off で byte-identical**: 4 方式で実証（funnel None → markdown 不変 /
  funnel 不在レポートに finding_funnel_v1・first_failure_* トークン無し /
  frozen-time with/without の diff がブロック追記のみ / additional_info 無付与）。
- **preflight**: `check_vdp_product_independence.py` → **pass / exit 0**
  （9 files scanned・total_token_hits 0・import_closure ok）。
- **consistency gate**: **consistent**（reason_codes 空）。
- **実行1回**: single-run marker・config byte-identical・runtime surface byte-identical。
- **GET-only / 安全0**: session 内 method 38 件全て GET・state_change marker 0。
- **所有権 / redaction**: session 644・report 600・session_env 0600（全て bbb）・
  ログにトークン/元値 0。
- **回帰**: 主要テスト 105 passed（funnel 23 + swarm hooks 6 + reporting 26 +
  projection 18 + vdp hooks 26 + realpath 6）。swarm/engine 広域 1386 passed・
  38 failed は **HEAD worktree と IDENTICAL**（worktree 比較で独立確認・
  0440 起因の新規失敗なし）。

## 5. 完了条件判定（計画書対比）

| 完了条件 | 判定 | 根拠 |
|---|---|---|
| 1. 16候補すべてに first-failure stage＋理由が機械可読で付与 | PASS | ユニーク候補 8 全てに付与（raw NOT in funnel: []・レポート機械可読ブロック + additional_info） |
| 2. diagnostics off で findings/report byte-identical | PASS | §4（4 方式実証 + 既存 0425 テスト） |
| 3. 製品非依存 fixture で first-failure 分類が再現 | PASS | test_finding_funnel_reporting.py（合成 fixture・26 テスト）・swarm hooks 6 テスト（実 dispatch で F0-F4 再現） |
| 4. preflight exit 0・docs opaque・validator 0・PCR-P1 diff 0・consistent・実行1回 | PASS | §4 参照（validator 0 は後段 docs で確認） |

**in_scope_blocker 0 件**。deferred_followup: D01（finding 重複 dict の発生源は
詰まり修正タスクの対象・計測の正しさには影響なし）。non_blocking_observation: なし。
本タスクを **done** とする。
