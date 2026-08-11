---
task_id: SGK-2026-0440
doc_type: plan
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/reports/2026-08-11_sgk-2026-0439_param-dependent-attack-enablement-safe_work_report.md
- docs/shigoku/subtasks/done/2026-08-05_sgk-2026-0425_vdp-causal-attack-funnel-diagnosis_subtask_plan.md
created_at: '2026-08-11'
updated_at: '2026-08-11'
tags:
- shigoku
- vdp
- diagnostics
target: src/core/engine/swarm_dispatcher.py,src/core/agents/swarm/injection/manager.py,src/core/engine/vdp_diagnostic_trace.py,src/reporting/finding_extractor.py
---

# 実装計画: 本物の攻撃経路（候補→確定）を正しく計測する — finding-pipeline 計装

## 背景 / 確定した事実（2026-08-11 実測・コード確認）

- **診断ファネル（S00-S12）は VDP follow-up 経路しか計測していない。** 診断イベントの発行元は
  `vdp_follow_up_executor.py` / `master_conductor.py` / `vdp_evidence_validator.py` / `vdp_diagnostic_trace.py` のみ。
  **本物の攻撃エンジン `InjectionSwarm`（`swarm/injection/manager.py`）は診断イベントを1件も出していない。**
- **本物の攻撃は動いて候補を上げている。** 封印 run（session_20260811_002205）の実測:
  `report_findings_summary: candidate 16 / confirmed 0`。swarm が16件の候補を検出しレポートへ到達させているが確定は0。
  （VDP canonical の candidate 5 とは別枠。）
- swarm findings は `swarm_dispatcher.py` が `all_findings` に集約している。 log には
  `Phase 1: N findings`・`phase1_early_return（Phase 2 スキップ）`・`Suppressing injection task … ownership already claimed` が出る。
- **結論**: 「16件見つけて0確定」の**どこで・なぜ落ちるかを、現行の計測器が見ていない**。診断基盤（SGK-2026-0425）は
  VDP 部分経路のために作られ、実際に findings が生まれて死ぬ経路（候補→検証→確定→レポート）を計装していない。

## 目的

**本物の攻撃経路（候補→検証→確定→レポート）を first-failure で正しく計測できるようにする。**
これは計測（可視化）タスクであり、**検出・確定のロジックや閾値は一切変えない**（confirmed を増やす操作をしない）。
計測器が「本当の詰まり所」を示せる状態にするまでが本タスク。詰まりの修正は本タスクの成果を見てから別タスクで行う。

## finding ライフサイクル stage（計測対象・製品非依存）

各候補（finding）について、次の一般的ライフサイクルの**最も早い停止点（first-failure）**と理由を記録する:

1. `F0 target_selected` — recon が対象/param を選定
2. `F1 attack_sent` — 攻撃 payload を送信（swarm が実際に叩いた）
3. `F2 signal_detected` — 検出シグナル（Phase 1 finding=候補生成）
4. `F3 validation_attempted` — 検証（Phase 2 / 独立証拠取得）を試みた
5. `F4 evidence_captured` — 確定に足る独立証拠を取得
6. `F5 confirmed_or_refuted` — Evidence Validator が confirmed / refuted 判定
7. `F6 reported` — レポートの findings に反映

- 停止理由コード（**データとして記録**・断定しない）: `phase2_skipped_early_return` / `task_suppressed_ownership` /
  `evidence_insufficient` / `false_positive_refuted` / `budget_exhausted` / `admission_denied` など。
- follow-up/retry は同 stage の反復として扱い、後の成功で最初の失敗を上書きしない（0425 の first-failure 規約を踏襲）。

## スコープ

1. `swarm_dispatcher` / `InjectionManager` の候補生成・early-return・suppression・検証結果を、上記 F0-F6 の診断イベントとして発行する
   （既存 `vdp_diagnostic_trace` の taxonomy を拡張 or finding-pipeline 用の並行 trace を追加。VDP funnel と1つの診断成果物へ統合）。
2. レポート集約点（`finding_extractor` / `report_findings_summary`）で、候補ごとの first-failure stage・理由を機械可読に出力。
3. 封印 run の16候補それぞれについて「どの stage で・なぜ確定に至らないか」を artifact 化（opaque・製品 token なし）。

## 不変条件（絶対に破らない）

- **計測は additive・default off で既存出力と bit 単位同一**（0425 契約踏襲：`enabled=false` で findings/report 完全不変）。
  `required=true` で評価 run。
- **検出・確定・閾値・Evidence Validator・admission・抑制ロジックを変更しない**（本タスクは"測る"だけ。confirmed 件数は指標にしない）。
- **製品非依存**: 製品 token を code/session/report/docs に入れない。`check_vdp_product_independence.py` exit 0・docs opaque。
- PCR-P1 assert 無改変。schema additive（§12）。
- 封印ローカルのみ・GET 攻撃＋auth-setup register/login のみ・安全0。

## 完了条件

1. 封印 run の**16候補すべてに first-failure stage（F0-F6）と理由コードが機械可読で付与**され、
   「どこで・なぜ落ちるか」が集計できる。
2. **diagnostics off で findings/report が byte-identical**（既存挙動不変の実証）。
3. 製品非依存 fixture で first-failure 分類が再現（診断自体の正しさを検証）。
4. preflight exit 0・docs opaque・validator 0・PCR-P1 diff 0・consistency consistent・実行1回。

## NOT in scope

- 詰まりの修正（Phase 2 の再有効化・suppression 緩和・候補の promotion・確定ロジック変更）。→ 本タスクの計測結果を見て別タスク。
- 証拠条件/閾値の緩和・confirmed 件数の指標化。
- 実VDP外部・状態変更・m3b 以上。

## 参照

- `src/core/agents/swarm/injection/manager.py`（Phase1/Phase2・`phase1_early_return`・suppression）。
- `src/core/engine/swarm_dispatcher.py`（`all_findings` 集約）。
- `src/core/engine/vdp_diagnostic_trace.py`（S-stage taxonomy・first-failure 規約）。
- `src/reporting/finding_extractor.py` / `report_findings_summary`（候補集約）。
- SGK-2026-0425（診断基盤・additive/off-by-default・first-failure 規約）。
