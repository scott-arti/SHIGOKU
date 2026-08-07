---
task_id: SGK-2026-0418
doc_type: work_report
status: done
parent_task_id: SGK-2026-0416
related_docs:
- docs/shigoku/plans/done/2026-07-31_vdp-capability-benchmark-and-evidence-contract_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0419_vdp-evidence-schema-safety-budget-and-recovery-foundation_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0420_vdp-capability-driven-hypothesis-generation-shadow-workflow_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0421_vdp-evidence-gap-driven-verification-and-safe-follow-up_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0422_vdp-canonical-evidence-reporting-and-separated-quality-gates_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0423_vdp-hidden-holdout-evaluation-shadow-rollout-and-recovery_subtask_plan.md
- docs/shigoku/subtasks/2026-08-05_sgk-2026-0424_vdp-m3a-readonly-pilot_subtask_plan.md
- docs/shigoku/worklogs/2026-08-05_sgk-2026-0418_vdp-capability-benchmark-and-evidence-contract_work_log.md
title: VDP capability benchmark and staged evidence system 親タスク最終監査・クローズ作業完了報告
created_at: '2026-08-05'
updated_at: '2026-08-07'
tags:
- shigoku
target: src/core/engine,src/core/agents/swarm,src/reporting,tests
deferred_tasks:
  - deferred_id: SGK-2026-0418-D01
    title: "承認済みVDPでのM3a読み取り専用パイロット実行（探索の広さ・検証の深さ・証拠品質の実測）"
    reason: "SGK-2026-0418は完了済み。M0-M4の基盤・評価・rollout機構は実証済みだが、承認済み実VDP対象でのM3a運用はユーザーの書面許可・scope・予算・停止条件の固定後に実施する将来段階の追跡事項（SGK-2026-0423-D01の後続）"
    impact: high
    tracking_task_id: SGK-2026-0424
    recommended_next_action: "SGK-2026-0424（M3a読み取り専用パイロット）を、許可・scope・ProgramCapabilityMatrix・予算・kill switchの固定後に実行する"
  - deferred_id: SGK-2026-0418-D02
    title: "WALとcheckpointの多重喪失時のwrite-ahead保証強化"
    reason: "SGK-2026-0418は完了済み。送信前durable WALとin_flight→Hold・自動再送禁止は実証済み。journalとcheckpointの両方が失われる多重障害時の保証は将来段階の追跡事項（SGK-2026-0423-D02の後続）"
    impact: low
    tracking_task_id: SGK-2026-0424
    recommended_next_action: "SGK-2026-0424のパイロットで二重送信防止の運用確認を行い、write-ahead journal化を後続タスクで設計・検証する"
---

# 作業完了報告書：SGK-2026-0418 VDP capability benchmark and staged evidence system（最終クローズ）

## 1. 最終状態

**DONE（2026-08-05 確定）**。固定済み完了条件（計画書 §13）を最終監査し、全条件 PASS・in_scope_blocker 0件。計画書 §1 の5ゴールすべて達成済みとして [x] に更新し、plan を `docs/shigoku/plans/done/` へ移動した。

M4 は未有効化のまま（effective stage=m3a、decision records で m4=hold を明示）。これは計画書 §13 の「M4のGo/Hold/No-Go判定根拠がartifactとして保存されている」を満たす状態であり、M4全面運用は SGK-2026-0424 以降の追跡事項である。

## 2. 固定済み完了条件の最終監査表

| # | 完了条件（計画書 §13） | 判定 | 根拠 |
|---|---|---|---|
| 1 | 0419-0423がすべてdoneで、各work reportとwork logが台帳に登録されている | **PASS** | 台帳（task_registry.yaml / task_ledger.md / task_ledger.csv）で0419-0423すべて done。各work report/work logが実在し、registry の related_docs に登録済み |
| 2 | M0-M3を通過し、M4のGo/Hold/No-Go判定根拠がartifactとして保存されている | **PASS** | 0423で M0-M3必須test・failure drill 26本・VDP全対象スイープ 1090 passed。`eval/decision_records.json`（m0-m3a=go / holdout=go / m3b・m3c・m4=hold、理由コード付き）と `reports/gate_real_holdout2.json`（decision=go / run_state=succeeded）を実artifactで保存 |
| 3 | 対象非依存fixtureとhidden holdoutで、事前固定した品質閾値を満たす | **PASS** | 0423最終クローズ（ランダムopaque holdout環境）: holdout評価 outcome=pass（recall 1.0≥0.5 / evidence_completeness 0.333≥0.2 / untested 0≤0.5 / fp 0≤0.2 / leakage 0）。閾値はiso-v2として**holdout閲覧前に凍結**（iso-v1と同値）、同一eval_versionでの改変は EvalVersionMismatch で拒否 |
| 4 | real artifactでreport/session consistencyがconsistentとなる | **PASS** | 公式 checker を本ターンで再実行: `verify_report_session_consistency.py --report <internal.md> --vdp-key-registry <key_registry.json>` → **status: consistent / rerun_required: false / reason_codes: []** |
| 5 | secret漏洩、scope逸脱、二重状態変更、理由不明confirmedが0件 | **PASS** | 0423監査表（POST=0・non_get_violations=0・WAL drill 15-18・confirmed 1は署名済みproof検証済み）。secret redaction は書込境界で再帰適用（0419）、テストで深さ2以上を確認 |
| 6 | rollback、kill switch、中断再開が検証済み | **PASS** | 0423: kill switch（2点）、旧処理rollback、中断再開（checkpoint復元・drill 9/10）、WAL crash跨ぎ非再送（drill 15-18）を実測。旧session互換reader維持 |

## 3. ゴール達成（計画書 §1）

| ゴール | 判定 | 根拠 |
|---|---|---|
| 既知脆弱性・固有URLを使わず広さ・深さ・完全性を測定 | PASS | 0420 capability-driven生成（label leakage 0）、0423 ランダムopaque holdout（runtimeに固有URL・ground truthなし） |
| 発見〜未検証を同一ID系列で追跡 | PASS | 0419 ID系列契約、0420 決定論的ID、0421 全record保存、0422 canonical index |
| クラス固有証拠がそろうまで昇格しない | PASS | 0422 Evidence Validator唯一の署名境界、0423 confirmed 1は構造化marker+proof検証済み |
| record-only→shadow→限定enforce→全面enforceの段階導入 | PASS | 0420 record-only/shadow、0421 限定enforce、0423 段階導入gate（stage飛越し拒否）、M4=holdで未有効化 |
| 中断・依存停止・保存失敗・旧session読取時に誤判定・二重送信なし | PASS | 0419 recovery、0421 degraded/pending維持、0423 WAL・drill群・旧session互換 |

## 4. 実証artifact（0423 最終クローズ、`workspace/projects/vdp-eval-0423/holdout2/`）

- `sessions/session_vdp-holdout-1785859506.json`（M0 PASS / confirmed 1 / candidate 2 / run_health=succeeded）
- `reports/haddix_20260805_010525_{submission,internal}.md` + `internal.json` + `manifest.json`
- `eval/thresholds_v1.json`（iso-v2、評価前に凍結）/ `eval/holdout_result_iso.json`（outcome=pass・fingerprint/hash）/ `eval/key_registry.json`（公開鍵のみ）/ `eval/decision_records.json` / `eval/run_summary.json`
- `reports/gate_real_holdout2.json`（status=pass / decision=go / run_state=succeeded）
- 隔離実証: runtimeコンテナ内 `/secrets`・`/repo/tests` は非mount（ENOENT）、POST=0・非GET=0

## 5. 検証（本ターン実行）

```bash
.venv/bin/python scripts/verify_report_session_consistency.py \
  --report workspace/projects/vdp-eval-0423/holdout2/reports/haddix_20260805_010525_internal.md \
  --vdp-key-registry workspace/projects/vdp-eval-0423/holdout2/eval/key_registry.json
# status: consistent / rerun_required: false / reason_codes: []（本ターン再実行で確認）
```

- 素のchecker（鍵registry指定なし）は **inconsistent** を返すが、これは confirmed 検証鍵provider未指定時の fail-closed 設計動作であり、0423の記録（CLI + `--vdp-key-registry` で consistent）と一致する。
- 0423の成果はコード・閾値・artifactとも変更していない（本ターンは文書整合のみ実施）。

## 6. deferred_followup

- SGK-2026-0423-D01（実VDPでのM4全面運用検証）→ SGK-2026-0424（M3aパイロット）で追跡継続。
- SGK-2026-0423-D02（WAL多重喪失時のjournal化）→ SGK-2026-0424 で追跡継続。
- 0420 subtask plan の §1 checkbox が未チェックのまま残っている（non_blocking_observation、0418完了契約には無関係。台帳・registry上の status は done で整合）。

## 7. 残存リスク

- M4 全面運用は未実施（effective m3a）。許可済み実VDP対象での運用実証は SGK-2026-0424 以降の追跡事項であり、本タスクの完了を阻害しない。
- 既存の環境依存テスト失敗（tests/core 系の30件・test_config_yaml の2件等）は本シリーズ差分外のpre-existing事象（0421/0423でbaseline比較済み）。
