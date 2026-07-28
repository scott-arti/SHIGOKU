---
task_id: SGK-2026-0370
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0282
related_docs:
- docs/shigoku/subtasks/2026-06-21_sgk-2026-0282_bug-bounty-scope-control_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-01_bug-bounty-scope-bundle-guard-policy-compile_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0323_phasegate-granularity-import-recon_subtask_plan.md
- docs/shigoku/subtasks/2026-07-02_sgk-2026-0336_bugbounty-bundle-v1-followups_subtask_plan.md
- docs/shigoku/specs/2026-07-01_sgk-2026-0335_bug-bounty-program-bundle-guard-policy-contract.md
- docs/shigoku/reports/2026-07-21_sgk-2026-0370_work_report.md
- docs/shigoku/worklogs/2026-07-21_sgk-2026-0370_work_log.md
title: Bug Bounty compiled guard と PhaseGate capability 接続計画
created_at: '2026-07-17'
updated_at: '2026-07-28'
tags:
- shigoku
target: src/core/engine/master_conductor.py, src/core/engine/phase_gate.py,
  src/core/security/guard_enforcement.py, src/core/security/compiled_guard_models.py,
  src/core/security/compiled_guard_evaluator.py, src/core/security/compiled_guard_loader.py
---

# 実装計画書：Bug Bounty compiled guard と PhaseGate capability 接続計画

## 1. 達成したいゴール（ユーザー視点）
- [ ] Bug Bounty 用 `program bundle` を有効化して実行すると、scope / policy で禁止された攻撃は task 化されず、安全なものだけが段階的に解放されること。
- [ ] `compiled_guard_policy.yaml` が `block` / `requires_hitl` / `degrade_to_report` を返したとき、`MasterConductor` と `PhaseGate` が食い違わず同じ理由で停止・保留・報告優先に倒れること。
- [ ] operator が session / report を見たときに、「program rule で止まった」のか「進行制御上まだ解放されていない」のかを区別して追跡できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/security/compiled_guard_loader.py`: active bundle から `compiled_guard_policy.yaml` を解決し、実行時の guard 正本を読み込む。
  - `src/core/security/compiled_guard_models.py`: `GuardInput` / `GuardDecision` などの guard 契約を定義する。
  - `src/core/security/compiled_guard_evaluator.py`: program rule を pure function で評価し、allow / block / requires_hitl / degrade を返す。
  - `src/core/security/guard_enforcement.py`: layer ごとの enforcement helper。MC / network / tool 実行前で共通判定を使う。
  - `src/core/engine/phase_gate.py`: Recon 結果・task metadata・runtime state を使って、どの attack capability を今解放してよいか判断する。
  - `src/core/engine/master_conductor.py`: guard decision と phase gate verdict をまとめ、task 生成・defer・report 優先化の最終責任を持つ。
- **データの流れ / 依存関係:**
  - `program bundle` -> `compiled_guard_loader` -> `compiled_guard_evaluator` -> `GuardDecision`
  - Recon signal + task metadata + runtime state -> `PhaseGate` -> capability verdict
  - `GuardDecision` + capability verdict -> `MasterConductor` -> `allow / defer / requires_hitl / route_to_report / lock_phase`
  - 最終 verdict -> session / report / operator 向け reason code / source refs

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - `GuardDecision`: `allow`, `block`, `requires_hitl`, `degrade_to_report`, `reason_codes`, `source_refs`
  - `PhaseGate` 入力: phase state, recon summary, task metadata (`attack_class`, `auth_required`, `risk`, `target_host`)
  - runtime state: `budget_remaining`, `critical_findings`, `pending_hitl`, `scope_source`
- **出力/結果 (Output):**
  - bridge verdict: `allow`, `defer`, `requires_hitl`, `route_to_report`, `lock_phase`
  - `reason_origin`: `compiled_guard` / `phase_gate` / `combined`
  - session / report に残す `reason_codes`, `source_refs`, `gate_summary`
- **制約・ルール:**
  - `compiled guard` は「その攻撃を program rule 上やってよいか」を決める正本であり、`PhaseGate` は `allow` された候補の中で「今やるか」を決める。
  - `compiled guard` が `block` を返した task を `PhaseGate` が再解放してはならない。
  - `requires_hitl` と `degrade_to_report` は deny と別扱いにし、queue から黙って消さず reason を残す。
  - Bug Bounty モードでは判定不能時に fail-open しない。
  - 既存の `EthicsGuard` / `PhaseGate.can_create_attack_task()` 互換呼び出しは壊さず、bridge 導入は additive に行う。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `compiled_guard_*` と `PhaseGate` / `MasterConductor` の既存 callsite を棚卸しし、どこで `GuardDecision` と capability verdict を突き合わせるかの接続表を作る。
- [x] ステップ2: `public_attack`, `auth_attack`, `high_risk_attack`, `report_priority` などの capability と、`allow / block / requires_hitl / degrade_to_report` の対応表を定義する。
- [x] ステップ3: `MasterConductor` に bridge helper を追加し、task 生成前・post exploit 起動前・report 退避前で共通 verdict を返せるようにする。
- [x] ステップ4: session / report / operator summary に `reason_origin` と `source_refs` を残し、`program rule` と `phase gate` の理由が混ざらないことを確認する。
- [x] ステップ5: targeted test と bug bounty 実行導線の回帰を通し、`SGK-2026-0336` へ残す follow-up と本タスクで完了させる範囲を切り分ける。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] task metadata が薄い task では `compiled guard` と capability の照合根拠が不足する - まず `attack_class` / `auth_required` / `risk` が明示できる経路から適用する。
- [ ] [重要度:高] `block` / `requires_hitl` / `degrade_to_report` の扱いを queue で同一視すると、危険な task が silently disappear する - queue から消す前に reason と state 遷移を固定する。
- [ ] [重要度:中] `compiled_guard` と `PhaseGate` の両方で似た reason code を出すと report 上で説明が二重化する - `reason_origin` と source ref の責務分離を先に決める。
- [ ] [重要度:中] `SGK-2026-0336` の stale / auto-promotion / legacy `--scope` 撤去と同時進行するとスコープが膨らむ - 本タスクは bridge 契約に集中し、運用改善は `0336` 側へ残す。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0370-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
