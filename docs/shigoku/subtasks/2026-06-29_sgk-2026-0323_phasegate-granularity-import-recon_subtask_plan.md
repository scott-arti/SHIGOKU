---
task_id: SGK-2026-0323
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0320
related_docs:
- docs/shigoku/plans/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md
- docs/shigoku/subtasks/2026-06-20_sgk-2026-0281_recon-resume-recipe-phasegate_subtask_plan.md
- docs/shigoku/subtasks/2026-06-29_sgk-2026-0321_recon-step-state-resume-diff_subtask_plan.md
- src/core/engine/recipe_loader.py
- src/core/engine/phase_gate.py
title: 'P2: PhaseGate細粒度化＋過去Recon成果物再利用(--import-recon)'
created_at: '2026-06-29'
updated_at: '2026-06-30'
tags:
- shigoku
- recon
- phasegate
- recipe
target: src/core/engine/phase_gate.py, src/core/engine/recipe_loader.py, src/core/engine/master_conductor.py, src/main.py
---

# 実装計画書：P2 PhaseGate細粒度化＋過去Recon成果物再利用

> たたき台（ブラッシュアップ前提）。SGK-2026-0281 の Phase B/C/D を具体化する。P0/SGK-2026-0321 の差分基盤を freshness 判定に利用する。

## 1. 達成したいゴール（ユーザー視点）
- [ ] 既知ターゲットで過去 Recon 成果物を `--import-recon <dir>` で再利用し、無駄な再走査を減らせる。
- [ ] 再利用成果物の freshness（鮮度）と provenance（出所）が判定・表示され、古すぎる場合は警告・再走査を促せる。
- [ ] PhaseGate が「Attack 全一括解放」ではなく、finding/auth_required/scope/budget で細粒度に段階解放する。
- [ ] RecipeLoader の `match_recipes_to_context()` が全件返しではなく score-based top-N 選抜になる。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/phase_gate.py`: `PhaseGate` の unlock 条件を細粒度化（`PhaseData` 拡張）。
  - `src/core/engine/recipe_loader.py`: `match_recipes_to_context()` を score-based 選抜へ（`RecipeCandidate` は既存なので活用）。
  - `src/core/engine/master_conductor.py`: import-recon 成果物の取り込みと `_create_attack_tasks_from_recon` の段階解放連動。
  - `src/main.py`: `--import-recon <dir>` フラグ。
- **データの流れ / 依存関係:**
  - import dir → freshness 判定（`compute_freshness_score` は recipe_loader.py に既存）→ 正規化 results → PhaseGate / RecipeLoader
  - Recon 成果（fresh/import 問わず）→ 細粒度 PhaseGate → 段階的 Attack 解放 → Recipe 選抜

## 3. 現状の前提（実装踏まえた評価）
- `PhaseGate` はバイナリ（`INIT`/`RECON` は常時解放、`ATTACK` は Recon 結果があれば一括解放。`phase_gate.py:69`）。
- `RecipeLoader.RecipeCandidate` は score/reasons/required_signals を持つが（`recipe_loader.py:67`）、`match_recipes_to_context` は現状 loaded recipe 全件を返す（SGK-2026-0281 課題）。
- `compute_freshness_score(first_seen_dead, last_seen_dead, ...)` が recipe_loader.py に既存（takeover 用）。これを汎用 freshness に拡張可能。
- 過去 Recon 成果物の import 機能は未実装。

## 4. 具体的な仕様と制約条件
- **入力情報 (Input):** import dir 内の recon 成果物（`*_subs.txt`, `httpx.json`, `takeover_candidates.json` 等）、tech_stack、classified results、scope/budget 設定。
- **出力/結果 (Output):**
  - freshness 判定結果（0.0-1.0 スコア＋理由、stale なら再走査推奨）
  - 細粒度 PhaseGate: `can_create_task(phase, context)` が auth_required/scope/budget/critical_finding を考慮
  - score-based Recipe 選抜（top-N、required signal 欠落は除外）
- **制約・ルール:**
  - 古い成果物混入による誤判定防止。freshness しきい値未満は明示警告し、利用する場合は provenance を記録。
  - PhaseGate は MC の代替ではなく判断材料を細かくする部品（SGK-2026-0281 制約）。
  - RecipeLoader は全面作り直しではなく現行接続を生かした選抜改善（同上）。
  - scope 逸脱や予算超過で Attack 全体を止めやすく、auth 必須と public を同熱量で解放しない。

## 5. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: 汎用 freshness 判定設計。`compute_freshness_score` を拡張し、成果物種別（subs/httpx/takeover）ごとの鮮度と provenance（source session/date）を返す。
- [ ] ステップ2: `--import-recon <dir>` で成果物を読み込み、正規化 results を構築。stale なら警告＋ユーザ確認（HITL 相当）。
- [ ] ステップ3: `PhaseGate.can_create_task` を細粒度化。`PhaseData` に `auth_required_endpoints`, `scope`, `budget_remaining`, `critical_findings` を追加し、unlock 条件を判定。
- [ ] ステップ4: 段階的 Attack 解放。auth 必須 endpoint と public を分離し、critical finding 発生時は Report/HITL 優先へ寄せる。
- [ ] ステップ5: `match_recipes_to_context()` を score-based top-N 選抜へ。required signal 欠落は除外、optional は加点。
- [ ] ステップ6: 単体テスト + 実 import dir での検証。

## 5.1 フェーズ分割
- Phase A: freshness/provenance 設計（ステップ1）※ SGK-2026-0281 の deferred 高重要度項目
- Phase B: import-recon と細粒度 PhaseGate（ステップ2-4）
- Phase C: Recipe score 選抜（ステップ5）
- Phase D: 検証（ステップ6）

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:高] artifact reuse の古い成果物混入。freshness しきい値と provenance 記録を必須化（SGK-2026-0281 deferred 対応）。
- [ ] [重要度:高] recipe score を粗く入れると全件返しと大差ない。required/optional signal と top-N 制限を必須に（同上）。
- [ ] [重要度:中] 細粒度 PhaseGate と MC 既存の `_create_attack_tasks_from_recon` の責務境界。PhaseGate は許可判定、MC は生成のまま分離。

### 6.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0323-D01
    title: "継続監視: freshness しきい値の運用チューニング"
    reason: "しきい値は実ターゲット運用で調整が必要"
    impact: medium
    tracking_task_id: SGK-2026-0323
    recommended_next_action: "複数ターゲットで freshness スコア分布を計測し既定値を見直す"
```
