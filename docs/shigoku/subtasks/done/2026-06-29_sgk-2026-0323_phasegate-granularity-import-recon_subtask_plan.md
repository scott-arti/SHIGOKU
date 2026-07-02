---
task_id: SGK-2026-0323
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0320
related_docs:
- docs/shigoku/plans/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md
- docs/shigoku/subtasks/2026-06-20_sgk-2026-0281_recon-resume-recipe-phasegate_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0321_recon-step-state-resume-diff_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0322_reconstate-completion-parallel-checkpoint-decision-tree_subtask_plan.md
- src/core/engine/recipe_loader.py
- src/core/engine/phase_gate.py
title: 'P2: PhaseGate細粒度化＋過去Recon成果物再利用(--import-recon)'
created_at: '2026-06-29'
updated_at: '2026-07-02'
tags:
- shigoku
- recon
- phasegate
- recipe
target: src/core/engine/phase_gate.py, src/core/engine/recipe_loader.py, src/core/engine/master_conductor.py, src/core/engine/recon_importer.py, src/core/conductor/interactive_bridge.py, src/main.py
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
  - `src/core/engine/recon_importer.py`: import-recon の読み込み・正規化・freshness/provenance 判定 helper（新設候補）。
  - `src/core/conductor/interactive_bridge.py`: CLI で受けた import-recon パスを `MasterConductor` へ橋渡し。
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
- [ ] ステップ2: P2b-1〜P2b-4 に従い、`--import-recon <dir>` の成果物読み込み、正規化、freshness/provenance 適用、CLI/bridge 接続を実装する。
- [ ] ステップ3: P2b-5〜P2b-6 に従い、import 済み Recon results を `MasterConductor` / `PhaseGate` へ接続し、`PhaseGate.can_create_task` を後方互換のまま細粒度化する。
- [ ] ステップ4: P2b-7 に従い、段階的 Attack 解放を実装する。auth 必須 endpoint と public を分離し、critical finding 発生時は Report/HITL 優先へ寄せる。
- [ ] ステップ5: `match_recipes_to_context()` を score-based top-N 選抜へ。required signal 欠落は除外、optional は加点。
- [ ] ステップ6: 単体テスト + 実 import dir での検証。

## 5.1 フェーズ分割
- Phase A: freshness/provenance 設計（ステップ1）※ SGK-2026-0281 の deferred 高重要度項目
- Phase B: import-recon と細粒度 PhaseGate（ステップ2-4）
- Phase C: Recipe score 選抜（ステップ5）
- Phase D: 検証（ステップ6）

## 5.2 P2b 実装単位への細分化

> P2b は「過去 Recon 成果物を安全に取り込み、PhaseGate が細粒度に Attack 生成可否を返す」までを実装単位とする。Recipe score 選抜（Phase C）は P2b では触らない。

### P2b-0: 前提確認と変更境界固定
- [ ] P0/P1a の `ReconState` 保存・差分・並行タスク checkpoint が利用可能であることを、既存テストと計画書リンクで確認する。
- [ ] P2a の freshness/provenance 契約が未実装の場合、P2b では最小 contract（score, threshold, reason_codes, source_path, source_mtime, source_kind）だけを先に実装し、運用チューニングは deferred に残す。
- [ ] `PhaseGate.can_create_task(Phase.ATTACK)` の既存呼び出しを壊さないため、context 引数追加は optional にする。
- [ ] import-recon は既存 Recon 実行結果を上書きせず、`source="imported"` / `source="fresh"` が追跡できる形で merge する。

### P2b-1: import-recon データ契約の定義
- [ ] `src/core/engine/recon_importer.py` を新設し、`ImportedReconArtifact` / `ImportedReconBundle` 相当の dataclass または TypedDict を定義する。
- [ ] import 対象の最小対応ファイルを固定する: `recon_state.json`, `*_subs.txt`, `httpx.json` / `httpx.jsonl`, `takeover_candidates.json`, step8 分類 results JSON。
- [ ] 各 artifact に `path`, `kind`, `exists`, `size`, `mtime`, `freshness_score`, `provenance`, `warnings`, `reason_codes` を持たせる。
- [ ] target 不一致、存在しないパス、0 byte、JSON parse failure、未知形式は fail-closed reason として記録し、silent fallback しない。

### P2b-2: 成果物読み込みと正規化
- [ ] `load_imported_recon_dir(import_dir: Path, target: str | None)` を実装し、読み込み結果を `ImportedReconBundle` として返す。
- [ ] subdomain / http endpoint / takeover candidate / classified category を、既存 `ReconState.results` と `_create_attack_tasks_from_recon()` が扱える category dict へ正規化する。
- [ ] duplicate は正規化 URL / host 単位で除去し、重複理由を `warnings` に残す。
- [ ] malformed artifact が混ざっても bundle 全体を破棄せず、破損 artifact のみ `rejected_artifacts` に分離する。

### P2b-3: freshness/provenance 適用
- [ ] P2a の freshness helper を呼び、artifact kind ごとの freshness を計算する。
- [ ] threshold 未満の artifact は既定で Attack 生成入力から除外し、`stale_artifact` reason を残す。
- [ ] stale だが情報提示には使う artifact は `informational_only=true` とし、PhaseGate unlock の根拠に使わない。
- [ ] provenance は report/session 追跡に使えるよう、source path と mtime だけでなく source kind と import time を残す。

### P2b-4: CLI と bridge 接続
- [ ] `src/main.py` に `--import-recon <dir>` を追加し、既存 `--recon-resume` / `--recon-start-step` と併用可能にする。
- [ ] `src/cli/messages.py` に help 文言 key を追加し、CLI help の表示崩れを防ぐ。
- [ ] `start_interactive_session(..., import_recon_dir=None)` を追加し、`MasterConductor` へパスを渡す。
- [ ] 非TTYで stale artifact がある場合は確認待ちにせず、stale artifact を Attack 入力から除外して warning を出す。

### P2b-5: MasterConductor への import bundle 接続
- [ ] `MasterConductor` 初期化または Recon 完了直後の合流点で import bundle を読み込む。
- [ ] import bundle から正規化した `recon_results` を `state.results` 相当の分類結果へ merge する。
- [ ] fresh Recon と imported Recon が同一 category を持つ場合、fresh を優先し、imported は provenance 付き補助情報として残す。
- [ ] import が全件 reject された場合は Attack を解放せず、明示 reason をログと decision context に残す。

### P2b-6: PhaseGate 細粒度判定
- [ ] `PhaseData` に `auth_required_endpoints`, `public_endpoints`, `scope_status`, `budget_remaining`, `critical_findings`, `import_provenance`, `gate_reasons` を追加する。
- [ ] `can_create_task(phase, context=None)` を後方互換で拡張し、context がない場合は従来の lock/unlock 判定を維持する。
- [ ] Attack 生成可否を category 単位で返せる helper（例: `can_create_attack_task(category, metadata)`）を追加し、scope 外・budget 不足・auth 必須・stale import を reason 付きで reject する。
- [ ] `get_summary()` に細粒度 gate の reason count を含め、P1b の decision-tree 可視化から参照しやすくする。

### P2b-7: 段階的 Attack 解放
- [ ] `_create_attack_tasks_from_recon()` の category loop 内で PhaseGate の category 判定を呼び、reject された category は task 化せず reason を残す。
- [ ] public endpoint と auth_required endpoint を分離し、認証情報なしの場合は auth_required 系を待機または reject に倒す。
- [ ] critical finding がある場合は追加攻撃タスクより Report/HITL 優先の task を先に作る。
- [ ] 既存 non-actionable category skip と low-value skip の挙動は維持し、PhaseGate reject と混同しない。

### P2b-8: テスト単位
- [ ] `tests/unit/engine/test_recon_importer.py`: missing dir、empty artifact、malformed JSON、fresh/stale、duplicate、target mismatch、partial reject を確認する。
- [ ] `tests/unit/engine/test_phase_gate_granularity.py`: `can_create_task()` 後方互換、category reject reason、auth_required/scope/budget/stale 判定を確認する。
- [ ] `tests/unit/main/test_import_recon_cli.py` または既存 main focus tests: `--import-recon` parse、bridge 引き渡し、help key を確認する。
- [ ] `tests/unit/engine/test_master_conductor_import_recon.py`: import-only で Attack task が生成されるケース、stale 全除外で生成されないケース、fresh 優先 merge を確認する。
- [ ] 既存回帰として P0/P1a の ReconState checkpoint/resume tests と PhaseGate/RecipeLoader 既存 tests を再実行する。

### P2b-9: 完了条件
- [ ] `--import-recon <dir>` で fresh artifact のみ Attack task 生成入力に使われる。
- [ ] stale / target mismatch / malformed artifact は Attack task 生成に使われず、reason がログまたは decision context に残る。
- [ ] `PhaseGate.can_create_task(Phase.ATTACK)` の既存呼び出しは壊れない。
- [ ] `MasterConductor._create_attack_tasks_from_recon()` は category 単位で許可・拒否を判断できる。
- [ ] targeted tests と `python3 scripts/sync_shigoku_updated_at.py && python3 scripts/validate_shigoku_docs.py` が通る。

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
