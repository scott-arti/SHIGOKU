---
task_id: SGK-2026-0321
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0320
related_docs:
- docs/shigoku/plans/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md
- docs/shigoku/subtasks/2026-06-20_sgk-2026-0281_recon-resume-recipe-phasegate_subtask_plan.md
- docs/shigoku/subtasks/2026-06-29_sgk-2026-0322_reconstate-completion-parallel-checkpoint-decision-tree_subtask_plan.md
- docs/shigoku/subtasks/2026-06-29_sgk-2026-0326_flexible-report-generation-reinjection_subtask_plan.md
title: 'P0: Recon step状態自動保存＋再開CLI＋前回差分可視化'
created_at: '2026-06-29'
updated_at: '2026-07-02'
tags:
- shigoku
- recon
- resume
target: src/recon/pipeline.py, src/recon/__init__.py, src/main.py, scripts/shigoku_ops_cli.py
---

# 実装計画書：P0 Recon step状態自動保存＋再開CLI＋前回差分可視化

> たたき台（ブラッシュアップ前提）。SGK-2026-0281 の Phase A 相当を具体化する。

## 1. 達成したいゴール（ユーザー視点）
- [ ] Recon が各 step 完了時に状態を自動保存し、中断後に「step N から再開」できる。
- [ ] `--recon-resume` / `--recon-start-step` を CLI から指定して途中再開できる。
- [ ] 前回の Recon 結果（サブドメイン/URL/ポート等）との added/removed/modified 差分を見て、再開やスキップを判断できる。
- [ ] 再開可能ポイントと現在の進捗が一覧で見える。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/recon/pipeline.py`: `ReconState` の保存完全化、`run()` への自動 checkpoint 挿入、差分生成。
  - `src/recon/__init__.py`: 差分フォーマッタの export。
  - `src/main.py`: `--recon-resume` / `--recon-start-step` の CLI ワイヤリング（`--recon-start-step`/`--recon-end-step` は既存フラグあり、復元連動を追加）。
  - `scripts/shigoku_ops_cli.py`: `recon status` / `recon diff` サブコマンド追加。
- **データの流れ / 依存関係:**
  - step 完了 → `ReconState.save()` 自動呼び出し → `projects/<target>/recon_state.json`
  - 再開時 → `ReconState.load()` → `start_step = current_step + 1` で `run()` へ
  - 前回 state.json と今回結果 → 差分（added/removed/modified）→ Markdown/JSON 出力

## 3. 現状の前提（実装踏まえた評価）
- `ReconPipeline.run(target, start_step=1, end_step=8)` は step レンジを既にサポート（`pipeline.py:3696`）。
- `ReconState.save()/load()` は存在するが本番未呼び出し（`pipeline.py:80/97`）。
- `mark_step_complete()` で `completed_steps`/`current_step` を更新するが保存しない。
- 保存フィールド不足: `tech_stack`, `screenshots_count`, `results` が `save()` に含まれない（完全化は P1/SGK-2026-0322 で扱うが、P0 でも最小限必要な分は追加する）。
- 差分比較機能は未存在。

## 4. 具体的な仕様と制約条件
- **入力情報 (Input):** ReconState（current_step, completed_steps, all_subs, live_subs, dead_subs, tech_stack, target, project_name）、前回 state.json パス。
- **出力/結果 (Output):**
  - `projects/<target>/recon_state.json`（各 step 完了時に上書き保存、schema_version 付き）
  - `shigoku-ops recon status` → 再開可能 step 一覧と進捗
  - `shigoku-ops recon diff` → added/removed/modified 差分（JSON/Markdown）
- **制約・ルール:**
  - 保存フォーマットに `recon_state_schema_version: 1` を付け、旧 reader を壊さない。
  - 差分は一次証拠（state.json）由来のみ。推定値は `estimated` 明記。
  - secret/PII マスクは既存 redactor を通す（Recon のサブドメインは概ね公開情報だが、内部名や cookie 由来は除く）。
  - Single URL Mode で Step 1-2 スキップ時も `*_skipped` マークを保存する。

## 5. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: 既存の `ReconState` 保存項目、`run(start_step, end_step)` 呼び出し経路、`recon_state.json` の reader を棚卸しし、`Implemented / Exists but not wired / Not started` の差分メモを作成する。
- [ ] ステップ2: checkpoint 契約を先に固定し、`recon_state_schema_version`, `saved_at`, `run_id`, `target_fingerprint`, `last_completed_step`, `resume_source`, `diff_base_run_id` の各フィールド、旧 state 欠損時の fallback、target 不一致時の fail-closed 条件を計画へ明記する。
- [ ] ステップ3: `ReconState.save()` / `load()` に `tech_stack`, `screenshots_count`, `results`(概要) を追加し、書き込みは temp file + rename の原子的保存、破損時の reason code、読込時の schema migration 分岐を実装する。
- [ ] ステップ4: `mark_step_complete()` 周辺に自動 checkpoint を組み込み、step 完了・skip・resume override の各イベントで `checkpoint_path = pm.project_dir / "recon_state.json"` を保存する。保存失敗時は `step_completed_but_checkpoint_failed` を明示記録する。
- [ ] ステップ5: `--recon-resume` と既存 `--recon-start-step` / `--recon-end-step` の優先順位を固定し、`main.py` から shared resume resolver を経由して `start_step` を算出する。無効 state、完了済み state、target 不一致 state は明示エラーにする。
- [ ] ステップ6: 差分生成関数 `compute_recon_diff(prev_state, curr_state)` を実装し、all_subs/live_subs/dead_subs/tech_stack の正規化比較に加えて、`saved_at`・`run_id`・`estimated`・`stale_state` を含む差分メタデータを返す。
- [ ] ステップ7: `shigoku-ops recon status` / `recon diff --prev <state.json>` サブコマンドを追加し、再開可能 step、checkpoint 健全性、diff 基準、reason code、`--json`/`--json-envelope` を同一フォーマッタで出力する。
- [ ] ステップ8: checkpoint / resume / diff の observability を追加し、secret を含まない範囲で `run_id`, `target_fingerprint`, `resume_source`, `verdict_reason_codes`, `checkpoint_result` をログ・trace に残す。
- [ ] ステップ9: 単体テストと実行系テストを追加し、save/load 往復、atomic save、schema fallback、resume precedence、target mismatch、破損 state、差分正規化、stale diff 表示を検証する。

## 5.1 フェーズ分割
- Phase A: 棚卸し + checkpoint 契約固定 + state 保存完全化（ステップ1-3）
- Phase B: 自動 checkpoint + resume CLI（ステップ4-5）
- Phase C: 差分可視化 + status/diff CLI + observability（ステップ6-8）
- Phase D: テストと実 artifact 検証（ステップ9）

## 6. 懸念点と対策
※責任者と工数は本計画では扱わない。各対策は `## 5. 実装ステップ` の対応ステップへ組み込む。

### 6.1 SRE/インフラエンジニア視点
- [ ] [SRE-1][発生確率:高][影響度:大] step 完了直後の state 保存が非原子的だと、プロセス中断やディスク断で `recon_state.json` が破損し、再開不能または誤再開になる。対策: checkpoint 契約に原子的保存、破損検知、fail-closed 条件を追加し、`save()` を temp file + rename 化する（対応: ステップ2, 3, 9）。
- [ ] [SRE-2][発生確率:中][影響度:大] 古い state や別 target の state を誤って再利用すると、別案件の途中成果で resume して誤スキャンや誤判断につながる。対策: `target_fingerprint`, `run_id`, `saved_at` を checkpoint に持たせ、resume 時に target 一致・鮮度・完了状態を検証して不整合は停止する（対応: ステップ2, 5, 7, 9）。
- [ ] [SRE-3][発生確率:中][影響度:中] 運用者が「checkpoint が保存されたのか」「どの state から再開したのか」を追えないと、障害時の切り分けが遅れる。対策: `checkpoint_result`, `resume_source`, `diff_base_run_id` を status/trace に露出し、CLI でも確認できるようにする（対応: ステップ7, 8, 9）。
- [ ] [SRE-4][発生確率:中][影響度:中] 旧 schema の state をそのまま読み込むと、欠損フィールドが silently ignore され diff や進捗表示が不正確になる。対策: schema migration と fallback reason code を計画に追加し、旧 state は `estimated` 表示や警告付きで扱う（対応: ステップ2, 3, 6, 9）。

### 6.2 ソフトウェアアーキテクト視点
- [ ] [ARCH-1][発生確率:高][影響度:大] `ReconState` に場当たり的に項目を足すだけだと、pipeline・CLI・ops がそれぞれ別解釈を持ち、将来の P1 拡張時に互換を壊しやすい。対策: P0 の時点で checkpoint 契約を明文化し、reader 一覧を棚卸しして変更影響を先に固定する（対応: ステップ1, 2）。
- [ ] [ARCH-2][発生確率:中][影響度:大] resume 判定ロジックが `main.py` と ops CLI に分散すると、優先順位やバリデーションがずれて運用経路ごとに挙動が変わる。対策: shared resume resolver / status formatter を前提にした設計へ計画を修正し、CLI ごとの差分を薄くする（対応: ステップ5, 7）。
- [ ] [ARCH-3][発生確率:中][影響度:中] diff が単なる set 差分のままだと、「削除済みなのか」「古い state 由来なのか」「推定値なのか」の意味が曖昧で、P2/P3 から再利用しにくい。対策: diff 出力を findings 本体とメタデータに分け、`estimated`, `stale_state`, `diff_base_run_id` を契約化する（対応: ステップ2, 6, 7）。
- [ ] [ARCH-4][発生確率:中][影響度:中] P0 で `results` を丸ごと保存対象に広げすぎると、SGK-2026-0322 の「ReconState完全化」と責務が重複し、スコープが膨らむ。対策: P0 は「resume と diff に必要な概要フィールドのみ」を保存対象に限定し、完全保存は P1 に明示委譲する文言を追記する（対応: ステップ1, 3, 7）。

### 6.3 デバッガー視点
- [ ] [DBG-1][発生確率:高][影響度:大] 「step は完了したが保存に失敗した」ケースが見えないと、resume 不具合を再現できず原因究明が難しい。対策: `step_completed_but_checkpoint_failed` などの reason code を導入し、status/trace に必ず残す（対応: ステップ4, 7, 8, 9）。
- [ ] [DBG-2][発生確率:中][影響度:大] `--recon-resume` と `--recon-start-step` の競合ルールが曖昧だと、利用者が「どの step から始まったか」を誤認する。対策: 優先順位表と無効組み合わせのエラー条件を計画に追記し、precedence test を必須化する（対応: ステップ5, 9）。
- [ ] [DBG-3][発生確率:中][影響度:中] 集合順序や正規化不足で diff が run ごとに揺れると、added/removed がノイズ化して regression を見逃す。対策: 比較前の正規化ルールを定義し、stale/estimated を含めた golden test を追加する（対応: ステップ6, 9）。
- [ ] [DBG-4][発生確率:中][影響度:中] 破損 state・欠損 state・完了済み state の失敗モードが未整理だと、CLI エラーが一律になりユーザーも開発者も詰まる。対策: failure mode ごとの reason code とメッセージを `recon status` / `recon diff` の出力契約に含める（対応: ステップ5, 7, 9）。

### 6.4 CTO視点
- [ ] [CTO-1][発生確率:高][影響度:大] 自動保存、resume、diff、ops CLI を一気に入れると、価値は高い一方で障害時の切り戻し単位が粗くなる。対策: フェーズを「checkpoint 契約」「resume」「diff/ops」「検証」に分け、各 Phase の完了条件を明記する（対応: ステップ1-9, フェーズ分割更新）。
- [ ] [CTO-2][発生確率:中][影響度:大] resume の安全性より利便性を優先すると、別案件 state 誤読込や古い結果再利用でユーザー信頼を損なう。対策: target 不一致・鮮度不明・完了済み state は fail-open ではなく fail-closed にする方針を計画へ追記する（対応: ステップ2, 5, 7, 9）。
- [ ] [CTO-3][発生確率:中][影響度:中] 運用可視化が弱いままリリースすると、「途中再開できるはずなのにできない」問い合わせが増え、P0 の成果が運用コストに吸われる。対策: `recon status` を実運用の一次窓口に位置づけ、checkpoint 健全性・基準 state・resume 可否理由を返すよう計画を修正する（対応: ステップ7, 8, 9）。
- [ ] [CTO-4][発生確率:中][影響度:中] P0 で状態永続化の責務を広げすぎると、P1/P2 の意思決定ツリーや並行タスク保存の設計余地を先に潰してしまう。対策: 本計画書に「P0 の保存対象は再開と差分判断に必要な最小限」「並行タスク途中状態は SGK-2026-0322 へ委譲」と明記する（対応: ステップ1, 3, 7）。

## 7. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:高] 並行タスク（Step5 Phase2 の fire-and-forget）の途中状態は保存対象外。→ SGK-2026-0322(P1) で扱う。
- [ ] [重要度:中] 古い state.json との後方互換。schema_version で判定し、欠損時は gracefully fallback。
- [ ] [重要度:中] 差分の modified 判定が粗い（URL/ポート詳細比較は別途）。P1 で粒度向上。

### 7.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0321-D01
    title: "継続監視: 並行タスク途中状態保存"
    reason: "本タスクはメインフロー step のみ。並行タスクは別設計"
    impact: medium
    tracking_task_id: SGK-2026-0322
    recommended_next_action: "SGK-2026-0322 で並行タスク checkpoint を設計する"
```
