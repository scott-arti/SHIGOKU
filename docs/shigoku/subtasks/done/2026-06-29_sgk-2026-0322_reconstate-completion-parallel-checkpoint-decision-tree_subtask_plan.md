---
task_id: SGK-2026-0322
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0320
related_docs:
- docs/shigoku/plans/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md
- docs/shigoku/subtasks/2026-06-29_sgk-2026-0321_recon-step-state-resume-diff_subtask_plan.md
- docs/shigoku/subtasks/2026-07-01_p1b-shigoku-ops-decision-tree-cli_subtask_plan.md
- docs/shigoku/plans/done/2026-06-24_sgk-2026-0298_internal-behavior-visibility-governance_plan.md
- docs/shigoku/subtasks/done/2026-06-24_sgk-2026-0300_run-narrative-target-profile-markdown_subtask_plan.md
title: 'P1a: ReconState完全化＋並行タスクcheckpoint/resume堅牢化'
created_at: '2026-06-29'
updated_at: '2026-07-02'
tags:
- shigoku
- recon
- visibility
target: src/recon/pipeline.py, src/recon/parallel_tasks.py
---

# 実装計画書：P1a ReconState完全化＋並行タスクcheckpoint/resume堅牢化

> たたき台（ブラッシュアップ前提）。SGK-2026-0321(P0) の保存基盤を拡張し、ReconState と fire-and-forget 並行タスクが安全に再開できる checkpoint/resume 基盤を完成させる。判断ツリー可視化は SGK-2026-0334(P1b) へ分離する。

## 1. 達成したいゴール（ユーザー視点）
- [ ] ReconState に欠落していた情報（`tech_stack` / `screenshots_count` / `results` 概要 / 並行タスク途中状態）が保存され、step 3-5 の部分再開で情報欠損しない。
- [ ] Step 5 Phase 2 の fire-and-forget 並行タスク（Full Port / Visual / Permutation / Dead Sub）の開始・進行・完了・失敗が checkpoint に残り、中断後も「未完了だけを安全に再実行」できる。
- [ ] artifact の存在だけで完了扱いせず、checkpoint と成果物参照の整合が取れた場合だけ resume / skip を判断できる。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/recon/pipeline.py`: `ReconState` schema の完全化、save/load の後方互換、checkpoint の保存経路。
  - `src/recon/parallel_tasks.py`: 並行タスク（`ParallelTasks`）の状態遷移を checkpoint に反映し、resume 判定に必要な証跡を残す。
- **データの流れ / 依存関係:**
  - 各 step / 並行タスク完了 → ReconState 更新 → save（P0 基盤を利用）
  - `parallel_task_progress` + `artifact_refs` + checkpoint metadata → resume 判定 → 未完了/不整合タスクのみ再実行

## 3. 現状の前提（実装踏まえた評価）
- `ReconState` は `src/recon/pipeline.py` にあり、P0 時点で `tech_stack` / `screenshots_count` / `results_summary`、atomic save、v0/v1 load fallback は実装済み。
- `ReconState` には `parallel_task_progress` がなく、各並行タスクの開始・進行・完了・失敗・成果物参照・再開理由は保存されない。
- `parallel_tasks.py` の `permutation_executed` は単純な bool で、タスクごとの artifact provenance や `checkpoint_version` とは結び付いていない。
- `visual_recon()` は現状 `state` を受け取らないため、checkpoint hook を全タスクへ統一的に差し込むためのインターフェース調整が必要。
- `run_parallel_tasks()` は全タスクを組み立てて `asyncio.gather()` するだけで、checkpoint と成果物の整合に基づく skip / rerun 判定を行わない。
- Run Ledger（`run_ledger`/`decision_traces`/`task_execution_records`）は SGK-2026-0299 で session に保存済みだが、本タスクでは可視化ロジックまで扱わない。

## 4. 具体的な仕様と制約条件
- **入力情報 (Input):** ReconState（完全版）、並行タスク進捗レコード、各タスク成果物の参照情報（artifact path / provenance / timestamps）。
- **出力/結果 (Output):**
  - 完全化された `recon_state.json`（並行タスク状態セクション付き）
  - 再開可否を判断できる `parallel_task_progress` と `artifact_refs`
- **制約・ルール:**
  - 並行タスク保存は冪等（同タスクの再保存は上書き）で、開始/進行/完了/失敗/スキップの状態遷移を保持する。
  - 中断直後でも前回正常 checkpoint へ戻れる保存経路を採る。
  - artifact の存在確認だけでなく provenance / checkpoint_version / 更新時刻を合わせて判定する。

## 5. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `ReconState` の P1a checkpoint schema を追加し、save/load round-trip と旧 state load の互換テストを先に固定する。
- [ ] ステップ2: 並行タスク状態更新 helper を実装し、開始・進行・完了・失敗・スキップが `parallel_task_progress` へ冪等にマージされるようにする。
- [ ] ステップ3: `ParallelTasks` の full_port / visual / permutation / dead_sub に checkpoint hook と artifact refs 記録を差し込む。
- [ ] ステップ4: `run_parallel_tasks()` に resume 判定を追加し、完了済みかつ成果物整合済みのタスクだけを skip し、不整合は `rerun_required` として安全側に倒す。
- [ ] ステップ5: checkpoint/resume 向けの targeted tests を追加し、正常系だけでなく中断復旧・重複成果物・部分生成 artifact・version 不整合・古い run 由来 artifact を検証する。
- [ ] ステップ6: 実 session artifact または最小再現 workspace を使って checkpoint 再開を検証し、「どこから何が再実行され、何が安全にスキップされたか」を運用者が確認できることを確かめる。

## 5.1 フェーズ分割
- Phase A: ReconState 完全化 + 並行タスク checkpoint（ステップ1-4）
- Phase B: 異常系を含む resume 検証（ステップ5）
- Phase C: 実 artifact 検証（ステップ6）

## 5.2 実装単位への細分化

### Unit 1: ReconState P1a schema contract
- **ゴール:** `parallel_task_progress` を保存契約に追加し、既存 v0/v1 state を壊さず読み込める。
- **対象ファイル:** `src/recon/pipeline.py`, `tests/unit/recon/test_recon_state_checkpoint.py`
- **実装アクション:**
  - `ReconState` に `parallel_task_progress: dict[str, dict[str, Any]] = field(default_factory=dict)` を追加する。
  - 各 task entry の標準キーを `status`, `started_at`, `updated_at`, `completed_at`, `checkpoint_version`, `artifact_refs`, `error_summary`, `resume_reason`, `attempt_count` に固定する。
  - `_build_serializable_dict()` に `parallel_task_progress` を追加する。
  - `_load_v0()` / `_load_v1()` で欠落時は `{}` に補完する。
- **先に追加するテスト:**
  - `test_parallel_task_progress_roundtrip`: populated state を save/load して全キーが保持される。
  - `test_v1_load_defaults_parallel_task_progress`: 既存 v1 JSON にキーがなくても `{}` で load できる。
  - `test_v0_load_defaults_parallel_task_progress`: v0 JSON でも `{}` で load できる。
- **検証コマンド:** `.venv/bin/pytest tests/unit/recon/test_recon_state_checkpoint.py -k "parallel_task_progress or v1_load or v0_load" -q`
- **完了条件:** 既存 resume/diff テストを壊さず、`parallel_task_progress` が保存・復元・欠落補完される。

### Unit 2: Checkpoint update helper and artifact normalization
- **ゴール:** 並行タスクが state dict を直接壊さず、同じ形式で状態遷移と成果物参照を記録できる。
- **対象ファイル:** `src/recon/pipeline.py`, `tests/unit/recon/test_recon_state_checkpoint.py`
- **実装アクション:**
  - `ReconState.update_parallel_task_progress(task_name, status, *, artifact_refs=None, error_summary="", resume_reason="")` を追加する。
  - `attempt_count` は `status == "running"` の初回または再実行時に増やす。
  - `started_at` は初回 running 時のみ設定し、`updated_at` は毎回更新する。
  - `completed_at` は `completed` / `skipped` / `failed` / `rerun_required` の終端状態で設定する。
  - `artifact_refs` は list of dict に正規化し、最低限 `path`, `kind`, `exists`, `size`, `mtime` を持たせる。
- **先に追加するテスト:**
  - `test_update_parallel_task_progress_records_running_then_completed`: running から completed へ遷移して時刻と artifact が残る。
  - `test_update_parallel_task_progress_merges_artifacts`: 既存 entry を消さず artifact を更新する。
  - `test_update_parallel_task_progress_records_failure`: 例外内容が `error_summary` に残る。
- **検証コマンド:** `.venv/bin/pytest tests/unit/recon/test_recon_state_checkpoint.py -k "update_parallel_task_progress" -q`
- **完了条件:** 並行タスク側から呼べる単一 helper に状態更新が集約される。

### Unit 3: ParallelTasks checkpoint hooks
- **ゴール:** full_port / visual / permutation / dead_sub の各タスクが開始・終了・失敗・スキップを checkpoint に残す。
- **対象ファイル:** `src/recon/parallel_tasks.py`, `tests/recon/test_parallel_tasks.py`
- **実装アクション:**
  - `visual_recon(live_subs, workspace, state=None)` に変更し、既存呼び出し互換のため `state` は任意引数にする。
  - 各タスクの戻り値分岐で、`state.update_parallel_task_progress()` に終端状態と成果物参照を渡す。
  - no input / tool missing / no results は `skipped` または `completed` として結果に合わせて記録する。
  - 例外を返す経路では `failed` と `error_summary` を記録する。
  - 正常終了時は output file や generated file を `artifact_refs` に入れて `completed` を記録する。
  - `running` 記録と `state.save()` は Unit 4 の pipeline wrapper に寄せ、タスク本体は戻り値と artifact refs の責務に集中する。
- **先に追加するテスト:**
  - `test_full_port_scan_updates_checkpoint_on_skip`: no live subs で `skipped` が残る。
  - `test_full_port_scan_updates_checkpoint_on_completed`: output file が artifact_refs に残る。
  - `test_visual_recon_accepts_state_and_updates_checkpoint`: visual でも state 付き呼び出しができる。
  - `test_permutation_scan_records_already_executed_skip`: `permutation_executed=True` が progress に残る。
  - `test_dead_subdomain_scan_updates_checkpoint_on_completed`: dead sub output が artifact_refs に残る。
- **検証コマンド:** `.venv/bin/pytest tests/recon/test_parallel_tasks.py -k "checkpoint or progress or already_executed" -q`
- **完了条件:** 4タスクすべてで `parallel_task_progress` が更新され、既存の戻り値形式は維持される。

### Unit 4: Pipeline checkpoint persistence wrapper
- **ゴール:** 並行タスクの状態更新後に `recon_state.json` が保存され、保存失敗時も reason code で追跡できる。
- **対象ファイル:** `src/recon/pipeline.py`, `tests/unit/recon/test_recon_state_checkpoint.py`
- **実装アクション:**
  - `ReconPipeline._save_checkpoint()` を並行タスク hook から再利用する前提で、`step_label` に `parallel:<task_name>:<status>` を渡せるようにする。
  - `run_parallel_tasks()` 内で各タスク coroutine を直接渡すのではなく、`_run_parallel_checkpointed(task_name, coro_factory)` のような wrapper を作る。
  - wrapper は実行前に running を記録して保存し、終了後にタスク結果を確認して保存する。
  - 例外時は failed を記録して保存し、`asyncio.gather(..., return_exceptions=True)` の既存挙動は維持する。
- **先に追加するテスト:**
  - `test_run_parallel_tasks_saves_checkpoint_on_task_completion`: `_save_checkpoint` が task completion ごとに呼ばれる。
  - `test_run_parallel_tasks_records_exception_as_failed`: coroutine 例外時に failed entry が残る。
- **検証コマンド:** `.venv/bin/pytest tests/unit/recon/test_recon_state_checkpoint.py -k "parallel_tasks_saves_checkpoint or records_exception" -q`
- **完了条件:** fire-and-forget 実行でも途中 state が `recon_state.json` に落ちる設計になる。

### Unit 5: Resume decision and artifact consistency
- **ゴール:** 完了済み checkpoint と artifact が一致するタスクだけを skip し、欠損・古い run・部分生成は再実行に回す。
- **対象ファイル:** `src/recon/pipeline.py`, `tests/unit/recon/test_recon_state_checkpoint.py`
- **実装アクション:**
  - `ReconState.get_parallel_task_resume_decision(task_name)` または module helper を追加する。
  - `status == "completed"` かつ `artifact_refs[*].exists == true` かつ実ファイルの `size` / `mtime` が記録値と矛盾しない場合だけ `skip` を返す。
  - artifact が存在しない、size が 0、mtime が記録より古い、`checkpoint_version` が未対応の場合は `rerun_required` を返す。
  - skip 時は `status="skipped"` ではなく、既存 completed を保持しつつ `resume_reason="checkpoint_artifacts_valid"` を追記する。
- **先に追加するテスト:**
  - `test_resume_decision_skips_completed_with_valid_artifact`
  - `test_resume_decision_reruns_missing_artifact`
  - `test_resume_decision_reruns_zero_byte_artifact`
  - `test_resume_decision_reruns_checkpoint_version_mismatch`
- **検証コマンド:** `.venv/bin/pytest tests/unit/recon/test_recon_state_checkpoint.py -k "resume_decision" -q`
- **完了条件:** resume 判定が artifact の存在だけに依存せず、安全側に倒れる。

### Unit 6: Wire resume decision into run_parallel_tasks
- **ゴール:** `run_parallel_tasks()` が未完了・不整合タスクだけを実行し、skip / rerun の理由を state に残す。
- **対象ファイル:** `src/recon/pipeline.py`, `tests/unit/recon/test_recon_state_checkpoint.py`
- **実装アクション:**
  - `run_parallel_tasks()` の task list 構築前に `full_port`, `visual`, `permutation`, `dead_sub` の resume decision を評価する。
  - `skip` のタスクは coroutine を作らず、`resume_reason` を progress に追記して checkpoint 保存する。
  - `rerun_required` のタスクは `attempt_count` を増やして実行対象に入れる。
  - chained task の full_port が skip でも dead_sub 判定は独立して評価する。
  - visual は Unit 3 の `state` 任意引数を使って progress 更新対象に含める。
- **先に追加するテスト:**
  - `test_run_parallel_tasks_skips_valid_completed_tasks`
  - `test_run_parallel_tasks_reruns_missing_artifact_tasks`
  - `test_run_parallel_tasks_evaluates_dead_sub_after_full_port_skip`
- **検証コマンド:** `.venv/bin/pytest tests/unit/recon/test_recon_state_checkpoint.py -k "run_parallel_tasks_skips or reruns_missing_artifact or dead_sub_after_full_port_skip" -q`
- **完了条件:** 中断後の再実行で、全タスクを無条件に再実行しない。

### Unit 7: Regression and integration verification
- **ゴール:** P0 resume/diff と P1a checkpoint/resume が同時に成立することを確認する。
- **対象ファイル:** `tests/unit/recon/test_recon_state_checkpoint.py`, `tests/recon/test_parallel_tasks.py`, 必要に応じて `tests/recon/test_integration.py`
- **実装アクション:**
  - Unit 1-6 の targeted tests を全て通す。
  - 既存の P0 checkpoint test 全体を通す。
  - ParallelTasks 既存テスト全体を通し、戻り値互換を確認する。
  - 実 artifact が用意できる場合は、`workspace/projects/<target>/recon_state.json` を使った resume dry-run 相当の手順を記録する。
- **検証コマンド:**
  - `.venv/bin/pytest tests/unit/recon/test_recon_state_checkpoint.py -q`
  - `.venv/bin/pytest tests/recon/test_parallel_tasks.py -q`
  - `python3 scripts/sync_shigoku_updated_at.py`
  - `python3 scripts/validate_shigoku_docs.py`
- **完了条件:** targeted tests と既存 checkpoint/parallel tests が通り、docs validation が 0 issue で終わる。

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:高] checkpoint schema を広げた結果、旧 state reader や途中保存ファイルとの互換が崩れる可能性がある。欠落キー補完と schema 差分テストを先に固定する。
- [ ] [重要度:中] 並行タスクの再開で重複ファイル生成を避ける（成果物ファイル名の日付プレフィックスと idempotency）。
- [ ] [重要度:中] decision tree 可視化は本タスクから分離したため、checkpoint 側で必要な event trace は SGK-2026-0334 と契約を合わせる。

## 6.2 懸念点と対策

### SRE/インフラエンジニア視点
- [ ] 懸念点: 中断やプロセス異常終了の瞬間に `recon_state.json` が破損すると、再開不能または誤再開になる。発生確率:高 / 影響度:大
  修正案: ステップ2を「一時ファイル経由の原子的置換・破損検知メタデータ・前回正常 checkpoint へのフォールバック」を含む内容へ修正し、保存経路そのものを耐障害化する。
- [ ] 懸念点: 並行タスクが近接タイミングで state を更新すると、最後に保存したタスクだけが残る競合上書きが起きうる。発生確率:中 / 影響度:大
  修正案: ステップ3に「開始/進行/完了/失敗/スキップごとのマージ更新」と `checkpoint_version` 記録を組み込み、再開時はステップ4で version 不整合を `rerun_required` 扱いにする。
- [ ] 懸念点: resume 判定が成果物の存在確認だけに寄ると、部分生成や古い run の artifact を誤採用する。発生確率:中 / 影響度:中
  修正案: ステップ4とステップ5に `artifact_refs` の provenance 照合と異常系テストを組み込み、存在だけでは skip しない判定へ固定する。

### ソフトウェアアーキテクト視点
- [ ] 懸念点: `parallel_task_progress` の構造が曖昧なまま実装すると、保存互換性と reader 側の前提が早期に崩れる。発生確率:高 / 影響度:大
  修正案: ステップ1を「保存する各キーと欠落時補完規則まで定義する schema 設計」を含む内容へ修正し、後方互換の前提を計画書で固定する。
- [ ] 懸念点: checkpoint 基盤と可視化基盤を1タスクで進めると、保存契約と表示契約の責務境界が曖昧になる。発生確率:中 / 影響度:大
  修正案: 本計画書では checkpoint/resume 契約に限定し、decision tree の表示契約は SGK-2026-0334 に分離する文言をゴール・全体像・リスクへ反映する。
- [ ] 懸念点: Recon / ParallelTasks の双方が resume 判定を独自実装すると、同じ矛盾状態への扱いが分岐する。発生確率:中 / 影響度:中
  修正案: ステップ4で再開判定の責務を `run_parallel_tasks` に集約し、ステップ3は状態記録だけに寄せる。

### デバッガー視点
- [ ] 懸念点: 再開失敗時に「どの状態遷移で壊れたか」が残らないと、再現も局所修正も難しい。発生確率:高 / 影響度:大
  修正案: ステップ3に `started_at` / `updated_at` / `completed_at` / `resume_reason` / `error_summary` を必須記録として含め、状態遷移の痕跡を残す。
- [ ] 懸念点: 成果物が存在しても中身が古い・部分生成・別 run 由来のケースを誤って完了扱いする可能性がある。発生確率:高 / 影響度:大
  修正案: ステップ4を `artifact_refs` 照合込みの再開判定へ修正し、証跡不一致はスキップせず `rerun_required` として扱う。
- [ ] 懸念点: テストが正常系中心だと、中断復旧や部分生成 artifact のような実障害パターンを取り逃がす。発生確率:中 / 影響度:大
  修正案: ステップ5に「中断復旧・重複成果物・部分生成 artifact・version 不整合」の異常系検証を明示して追加する。

### CTO視点
- [ ] 懸念点: checkpoint 基盤が可視化機能に引きずられると、先に欲しい「安全に途中再開できる状態」に到達するまでが遅くなる。発生確率:中 / 影響度:大
  修正案: ゴールとフェーズ分割を checkpoint/resume 完結へ絞り、可視化は SGK-2026-0334 の完了条件として切り出す。
- [ ] 懸念点: 実 artifact で resume の可用性確認をしないと、机上では通っても運用導入時に信用されない。発生確率:低 / 影響度:大
  修正案: ステップ6で実 session artifact を使った再開検証を完了条件へ格上げする。
- [ ] 懸念点: P1a の完了条件が「state に書いた」だけで終わると、ユーザー価値である再実行時間短縮と誤再実行防止が測れない。発生確率:中 / 影響度:中
  修正案: Unit 6 と Unit 7 に skip / rerun の観測可能な検証を入れ、完了条件を「未完了・不整合タスクだけが実行されること」に固定する。

### 6.3 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0322-D01
    title: "継続監視: checkpoint metadata と decision tree 表示契約の接続"
    reason: "P1a は checkpoint/resume に限定し、可視化は P1b に分離したため"
    impact: medium
    tracking_task_id: SGK-2026-0334
    recommended_next_action: "SGK-2026-0334 で checkpoint metadata を decision tree の再開判断ノードへ接続する"
```
