---
task_id: SGK-2026-0431
doc_type: work_report
status: done
parent_task_id: SGK-2026-0430
related_docs:
- docs/shigoku/plans/done/2026-08-08_sgk-2026-0431_parallel-executor-vdp-followup-drain-rehoming_plan.md
- docs/shigoku/reports/2026-08-07_sgk-2026-0430_sealed-live-rerun-verification_work_report.md
- docs/shigoku/reports/2026-08-10_sgk-2026-0437_authz-gap-closure-e2e-verification_work_report.md
- docs/shigoku/worklogs/2026-08-10_sgk-2026-0431_off-main-vdp-drain-main-threadization_work_log.md
title: off-main VDP drain の main-thread 化（recon crash 除去・breadth 回復）作業完了報告
created_at: '2026-08-10'
updated_at: '2026-08-10'
tags:
- shigoku
- vdp
- anti-curve-fitting
target: src/core/engine/master_conductor.py,src/recon/pipeline.py,src/recon/parallel_tasks.py,tests
---

# 作業完了報告: SGK-2026-0431（off-main VDP drain の main-thread 化）

## 0. 成果物サマリ

- **根本原因（0437 実証）を修正**: `_execute_single_task_full_flow`（7667）の
  未ガード drain が、並列 executor ワーカースレッド上で PCR-P1 assert（11724）を
  発火 → task_002 critical failure → recon truncate → breadth 削減。
- **修正は「off-main では drain せず main-thread へ委譲」方向のみ**。
  PCR-P1 assert（task_queue.py・drain 11724）は一切無改変。
- **封印 run で実測**: PCR-P1 0 件・critical failure 0 件・
  **scenario coverage 1/12 → 8/12**（breadth 回復）。
  confirmed 件数は指標にしていない（反 curve-fitting 維持）。

## 1. 実施内容

### 1.1 drain callsite 棚卸し（全 3 callsite を特定）

| callsite | 関数 | スレッド文脈 | 処置 |
|---|---|---|---|
| 7667 | `_execute_single_task_full_flow` | 並列 executor ワーカー / serial / recovery | **main-thread ガード追加** |
| 6702 | `_apply_post_batch_feedback` | main（参照 drain） | 不変（合流点） |
| 11695 | `_queue_vdp_follow_ups` | ガード済み（0426 W2 参照実装） | 不変 |

- `execute_parallel`（15256）・`resume_session`（15561）は drain 呼び出しなし
  （docstring の記述は stale。実行コードには無関係）。

### 1.2 修正 1: 7667 の main-thread ガード（11695 と同型）

```python
if threading.current_thread() is threading.main_thread():
    self._drain_vdp_pending_follow_up_injections()
```

off-main（並列ワーカー）では drain せず buffer に残し、main-thread 合流点
`_apply_post_batch_feedback`（6702）で必ず drain。serial/recovery（main）は
従来どおり同期 drain（回帰 0）。

### 1.3 修正 2（完了条件 3）: 例外経路の drain 合流点

`execute_with_replan` の batch 例外ハンドラ（旧 L7322-7364）では
`_apply_post_batch_feedback` が `if recovery_results:` の下でのみ呼ばれ、
非タイムアウト例外 or 空 recovery ではその batch の drain がスキップされ得た。
`continue` 前に main-thread drain（VDP drain + off-main task buffer drain）を
追加し、**どの batch 終了経路でも合流点が必ず存在**することを保証
（injection 滞留・喪失を作らない）。

### 1.4 修正 3（修正項目 4）: off-main task_queue mutation の一括委譲

recon チェーンに残る off-main の task_queue 直接 mutation（計 9 サイト）を
1 つの安全な入口に統一:

- `MasterConductor._add_tasks_main_safe(tasks, source)`（新規・3646）:
  main → 従来の `_add_tasks`（回帰 0）／off-main → buffer へ追加（queue 非 mutation）。
- `_ensure_off_main_task_buffer()`（3676・lazy init・hasattr ガード付き）:
  `{'lock', 'items'}` 構造で `_pending_off_main_task_batches` を保持。
- `_drain_pending_off_main_tasks()`（3694）: main-thread 限定 drain
  （fail-closed assert・task_queue.py 契約維持）。
- 合流点: `_apply_post_batch_feedback`（6793-6794・VDP drain の直後）と
  例外経路（7466-7467）。
- 置換サイト:
  - `_execute_recipe_task`（旧 6304・recipe 分岐・off-main）→ `_add_tasks_main_safe`
  - recon_master ブロック（旧 9908・`source="recon_result"`・off-main）→ `_add_tasks_main_safe`
  - `src/recon/pipeline.py`（4585/4616/4657/4717）・`src/recon/parallel_tasks.py`
    （204/570/729）の `mc._add_tasks(...)` → `mc._add_tasks_main_safe(...)`

## 2. 検証結果

### 2.1 self-checking テスト（新規 7 件・修正なしでは失敗することを確認済み）

`tests/unit/engine/test_mc_vdp_drain_off_main_delegation.py` → **7 passed**:

1. off-main full-flow が assert せず buffer 保持（7667 ガード）
2. main-thread batch feedback が buffered items を drain
3. `safe_run_async` 経由の recon body が critical fail しない
4. 例外経路が buffered injections を `continue` 前に drain（Gap #3）
5. main = 即時 enqueue / off-main = buffer → confluence で反映（Gap #4a）
6. recon pipeline の `_add_tasks_main_safe`（SharedLoop 経由）が buffer → confluence
7. off-main task buffer drain は fail-closed（PCR-P1 スタイル）

**自己検証**: Gap #3 drain 除去 → テスト4 FAILED。Gap #4 ガード無効化 →
テスト5-7 が `AssertionError('PCR-P1: task_queue mutation must be on main thread')`
で FAILED。修正復元後は全緑（修正が実効であることの証明）。

### 2.2 回帰（serial 経路 0426/0430 挙動不変）

- thread confinement / failopen / drain main-thread / task_queue main-thread:
  **18 passed**。
- VDP resilience / failure drill / holdout: **40 passed**。
- tests/recon: **129 passed**（2 failed は stash baseline で pre-existing と確認済み）。
- 追加ドライバ群（post-batch / recipe / parallel dispatch / intelligence /
  phase5 / phase7 / strategic / caido）: 既存 failure のみ（stash baseline 同一）。

### 2.3 不変条件

- **PCR-P1**: task_queue.py diff **0 行**（assert 無改変）。drain 11724 も無改変。
- **preflight**: `check_vdp_product_independence.py` → **verdict pass / exit 0**
  （4 ファイル走査・token hit 0・import closure OK）。
- **secret redaction**: run 成果物で **0 件**（digest のみ・session_env 0600 bbb）。
- **状態変更 0**: m3a run は GET のみ（auth-setup POST は guard 内のみ）。

## 3. 封印 run 実測（完了条件 5）

`session_20260810_012214.json`（exit 0・consistent・phase 9 rc=0）:

| 指標 | 0437（修正前） | 0431（修正後） |
|---|---|---|
| PCR-P1 / critical failure | task_002 crash | **0 件** |
| Scenario Coverage | 1/12 | **8/12** |
| recon 経路 | truncate | 完走（ATTACK phase unlocked） |

- authz 比較 evidence（ev-87cbedb909e33a28）は健在
  （`second_account_compared=true`・越境なし = 反 curve-fitting 維持・
  閾値/Validator 不変）。
- 成果物所有権: session 644 bbb:bbb / haddix report 600 bbb:bbb /
  session_env 0600 bbb（0436 chown 方式の恒久化が機能）。
- 広さ回復の解釈: **crash で breadth を削る欠陥の除去**であり、
  confirmed 件数は指標にしない（NOT in scope どおり）。

## 4. 完了条件判定（計画書対比）

| 完了条件 | 判定 | 根拠 |
|---|---|---|
| 1. 全 drain callsite 棚卸し | PASS | 3 callsite 特定（7667/6702/11695） |
| 2. off-main callsite を 11695 と同型ガードに統一 | PASS | 7667 ガード実装・自己検証テスト |
| 3. buffered injection の main-thread drain 保証（取りこぼし 0） | PASS | 合流点 6793-6794 + 例外経路 7466-7467 |
| 4. 回帰テスト（off-main で落ちない / main で反映 / recon 経路で critical failure なし） | PASS | 新規 7 テスト + 回帰 58 + recon 129 |
| 5. 封印 run で recon crash 解消・breadth 回復の実測 | PASS | coverage 1/12 → 8/12・PCR-P1 0 |
| 6. PCR-P1 assert 無改変 | PASS | task_queue.py diff 0 |

**in_scope_blocker 0 件**。

- `deferred_followup`: `execute_single_task`（インタラクティブ経路・src/ 内
  呼び出し元なし）には合流点が無く、off-main body の buffered task は
  次の `_apply_post_batch_feedback` / `execute_with_replan` まで滞留し得る
  （喪失はしない・バッチループ外・完了契約外として報告のみ）。
- `non_blocking_observation`: tests/recon の 2 failed と追加ドライバ群の
  既存 failure は pre-existing（stash baseline で確認・本変更と無関係）。

本タスクを **done** とする。
