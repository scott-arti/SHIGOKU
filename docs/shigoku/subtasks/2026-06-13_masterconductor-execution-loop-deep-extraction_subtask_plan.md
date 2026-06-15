---
task_id: SGK-2026-0287
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0264
related_docs:
- docs/shigoku/plans/2026-06-05_master-conductor-split-plan_plan.md
- docs/shigoku/subtasks/2026-06-12_masterconductor-execution-loop-dispatch-hitl_subtask_plan.md
- docs/shigoku/reports/2026-06-13_sgk-2026-0286_work_report.md
title: 'MasterConductor execution loop 深層抽出: Plan/Apply/FailurePolicy 分解'
created_at: '2026-06-13'
updated_at: '2026-06-16'
tags:
- shigoku
target: src/core/engine/master_conductor.py::execute_with_replan, src/core/engine/master_conductor.py::_execute_single_task_full_flow
---

# 実装計画書：MasterConductor execution loop 深層抽出: Plan/Apply/FailurePolicy 分解

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

## 1. 達成したいゴール（ユーザー視点）
- [ ] `src/core/engine/master_conductor.py` に残る `execute_with_replan` と `_execute_single_task_full_flow` を、公開 method 名・戻り値・副作用順序を維持したまま段階的に薄くできること。
- [ ] `master_conductor.py` を現行 5913 行から 5300-5500 行台まで圧縮し、少なくとも 450 行以上の純減を狙えること。
- [ ] `batch execution plan`, `timeout recovery plan`, `task result apply plan`, `failure/replan policy` の順で小さく外出しし、production caller を壊さないこと。
- [ ] `MasterConductor` は state owner / final mutation owner のまま維持し、`master_conductor_execution_runner_service.py` は pure helper と plan builder に限定すること。
- [ ] `SGK-2026-0286` の未達事項である `execute_with_replan` 深層抽出、batch recovery service 化、Plan/Apply 分解を本タスクで追跡できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: （修正）`execute_with_replan` と `_execute_single_task_full_flow` の facade wrapper / final mutation owner。`_state_lock`, `task_queue`, `completed_tasks`, `execution_log`, `pending_hitl`, `event_bus`, `context`, checkpoint はここに残す。
  - `src/core/engine/master_conductor_execution_runner_service.py`: （修正）既存の event payload / execution record / batch size helper を拡張し、`BatchExecutionPlan`, `TimeoutRecoveryPlan`, `TaskResultApplyPlan`, `FailureReplanDecision` の pure builder を追加する。
  - `src/core/engine/master_conductor_dependencies.py`: （修正候補）callable が増えすぎる場合のみ `ExecutionLoopDependencies` を追加する。未使用 field は追加しない。
  - `tests/core/engine/test_master_conductor_execution_runner_service.py`: （新規）service helper の pure tests。batch plan、timeout recovery plan、failure/replan policy、result apply plan を直接検証する。
  - `tests/core/engine/test_mc_injection_parallel_dispatch.py`: （修正）injection batch size / timeout / chunking / sequential recovery の facade parity tests。
  - `tests/core/engine/test_mc_intelligence_integration.py`: （修正）`_execute_single_task_full_flow` の success/failure/replan/HITL/context propagation parity tests。
  - `tests/core/engine/test_mc_strategic_upgrade.py`: （修正候補）`execute_with_replan(max_tasks=...)` の strategy review / summary call の regression tests。
  - `tests/core/engine/test_integration_mc_context_designer.py`: （修正候補）context enrichment と dispatch 前後の state parity tests。
- **データの流れ / 依存関係:**
  - `execute_with_replan` -> facade が global guard / queue selection を実行 -> service が `BatchExecutionPlan` を構築 -> facade が orchestrator 実行 -> service が `TimeoutRecoveryPlan` / `BatchResultApplyPlan` を構築 -> facade が lock 下で task state / completed_tasks / checkpoint を適用
  - `_execute_single_task_full_flow` -> facade が task enrichment / event emit / dispatch を実行 -> service が result classification と apply plan を構築 -> facade が execution_log / task state / context / replan / HITL final mutation を適用
  - failure path -> service が `FailureReplanDecision` を返す -> facade が `replan()`, `_add_tasks()`, quarantine metadata, failure context を適用
  - summary tail -> facade が `_generate_summary()` を呼ぶ。summary の追加抽出は本タスクの副次対象にし、primary target は execution loop の状態遷移に置く。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `Task`, `TaskExecutionRecord`, `ParallelTask` results, `ExecutionContext`, `task_queue`, `completed_tasks`, `execution_log`, `settings`, `resource_manager`, `orchestrator`, `pending_hitl`
- **出力/結果 (Output):** `dict` summary、`dict` dispatch result、`BatchExecutionPlan`、`TimeoutRecoveryPlan`、`TaskResultApplyPlan`、`FailureReplanDecision`
- **制約・ルール:**
  - `execute_with_replan(max_tasks: int | None = None) -> dict` と `_execute_single_task_full_flow(task: Task) -> dict` の method 名、呼び出し元、戻り値 shape は維持する。
  - service は `MasterConductor` instance を保持しない。`master_conductor.py` への import は禁止する。
  - `task_queue`, `completed_tasks`, `execution_log`, `pending_hitl`, `_state_lock`, `context`, `event_bus`, `audit_logger`, `writer`, `resource_manager.start()`, `save_session()` の final mutation は facade に残す。
  - global guard 注入 (`_ensure_global_csrf_guard_task`, `_ensure_global_xss_guard_task`, `_ensure_global_oob_guard_task`) は facade に残す。
  - service helper は pure function を基本とし、戻り値は dataclass / TypedDict / plain dict のいずれかで構造を明示する。
  - callable 依存が 1 helper で 5 個を超える場合は `ExecutionLoopDependencies` を作る。field ごとに利用箇所と代表テストを持たせる。
  - `TaskState.SUCCESS`, `TaskState.FAILED`, `TaskState.SKIPPED` の扱い、completed_tasks 追加回数、checkpoint cadence、batch timeout recovery の挙動を変えない。
  - HITL pending completion、`TASK_STARTED` / `TASK_COMPLETED` / `TASK_FAILED` event payload、failure reason code / category、flaky quarantine、replan_depth を維持する。
  - cookie、auth header、token、session secret は logs / tests / plan examples に出さない。
  - ReconPipeline adapter、Recon branch 完全抽出、dispatch 追加 branch 抽出は本タスクの non-goal とする。

## 3.1 現行 baseline
- `src/core/engine/master_conductor.py`: 5913 行
- `execute_with_replan`: 3311-3586、276 行
- `_execute_single_task_full_flow`: 3588-3977、390 行
- `_dispatch`: 5077-5371、295 行。本タスクでは追加抽出しない。
- `_generate_summary`: 5741-5796、56 行。本タスクでは primary target にしない。
- `src/core/engine/master_conductor_execution_runner_service.py`: 201 行。既存 helper は `build_task_started_payload`, `build_task_state_event_payload`, `build_execution_record_init`, `compute_batch_size`, `build_parallel_tasks`, `compute_batch_timeout_params`。

## 3.2 抽出単位
| Unit | 抽出対象 | service 側の責務 | facade 側に残す責務 |
|---|---|---|---|
| BatchExecutionPlan | batch task list、parallel task list、timeout、chunk size、mixed agent 判定 | `BatchExecutionPlan` を構築し、injection/recon timeout 条件を計算する | queue selection、lock、orchestrator 実行 |
| TimeoutRecoveryPlan | batch timeout 例外時の逐次 recovery 対象と failure reason | 未完了 task の抽出、failure reason の分類、mark failed 対象を返す | `_execute_single_task_full_flow`, task mutation, `_record_failure_context`, completed_tasks |
| BatchResultApplyPlan | orchestrator results から task state に反映すべき失敗情報 | `timeout_orchestrator` / `orchestrator_failed` の判定と apply 対象を返す | task mutation、completed_tasks 追加、checkpoint |
| TaskResultApplyPlan | dispatch result 成功/失敗の state transition | success/failure branch の apply intent、context update intent、finding handling intent を構築する | `execution_log.add_record`, context merge, task_queue mutation, event emit |
| FailureReplanDecision | failure/replan policy | root cause、flaky verdict、max depth から should_replan / wait_seconds / quarantine を判定する | `replan()`, `_add_tasks()`, `time.sleep`, task.params mutation |

## 3.3 Non-Negotiable Behavior Matrix
| 領域 | 維持する挙動 | 固定方法 |
|---|---|---|
| batch timeout | batch timeout 時は未完了 task のみ逐次 recovery し、完了済み task は再実行しない。 | `test_mc_injection_parallel_dispatch.py` に timeout recovery tests を追加する。 |
| completed_tasks | 通常 batch と exception batch の両方で、同じ task を二重追加しない。 | service unit test と facade parity test で completed count を確認する。 |
| checkpoint | `executed % checkpoint_interval == 0` の save cadence を維持する。 | `execute_with_replan(max_tasks=...)` fixture で `save_session` 呼び出しを確認する。 |
| lifecycle event | `TASK_STARTED`, `TASK_COMPLETED`, `TASK_FAILED` payload shape と順序を維持する。 | `test_mc_intelligence_integration.py` で event emission を確認する。 |
| HITL pending | intervention block、approval request、pending completion を維持する。 | 既存 HITL tests と `_execute_single_task_full_flow` parity tests を再実行する。 |
| failure/replan | replan_depth、flaky quarantine、root_cause.retry_recommended、recon timeout replan policy を維持する。 | failure/replan policy tests と timeout policy tests を追加・再実行する。 |
| context propagation | accumulated_context merge、wordlist learning、target_info update を維持する。 | context designer integration tests を再実行する。 |
| startup / checkpoint resilience | `writer.start`, `resource_manager.start()`, checkpoint / final `save_session()` の継続性を維持する。 | startup/checkpoint resilience tests を追加し、resource manager start 失敗時も loop 継続・終了時保存を確認する。 |
| background worker wait | queue 空でも `ReconWorker-*` が生存中なら premature exit せず待機継続する。 | `threading.enumerate()` を差し替える facade parity test を追加する。 |
| pre-batch intelligence | SelfReflection、strategy review、KG-based dynamic task inference の cadence と呼び出し順を維持する。 | `test_mc_strategic_upgrade.py` に pre-batch phase parity tests を追加する。 |
| precheck early return | RiskPredictor block と intervention block の early return 時の state / log / pending HITL / prioritizer outcome を維持する。 | `test_mc_intelligence_integration.py` と HITL 系 tests に early-return parity を追加する。 |
| side-effect order | execution_log、event emit、finding、react、handoff、context、pending HITL の順序を維持する。 | call-order recorder fixture を使って success/failure/exception path の順序を固定する。 |

## 3.4 懸念点と対策
### SRE / インフラエンジニア観点
| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|---|---|---|---|
| `writer.start`, `resource_manager.start()`, `save_session()` の障害時継続性が tests で固定されていない。 | 中 | 大 | `§3.3` に startup/checkpoint resilience を追加し、Step 5 と Step 11 で resource manager 起動失敗時も loop が継続し、final `save_session()` が呼ばれることを固定する。 |
| queue 空かつ `ReconWorker-*` 生存中の待機分岐が抽出対象として明文化されていない。 | 高 | 中 | `§3.3` に background worker wait を追加し、Step 5 で `threading.enumerate()` 差し替え test を追加して、worker 生存時は continue、非生存時は break を固定する。 |
| timeout recovery の再実行上限と skipped task の証跡が plan contract にない。 | 中 | 大 | `TimeoutRecoveryPlan` に `recovery_task_ids`, `skipped_completed_task_ids`, `decision_reason` を追加し、Step 7-8 で各 task が batch 1 回 + recovery 1 回までであることを固定する。 |

### ソフトウェアアーキテクト観点
| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|---|---|---|---|
| SelfReflection、strategy review、KG-based dynamic task inference の facade-only 境界が明記されていない。 | 高 | 大 | `§2` と Step 5 / Step 24 に pre-batch intelligence phase は facade に残すと追記し、cadence と呼び出し順を tests で固定する。 |
| `master_conductor_execution_runner_service.py` が新しい god service になる可能性がある。 | 高 | 中 | `§3` と Step 2 に「1 helper = 1 unit」「service が 400 行超または 2 unit 混在なら分割検討」を追加し、代表 test と利用箇所がない helper / dependency field を追加しない。 |
| `TaskResultApplyPlan` が hook 群まで抱え、pure plan と facade side effect の境界が崩れる可能性がある。 | 中 | 大 | `§3.2` と Step 16-17 で `TaskResultApplyPlan` は state/context/finding intent までに限定し、DecisionEnhancer、DiffAnalyzer、PriorityBooster、handoff、event emit は facade-only hook zone として残す。 |

### デバッガー観点
| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|---|---|---|---|
| RiskPredictor block と intervention block の early return が抽出中に崩れても発見しづらい。 | 高 | 大 | `§3.3` に precheck early return parity を追加し、Step 14 で state、execution_log、pending HITL、prioritizer outcome、event 有無を固定する。 |
| 最終状態だけの検証では、execution_log / event / finding / react / handoff / context / pending HITL の順序崩れを拾えない。 | 中 | 大 | Step 15 と Step 21 に call-order recorder fixture を追加し、success/failure/exception path の副作用順序を固定する。 |
| 新しい plan dataclass に provenance がないと、parity 崩れ時に plan 側か apply 側か切り分けにくい。 | 中 | 中 | `BatchExecutionPlan`, `TimeoutRecoveryPlan`, `BatchResultApplyPlan`, `TaskResultApplyPlan`, `FailureReplanDecision` に `source_phase`, `decision_reason`, `affected_task_ids`, `skipped_task_ids` など必要最小限の trace field を持たせ、Step 2-4 で pure tests を追加する。 |

### CTO観点
| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|---|---|---|---|
| 完了条件が LOC 圧縮に寄りすぎると、behavior parity より行数削減が優先される可能性がある。 | 高 | 大 | `§4.2` で parity gates 全通過を必須条件、450 行純減を stretch goal として扱い、削減行数は work_report に実績として記録する。 |
| 20 step を一気通貫で進めると、差し戻し時の停止点が曖昧になる。 | 高 | 大 | `§4` を Phase A: `execute_with_replan`、Phase B: `_execute_single_task_full_flow` に分け、Step 12 と Step 23 に go/no-go gate を追加する。 |
| ロールバック / 停止条件が未定義で、後続抽出が前半の安定性を巻き込みやすい。 | 中 | 大 | `§4.3` を追加し、`test_mc_intelligence_integration.py`, `test_master_conductor_timeout_policy.py`, `test_master_conductor_hitl_pending.py` などの critical tests が崩れたら次 step へ進まないと明記する。 |

## 4. 実装ステップ（AIに指示する手順）
- [ ] Step 1: baseline を固定する。`wc -l src/core/engine/master_conductor.py`、AST 行数、`git status --short --branch`、`rg "execute_with_replan|_execute_single_task_full_flow"` の外部参照、`SGK-2026-0286` work_report の deferred_tasks、`§3.4` の懸念点対応状況を記録する。
- [ ] Step 2: 抽出 contract を先に固定する。各 plan dataclass の最小 field、`source_phase` / `decision_reason` / `affected_task_ids` / `skipped_task_ids` の採否、facade-only hook zone、service 行数・責務分割の gate を `tests/core/engine/test_master_conductor_execution_runner_service.py` の pure tests で表現する。
- [ ] Step 3: `tests/core/engine/test_master_conductor_execution_runner_service.py` を新設し、既存 helper の pure tests を先に追加する。対象は `compute_batch_size`, `compute_batch_timeout_params`, `build_parallel_tasks`, `build_task_started_payload`, `build_task_state_event_payload`, `build_execution_record_init`。
- [ ] Step 4: `BatchExecutionPlan` dataclass を `master_conductor_execution_runner_service.py` に追加する。`batch_tasks`, `parallel_tasks`, `batch_timeout`, `chunk_size`, `has_injection`, `has_recon_master`, `mixed_agents`, `execution_mode`, trace field を持たせ、`execute_with_replan` の 3423-3463 相当を plan builder に寄せる。
- [ ] Step 5: Phase A の facade-only pre-batch parity tests を追加する。`writer.start`, `resource_manager.start()` 失敗時の継続、ReconWorker 生存時の queue-empty wait、SelfReflection / strategy review / KG-based dynamic task inference の cadence と呼び出し順を固定する。
- [ ] Step 6: `execute_with_replan` を `BatchExecutionPlan` に配線する。global guard、queue selection、pre-batch intelligence、background worker wait、orchestrator 実行は facade に残し、timeout / chunking / parallel task construction の詳細を service から受け取る。
- [ ] Step 7: timeout recovery tests を追加する。batch timeout 時に `TaskState.SUCCESS` / `TaskState.FAILED` の task を再実行しないこと、未完了 task だけ `_execute_single_task_full_flow` に渡すこと、各 task が batch 1 回 + recovery 1 回までであること、`timeout_recovery` / exception type の failure reason が維持されることを固定する。
- [ ] Step 8: `TimeoutRecoveryPlan` と `BatchFailureApplyPlan` を追加する。service は未完了 task、skipped completed task、failure reason、mark failed 対象、decision reason を返し、facade は `_state_lock` 下で task state / error / `_record_failure_context` / `completed_tasks` を適用する。
- [ ] Step 9: orchestrator result apply tests を追加する。`res.success=False` かつ task が未完了の場合のみ `TaskState.FAILED` へ遷移し、既に SUCCESS / FAILED / SKIPPED の task は上書きしないことを固定する。
- [ ] Step 10: `BatchResultApplyPlan` を追加し、`execute_with_replan` の 3505-3518 相当を service plan + facade apply に分離する。`completed_tasks.extend(batch_tasks)` の二重追加がないことを tests で確認する。
- [ ] Step 11: checkpoint / summary tail / startup resilience の facade 境界を整理する。`save_session`, `_generate_summary`, `rich_logger.summary_table`, `context.metrics` の final mutation は facade に残し、checkpoint cadence と final `save_session()` を tests で固定する。
- [ ] Step 12: Phase A go/no-go gate を実行する。`.venv/bin/python -m py_compile` と `test_mc_injection_parallel_dispatch.py`, `test_mc_strategic_upgrade.py`, `test_master_conductor_timeout_policy.py` を通し、失敗時は Phase B に進まず plan/apply/facade のどこで parity が崩れたかを修正する。
- [ ] Step 13: `_execute_single_task_full_flow` の dispatch timeout decision を helper 化する。Injection 系 agent 判定と `injection_manager_timeout` の選択を service に寄せ、実際の `_dispatch_with_timeout_retry` 呼び出しは facade に残す。
- [ ] Step 14: precheck early-return tests を追加する。RiskPredictor block と intervention block で、task state、failure context、execution_log、pending HITL、prioritizer outcome、event emit の有無が従来どおりになることを固定する。
- [ ] Step 15: `TaskResultApplyPlan` tests を追加する。success result、failure result、timeout_result、findings あり、new_assets あり、context update ありの fixture に加え、call-order recorder fixture で execution_log / event / finding / react / handoff / context / pending HITL の順序を確認する。
- [ ] Step 16: facade-only hook zone を固定する。DecisionEnhancer、DiffAnalyzer、PriorityBooster、critical path analyzer、handoff、event emit、context merge、task_queue mutation は facade apply 側に残すことを tests と code review checklist に明記する。
- [ ] Step 17: `_execute_single_task_full_flow` の success branch を小分けに移す。execution record completion metadata、success state reset、failure metadata clear、context propagation intent、finding handling intent、react task intent を service plan に寄せ、facade が final mutation と hook zone を適用する。
- [ ] Step 18: failure/replan policy tests を追加する。`root_cause.retry_recommended=False`, flaky quarantine, `task.replan_depth >= max_replan_depth`, timeout failure, generic failure の各ケースで should_replan / quarantine / wait_seconds が維持されることを確認する。
- [ ] Step 19: `FailureReplanDecision` を追加し、failure branch の policy 判定を service 化する。`replan()`, `_add_tasks()`, `time.sleep`, task params mutation は facade に残す。
- [ ] Step 20: critical exception path を固定する。`_dispatch_with_timeout_retry` が例外を投げた場合、task state、`dispatch_exception`、execution_log、`TASK_FAILED` event、pending HITL completion、prioritizer outcome が従来どおりになることを test で確認する。
- [ ] Step 21: HITL / side-effect order parity tests を追加する。approval request、pending completion、TASK_STARTED / TASK_COMPLETED / TASK_FAILED、failure reason category、context propagation の順序を success/failure/exception path で固定する。
- [ ] Step 22: `_execute_single_task_full_flow` を thin wrapper 化する。preparation / dispatch / result apply / failure policy の helper 呼び出しへ再構成し、1 patch で複数責務を動かさない。
- [ ] Step 23: Phase B go/no-go gate を実行する。`.venv/bin/pytest -q tests/core/engine/test_mc_intelligence_integration.py tests/core/engine/test_master_conductor_intervention_gate.py tests/core/engine/test_master_conductor_hitl_pending.py tests/core/engine/test_master_conductor_hitl_priority.py` を通し、失敗時は次の抽出へ進まない。
- [ ] Step 24: `execute_with_replan` を thin loop 化する。global guard、queue selection、resource manager start、writer start、pre-batch intelligence、background worker wait、checkpoint、summary tail は facade に残し、batch planning / recovery / result apply の branch-heavy 部分だけ service に寄せる。
- [ ] Step 25: targeted tests を実行する。失敗した場合は次の抽出へ進まず、該当 plan/apply helper か facade apply 側のどちらで parity が崩れたかを修正する。
- [ ] Step 26: broad related tests と compile を実行する。`.venv/bin/python -m py_compile` と関連 pytest を通し、未実行があれば work_report に理由を残す。
- [ ] Step 27: 完了条件を確認する。behavior parity gates、critical tests、service import direction、facade final mutation owner を必須確認し、450 行純減は stretch goal として実績値を記録する。
- [ ] Step 28: `wc -l`, `graphify update .`, `python3 scripts/sync_shigoku_updated_at.py`, `python3 scripts/validate_shigoku_docs.py` を実行し、削減行数・残リスク・deferred_tasks を work_report / work_log に残す。

## 4.1 検証コマンド
baseline / compile:
```bash
wc -l src/core/engine/master_conductor.py

.venv/bin/python -m py_compile \
  src/core/engine/master_conductor.py \
  src/core/engine/master_conductor_execution_runner_service.py \
  src/core/engine/master_conductor_dependencies.py
```

service unit:
```bash
.venv/bin/pytest -q \
  tests/core/engine/test_master_conductor_execution_runner_service.py
```

execution loop targeted:
```bash
.venv/bin/pytest -q \
  tests/core/engine/test_mc_injection_parallel_dispatch.py \
  tests/core/engine/test_mc_intelligence_integration.py \
  tests/core/engine/test_mc_strategic_upgrade.py \
  tests/core/engine/test_integration_mc_context_designer.py \
  tests/core/engine/test_master_conductor_timeout_policy.py
```

regression set inherited from SGK-2026-0286:
```bash
.venv/bin/pytest -q \
  tests/core/engine/test_master_conductor_intervention_gate.py \
  tests/core/engine/test_master_conductor_hitl_pending.py \
  tests/core/engine/test_master_conductor_hitl_priority.py \
  tests/core/engine/test_master_conductor_dispatch_routing.py \
  tests/core/engine/test_master_conductor_recon_nonblocking.py \
  tests/core/engine/test_master_conductor_failure_reason_codes.py \
  tests/core/engine/test_master_conductor_vuln_family_gate.py
```

docs / graph:
```bash
graphify update .
python3 scripts/sync_shigoku_updated_at.py
python3 scripts/validate_shigoku_docs.py
```

## 4.2 完了条件
- [ ] behavior parity gates が全通過し、critical tests の失敗を残したまま完了扱いにしない。
- [ ] `master_conductor.py` が 5913 行から 5300-5500 行台に近づく。450 行以上の純減は stretch goal とし、未達の場合は work_report に理由と残抽出候補を残す。
- [ ] `execute_with_replan` が 276 行から 160 行以下、`_execute_single_task_full_flow` が 390 行から 240 行以下になる。
- [ ] `master_conductor_execution_runner_service.py` から `master_conductor.py` への import が 0 件である。
- [ ] service が `MasterConductor` instance を保持しない。
- [ ] `task_queue`, `completed_tasks`, `execution_log`, `pending_hitl`, `_state_lock`, `context`, `event_bus` の final mutation が facade に残る。
- [ ] batch timeout sequential recovery、orchestrator result apply、checkpoint cadence、completed_tasks 追加回数が tests で固定される。
- [ ] success/failure/replan/HITL/context propagation/event payload の parity が tests で固定される。
- [ ] targeted tests が全通過する。
- [ ] broad related tests が全通過するか、未実行理由と代替確認が work_report に残る。
- [ ] `graphify update .` と SHIGOKU docs validation が通る。

## 4.3 停止条件 / ロールバック条件
- [ ] `test_mc_intelligence_integration.py`, `test_master_conductor_timeout_policy.py`, `test_master_conductor_hitl_pending.py` のいずれかが失敗した場合は、次の抽出 step へ進まず、直近 patch 内で修正または切り戻し方針を決める。
- [ ] Phase A go/no-go gate が失敗した場合は `_execute_single_task_full_flow` 側の抽出へ進まない。
- [ ] Phase B go/no-go gate が失敗した場合は `execute_with_replan` の追加 thin loop 化へ進まない。
- [ ] service が `MasterConductor` instance を保持する、または `master_conductor.py` を import する変更が入った場合は、その patch を完了扱いにしない。
- [ ] 行数削減のために lifecycle event、HITL pending、context propagation、failure/replan policy の parity test を削る変更は禁止する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] 【発生確率：高】【影響度：大】`completed_tasks` の二重追加や未追加が発生し、summary と report-facing fields がずれる。
  - 対策: Step 7-8 で `BatchResultApplyPlan` tests を追加し、SUCCESS / FAILED / SKIPPED / timeout の各状態で追加回数を固定する。
- [ ] 【発生確率：中】【影響度：大】batch timeout recovery を service 化する過程で、完了済み task の再実行や未完了 task の取りこぼしが起きる。
  - 対策: Step 5-6 で timeout recovery plan を先に tests 化し、facade が final mutation を保持する。
- [ ] 【発生確率：中】【影響度：大】`_execute_single_task_full_flow` の success branch を動かして、context propagation、finding handling、react tasks、handoff の順序が変わる。
  - 対策: Step 11-12 で apply intent tests を追加し、facade apply order を明記する。
- [ ] 【発生確率：中】【影響度：大】failure/replan policy の抽出で flaky quarantine、root_cause.retry_recommended、replan_depth の条件が変わる。
  - 対策: Step 13-14 で `FailureReplanDecision` を pure test し、`replan()` と `_add_tasks()` は facade に残す。
- [ ] 【発生確率：中】【影響度：中】`master_conductor_execution_runner_service.py` が新しい god service になる。
  - 対策: Unit ごとに dataclass と tests を分け、batch planning / recovery / result apply / failure policy の責務を混ぜない。
- [ ] 【発生確率：中】【影響度：中】行数削減を急ぎすぎて production caller (`main.py`, `interactive_bridge.py`) の互換性を壊す。
  - 対策: public wrapper を維持し、`execute_with_replan(max_tasks=...)` の integration tests を先に通してから facade を薄くする。
- [ ] 【発生確率：低】【影響度：大】ReconPipeline adapter や dispatch 追加抽出へ scope creep し、execution loop の検証が薄くなる。
  - 対策: 本タスクでは Recon adapter と dispatch 追加抽出を non-goal とし、必要なら別 task として起票する。

### 5.1 work_report の deferred_tasks 記載ルール
- 未対応事項を残す場合は、work_report 作成前に別の実在する SHIGOKU tracking task を起票し、`tracking_task_id` にその task ID を入れる。
- 空値や仮 ID は使わない。
- 本タスクから defer してよい候補は、ReconPipeline adapter、dispatch 追加 branch 抽出、summary report artifact の長期監視に限定する。
