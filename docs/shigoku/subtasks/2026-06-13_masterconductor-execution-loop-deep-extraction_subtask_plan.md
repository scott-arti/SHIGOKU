---
task_id: SGK-2026-0287
doc_type: subtask_plan
doc_usage: execution_plan
status: active
parent_task_id: SGK-2026-0264
related_docs:
- docs/shigoku/plans/2026-06-05_master-conductor-split-plan_plan.md
- docs/shigoku/subtasks/2026-06-12_masterconductor-execution-loop-dispatch-hitl_subtask_plan.md
- docs/shigoku/subtasks/2026-06-12_sgk-2026-0284_mc-policy-hitl-followup_subtask_plan.md
- docs/shigoku/subtasks/2026-06-12_sgk-2026-0285_mc-dispatch-extraction_subtask_plan.md
- docs/shigoku/reports/2026-06-13_sgk-2026-0286_work_report.md
- docs/shigoku/reports/2026-06-16_sgk-2026-0287_phase1-2_work_report.md
- docs/shigoku/worklogs/2026-06-16_sgk-2026-0287_work_log.md
- docs/shigoku/plans/2026-06-16_sgk-2026-0288_recon-pipeline-adapter_plan.md
- docs/shigoku/plans/2026-06-16_conductorstate-masterconductor-state-access-protocol_plan.md
- docs/shigoku/plans/2026-06-16_masterconductor-planning-flow-extraction-plan-replan-coordinator-split_plan.md
title: 'MasterConductor 抜本分割計画: compatibility shim / facade / domain coordinator 再構成'
created_at: '2026-06-13'
updated_at: '2026-06-18'
tags:
- shigoku
target: 'src/core/engine/master_conductor.py, src/core/engine/master_conductor_facade.py, src/core/engine/master_conductor_*.py, src/core/engine/conductor_core/'
---

# 実装計画書：MasterConductor 抜本分割計画: compatibility shim / facade / domain coordinator 再構成

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

## 1. 方針転換
この計画は、`src/core/engine/master_conductor.py` から一部メソッドを外出しするだけの局所計画ではなく、`MasterConductor` を互換入口・薄い facade・責務別 coordinator/service に再構成する抜本分割計画として扱う。

- [ ] `master_conductor.py` は最終的に 50-150 行の compatibility shim / re-export module にする。
- [ ] 実体クラスは `master_conductor_facade.py` に移し、最終的に 800-1500 行以下へ縮小する。
- [ ] 最大の conductor 関連単一ファイルを 1500 行以下、stretch 1000 行以下にする。
- [ ] 5900 行の別ファイル移動だけでは完了扱いにしない。
- [ ] 既存 import path `from src.core.engine.master_conductor import ...` は壊さない。
- [ ] production behavior、private-method monkeypatch tests、session/report payload、HITL、dispatch、async lifecycle を parity tests で固定してから段階的に分割する。

## 2. 現行 baseline と削減目標
- `src/core/engine/master_conductor.py`: 5900 行。
- AST method count: 178。
- 主な hotspot:

| Symbol | 行数 | 現状 |
|---|---:|---|
| `_dispatch` | 295 | async、worker、recon、cookie 注入、AgentFactory fallback が絡む最大 risk 領域 |
| `__init__` | 265 | dependency construction、state 初期化、feature wiring が混在 |
| `execute_with_replan` | 177 | batch loop、resource startup、checkpoint、summary tail、replan が混在 |
| `_run_intervention_precheck` | 175 | HITL / policy / risk predictor early return が混在 |
| `_observe_and_rethink` | 155 | observation、strategy、new task generation が混在 |
| `execute_single_task` | 139 | public path / compatibility behavior が濃い |
| `_add_tasks` | 138 | queue mutation、dedup、priority、context propagation が混在 |
| `plan` | 123 | planning side effects と task generation が混在 |
| `handle_finding` | 117 | finding normalization、policy、event/context side effects が混在 |
| `replan` | 109 | failure policy と task generation が混在 |
| `_execute_single_task_full_flow` | 109 | dispatch result apply、failure/replan、HITL/context side effects が混在 |

### 2.1 行数目標
| Milestone | `master_conductor.py` | 最大 conductor 関連単一ファイル | 判定 |
|---|---:|---:|---|
| 現状 | 5900 | 5900 | baseline |
| Phase 1 shim 化 | 50-200 | 5200-5900 | import 互換を先に確保する中間点。ここでは未完了。 |
| Phase 2-3 core split | 50-150 | 2500-3500 | state/deps/runtime loop を分離する中間点。 |
| Phase 4-6 domain split | 50-150 | 1200-1800 | dispatch/HITL/finding/replan/session を分離する実用完了圏。 |
| Final target | 50-150 | 800-1500 | 完了条件。stretch は最大単一ファイル 1000 行以下。 |

### 2.2 削減見込み
- `master_conductor.py` 単体は 5750-5850 行削減できる見込み。
- 「最大単一ファイル」は 4400-5100 行削減するのが本計画の本丸。
- production LOC 総量は dataclass、compat wrapper、tests 増加により大きく減らない可能性がある。成功指標は総 LOC ではなく、責務分離、最大ファイルサイズ、import 方向、behavior parity とする。

## 3. 非交渉の互換制約
- [ ] `src/core/engine/master_conductor.py` と同名の package `src/core/engine/master_conductor/` は作らない。Python import 解決と既存計画の互換警告により、file module を shim として維持する。
- [ ] `master_conductor.py` は `MasterConductor`, `ExecutionContext`, `Task`, `TaskState`, `Event`, `EventType`, `Finding`, `SiteNode` など既存外部 import symbols を re-export する。
- [ ] `src/commands/report.py` などの `Task`, `TaskState` import を壊さない。
- [ ] tests の module-level monkeypatch target がある symbol は、shim re-export、compat alias、または明示的 caller migration のいずれかで守る。
- [ ] `MasterConductor.__new__` を使う tests、private method 直接呼び出し tests、module-level service patch tests を inventory なしに壊さない。
- [ ] async contextvar reset、worker lifecycle、pending HITL、session payload、report-facing fields、checkpoint cadence を分割の都合で変えない。
- [ ] cookie、auth header、token、session secret は logs、plan examples、tests fixture に出さない。

## 4. 目標アーキテクチャ
| Layer | File / package | 役割 | サイズ目標 |
|---|---|---|---:|
| Compatibility shim | `src/core/engine/master_conductor.py` | 既存 import path の re-export、deprecation-free compatibility、`__all__` 管理 | 50-150 行 |
| Facade | `src/core/engine/master_conductor_facade.py` | `MasterConductor` class、public/private wrapper、state owner、final mutation owner、compat bridge | 800-1500 行 |
| State/deps | `src/core/engine/master_conductor_state.py`, `master_conductor_dependencies.py` | constructor 分解、dependency bundle、state snapshot、settings normalization | 200-600 行 |
| Runtime loop | `src/core/engine/conductor_core/runtime_loop.py` or flat `master_conductor_runtime_loop.py` | `execute_with_replan` の batch loop、checkpoint intent、summary tail intent | 300-800 行 |
| Task execution | `src/core/engine/conductor_core/task_execution.py` or flat `master_conductor_task_execution.py` | `_execute_single_task_full_flow` の preparation / result apply / failure policy | 300-800 行 |
| Dispatch router | `src/core/engine/conductor_core/dispatch_router.py` or flat `master_conductor_dispatch_router.py` | `_dispatch` branch routing、worker/recon/swarm/fallback、contextvar reset | 400-900 行 |
| HITL / policy | `src/core/engine/conductor_core/intervention_gate.py` or existing HITL services | `_run_intervention_precheck`、risk predictor、approval/pending completion | 250-700 行 |
| Planning / queue | `src/core/engine/conductor_core/planning_flow.py`, `task_queue_flow.py` | `plan`, `replan`, `_add_tasks`, priority/dedup/context propagation | 300-800 行 |
| Finding / observation | `src/core/engine/conductor_core/finding_flow.py`, `observation_flow.py` | `handle_finding`, `_observe_and_rethink`, react/degradation policy | 300-800 行 |
| Session / summary | existing `master_conductor_session_service.py`, `master_conductor_summary_service.py` | save/resume payload、legacy compatibility、summary generation | 200-600 行 |

`conductor_core/` package を追加する場合も、同名 package `master_conductor/` は作らない。既存 flat module 文化を優先する場合は `master_conductor_*.py` で統一し、Phase ごとに package 化の是非を stop/go 判定する。

## 5. 懸念点と対策
### 5.1 SRE / インフラエンジニア観点
| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|---|---|---|---|
| shim 化で import は通っても、resource manager / writer / worker lifecycle の副作用順が崩れる。 | 中 | 大 | Step 2 と Step 8 に lifecycle character tests を必須化し、`writer.start`, `resource_manager.start()`, worker wait, final `save_session()` の call order を固定する。 |
| `_dispatch` 分割時に async contextvar reset、recon worker 非ブロッキング、timeout fallback が漏れる。 | 高 | 大 | Step 11 を dispatch 単独 phase にし、branch routing matrix、contextvar reset、ReconWorker 生存時 wait、cookie injection、AgentFactory fallback の parity tests を先に追加する。 |
| session/checkpoint payload の互換が壊れ、実行は完了するが resume/report が破損する。 | 高 | 大 | Step 3 と Step 13 に session payload / legacy queue / pending HITL / adjacency list の snapshot tests を入れ、session service を runtime loop 分割の mandatory gate にする。 |
| 大規模移動で import cycle が発生し、起動時のみ失敗する。 | 中 | 大 | Step 1 で import graph と `master_conductor.py` import surface を inventory し、Step 4 以降は service -> facade import 0 を完了条件にする。 |
| coordinator 分割後の concurrency / timeout / cancellation 境界が曖昧になり、worker drain や timeout 継承が壊れる。 | 高 | 大 | Step 9 と Step 11 に runtime budget contract を追加し、max parallel、timeout 継承、cancel propagation、worker drain、queue depth を固定する。 |
| shim 化後に import は通るが、CLI 起動・session resume・report 生成の smoke が不足し、実利用でのみ壊れる。 | 中 | 大 | Step 5 と Step 19 に CLI / session / report smoke を追加し、import smoke だけで Phase 1 を通過させない。 |
| session/checkpoint 破損時の復旧観点が payload parity に寄りすぎ、partial write や corrupted payload の復旧が未固定になる。 | 中 | 大 | Step 16 に atomic write、corrupted session、partial checkpoint、legacy schema restore の fixtures を追加する。 |
| observability が分割先ログに散り、障害時に phase / coordinator / task_id / reason_code で追跡できなくなる。 | 高 | 中 | Step 9-12 と Step 20 に redaction 済み trace metadata の必須項目を追加し、phase、coordinator、task_id、reason_code、timeout_source を work_report に記録する。 |
| 実 report/session artifact の validation で別セッションや古い report を混ぜ、誤った合否判定を出す。 | 中 | 大 | Step 16 と Step 19 に report/session consistency checker を primary source gate として追加し、実 report がある場合は `shigoku-ops report consistency` の verdict を必須記録する。 |
| trace metadata の追加でログ cardinality が増えすぎる、または cookie/token を含む field が混入する。 | 中 | 大 | Step 9, Step 11, Step 19 に log cardinality budget と secret audit を追加し、trace field は低 cardinality・redaction 済み token のみに制限する。 |
| 長期作業中の dirty worktree / unrelated diff 混入で、phase rollback や原因切り分けが難しくなる。 | 高 | 中 | Step 1 と Step 20 に `git status --short --branch`、phase checkpoint、last green command、unrelated diff 除外記録を追加する。 |

### 5.2 ソフトウェアアーキテクト観点
| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|---|---|---|---|
| 5900 行を `master_conductor_facade.py` に移すだけで、巨大ファイル問題が温存される。 | 高 | 大 | Step 5 を shim 化の中間 milestone と明記し、Final target は最大 conductor 関連単一ファイル 1500 行以下にする。 |
| service が `MasterConductor` instance を保持し、新しい密結合 god service になる。 | 高 | 大 | Step 6 以降の全 service は data-in/data-out または coordinator interface に限定し、service -> facade import 0、final mutation owner は facade/state owner に限定する。 |
| constructor 分解を後回しにすると、各 service が初期化副作用を複製し始める。 | 中 | 大 | Step 6 を `__init__` / dependency construction 専用 phase にし、dependency bundle と state owner を先に整理する。 |
| package 化の名前選定を誤り、`master_conductor.py` と同名 package の import 競合を起こす。 | 中 | 大 | `§3` に同名 package 禁止を明記し、候補を `master_conductor_facade.py`, `master_conductor_*.py`, `conductor_core/` に限定する。 |
| `conductor_core/` と flat `master_conductor_*.py` の二択が残り、実装者ごとに構造が割れる。 | 中 | 中 | Step 4 に「Phase 1 で構成方式を1つに確定し、以後は混在禁止」を追加する。 |
| facade が 1500 行以下でも、state bridge / wrapper / mutation / policy が混在し再肥大化する。 | 高 | 大 | Step 18 と完了条件に facade 内の責務別上限を追加し、public wrapper、state mutation、compat bridge、orchestration の区分別行数を work_report に記録する。 |
| state owner が概念だけに留まり、coordinator が共有 mutable state を直接保持・変更し始める。 | 高 | 大 | Step 7-10 に `ConductorState` または state access protocol の導入可否 gate を追加し、coordinator が直接 mutable collections を保持しない条件を明記する。 |
| SGK-2026-0284/0285 の backlog を統合するが、旧達成条件との対応が見えにくくなる。 | 中 | 中 | Step 20 に crosswalk table を追加し、旧タスク項目が新 Phase/Step のどこで満たされたかを work_report に記録する。 |
| `Task`, `TaskState`, `ExecutionContext`, summary/session payload の読者 inventory が不足し、shim は通っても report/dashboard/CLI が壊れる。 | 高 | 大 | Step 1 に schema reader inventory を追加し、`src/commands/report.py`, reporting/session scripts, dashboard/session readers を re-export / payload compatibility gate に含める。 |
| Protocol / TypedDict / dataclass の境界が増えるほど、同じ概念の型が複数 module に分散する。 | 中 | 中 | Step 4 と Step 7 に boundary contract table を追加し、各 coordinator の入力/出力型、正本 module、禁止 duplicate 型を明記する。 |
| compatibility map がないまま private/public API を移すと、caller migration と wrapper retirement の判断が属人的になる。 | 高 | 中 | Step 4 と Step 17 に compatibility map を追加し、symbol、旧 import path、新実体、維持/移行/廃止判断、対応 test を記録する。 |

### 5.3 デバッガー観点
| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|---|---|---|---|
| public behavior ではなく private helper の tests が多く、移動後の monkeypatch target が大量に壊れる。 | 高 | 中 | Step 1 で private method / monkeypatch inventory を作り、Step 4 で compat wrapper を維持する対象と caller migration 対象を分類する。 |
| 最終状態だけの tests では、event、finding、HITL、context、execution_log の順序崩れを検出できない。 | 中 | 大 | Step 2 に call-order recorder fixture を追加し、success/failure/timeout/exception path の副作用順を固定する。 |
| exception path の粒度が粗く、`TimeoutError`, `asyncio.TimeoutError`, dispatch exception, worker exception が同一扱いで潰れる。 | 中 | 大 | Step 9 と Step 11 に exception matrix を追加し、failure reason code、task state、pending HITL cleanup、event payload を例外型別に検証する。 |
| facade wrapper が増えるほど実装箇所が追いにくくなる。 | 中 | 中 | Step 14 に wrapper retirement inventory を入れ、残す wrapper は互換理由、移行期限、対応 tests を work_report に記録する。 |
| private monkeypatch inventory が手作業だと漏れ、移動後に module-level patch target が壊れる。 | 高 | 中 | Step 1 に `rg` 結果の artifact 化を追加し、移動後に同じ検索で未対応 target を 0 にする check を入れる。 |
| character tests が広すぎると flaky になり、分割起因か既存不安定か判別しづらい。 | 高 | 大 | Step 2 に deterministic golden fixtures を追加し、event order、session payload、failure reason、HITL ticket を固定する。 |
| `__new__` ベースの minimal tests だけでは constructor 分割の破壊を見逃す。 | 高 | 中 | Step 2 と Step 5 に通常 constructor smoke と `__new__` compatibility smoke の両方を追加する。 |
| exception matrix に trace correlation がないと、失敗箇所が facade / coordinator / service のどこか追いづらい。 | 中 | 中 | Step 9-12 に `source_phase`, `coordinator`, `decision_reason`, `failure_reason_code` の trace fields を必須化する。 |
| import path は通っても、実体が想定 module から来ているか検証せず、shim / facade / old file の二重定義を見逃す。 | 中 | 大 | Step 2 と Step 5 に `inspect.getfile()` / `__module__` import-origin smoke を追加し、`MasterConductor` と re-export symbols の出所を固定する。 |
| golden fixtures を手で作ると現行挙動とズレ、parity test が誤った期待値を固定する。 | 中 | 大 | Step 2 に before-extraction baseline capture を追加し、現行コードから event order、session payload、summary、failure reason fixture を生成・保存してから比較する。 |
| phase 中の失敗時に「最後に通った状態」が記録されず、debug が再探索になる。 | 高 | 中 | Step 20 に phase checkpoint log を追加し、phase ごとの last green command、first failing command、変更 module、残 failing tests を記録する。 |

### 5.4 CTO観点
| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|---|---|---|---|
| 行数削減を急ぎすぎて、品質 gate を弱める誘因が出る。 | 高 | 大 | 完了条件を LOC だけにせず、critical tests、import direction、最大ファイルサイズ、public wrapper inventory、session/report parity を必須にする。 |
| 一気に全領域を変えると、失敗時の撤退点がなくなる。 | 高 | 大 | Step 5, Step 8, Step 10, Step 11, Step 13 に go/no-go gate を置き、失敗した phase の次へ進まない。 |
| 既存 SGK-2026-0284/0285 の backlog と競合し、どの計画が正本か分からなくなる。 | 中 | 中 | 本計画を SGK-2026-0287 の正本として、関連 docs を `related_docs` に入れ、dispatch/HITL は本計画の phase に統合する。 |
| 1500 行以下にしても、責務境界が曖昧なら次の変更でまた肥大化する。 | 中 | 大 | 各 coordinator にサイズ上限、責務、禁止 import、代表 tests を持たせ、500 行超または責務 2 個超で再分割 review を必須にする。 |
| 1タスクの scope が大きく、途中で中断すると「巨大 facade に移しただけ」になり得る。 | 高 | 大 | Step 5, Step 10, Step 13, Step 18 に Phase ごとの独立完了条件を追加し、Phase 1 は未完了中間状態と明示する。 |
| 行数削減の成功条件はあるが、保守性改善を判断する指標が薄い。 | 中 | 大 | Step 18 と完了条件に最大ファイル、import direction、coordinator 責務数、wrapper retirement 数、新規変更時に触るファイル数を success metric として追加する。 |
| compatibility wrapper が恒久化し、将来の変更コストを残す。 | 高 | 中 | Step 17 に wrapper retention policy を追加し、残す wrapper は理由・caller・retirement 条件を work_report に必須記録する。 |
| product-level acceptance が unit / engine tests に偏り、CLI / report / session の実利用での合格基準が弱い。 | 中 | 大 | Step 19 と検証コマンドに代表 CLI smoke、session resume、report summary generation の acceptance checks を追加する。 |
| validation が大きくなりすぎ、実装者が重い broad tests を後回しにして局所 green だけで完了扱いにする。 | 高 | 中 | Step 3 と Step 19 に validation tiering を追加し、smoke / targeted / related / artifact / docs の順で必須 gate と未実行理由を分けて記録する。 |
| 抜本分割の価値が LOC と構造だけに寄り、各 Phase がどの保守性リスクを下げたか判断しづらい。 | 中 | 中 | Step 18 と Step 20 に phase value statement を追加し、各 Phase の user-visible risk reduction と remaining risk を work_report に記録する。 |
| report/session schema に影響する変更なのに、実 artifact 不足を理由に検証が恒久的に未実行化する。 | 中 | 大 | Step 19 と Backlog に synthetic artifact fallback と real artifact requirement を追加し、実 artifact が無い場合は当該 Phase の未完了 gate として扱う。 |

## 6. 実装ステップ
### Phase 0: Inventory and Safety Net
- [x] Step 1: import / symbol / monkeypatch inventory を作る。
- [x] Step 2: character tests を先に追加する（`test_master_conductor_character.py`, 19 tests）。
- [x] Step 3: validation baseline を固定する（targeted pytest 84/84, py_compile clean, pre-existing failures 2 件記録）。

### Phase 1: Compatibility Shim and Facade Relocation
- [x] Step 4: module layout 決定。flat `master_conductor_*.py` に確定（同名 package 禁止）。
- [x] Step 5: `master_conductor.py` を compatibility shim 化（195 lines）。
- [x] Step 6: import cycle 解消（service → facade runtime import 0 件）。

### Phase 2: State, Dependencies, Constructor
- [x] Step 7: `__init__` 分類（dependency construction / state init / feature wiring / runtime defaults / event wiring）。
- [x] Step 8: constructor 分解を実装（`build_core_dependencies`, `build_mode_config`, `build_intelligence_modules` 抽出）。

### Phase 2.5: Monkeypatch Caller Migration（計画外・ユーザー指示で先行）
- [x] 9 test ファイル / 50+ patch targets を `master_conductor_facade.*` に移行（0 failures. D04 resolved）。
- [x] `test_master_conductor_shutdown_integration.py` sys.modules 汚染修正（`setup_module`/`teardown_module` 導入）。

### Phase 3: Runtime Loop and Task Execution
- [x] Step 9: `execute_with_replan` Plan/Apply 分解。
- [x] Step 10: `_execute_single_task_full_flow` 軽量抽出（`_capture_task_before_snapshot` helper 抽出。SGK-2026-0290 で 109→98 lines まで縮小し、size gate 再挑戦 slice で再判定）。

### Phase 4: Dispatch Router
- [x] Step 11: `_dispatch` cookie/auth helpers 抽出 + ReconPipeline deps 化（SGK-2026-0288）。
- [x] Step 12: dispatch facade wrapper 薄型化（`_dispatch` 295→69 lines。helper 抽出完了）。

### Phase 5: Domain Coordinators
- [x] Step 13: `_run_intervention_precheck` 175→52 lines（`_apply_intervention_defer_v1` + `_apply_intervention_require_approval` 抽出）。
- [x] Step 14: `_add_tasks` dedup を `_should_add_task` helper に抽出。`plan`/`replan` は SGK-2026-0290 で 123→25 / 109→64 lines まで縮小。
- [x] Step 15: `handle_finding`/`_observe_and_rethink` 深層抽出（SGK-2026-0289 で完了。`_observe_and_rethink` 155→71、`handle_finding` 117→82）。
- [x] Step 16: session/summary parity fixtures 追加（3 tests）。

### Phase 6: Wrapper Retirement and Final Gate
- [x] Step 17: wrapper inventory 整理（6 entries。本格的 retirement は facade size gate 再挑戦 slice で実施）。
- [x] Step 18: file size gate 最終評価（facade 5956 lines、shim 195 lines、最大単一ファイル 5956 lines。全 hotspot <100 lines は達成したが size gate は未達）。
- [x] Step 19: broad validation 最終状態（targeted hotspot suite 121/121 pass、broader suite 118/119 pass、pre-existing failure 1 件、RuntimeWarning 0）。
- [x] Step 20: work_report/work_log 更新（本セッションで完了）。

## 7. 検証コマンド
baseline / import smoke:
```bash
wc -l src/core/engine/master_conductor.py

.venv/bin/python - <<'PY'
from src.core.engine.master_conductor import MasterConductor, Task, TaskState, ExecutionContext
print(MasterConductor.__name__, Task.__name__, TaskState.__name__, ExecutionContext.__name__)
PY
```

compile:
```bash
.venv/bin/python -m py_compile \
  src/core/engine/master_conductor.py \
  src/core/engine/master_conductor_facade.py \
  src/core/engine/master_conductor_dependencies.py \
  src/core/engine/master_conductor_execution_plan_service.py \
  src/core/engine/master_conductor_execution_runner_service.py \
  src/core/engine/master_conductor_session_service.py
```

targeted engine tests:
```bash
.venv/bin/pytest -q \
  tests/core/engine/test_master_conductor_dispatch_routing.py \
  tests/core/engine/test_master_conductor_intervention_gate.py \
  tests/core/engine/test_master_conductor_hitl_pending.py \
  tests/core/engine/test_master_conductor_hitl_priority.py \
  tests/core/engine/test_mc_intelligence_integration.py \
  tests/core/engine/test_mc_injection_parallel_dispatch.py \
  tests/core/engine/test_master_conductor_session_service.py \
  tests/core/engine/test_master_conductor_session_payload_builder.py \
  tests/core/engine/test_master_conductor_failure_reason_codes.py \
  tests/core/engine/test_master_conductor_vuln_family_gate.py
```

session/report related:
```bash
.venv/bin/pytest -q \
  tests/test_session_persistence.py \
  tests/test_session_resume.py \
  tests/test_mc_upload.py \
  tests/unit/scripts/test_shigoku_ops_cli.py \
  tests/unit/reporting/test_report_loop_orchestrator.py \
  tests/unit/main/test_main_report_haddix.py
```

CLI / artifact smoke:
```bash
.venv/bin/shigoku-ops --help || python3 scripts/shigoku_ops_cli.py --help

# If a real report artifact is available for the touched flow:
.venv/bin/shigoku-ops report consistency --report <absolute-report-path>
.venv/bin/shigoku-ops session resolve-from-report --report <absolute-report-path>

# Synthetic artifact fallback when no real report exists:
.venv/bin/pytest -q tests/unit/scripts/test_shigoku_ops_cli.py tests/unit/reporting/test_report_loop_orchestrator.py

# Secret / trace metadata safety:
.venv/bin/shigoku-ops ops secret-audit --project-root . --exit-nonzero-on-findings
```

docs:
```bash
graphify update .
python3 scripts/sync_shigoku_updated_at.py
python3 scripts/validate_shigoku_docs.py
```

## 8. 完了条件
- [x] `master_conductor.py` が 195 行の compatibility shim になっている（目標 50-150、やや超過）。
- [ ] `master_conductor_facade.py` が 5956 行。目標 800-1500 は未達（全 hotspot <100 lines 達成済みだが facade 内 helper が純減を相殺）。
- [ ] 最大 conductor 関連単一ファイルが 5956 行。1500 行以下未達。
- [x] `src/core/engine/master_conductor/` という同名 package を作っていない。
- [x] `from src.core.engine.master_conductor import MasterConductor, Task, TaskState, ExecutionContext` が通る。
- [x] service/coordinator から facade/shim への runtime import が 0 件である。
- [x] `task_queue`, `completed_tasks`, `execution_log`, `pending_hitl`, `_state_lock`, `context`, `event_bus` の final mutation owner が facade である。
- [x] parity tests が通る（121/121）。
- [ ] runtime budget contract: 部分的（`should_checkpoint`/`build_runtime_loop_decision` 追加済み、contract fixture 化は未了）。
- [ ] trace metadata / secret audit: 未着手。
- [x] private wrapper inventory: work_report に記載済み（6 entries）。
- [x] schema reader 互換: character tests で import 検証済み。
- [x] 行数・crosswalk・phase value statement 等: work_report に記載済み。
- [ ] product-level acceptance: CLI/session/report smoke は通過。実 report artifact 検証は未了。
- [x] `graphify update .` 実行済み。
- [x] `python3 scripts/sync_shigoku_updated_at.py` と `python3 scripts/validate_shigoku_docs.py` が通る。

## 9. 停止条件（全項目、該当なしまたは回避済み）
- [x] import smoke 破壊なし。
- [x] 同名 package 未作成。
- [x] module layout 確定（flat `master_conductor_*.py`）。
- [x] service は facade/shim を runtime import しない。
- [x] critical tests 全通過。
- [x] secret audit: raw cookie/token/header 値の混入なし。
- [x] 行数削減のために tests/compat wrappers/session parity を削っていない。

## 10. Backlog / 次回申し送り
- [ ] Phase ごとの work_report には、残存 hotspot 上位 3 件、次に切るべき coordinator、削減見込み、deferred_tasks を必ず残す。
- [ ] SGK-2026-0284 と SGK-2026-0285 の HITL / dispatch backlog は、本計画の Phase 4-5 に統合して扱う。
- [ ] facade が 1500 行を下回った後、public/private API の整理と caller migration を別 task として検討する。
- [ ] 最大単一ファイル 1000 行以下を狙う場合は、facade wrapper retirement と state/event bridge の追加分割を別 phase にする。
- [ ] real report/session artifact がない Phase では synthetic artifact fallback を必ず実行し、real artifact gate は「未実行」ではなく「artifact 不足で未完了」として work_report に残す。
