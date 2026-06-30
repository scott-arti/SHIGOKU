---
task_id: SGK-2026-0314
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0291
related_docs:
- docs/shigoku/subtasks/done/2026-06-23_sgk-2026-0291_swarm-parallelism-review_subtask_plan.md
- docs/shigoku/reports/2026-06-30_sgk-2026-0314_work_report.md
- docs/shigoku/worklogs/2026-06-30_sgk-2026-0314_work_log.md
title: 'Swarm並列化 Phase 5: read_only outer task parallelism 限定解禁'
created_at: '2026-06-26'
updated_at: '2026-06-30'
tags:
- shigoku
target: src/core/engine/master_conductor.py, src/core/engine/parallel_orchestrator.py,
  lane scheduler
---

# 実装計画書：Swarm並列化 Phase 5: read_only outer task parallelism 限定解禁

## 1. 達成したいゴール（ユーザー視点）
- [ ] 初めての実並列化を、MC外側の `read_only` / passive / 独立origin task に限定して解禁すること。
- [ ] serial baseline と比較して High/Critical finding parity 100%、scope violation 0、origin budget violation 0 を満たすこと。
- [ ] kill switch または `parallelism.enabled=false` で即serial互換に戻せること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: batch selection / task dispatch条件の限定解禁。
  - `src/core/engine/parallel_orchestrator.py`: lane / origin budgetに基づく実行。
  - `LanePolicy` / `ExecutionBudgetPolicy`: Phase 4 shadow decisionを実スケジュールへ反映。
  - `tests/`: serial vs parallel parity、budget、kill switch回帰。
- **データの流れ / 依存関係:**
  - TaskQueue -> lane/admission/budget decision -> read_only parallel executor -> SwarmDispatcher -> result aggregation -> session/report parity check。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** lane=`read_only`、parallel_safe=true、origin budget available、scope allowed、shadow decision history。
- **出力/結果 (Output):** 実並列実行結果、queue_wait_ms、origin budget metrics、serial_gap_summary、rollback signal。
- **制約・ルール:**
  - `stateful_read`、`mutating`、`aggressive_exclusive` は実並列化しない。
  - SwarmDispatcher複数Swarm同時呼び出し、SwarmManager specialist並列化、Injection URL並列化は対象外。
  - High/Critical findingによる後続skip、Event-Driven Chaining、pruning候補生成の意味論を変えない。
  - request数増加は shadow baseline 比 1.2x 以下を初期目安にする。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: Phase 4 shadow decisionから `read_only` かつ `parallel_safe` の候補だけを抽出する。
- [ ] ステップ2: `parallelism.enabled` / `shadow_mode` / lane別flag / kill switch の判定順序を実装する。
- [ ] ステップ3: MasterConductorのbatch selectionで read_only outer task のみ並列実行へ流す。
- [ ] ステップ4: origin budget、queue wait、request count、Finding parity、skip/retire差分を記録する。
- [ ] ステップ5: serial baseline比較テストとrequest budget assertionを追加する。
- [ ] ステップ6: kill switch rollback testを実行し、serial互換に戻ることを確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] read_only分類ミスで状態変更が混入する - Phase 4分類とadmission policyで二重に防ぐ。
- [ ] [重要度:高] 並列化でFinding欠落が起きる - High/Critical parity 100%をGo条件にする。
- [ ] [重要度:中] request数が増えすぎる - origin budgetと1.2x目安を初期release gateにする。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0314-D01
    title: "継続監視: read_only並列化のFinding parity"
    reason: "最初の実並列化後もbaseline差分の監視が必要"
    impact: medium
    tracking_task_id: SGK-2026-0314
    recommended_next_action: "canary対象でserial/parallel比較を継続し、差分があればPhase 4分類へ戻す"
```

### 5.2 完了クローズ（2026-06-30）
- **判定:** done。
- **根拠:** Phase 5 の目的は「既存の無門番 outer task 並列へ gate を被せ、`read_only` + `parallel_safe` 以外を serial / hold へ倒せること」。関連実装とテストが完了し、Phase 9 の pre-flight / release gate でも前提 Phase evidence として参照済み。
- **検証:** `.venv/bin/pytest -q tests/core/engine/test_master_conductor_phase5_parallelism.py tests/unit/config/test_parallelism_settings.py tests/unit/engine/test_budget_policy.py tests/unit/engine/test_lane_policy.py` -> 101 passed。

---

## 6. 実装前レビュー結果（2026-06-27）

### 6.1 Phase要約（コード根拠ベース）
- **目的:** `read_only` / passive / 独立origin task のみを outer task level で並列実行可能にし、High/Critical finding parity 100% / scope violation 0 / origin budget violation 0 / kill switch で serial 互換復帰 を満たす。
- **Non-Goals:** `stateful_read` / `mutating` / `aggressive_exclusive` の実並列化、SwarmDispatcher 複数Swarm同時呼び出し、SwarmManager specialist 並列化、Injection URL 並列化（いずれ Phase 8）、Event-Driven Chaining / pruning（Phase 6）、protective degrade mode（Phase 7）、TaskState enum 変更（Phase 1 deferred）。
- **前提条件（実コード確認）:**
  - Phase 2 成果物実在: `admission_policy.py:46`（`ActionAdmissionPolicy`）/ `budget_policy.py:43`（`ExecutionBudgetPolicy`）/ `origin_normalizer.py:21`（`normalize_origin_key`）/ `ParallelismSettings`（`settings.py:247-259`, `enabled=False`, `shadow_mode=True`）。
  - Phase 3 done: per-dispatch instance（`swarm_dispatcher.py` の `_swarm_pool` キャッシュ廃止・`try/finally` close）。
  - Phase 4 done: `LanePolicy`（`lane_policy.py:21`）/ `MutexPolicy` / `SchedulingDecision` / `PHASE0_CLASS_TO_LANE`（`lane_policy.py:10-18`）実装済み。shadow decision は `build_async_session_payload(decision_traces=...)` へ永続化済み。
  - Phase 1 metadata 実在: `Task.metadata`（`task.py:93`）に `origin_key` / `session_key` / `auth_context_version` / `canonical_endpoint_key` あり。
- **完了条件:** gated 並列（`read_only` + `parallel_safe=true` のみ許可、他 lane は serial 強制降格）で、serial 強制実行と比較して High/Critical finding parity 100%、scope violation 0、origin budget violation 0、kill switch / `parallelism.enabled=false` で即 serial 互換復帰。

### 6.2 Ready / Not Ready
- **判定（2026-06-27）: Not Ready — 8 件の Local Blocker（LB-0〜LB-7）。** 最大は LB-0（前提の破綻）。全 Blocker は Phase 5 内部の設計/実装で解消可能（他 Phase のコード・計画書は変更不要）。解消後 Go 可能。
- **LB-0（構造的発見・前提破綻）:** 計画書 section 1 / step 3 は「初めての実並列化を解禁」「read_only outer task のみ並列実行へ流す」を前提とするが、実コードでは **MasterConductor は既に非 injection バッチを `self.orchestrator.execute_parallel()` で並列実行している**（`master_conductor.py:5843-5858` → `parallel_orchestrator.py:283-288` の `asyncio.create_task` + `asyncio.wait`）。かつ `settings.parallelism` は `master_conductor.py` 内で **1 箇所も消費されていない**（grep: `parallelism.` / `shadow_mode` / `kill_switch` / `.enabled` の消費 0、`mc:5862` の `injection_full_parallel_dispatch` と takeover 専用 `chain_llm_shadow_mode`(`mc:4323`) のみ）。つまり現状は「全 lane が無門番で既に並列」であり、Phase 5 の実タスクは **(a) gate 追加（`read_only`+`parallel_safe` のみ並列許可）(b) 非 read_only lane を serial 強制降格（現在は危険側に並列化されている）(c) kill switch / serial 復帰路の新設** である。step をこの現状に合わせて書き直すこと（6.3 LB-0 解決案）。このまま「read_only を並列化する」だけ実装すると `stateful`/`mutating`/`aggressive_exclusive` が引き続き無門番並列のまま残り、Non-Goals 違反かつ No-Go 条件（adaptive skip 破壊）に直結する。

### 6.3 Local Blocker（Phase 5 実装前に必ず解決）
- [ ] **LB-0: 前提破綻 — 計画書 step を「既存無門番並列へ gate を被せる」現状に書き直す → 解決案（本 section 6 + step 更新）。** step3「read_only outer task のみ並列実行へ流す」を「(i) dispatch 前 live 判定（`LanePolicy.classify(agent_type, metadata)`）で `read_only`+`parallel_safe=true` の task のみ並列バッチへ、(ii) それ以外の lane は serial 強制降格（現在は危険側に並列）、(iii) kill switch / `parallelism.enabled=false` で全バッチを serial 強制」へ修正。コード根拠: `master_conductor.py:5800-5858` が現状すべて `execute_parallel` へ流す。
- [ ] **LB-1: serial 復帰路が存在しない → 解決。** MC は常に `execute_parallel` を呼ぶ（`mc:5856`）。`parallelism.enabled=false` / kill switch で serial に戻る分岐なし。`kill_switch` field も `ParallelismSettings`（`settings.py:247-259`）に存在しない（Phase 4 PCR-2 から未解決）。解決: (1) `ParallelismSettings` に `kill_switch: bool = False` 追加、(2) MC の batch dispatch に serial 分岐を新設（`parallelism.enabled==False OR kill_switch` で `suggested_batch=1` 相当の逐次、または serial executor 呼び出し）。これが無いと parity 比較の serial baseline が作れない。
- [ ] **LB-2: `_execute_single_task_full_flow` テールの `_state_lock` 保持による並列効果低下・デッドロックリスク（最重要・@oracle 設計・@explorer 検証 2026-06-27）→ 採用設計 6.3.1。** 【訂正 2026-06-27】当初「テールが共有状態を並行 mutate し heap 破壊・lost update が顕在化する race」と書いたが **実コード確認で誤り**。テール（`mc:6164-6330+`）は全体が `with self._state_lock:`（`mc:6164`）の内側で走り、worker 間で直列化されるため **corruption race は起きない**（@explorer 確認）。実害の本体は別物: (1) テールが lock を握ったまま走るため、ある worker のテールが終わるまで他 worker のテールが待たされ **並列効果が削がれる**（並列度を上げると顕著化）、(2) テール内の重い処理（`_observe_and_rethink`(`mc:6309`) の LLM 呼び出し疑い・`wordlist_manager.learn_params`(`mc:6319`) のファイル I/O・`accumulated_context.merge`(`mc:6318`)・`task_queue.inject_context`(`mc:6321`)・`priority_booster.boost_priority`(`mc:6283`)）が lock 下でブロックすると **デッドロック/長期保有リスク**。Oracle の defer 設計（6.3.1）はテールを worker から外し batch join 後に main thread で処理してこれらを解消する。**corruption 修正ではなく、並列効果最大化＋ロック保有リスク解消の改善**。intra-swarm の adaptive skip（`base.py:356-357`）は Phase 3 per-dispatch instance で保護済み・別軸。
- [ ] **LB-3: `origin_key` / `target_key` / `lane` / `scope_verdict` 未伝播 → 解決。** `master_conductor.py:5800-5803` の `create_parallel_task(t.id, self._execute_single_task_full_flow, t, category=t.agent_type)` にこれらが一切渡されていない（Phase 4 D-2 が Phase 5 へ deferred 済）。結果: `ExecutionBudgetPolicy.consume(None)`（`budget_policy.py:69` は origin_key で keying）となり per-origin budget が無意味化、admission は `CATEGORY_TO_LANE`（`po:321`）で auto 推論され Phase 4 権威 lane と不一致。解決: `Task.metadata` から `origin_key`/`target_key`/`scope_verdict` を、`LanePolicy.classify` から `lane` を `create_parallel_task` へ伝播（`mc:5801` の呼び出し拡張）。
- [ ] **LB-4: `ExecutionBudgetPolicy` が非スレッドセーフ → 解決。** `budget_policy.py:7-8` が明示「Thread-safety is NOT guaranteed. Thread-safe enforcement is deferred to Phase 5 (SGK-2026-0314, D-6)」と記載。`consume()` が lock なしで `self._budgets` dict を更新（`budget_policy.py:69-97`）→ 並列 dispatch で lost update / budget 違反（「origin budget violation 0」Go 条件が脅かされる）。解決: `consume()` / `get_usage()` に `threading.Lock`（または per-origin lock dict）を追加。`ParallelOrchestrator` が `ThreadPoolExecutor`（`po:114`）+ `asyncio`（`po:271`）で実行するため lock は必須。
- [ ] **LB-5: shadow 読み vs live 判定の混同 → 解決。** step1「Phase 4 shadow decision から `read_only` かつ `parallel_safe` の候補だけを抽出する」だが、Phase 4 shadow decision（`SchedulingDecision`, `shadow_only=True`）は事後記録であり実行順を変えない。Phase 5 は dispatch 前の **live 判定**（`LanePolicy.classify(agent_type, task_metadata)` を実行前に呼び gate へ反映）しなければならない。shadow 記録との一致率は観測指標（S-4）として使うが、gate 入力は live 判定。step1 表現を「live LanePolicy 判定で gate」に修正。
- [ ] **LB-6: parity 比較器が存在しない → 解決（最小版）。** `serial_gap_summary` / `rollback_signal` / `queue_wait_ms` / `finding_parity` は `src/` 内 0 件（docs のみ）。Go 条件「serial baseline と比較して High/Critical finding parity 100%」の比較器が未構築。かつ serial baseline は LB-1 の serial 復帰路が無いと作れない。解決: 最小 parity 比較器（同一 queue snapshot を serial 強制経路と gated 並列経路で 2 回実行し、High/Critical finding の severity+id 集合の集合相等を assert）を実装。リッチ telemetry（恒久 runtime metrics）は D-1 で Phase 9 へ deferred。
- [ ] **LB-7: dispatcher singleton race → @explorer 検証で PROTECTED 判定（2026-06-27）。** `_dispatcher` singleton（`swarm_dispatcher.py:601`）は `get_swarm_dispatcher`(`:604-630`) で lock なし再設定（`:612` TOCTOU, `:620-628` 属性上書き）されるが、`_execute_single_task_full_flow` からは `agent_type=="swarm"`(`mc:7719`) の場合のみ到達可能。標準の非 swarm batch（web_scanner/fingerprinter/cartographer/recon_master/intel_* 等）は `mc:7712/7819/7847/7940+` で早期 return し singleton に触れない。read_only 並列候補が swarm 型 task を含まない限り race は起きない。解決（防御的）: `get_swarm_dispatcher`(`:612-628`) に `threading.Lock` を追加し swarm 型 task が並列に入っても安全化（~5行）、または Phase 5 gate で swarm 型 task を並列対象外へ。実装前の「検証必須」は解除済み。

### 6.3.1 LB-2 採用設計（@oracle 設計レビュー 2026-06-27）

**決定: (d) immutable snapshot handoff ＋ (b) 全共有状態 mutate を batch join 後の main thread へ defer。**

- **【目の訂正 2026-06-27】** 本設計の目的は「corruption race の修正」ではなく「テールの `_state_lock` 保持を解消し、worker を lock 待ちさせず完全に並列させる」こと。corruption は現状起きない（`_state_lock` 直列化済み・`mc:6164`）。defer 後は worker が `_state_lock` をテールで握らなくなり、main thread 単一で処理するため lock すら不要になる。

- **決定的根拠（実コード）:** 並列 task A の finding は 並列 task B の実行中に見える必要はない。各 task は dispatch 時に snapshot を受ける（`task.params["_context"] = self.accumulated_context.to_dict()` `mc:5997`, `self._state_lock` 下）。並列バッチ内の task は全て既に dispatch 済みで実行中（`mc:5801-5802`, `po:283`）なので、同一バッチ内の task への boost はその run では no-op。trigger 効果は **未来のバッチ** にのみ影響する。よって共有状態 mutate を `asyncio.wait` join 後（`po:288`）に main thread で直列再現すると、serial baseline と **観測上同一** になる。parity は構造的に保証される（`critical_findings` は `dict.fromkeys` で順序非依存の集合 `task_queue.py:68-70`、boost は絶対 priority 設定）。
- **lock(a) 不採用の理由:** `critical_findings` 単体の lock は `boost_priority`/`add_tasks` 等の隣接 race を取りこぼす。defer 方式は隣接 race も一括で閉じ、deadlock 表面も持たない（holder が queue コードへ再入する経路がない）。
- **除外(c) 不採用:** trigger 依存 task の検出が曖昧で read_only を過剰直列化する。
- **変更点（minimal diff・Phase 5 スコープ内）:**
  1. `_execute_single_task_full_flow` テール（`mc:~6287-6321`）を thread-local 化。`extract`/`analyze`/`rethink` は局所変数へ計算し、`task_queue.add/boost_priority/inject_context`・`accumulated_context.merge`・`_add_tasks`・`_expand_plan_for_assets`・`_process_handoff`・`handle_finding`・`wordlist_manager.learn_params` の **直接呼び出しを全て削除**。代わりに `result["_post_batch_feedback"]` へ feedback（new_context / findings / new_assets / boost_event+affected_ids / critical_actions / react_tasks / handoff payload）を格納（Option A・推奨）。
  2. 新 helper `_apply_post_batch_feedback(self, batch_tasks, results)` を追加（`mc:~5910` 付近）。**dispatch 順（`batch_tasks`）で**（`results` の完了順ではない）結果を取り出し、main thread 上で serial に再現: handle_finding → critical_path_analyzer.analyze → boost_priority → _expand_plan_for_assets → _observe_and_rethink/_add_tasks → _process_handoff → accumulated_context.merge → wordlist_manager.learn_params → task_queue.inject_context。
  3. 通常バッチ経路: results 調整 loop 後（`mc:~5910`）に `_apply_post_batch_feedback` を呼ぶ。
  4. recovery 経路（`mc:5869-5875`）: `rec_result` を capture し、recovery loop 後に同 helper を呼ぶ。
  5. debug assert 推奨: `inject_context`/`boost_priority`/`merge` が `threading.main_thread()` 上かつ `execute_parallel` 返却後にのみ呼ばれることを保証。
- **`context_propagator.py` / `task_queue.py`（trigger 本体）/ `parallel_orchestrator.py` は変更不要。**
- **残リスク（実装中 No-Go 条件）:** (1) テール subsystem の intra-batch 順序依存 → **@explorer 検証で解消済み（2026-06-27）**: `priority_booster`/`critical_path_analyzer`(PURE_DATA)/`_observe_and_rethink`/`_add_tasks`/`_expand_plan_for_assets`/`_process_handoff`/`accumulated_context.merge`/`wordlist_manager.learn_params`/`task_queue.inject_context` は全て PURE_DATA または READS_SHARED_STATE で **ORDERING_DEPENDENT なし**。defer 設計は妥当。ただし `DynamicTaskQueue`（`task_queue.py`）の `_heap`/`_task_index`/`_removed_seqs` に内部 lock がないため、defer（main thread 単一）以外の経路で queue への並行 access を許さないこと（PCR-4）。 (2) `_execute_single_task_full_flow` の第三呼び出し点（debug CLI / session replay 等）が無いことの `rg` 確認（現状 `mc:5802`(並列)・`mc:5873`(recovery) のみ確認済み）。(3) `result` dict が live で `_post_batch_feedback` 追加可能ことの assert。
- **参照ルール:** 実装前に `rules/lessons.md`・`rules/codingrules.md`（concurrency/共有状態）をロード（AGENTS.md §17）。

### 6.3.2 LB-1 / LB-5 / LB-6 小設計（実装前に固定・2026-06-27）

**共通構造:** `master_conductor.py` の batch dispatch（`mc:5800-5858`）を新 helper `_dispatch_batch(self, batch_tasks)` へ抽出し、LB-1（kill switch/serial）・LB-5（lane gate）・LB-0（非 read_only 降格）を1箇所で処理する。これにより3 Blocker の分岐が1関数に集約され、テストとレビューが容易になる。

**LB-1: kill_switch + serial 復帰路**
- `ParallelismSettings`（`settings.py:247-259`）へ `kill_switch: bool = False` を追加。
- MC が batch dispatch で `settings.parallelism.enabled` / `settings.parallelism.kill_switch` を読む（現状は両方とも未消費・grep 0）。
- serial 強制条件: `force_serial = (not parallelism.enabled) or parallelism.kill_switch`。
- serial 実行: orchestrator を経由せず `batch_tasks` を1件ずつ `_execute_single_task_full_flow(task)` の直接呼び出しで処理（真の serial）。**T-0.1 の baseline はこの経路を使う**（parity 比較の基準）。
- kill switch は実行中でも次バッチから即時反映。T-5.1 で「実行中に kill switch を立てると以降が serial に切替」を検証。

**LB-5: live LanePolicy gate（Phase 4 shadow 記録ではなく dispatch 前の live 判定）**
- `_dispatch_batch` 内で、batch 構築後・dispatch 前に各 task を `LanePolicy.classify(task.agent_type, task.metadata)`（`lane_policy.py:206`）で **live** 判定。
- 分岐:
  - `parallel_eligible` = `lane == "read_only"` AND `parallel_safe == True` AND `not force_serial`
  - `serial_rest` = それ以外（`stateful_read`/`mutating`/`aggressive_exclusive`/`sequential_required`/`unknown`、および `force_serial` 時の全 task）
- `parallel_eligible` → `execute_parallel`。`serial_rest` → 1件ずつ直接呼び出し。
- **Phase 4 shadow 記録（SchedulingDecision）は読まない。** gate 入力は live `LanePolicy.classify` のみ。shadow との一致率は観測指標 S-4。
- この gate の本務は **現在無門番で並列している `stateful_read`/`mutating`/`aggressive_exclusive` を serial へ降格すること**（LB-0）。read_only を「新たに並列化」するのではなく、非 read_only を「安全側へ直列化」する。
- T-1.1（read_only のみ並列・他は serial）・T-1.2（live 判定が gate 入力）で検証。

**LB-6: parity 比較テスト harness（production code ではなく test fixture）**
- seed 固定の task list を用意。
- 同一 queue snapshot を (1) serial 強制経路（`force_serial=True`）(2) gated 並列経路 の2通りで実行。
- それぞれ `src/reporting/finding_extractor.extract_all_findings()`（`rules/lessons.md` の真正性ルール・canonical extractor 使用）で High/Critical finding を抽出し、(severity+id) 集合の **集合相等** を assert。
- MC は状態を持つ（`accumulated_context`/`task_queue` が run 中に変化）ため、**2 run 間で MC state をリセット**する test-only エントリポイント（または fresh MC インスタンス×2）を用意する。
- リッチ telemetry（`serial_gap_summary`/`rollback_signal`/`queue_wait_ms` の恒久 runtime metrics）は D-1 で Phase 9 へ deferred。Phase 5 は finding 集合の集合相等だけで Go を判定する。
- T-6.1 で検証。

### 6.4 TDDチェックリスト
- [ ] **T-0.1: `test_kill_switch_serial_baseline`** — `parallelism.enabled=false`（新 serial 分岐）で同一 queue を実行した結果（findings/実行順/request 数）を characterization として固定。変更前に追加し、gated 並列実装後も serial 経路が同一であることを回帰で使う（LB-1/LB-6 の前提）。
- [ ] **T-1.1: `test_only_read_only_parallel_others_serial`** — `read_only`+`parallel_safe=true` task のみ並列バッチへ、`stateful_read`/`mutating`/`aggressive_exclusive`/`sequential_required` task は serial 強制降格される（LB-0/LB-5）。現在これらが無門番で並列する回帰を検出。
- [ ] **T-1.2: `test_live_lane_policy_gates_dispatch`** — dispatch 前 `LanePolicy.classify(agent_type, metadata)` が gate 入力であり、Phase 4 shadow 記録（事後）ではないことを固定（LB-5）。
- [ ] **T-2.1: `test_post_batch_feedback_runs_only_on_main_thread`** — `inject_context`/`merge`/`boost_priority` に `threading.current_thread()` 記録を仕込み、並列バッチ後にこれらが全て MainThread 上かつ `execute_parallel` 返却後に呼ばれたことを assert（LB-2・6.3.1）。
- [ ] **T-2.2: `test_race_window_forced_with_barrier_proves_no_lost_update`**（決定的 parity test）— N=8 並列 task。`context_propagator.extract` を monkeypatch して (a) task 固有の critical tag を返し (b) `threading.Barrier(N)` で同時到達させ race 窓を最大化。post-batch の `accumulated_context.critical_findings` が N tag 全てを含むこと。`suggested_batch=1` 強制 serial baseline と集合が一致すること（LB-2・6.3.1）。
- [ ] **T-2.3: `test_critical_finding_propagates_to_next_batch_priority`** — batch1 の task A が `critical_findings=['admin_panel']` を出した場合、batch2 の auth task B が join 後に priority=999 に boost されること（trigger が post-join で効くことの証明: LB-2・6.3.1）。
- [ ] **T-2.4: `test_no_concurrent_task_queue_mutation_during_batch`** — `task_queue.add/boost_priority/inject_context/remove_by_id` を re-entrancy detector で wrap し、並列バッチ中の同時進入が 0 件であることを assert（全テール mutate の post-join 化検証: LB-2・6.3.1）。
- [ ] **T-2.5: `test_recovery_path_propagates_context`** — `execute_parallel` を timeout で失敗させ、recovery が未完了 task を逐次実行した場合も recovery task の `critical_findings`/`new_assets` が `_apply_post_batch_feedback` 経由で伝播すること（LB-2・6.3.1）。
- [ ] **T-2.6: `test_no_secret_leak_via_post_batch_handoff`** — `result["_post_batch_feedback"]` が raw token 文字列を含まないこと。`auth_tokens` は serial baseline と同等に `accumulated_context` へ存在し新規 field/暴露がないこと（秘密境界保全: LB-2・6.3.1）。
- [ ] **T-3.1: `test_origin_key_propagated_to_parallel_task`** — `Task.metadata.origin_key` が `create_parallel_task` 経由で `ParallelTask.origin_key` に伝播する（LB-3）。
- [ ] **T-3.2: `test_per_origin_budget_isolated`** — 異なる origin の task が別 budget bucket で追跡され、同一 origin に集約されない（LB-3）。
- [ ] **T-4.1: `test_budget_consume_threadsafe_under_parallelism`** — 並列高負荷下で `ExecutionBudgetPolicy.consume()` を多数同時に呼んでも lost update が起きず、burst 超過時に正しく reject される（LB-4）。
- [ ] **T-5.1: `test_kill_switch_immediate_serial_revert`** — 実行中に kill switch を立てると以降の batch が即座に serial 強制に切り替わる（LB-1）。
- [ ] **T-5.2: `test_parallelism_disabled_serial_path`** — `parallelism.enabled=false` で全バッチが serial 互換（`execute_parallel` を呼ばない、または batch size 1 強制）（LB-1）。
- [ ] **T-6.1: `test_finding_parity_serial_vs_gated_parallel`** — 同一 queue snapshot で serial 強制経路と gated 並列経路の High/Critical finding（severity+id）集合が完全一致（LB-6・Go 条件）。
- [ ] **T-6.2: `test_request_count_not_above_serial_baseline`** — gated 並列の総 request 数が serial baseline を超えない（現状は既に並列のため 1.2x 目安は不当に緩い；正しくは per-origin burst violation 0 で評価: T-4.1）。
- [ ] **T-7.1: `test_dispatcher_singleton_no_race_under_parallel_dispatch`** — `swarm_dispatcher.py:599-607` の singleton 再設定が並列 dispatch で race しない（到達不能 または idempotent）。Phase 3 per-dispatch instance 設計と整合（LB-7）。
- [ ] **T-8.1: `test_phase4_shadow_vs_phase5_live_gate_agreement`** — Phase 4 shadow decision（`read_only`+`parallel_safe`）と Phase 5 live gate の一致率を観測（S-4）。
- [ ] **T-9.1: `test_phase2_admission_regression`** — LB-3 で origin_key/lane を伝播しても Phase 2 admission/budget 回帰が壊れない。
- [ ] **T-9.2: `test_phase3_isolation_regression`** — Phase 3 per-dispatch instance 分離が gated 並列下でも維持される（findings/auth_headers/cookies/url_results 混入なし）。

### 6.5 Go/No-Go Gate
- [ ] **Go:** `read_only`+`parallel_safe=true` の task のみ並列バッチへ入り、他 lane は serial 強制降格される（T-1.1, LB-0/LB-5）。
- [ ] **Go:** gate 入力が Phase 4 shadow 記録ではなく live `LanePolicy.classify` 判定である（T-1.2, LB-5）。
- [ ] **Go:** `_execute_single_task_full_flow` テールが worker thread から完全に分離され（main thread のみで処理）、worker がテールで `_state_lock` を保持しない。バリア強制で全 finding が伝播する（T-2.1/T-2.2/T-2.4, LB-2・6.3.1）。
- [ ] **Go:** `origin_key` が `ParallelTask` へ伝播し per-origin budget が分離追跡される（T-3.1/T-3.2, LB-3）。
- [ ] **Go:** 並列高負荷下で `ExecutionBudgetPolicy` の budget violation 0（lock 付き: T-4.1, LB-4）。
- [ ] **Go:** `parallelism.enabled=false` / kill switch で即座に serial 互換に復帰（T-5.1/T-5.2, LB-1）。
- [ ] **Go:** serial 強制経路と gated 並列経路で High/Critical finding（severity+id）集合が完全一致（T-6.1）。
- [ ] **Go:** dispatcher singleton が並列 dispatch で race しない（T-7.1, LB-7）。
- [ ] **Go:** Phase 3 dispatch context isolation が gated 並列下でも維持される（T-9.2）。
- [ ] **Go:** T-0.1〜T-9.2 の全テストが PASS。`python3 scripts/sync_shigoku_updated_at.py` 後に `python3 scripts/validate_shigoku_docs.py` が 0 エラー。
- [ ] **No-Go（未該当確認）:** 非 read_only lane（`stateful_read`/`mutating`/`aggressive_exclusive`/`sequential_required`）が並列実行される（T-1.1 fail → Non-Goals 違反・現在の無門番並列が残存）。
- [ ] **No-Go（未該当確認）:** テールの post-join 化が漏れて worker がテールで `_state_lock` を保持したまま残る（並列効果低下・デッドロックリスク残存）、またはバリア強制で finding 伝播が欠ける（T-2.1/T-2.2/T-2.4 fail → parity 100% 崩壊）。
- [ ] **No-Go（未該当確認）:** budget consume の並列 race で violation（T-4.1 fail）。
- [ ] **No-Go（未該当確認）:** kill switch / `parallelism.enabled=false` で serial に戻らない（T-5.1/T-5.2 fail）。
- [ ] **No-Go（未該当確認）:** dispatcher singleton race が再現する（T-7.1 fail）。
- [ ] **No-Go（未該当確認）:** Phase 2/3/4 回帰が壊れる（T-8.1/T-9.1/T-9.2 fail）。

### 6.6 Shadow / Differential Testing
- [ ] **S-1: serial vs gated-parallel finding parity differential** — 同一 queue snapshot を `parallelism.enabled=false`（新 serial 経路）と gated 並列で 2 回実行し、findings/実行順/request 数を差分比較（LB-1/LB-6 の観測基盤）。
- [ ] **S-2: critical_findings cross-task 漏れ監査** — 各 task に固有 marker を与え、`TaskContext.critical_findings` への書き込みと trigger skip が他 task に誤って伝播／欠落しないことを instrumentation で事後検出（LB-2）。
- [ ] **S-3: budget 並列高負計** — 同一 origin への並列 request 集中で `consume()` が正しく reject し burst 違反 0 を監視（LB-4）。第三-party API rate は別途観測（Phase 7 degrade mode 入力）。
- [ ] **S-4: shadow vs live gate 一致率** — Phase 4 shadow decision（`read_only`+`parallel_safe`）と Phase 5 live `LanePolicy` gate の一致率を記録（不一致は分類ミスの早期シグナル: LB-5）。
- [ ] **S-5: 既存 shadow baseline との request 数比較** — Phase 4 shadow baseline（現状の既並列実行）と gated 並列の request 数を比較。現状は既に並列のため 1.2x 目安は不当に緩い（gated はむしろ減少方向）。正しい評価軸は per-origin burst violation（T-4.1）。

### 6.7 Local Deferred（後続Phaseへ送る）
| # | 項目 | Deferred先 | 安全な理由 | 検出方法 |
|---|---|---|---|---|
| D-1 | リッチ parity telemetry（`serial_gap_summary` / `rollback_signal` / `queue_wait_ms` の恒久 runtime metrics）| Phase 9 (SGK-2026-0318) | 最小 parity 比較器（T-6.1）で Phase 5 Go 条件を満たせる。恒久ダッシュボード化は rollout 段階 | Phase 9 shadow compare report / release gate script |
| D-2 | pool 再利用復活（stateless Swarm 最適化・Phase 3 D-3 指名）| Phase 8 (SGK-2026-0317) | per-dispatch instance で正確性は確保済み。pool 復活は性能最適化のみで Phase 5 の parity/budget 正確性に不要。deferral 先変更は PCR-5 で親へ通知 | Phase 8 performance parity test / specialist parity test |
| D-3 | parity 比較の豊富な response 比較軸（status/body length/JSON shape/DOM marker/redirect chain/cache header/timing delta）| Phase 9 (SGK-2026-0318) | Phase 5 は finding parity（severity+id 集合）のみで Go 十分。詳細差分軸は rollout 段階 | Phase 9 release gate / downstream reader compatibility check |

### 6.8 Parent Change Request（親計画へ反映提案・本Phaseでは適用しない）
- [ ] **PCR-1: Phase 5 目的の再枠付け（親 4.5 step5 / 4.4 Go条件 へ反映提案）。** 実コードでは外側 task 並列は「既存・無門番」（`mc:5855-5857`, `po:283-288`）であり、Phase 5 は並列の有効化ではなく「安全性 gate 付与 ＋ 非 read_only の serial 強制降格 ＋ kill switch 復帰路の新設」である。親の「最初の実並列化」表現は Phase 9 成功指標・CTO metric にも誤伝播するため、親レベルで是正すべき。
- [ ] **PCR-2（Phase 4 から継続）: `kill_switch` field（親 4.1/4.4 へ反映提案）。** `ParallelismSettings`（`settings.py:247-259`）に `kill_switch` がない（Phase 4 PCR-2 から未解決）。Phase 5 で追加（LB-1）するが、親 4.1/4.4 の「kill switch」参照を正本化。
- [ ] **PCR-3（Phase 4 から継続）: decision / parity 永続化 sink の正規化（親 4.3/4.4 へ反映提案）。** scheduling/admission/budget/parity decision の単一 canonical sink を定義（`decision_traces` vs `RunLedgerEvent.DECISION_MADE` vs debug bundle）。各 Phase が「debug bundle」を参照するが未実装（grep 0 hit）。Phase 5/6/9 共通。
- [ ] **PCR-4: `TaskContext` / `DynamicTaskQueue` の並行性契約を親レベルで定義（親 4.1/4.4 へ反映提案）。** `context_propagator.py` の書きと `task_queue.py:202,218` の trigger 読みが共有 mutable list で並行安全でない（LB-2）。加えて `DynamicTaskQueue` の `_heap`/`_task_index`/`_removed_seqs` に内部 lock がない（@explorer 確認・`task_queue.py:503-587`）。Phase 5 は「共有状態 mutate は batch join 後 main thread のみ」で回避するが、Phase 6/7/8 が worker 経路へ queue/context 書き込みを戻すと race 再発。lock 所有権・評価タイミングを Phase 5/6/7/8 共通契約として親へ集約すべき。
- [ ] **PCR-5: Phase 3 D-3（pool 復活）の deferral 先変更を台帳へ反映（親 4.5 へ反映提案）。** Phase 3 は pool 復活を Phase 5 指名したが、Phase 5 の主眼は gate/serial 復帰/budget thread-safe/skip 保護であり pool 復活を入れると範囲・リスクが膨張する。Phase 8（内側並列化評価）へ再委譲（D-2）。Phase 5 Go 条件は壊さない。

### 6.9 Out of Scope（本Phaseでは実装しない）
- [ ] SwarmDispatcher 複数 Swarm 同時呼び出し（Phase 8）
- [ ] SwarmManager specialist 内側並列化（Phase 8）
- [ ] Injection URL 処理の並列化（Phase 8）
- [ ] Event-Driven Chaining / pruning / invalidation（Phase 6）
- [ ] protective degrade mode / `mutating`/`aggressive_exclusive` lane の enablement（Phase 7）
- [ ] `TaskState` enum 変更（Phase 1 で deferred 済み）
- [ ] リッチ parity telemetry の恒久化（D-1, Phase 9）
- [ ] pool 再利用復活（D-2, Phase 8）
- [ ] 外部依存ライブラリの追加

### 6.10 Phase順序再レビュー
- **Phase 2 → Phase 5:** ✅ Phase 5 は Phase 2 の `ActionAdmissionPolicy` / `ExecutionBudgetPolicy` / `origin_key` / `ParallelismSettings` に依存（実コード確認済み）。LB-3/LB-4 で Phase 2 成果物を Phase 5 が消費可能状態へ wire する。順序正当。
- **Phase 3 → Phase 5:** ✅✅ Phase 3 per-dispatch instance は Phase 5 並列 dispatch の硬前提（親 4.4「dispatch context isolation test」が Go 条件）。Phase 5 は Phase 3 の分離を前提に gated 並列を載せる。順序正当。
- **Phase 4 → Phase 5:** ✅✅ Phase 5 は Phase 4 `LanePolicy.classify` を **live gate 入力**として消費（LB-5）。Phase 4 shadow は事後記録だが、`LanePolicy`/`PHASE0_CLASS_TO_LANE` は live 計算可能なので Phase 5 は shadow を待たず gate を実装できる。順序正当。
- **Phase 5 → Phase 6/7/8:** ✅✅ Phase 5 が「既存無門番並列へ gate を被せる」性質上、Phase 5 未完だと Phase 6（event-driven chaining）/ Phase 7（stateful lane）/ Phase 8（内側並列）が無門番並列の上に積まれ危険。Phase 5 の gate 完了が Phase 6+ のより強固な前提（PCR-1）。順序正当かつ依存強化の根拠あり。
- **結論:** Phase 順序は壊れていない。実際の依存関係にも適合する。ただし LB-0（前提破綻）を解消しないまま Phase 5 を出すと、実装者が read_only だけ並列化し非 read_only の無門番並列を残す事故が起きるため、step の書き直し（LB-0）が Phase 5 実装前の必須条件。

### 6.11 実装可否判定（Blocker解消後）
- **判定（2026-06-27）: 条件付き実装可能 — 8 Blocker 解消後 Go。** Blocker はすべて Phase 5 内部の設計/実装で解消可能（他 Phase のコード・計画書は変更不要）。
- **変更規模（局所〜中規模）:**
  - `src/core/engine/master_conductor.py`: batch dispatch（`5800-5858`）に serial 強制分岐（`parallelism.enabled==False` / `kill_switch` / 非 read_only lane）を追加、`create_parallel_task` 呼び出し（`5801`）へ `origin_key`/`target_key`/`lane`/`scope_verdict` 伝播、dispatch 前 live `LanePolicy.classify` gate。
  - `src/core/engine/budget_policy.py`: `consume()`/`get_usage()` に `threading.Lock`（LB-4）。
  - `src/core/config/settings.py`: `ParallelismSettings` に `kill_switch` field 追加（LB-1）。
  - `master_conductor.py` `_execute_single_task_full_flow` テール（`~6287-6321`）の thread-local 化 ＋ 新 helper `_apply_post_batch_feedback`（batch join 後 main thread で serial 再現）。`context_propagator.py`/`task_queue.py`(trigger)/`parallel_orchestrator.py` は不改修（LB-2・6.3.1 採用設計）。
  - `swarm_dispatcher.py:599-607` の singleton race 検証と必要なら idempotent 化（LB-7）。
  - `tests/`: T-0.1〜T-9.2 を追加。
- **TDD順序:** T-0.1（serial baseline 固定・kill switch 経路）→ T-5.1/T-5.2（serial 復帰）→ T-1.1/T-1.2（gate）→ T-3.1/T-3.2（origin_key 伝播）→ T-4.1（budget thread-safe）→ T-2.1/T-2.2/T-2.3/T-2.4（テール mutate post-join 化・LB-2・6.3.1）→ T-7.1（singleton race）→ T-6.1（parity）→ T-8.1/T-9.1/T-9.2（回帰）。
- **他フェーズへの影響:** なし。pool 復活は Phase 8（D-2）、リッチ telemetry は Phase 9（D-1）が所管。Phase 3/4 の計画書は編集しない（deferral 先変更 D-2 は PCR-5 で親へ通知のみ）。
- **残リスク（実装中に No-Go に戻す条件）:** (1) `_execute_single_task_full_flow` テールの subsystem に intra-batch 順序依存が見つかり defer 不可（6.3.1 残リスク）の場合 per-call lock へ切替再評価、(2) LB-7 の singleton が並列到達可能で idempotent 化が困難、(3) LB-3 の origin_key 伝播で既存 admission/budget 回帰が壊れる、場合は実装を止めて再評価する。

### 6.12 参照ルール
- 本タスクのレビュー・編集にあたり参照したルールファイル: `rules/lessons.md`（report/session 真正性・秘密境界・並列 fixer 汚染・ドキュメント検証）、`rules/shigoku-docs.md`（front matter・deferred_tasks・done 移動規則）、`rules/report-session-consistency.md`（finding parity 比較の真正性原則）。

### 6.13 実装後レビューで発見された Follow-up（Phase 6+ 見据える・Non-blocking）
Phase 5 は Complete with Follow-ups（125 テスト合格・Go gate 満足）。ただし実装後レビューで、Phase 5 の完了を阻害しないが Phase 6+ で効く懸念を 3 件記録する（手戻り防止）。

| # | 懸念 | 根拠（file:line） | 影響 Phase | 推奨対応 | 検出方法 |
|---|---|---|---|---|---|
| **FU-1** | **B1 lock-free 化が残した shared-state race。** `_observe_and_rethink` と `priority_booster.boost_on_discovery` が lock なしで instance counter/dict を更新。以前は `_state_lock` 内で安全だったが、B1 の lock-free 化で並列 worker が同時更新。Phase 5 では低severity（counter 誤差程度・本体の finding parity/task_queue は main thread 保護）だが Phase 7 で状態追跡精度が要求されると昇格。 | `mc:6524`(`_observe_and_rethink` が `self._react_observation_inflight`/`_react_observation_executed_total`/`_react_observation_pending_queue` を lock なし update)・`mc:6507`(`priority_booster.boost_on_discovery` が `self._boosts`/`self._task_priorities` を lock なし update)。exp-2 が READS_SHARED_STATE（PURE_DATA ではない）と分類。oracle 設計は「全 shared-state mutation を defer」だったが実装は task_queue 系のみ defer。 | Phase 7（stateful lane で状態追跡が要求） | (a) 当該 subsystem へ内部 `threading.Lock` 追加、または (b) 入力 capture して main thread で適用（oracle 本来設計へ完全合致）。Phase 6 開始前に対処推奨。 | Phase 7 で mutex contention / state mutation assertion test。または `priority_booster`/`_observe_and_rethink` への並行高負荷 test で counter lost-update 検出。 |
| **FU-2** | **`_post_batch_feedback` の god-object 化。** 現在 8 field（deferred_findings/critical_actions/boost_event/new_assets/react_tasks/handoff/new_context/decision_enhancer_tasks）。型なし string-key dict で、Phase 6 が event/pruning、Phase 7 が state assertion/mutex を追加すると破綻・typo bug が入り込む。 | `mc:6610`(`result["_post_batch_feedback"] = _post_fb`)・`_apply_post_batch_feedback`(`mc:5693-5800`) が 8 種の `fb.get("deferred_*")` を string-key で読む。 | Phase 6/7（field 追加時） | Phase 6 実装前に `PostBatchFeedback` dataclass（typed）へ移行。低コスト・高効果。 | Phase 6 実装時の field 追加で dataclass 化のテストを追加。 |
| **FU-3** | **injection 経路の feedback 伝播が未テスト。** injection 分岐も `_execute_single_task_full_flow`（defer 版）を通り、結果は `_apply_post_batch_feedback` へ達する見込みだが、injection タスクの feedback 伝播を確認するテストがない。非 injection 経路は十分テスト済み。injection は finding の主要源なので、ここが壊れると detect 網羅に直結。 | injection 分岐(`mc:~5981-6020`)は `execute_parallel` chunk 経由で `_execute_single_task_full_flow` を呼び、`results` へ格納後 `_apply_post_batch_feedback(batch_tasks, results)`(`mc:6123`) へ流れる。だがこの経路の feedback 伝播を assert するテストが Phase 5 test suite にない。 | Phase 6（event-driven chaining が injection finding に依存） | Phase 6 開始前に、injection-type task を batch へ流し findings が `_apply_post_batch_feedback` 経由で伝播することを確認する test を 1 本追加。 | injection task を含む batch での parity / feedback 伝播 test。 |

**Phase 6 計画書（SGK-2026-0315）へ送るべき設計制約（本 Phase では記録のみ・Phase 6 計画書は未編集）:**
- Phase 6 が `_apply_post_batch_feedback` へ event emission を繋ぐ場合、**event handler の同期的 task_queue.add は再入リスク**（イテレーション中の `task_queue` mutation）。遅延キュー設計必須。Phase 6 計画書の事前レビューで Blocker 級制約として扱うこと。
- **PCR-4（`DynamicTaskQueue` が内部 lock ゼロ・`task_queue` mutation は main thread のみ）** を親計画 SGK-2026-0291 へ反映し、`task_queue` mutation に `threading.main_thread()` assert を入れること（Phase 6/8 での回帰検出網）。これも Phase 6 計画書の前提条件候補。
