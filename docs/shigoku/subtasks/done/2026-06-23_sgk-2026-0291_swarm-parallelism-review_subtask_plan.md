---
task_id: SGK-2026-0291
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0289
related_docs:
- docs/shigoku/plans/2026-06-21_sgk-2026-0289_commonization-technical-debt-roadmap_plan.md
- docs/shigoku/plans/2026-06-20_sgk-2026-0278_ver-2-planning-bundle-dev-mode-recon_plan.md
- docs/shigoku/subtasks/2026-06-21_sgk-2026-0287_task-queue-pruning-policy_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-0_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-1-additive-execution-contract-debug-metadata_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-2-scope-admission-per-origin-budget-policy_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-3-dispatch-context-isolation-swarm-pool_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-4-lane-scheduler-shadow-mode_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-5-read-only-outer-task-parallelism_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-6-event-driven-chaining-pruning-invalidation_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-7-stateful-mutating-aggressive-lanes_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-8-swarmdispatcher-swarmmanager_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-9-release-gate-rollout-policy-promotion_subtask_plan.md
- docs/shigoku/reports/2026-06-30_sgk-2026-0291_work_report.md
- docs/shigoku/worklogs/2026-06-30_sgk-2026-0291_work_log.md
title: Swarm並列処理検討 設計議論計画
created_at: '2026-06-23'
updated_at: '2026-06-30'
tags:
- shigoku
target: src/core/engine/master_conductor.py, src/core/engine/swarm_dispatcher.py,
  src/core/agents/swarm/
---

# 実装計画書：Swarm並列処理検討 設計議論計画

## 1. 達成したいゴール（ユーザー視点）
- [ ] SHIGOKU の Swarm 並列化について、現状の実行順序と共有状態を正確に整理し、実装前に壊してはいけない不変条件を明文化すること。
- [ ] 「MasterConductor 外側のタスク並列」「SwarmDispatcher の Swarm 呼び出し」「Swarm 内 specialist 実行」「specialist 内部の局所並列」を別フェーズとして扱い、同時に実装しないこと。
- [ ] 並列化してよい処理、順序を守るべき処理、rate limit や副作用が危険な処理、未実施のまま不要化できる処理を分類すること。
- [ ] Event-Driven Chaining、Target/Session Mutex、Lane Scheduler、per-origin rate limit、dispatch context isolation、task pruning / invalidation を段階実装できる粒度に分解すること。
- [ ] 各フェーズについて、実装範囲、非対象、対象ファイル、契約変更、テスト、受け入れ条件、rollback / kill switch を定義し、Go判断後に実装チケットへ分割できる状態にすること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: task queue から複数タスクを取り出し `ParallelOrchestrator` に渡す外側の並列制御。
  - `src/core/engine/parallel_orchestrator.py`: カテゴリ別 worker/rate limit を持つタスク並列実行基盤。
  - `src/core/engine/swarm_dispatcher.py`: タグから複数 Swarm を選び、現状は Swarm を順番に呼び出す入口。
  - `src/core/agents/swarm/base.py`: 標準 SwarmManager。現状は specialist を順番に実行する。
  - `src/core/agents/swarm/base_manager.py`: LLM Think Loop 系 manager。turn ごとに LLM/tool を順番に実行する。
  - `src/core/agents/swarm/injection/manager.py`: InjectionManager。Phase 1/Phase 2 の二段構えで、現状は injection 系の並列がかなり抑制されている。
- **データの流れ / 依存関係:**
  - MasterConductor task queue -> batch_tasks -> ParallelOrchestrator -> 各 task の full flow -> SwarmDispatcher -> Swarm -> specialist -> finding/result。
  - 現状の大枠は「外側 task は一部並列」「Swarm 呼び出しは直列」「Swarm 内 specialist は基本直列」「specialist 内部で一部 `asyncio.gather` 等の局所並列あり」。
  - 例: MFA race check、ActorCriticFuzzer payload送信、Stored XSS reflection check などは specialist 内部で複数リクエストを同時に投げる。

## 2.1 現状認識
- [ ] `SwarmDispatcher.dispatch()` は複数 Swarm 候補を `for swarm_name in swarm_names` で順番に実行している。
- [ ] 標準 `SwarmManager.dispatch()` は `for specialist in specialists` で specialist を順番に実行している。
- [ ] `InjectionManager` はコメント上はバッチ並列の意図があるが、Phase 1 の URL 処理は現状かなり直列寄りで、MC側でも injection task は既定で batch size 1 に制限されやすい。
- [ ] 並列化されているのは主に MC 外側の非 injection task と、一部 specialist 内部の局所的なリクエスト並列。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** task tags、agent_type、target、rate limit 設定、scope/認証状態、specialist の副作用有無、recon snapshot、auth context、EventBus event、TaskQueue snapshot、pruning decision。
- **出力/結果 (Output):** 実装フェーズ、非対象リスト、契約変更一覧、lane / mutex / budget policy、task lifecycle、event contract、検証マトリクス、Go/No-Go gate、rollback 手順。
- **制約・ルール:**
  - 認証状態、セッション更新、状態変更リクエスト、rate limit が厳しい対象は無条件並列にしない。
  - scope確認、recon結果依存、chain/handoff、post-exploit、report/evidence生成は順序を明示する。
  - passive/低リクエスト/読み取り専用/独立targetの処理は並列候補にする。
  - 並列化後もログと execution trail が人間に追えるように、task_id/swarm/specialist/target/correlation を残す。
  - Phase 1 では互換性維持を優先し、既存 `TaskState` enum の破壊的変更は行わず、追加 metadata / debug fields で表現する。
  - `SwarmManager.dispatch()` の specialist 直列実行と High/Critical finding 時の adaptive skip は、専用フェーズまで意味論を維持する。
  - `mutating` / `aggressive_exclusive` は explicit admission gate、target risk tier、scope allowlist、kill switch が揃うまで実実行の並列化対象にしない。
  - `SGK-2026-0287` の pruning / invalidation と矛盾しないように、未実施 task の不要化は `retired` / `superseded` / `invalidated` として失敗とは別扱いにする。
  - `execution_contract_schema_version`: 未指定は version 0、Phase 1 追加後は version 1。未知 version の artifact は実行停止せず reader 互換の警告または unknown metadata 保持に倒す。各 Phase は自 Phase が書く version と読めるべき version 範囲を明示すること。
  - **Debug metadata 秘密情報境界:** `auth_context_version` は保存してよいが、cookie / token / header 実値、API key、secret、password などの秘密情報は全 write API（`Task.to_dict()`、`build_async_session_payload()`、legacy checkpoint serializer を含む）で `[REDACTED]` に置換し、disk 上に実値を一切保存しない。

## 4. 実装ステップ（AIに指示する手順）
- [ ] フェーズ0: 現状正本化と非対象固定（挙動変更なし）
  - **目的:** MC batch、SwarmDispatcher、SwarmManager、specialist内部の4層で、実際の `await` / `for` / `gather` / semaphore / worker 数を棚卸しし、「本当に並列な箇所」と「直列意味論を持つ箇所」を正本化する。
  - **対象:** `src/core/engine/master_conductor.py`、`src/core/engine/parallel_orchestrator.py`、`src/core/engine/swarm_dispatcher.py`、`src/core/agents/swarm/base.py`、`src/core/agents/swarm/base_manager.py`、`src/core/agents/swarm/injection/manager.py`。
  - **アクション:** 既存実行フロー図、mutable state inventory、specialist分類表、既存並列箇所一覧、直列維持リストを作成する。
  - **非対象:** 並列度変更、TaskState enum変更、EventBus仕様変更、Swarm内部specialist並列化。
  - **完了条件:** `parallel_safe` / `sequential_required` / `rate_limited` / `stateful` / `aggressive_exclusive` の初期分類表がある。High/Critical finding 時の adaptive skip の意味論が保護対象として明記されている。
  - **検証:** ドキュメント検証のみ。コード挙動変更なし。
- [ ] フェーズ1: additive execution contract と debug metadata（挙動変更なし）
  - **目的:** 後続フェーズが同じ実行単位を参照できるように、互換性を壊さない追加metadataを定義する。
  - **対象候補:** `src/core/domain/model/task.py`、session保存処理、report/session reader、debug log formatter。
  - **アクション:** `target_key`、`origin_key`、`canonical_endpoint_key`、`session_key`、`auth_context_version`、`recon_snapshot_version`、`correlation_id`、`generation_reason`、`evidence_key`、`attack_hypothesis_id`、`request_fingerprint`、`payload_fingerprint`、`mutation_chain_id`、`schema_version` を追加metadataとして扱う方針を実装計画へ固定する。
  - **アクション:** `pending`、`waiting_dependency`、`admitted`、`running`、`invalidated`、`retired`、`superseded`、`skipped`、`failed`、`replanned`、`success` は Phase 1 では永続enumへ即追加せず、`lifecycle_status` / `lifecycle_reason` などの互換metadataで表現する。
  - **非対象:** 既存 `TaskState` の破壊的変更、report/session schema field の削除/改名。
  - **完了条件:** 既存session/report readerが旧artifactを読める。新metadataが欠落してもserial実行が動く。
  - **検証:** `.venv/bin/pytest` で Task serialization / session reader / report reader の関連テストを追加・実行する。
- [ ] フェーズ2: scope / admission / budget policy のfail-closed化
  - **目的:** 並列化前に、実ホスト単位の流量制御と安全な実行許可を共通化する。
  - **対象候補:** `src/core/engine/parallel_orchestrator.py`、`src/core/security/ethics_guard.py`、`config/shigoku.yaml`、設定ロード/validation、MasterConductor preflight。
  - **アクション:** `ParallelTask` / task metadata に `origin_key` / `target_key` を明示し、rate limiter が Task object文字列ではなく正規化originで制御するようにする。
  - **アクション:** `ActionAdmissionPolicy` / `ExecutionBudgetPolicy` を定義し、`read_only` 以外は scope unknown 時に fail closed とする。`mutating` / `aggressive_exclusive` は allowlist + explicit flag + audit trail を必須にする。
  - **アクション:** `config/shigoku.yaml` に `parallelism` セクションを設計し、`enabled`、`shadow_mode`、`default_executor`、lane別workers、per-origin budget、kill switch、risk tier別defaultを定義する。
  - **完了条件:** scope不明・out-of-scope・origin_key欠落の active/mutating/aggressive task が実行前に拒否される。serial mode は従来互換。
  - **検証:** admission policy unit test、config validation test、parallel_orchestrator の origin rate limit regression test。
- [ ] フェーズ3: dispatch context isolation と Swarm pool安全化
  - **目的:** 並列度を上げる前に、`SwarmDispatcher` の pool再利用と `BaseManagerAgent` / `InjectionManagerAgent` の `current_context` 上書きによるコンテキスト汚染を防ぐ。
  - **対象候補:** `src/core/engine/swarm_dispatcher.py`、`src/core/agents/swarm/base_manager.py`、`src/core/agents/swarm/injection/manager.py`、Swarm factory / manager lifecycle。
  - **アクション:** dispatch-local context object を導入する。既存 `current_context` 参照が残る箇所は compatibility shim を挟み、同時dispatchで混ざらないことをテストする。
  - **アクション:** Swarm poolは `stateless_reusable` と `dispatch_scoped` を分類し、stateful manager は per-dispatch instance または guarded reuse に限定する。
  - **非対象:** SwarmManager specialist の内側並列化。Injection URL処理の並列化。
  - **完了条件:** 同一 Swarm/Manager 型へ2つの task を同時dispatchしても findings / url_results / auth_headers / cookies が混ざらない。
  - **検証:** concurrent dispatch isolation test、InjectionManager context isolation regression、既存Swarm dispatch test。
- [ ] フェーズ4: Lane Scheduler shadow mode（実スケジュール変更なし）
  - **目的:** `read_only`、`stateful_read`、`mutating`、`aggressive_exclusive` の lane 判定と mutex 判定を観測し、実行順序を変えずに妥当性を確認する。
  - **対象候補:** 新規 `LanePolicy` / `MutexPolicy` / `SchedulingDecision`、MasterConductor task dequeue前後、session/debug event。
  - **アクション:** specialist / task の `parallel_safe`、`sequential_required`、`rate_limited`、`stateful`、`aggressive_exclusive`、`preconditions`、`expected_observable`、`state_assertion` を判定し、shadow scheduling decision と reason code を記録する。
  - **アクション:** Target/Session Mutex key を `origin_key + session_key + auth_context_version + mutation surface` を基準に設計し、mutex取得予定・待機予定・排他理由をshadow記録する。
  - **完了条件:** serial実行結果を変えずに、全taskへ lane / mutex / admission / budget のshadow decisionが付く。
  - **検証:** lane classification unit test、mutex key normalization test、shadow decision snapshot test。
- [ ] フェーズ5: read_only outer task parallelism の限定解禁
  - **目的:** 最初の実並列化は MC 外側の `read_only` / passive / 独立origin task に限定する。
    - **【訂正 2026-06-28・SGK-2026-0314 PCR-1 昇格】** 本計画 2.1 現状認識のとおり、MC 外側 task 並列は Phase 5 以前から**無門番で既存**（`master_conductor.py:5855`→`parallel_orchestrator.py:283`）。Phase 5 の実タスクは「並列の有効化」ではなく **(a) gate 追加（`read_only`+`parallel_safe` のみ許可）(b) 非 read_only lane の serial 強制降格（現在は危険側に並列）(c) kill switch / serial 復帰路の新設**。Phase 9 の速度指標は「serial 強制 vs gated」で測ること（「無門番時代 vs gated」は速度だけ出て品質低下を見逃すため misleading）。
  - **対象候補:** `MasterConductor` batch selection、`ParallelOrchestrator`、lane scheduler、rate limiter。
  - **アクション:** `parallelism.enabled=true` かつ `lane=read_only` かつ `parallel_safe` かつ `origin budget available` の task のみ、outer task level で並列実行する。
  - **アクション:** High/Critical finding による後続skip、Event-Driven Chaining、pruning候補生成は既存意味論を維持し、未完了taskの退役は `SGK-2026-0287` の policy に委譲する。
  - **非対象:** `stateful_read`、`mutating`、`aggressive_exclusive` の実並列化。SwarmDispatcher 複数Swarm同時呼び出し。SwarmManager specialist並列化。
  - **完了条件:** serial baseline と High/Critical finding parity 100%。scope violation 0。origin budget違反 0。request数増加は shadow baseline 比 1.2x 以下を初期目安にする。
  - **検証:** serial vs parallel shadow compare、Finding parity regression、request budget assertion、kill switch rollback test。
- [ ] フェーズ6: Event-Driven Chaining と pruning / invalidation 統合
  - **目的:** 順序依存taskを最初から一括queue投入せず、先行event起点で後続taskを遅延生成し、不要化したpending taskを安全に退役させる。
  - **対象候補:** `src/core/infra/event_bus.py`、MasterConductor event handlers、`SGK-2026-0287` の `TaskPruningPolicy`、TaskQueue、session/debug audit。
  - **アクション:** event を `critical`、`important`、`best_effort` に分類し、queue full / handler error / retry / dead-letter / duplicate event の扱いを定義する。
  - **アクション:** `TaskPruningPolicy` の shadow decision を `retired` / `superseded` / `invalidated` lifecycle metadata と接続し、未実施だが不要化したtaskを「失敗」と区別して記録する。
  - **完了条件:** 発見eventから後続taskが重複なく生成される。古いrecon/auth snapshotのpending taskは3点validity checkで止まる。prune protected taskは退役しない。
  - **検証:** EventBus queue full test、handler failure / retry test、stale task invalidation test、protected task pruning test、report/session audit test。
- [ ] フェーズ7: stateful_read / mutating / aggressive_exclusive の限定解禁
  - **目的:** 状態依存・破壊的・高負荷系を、明示gateと専用laneで限定的に扱う。
  - **対象候補:** lane scheduler、Target/Session Mutex、ResourceManager、admission policy、operator control。
  - **アクション:** `stateful_read` は同一session mutex内で順序保証する。`mutating` は state assertion / precondition / postcondition を必須にする。`aggressive_exclusive` は同一originの他lane抑制、low-noise profile、manual/explicit flag を必須にする。
  - **アクション:** 403/406/429、timeout急増、connection pool逼迫、scope warning、auth instability を検知したら protective degrade mode に移行する。
  - **完了条件:** race condition再現テストで認証/セッション破壊が起きない。aggressive lane稼働中に他laneがbudgetを侵食しない。operator kill switchでserialへ戻せる。
  - **検証:** mutex contention simulation、reauth競合 test、state mutation assertion test、aggressive lane suppress test、protective degrade test。
- [ ] フェーズ8: SwarmDispatcher / SwarmManager 内側並列化の個別評価
  - **目的:** 外側並列化が安定した後、SwarmDispatcher複数Swarm呼び出し、Injection URL処理、specialist内部並列化を別々に評価する。
  - **対象候補:** `SwarmDispatcher.dispatch()`、`SwarmManager.dispatch()`、`InjectionManager.dispatch()`、specialistごとの concurrency safety note。
  - **アクション:** SwarmDispatcher は state isolation 済みの `read_only` Swarm のみ候補にする。SwarmManager specialist 並列化は High/Critical adaptive skip の意味論を壊さない設計ができるまで保留する。Injection URL並列化は per-origin budget と payload fingerprint が揃ってから限定解禁する。
  - **完了条件:** 内側並列化を有効にしても adaptive skip / finding aggregation / partial failure / replay が説明可能である。
  - **検証:** specialist parity test、partial failure aggregation test、Injection URL request budget test、deterministic replay test。
- [ ] フェーズ9: release gate / rollout / policy promotion
  - **目的:** 並列runtimeを一度にGA化せず、shadow -> canary -> limited default -> broader default の順に昇格する。
  - **アクション:** `public / authenticated / admin / mutating-heavy` の target risk tier と `ga / beta / experimental` の specialist maturity を組み合わせ、default flag を決める。
  - **アクション:** `lane pause`、`queue drain`、`aggressive lane suppress`、`parallelism kill switch`、`invalidation summary` を operator control 要件として固定する。
  - **完了条件:** release gate、rollback trigger、compatibility window、reader impact check、operator runbook が揃う。
  - **検証:** shadow compare report、release gate script、rollback drill、downstream reader compatibility check。

### 4.1 実装前に固定する契約
- [ ] **Task lifecycle:** Phase 1 では既存 `TaskState` を壊さず `lifecycle_status` / `lifecycle_reason` / `superseded_by` / `invalidated_by` / `retired_by_event_id` の追加metadataで表現する。永続enum化はreader互換性確認後に別フェーズで判断する。**【依存順序裁定・昇格元: SGK-2026-0315 PCR-P2】** pruning lifecycle（`retired`/`superseded`/`invalidated`）の shadow decision producer である `TaskPruningPolicy`（SGK-2026-0287）は 2026-06-29 時点で未実装（`src/core/engine/task_pruning_policy.py` 0件・`task_queue.py` に `remove_matching`/`remove_by_ids` なし・registry status=active）。Phase 6/7/9 が全て pruning に依存するため、Phase 6 実装開始前に親が (i) SGK-2026-0287 を Phase 6 の前に完了 または (ii) Phase 6 スコープ内で最小 `TaskPruningPolicy`（shadow decision 生成・protected list・reason_code）を新設し aggressive 実削除のみ 0287 へ残す、のいずれかを裁定すること。裁定なしに Phase 6 step3 へ進むと pruning ゴールが空振りする。pruning decision の永続化は `decision_traces`（`build_async_session_payload(decision_traces=...)`）へ `DecisionType` enum へ `TASK_RETIRED`/`TASK_SUPERSEDED`/`TASK_INVALIDATED` を追加した上で格納する。
- [ ] **Target identity:** rate limit / mutex / queue fairness は `Task` object文字列ではなく、正規化した `origin_key`、`target_key`、`canonical_endpoint_key` を使う。`Task.metadata` の識別子は `create_parallel_task()`（または同等の factory）経由で `ParallelTask` へ伝播し、Phase 2-7 の全 rate limit / admission / budget / mutex 判定が同一の正規化値を参照する（昇格元: SGK-2026-0311 PCR-1）。`origin_key` の正規化ルールは `scheme`（lowercase）+ `host`（lowercase）+ `port`（default port 80/443 は省略）とし、path/fragment/query を含まない（例: `HTTPS://Example.COM:443/x` → `https://example.com`）（昇格元: SGK-2026-0311 PCR-2）。
- [ ] **Event reliability:** Event-Driven Chainingで後続taskを生成するeventは `critical` または `important` とし、queue fullで黙ってdropしない。drop可能なのは観測用 `best_effort` event のみとする。
- [ ] **Swarm instance lifecycle:** shared immutable service と dispatch-local mutable state を分離する。stateful manager は pool再利用しないか、reuse前にcontextが空であることを検証する。stateful/stateless の分類基準は継承ベースとする: `BaseManagerAgent` 継承 Swarm（injection/auth/logic/discovery）は `current_context`/`history` 等の mutable instance state を持ち `dispatch_scoped`、plain `SwarmManager` 継承 Swarm（secret/scanner/intelligence/fuzzing）は `stateless_reusable` 候補。この軸は Phase 3/4/5/8 の pool 再利用可否・lane 分類・内側並列化評価の共通入力とする（昇格元: SGK-2026-0312 PCR-1）。
- [ ] **Ordering model:** 前提taskを後続taskが直接待つDAGを最初から巨大化させない。基本は「先行結果eventが後続taskを生成する」。ただしauth/session/mutationのような状態保護は mutex で守る。
- [ ] **Pruning model:** 不要化した未実施taskは削除ではなく decision record を残す。`retired` は「価値がなくなった」、`superseded` は「別taskが代替した」、`invalidated` は「前提snapshotが古くなった」、`skipped` は「実行判断で飛ばした」と定義する。
- [ ] **Shared-state mutation contract（PCR-4・昇格元: SGK-2026-0314／PCR-P1 強化元: SGK-2026-0315）:** `task_queue`（`DynamicTaskQueue` の `_heap`/`_task_index`/`_removed_seqs` は内部 lock なし）および `accumulated_context` の mutation は **main thread のみ**。Phase 5 は `_apply_post_batch_feedback`（batch join 後）で main thread 集約にした。Phase 6/7/8 が worker / EventBus handler / specialist からこれらへ直接 mutate すると queue 破壊・lost update が起きる。**EventBus handler 群（`_handle_vuln_found`/`_handle_reauth_*` 等）は `SharedLoopManager` が生成する `ShigokuSharedLoop` daemon thread（`async_utils.py:43-49`）で動くため、handler 内での `task_queue`/`accumulated_context` 直接 mutate は明示的に禁止。** main-thread marshal（`asyncio.run_coroutine_threadsafe`/`call_soon_threadsafe` で main loop へ）または遅延キュー経由（event をキューへ入れ main thread で処理）のみ許可。各 Phase は `task_queue` mutation 箇所へ `threading.main_thread()` assert を入れ、回帰をフェイルファストで検出すること。この契約は Phase 5/6/7/8/9 共通の安全網であり、内側並列化（Phase 8）でも例外なし。
- [ ] **Safety default:** `parallelism.enabled=false`、`shadow_mode=true`、`mutating.enabled=false`、`aggressive_exclusive.enabled=false` を初期defaultにする。

### 4.2 初期非対象（Go後も最初に実装しない）
- [ ] SwarmManager specialist の全面並列化。
- [ ] InjectionManager Phase 1 URL処理の全面並列化。
- [ ] `mutating` / `aggressive_exclusive` lane のdefault有効化。
- [ ] 既存session/report schema field の削除・改名。
- [ ] 外部依存ライブラリの追加。
- [ ] scope不明targetへのactive/mutating/aggressive実行。
- [ ] High/Critical finding 時の adaptive skip 意味論を変える実装。

### 4.3 検証マトリクス
- [ ] **unit:** origin正規化、lane分類、mutex key、admission decision、budget decision、config validation、lifecycle metadata serialization。
- [ ] **simulation:** 複数target、同一origin集中、429連発、EventBus queue full、connection budget枯渇、reauth競合、mutex contention。
- [ ] **replay:** seed固定、task queue snapshot、event trace、mutex state、payload fingerprint、tool / adapter / LLM profile version を含めた再現。
- [ ] **shadow compare:** serial baseline と parallel shadow の Finding parity、request count、runtime、skip/retire/supersede差分を比較する。
- [ ] **fault injection:** handler error、timeout stage別失敗、orphan task、stale recon/auth snapshot、kill switch発動、protective degrade mode移行。
- [ ] **compatibility:** 旧session/report reader、新metadata欠落artifact、schema_version差分、debug bundle reader、release gate script。

### 4.4 Go / No-Go gate
- [ ] **Go条件:** Phase 0-4 が完了し、挙動変更なしで lane / mutex / budget / pruning shadow decision が記録できている。
- [ ] **Go条件:** `read_only` outer task parallelism のserial baseline比較で High/Critical finding parity 100%、scope violation 0、origin budget violation 0。
- [ ] **Go条件:** EventBus critical / important event が queue full 時に失われない設計とテストがある。
- [ ] **Go条件:** dispatch context isolation test があり、同時dispatchで `current_context`、findings、auth_headers、cookies、url_results が混ざらない。finding は Phase 1 metadata の `correlation_id`（必要に応じて `dispatch_id`）で帰属を同定でき、parity / isolation 比較で cross-dispatch 漏れを検出可能であること（昇格元: SGK-2026-0312 PCR-3）。
- [ ] **Go条件:** `parallelism.enabled=false` または kill switch で即serial互換に戻せる。
- [ ] **No-Go条件:** scope unknown で active/mutating/aggressive が実行される。
- [ ] **No-Go条件:** High/Critical finding の欠落、adaptive skip意味論の破壊、session/report reader互換性破壊、event dropによる後続task欠落が1件でもある。
- [ ] **No-Go条件:** mutating/aggressive lane に operator control / audit trail / rollback がない。

### 4.5 実装サブタスク分割
- [x] `SGK-2026-0309`: Phase 0 現状正本化と非対象固定。挙動変更なしで、並列/直列実態、共有状態、specialist分類を正本化する。
- [x] `SGK-2026-0310`: Phase 1 additive execution contract と debug metadata。既存schemaを壊さず、実行単位識別子とlifecycle metadataを追加する。
- [x] `SGK-2026-0311`: Phase 2 scope admission と per-origin budget policy。scope unknown fail-closed、origin単位rate limit、parallelism configを入れる。
- [x] `SGK-2026-0312`: Phase 3 dispatch context isolation と Swarm pool安全化。`current_context` 汚染とstateful pool再利用を止める。
- [x] `SGK-2026-0313`: Phase 4 Lane Scheduler shadow mode。実行順を変えずにlane / mutex / admission / budget decisionを記録する。
- [x] `SGK-2026-0314`: Phase 5 read_only outer task parallelism 限定解禁。最初の実並列化をMC外側のread_only taskに限定する。
- [x] `SGK-2026-0315`: Phase 6 Event-Driven Chaining と pruning invalidation 統合。順序依存taskの遅延生成と不要化taskの退役を扱う。
- [x] `SGK-2026-0316`: Phase 7 stateful / mutating / aggressive lanes 限定解禁。高リスクlaneをmutex、admission、operator control付きで扱う。
- [x] `SGK-2026-0317`: Phase 8 SwarmDispatcher / SwarmManager 内側並列化評価。外側並列化安定後に内側並列化を個別評価する。
- [x] `SGK-2026-0318`: Phase 9 release gate / rollout / policy promotion。shadow/canary/default昇格、rollback、operator runbookを整える。

## 5. 懸念点と対策 / 次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
### 5.1 SRE / インフラ観点
- [ ] [重要度:高] origin / host 単位の送信予算が未定義 - task / request に `origin_key` を持たせ、`rpm`、`burst`、`max_inflight_per_origin`、`cooldown_seconds` を定義する。
- [ ] [重要度:高] queue admission control がなく、並列化で task が過剰流入する - lane 別 queue 長上限、per-target 派生 task 上限、best-effort task の defer / drop 条件を追加する。
- [ ] [重要度:高] pending task が古い recon / auth 文脈のまま走る - `requires`、`invalidated_by`、`auth_context_version`、`recon_snapshot_version` を task に持たせ、3点 validity check を必須にする。
- [ ] [重要度:高] 状態変更系や認証系で結果が不安定になる - specialist分類に加え、以下の順序依存解決策を導入する。
  - **Event-Driven Chaining**: 順序依存タスクは事前一括登録せず、先行タスクの結果イベント（`_handle_vuln_found`等）をフックにして動的生成（遅延評価）する。
  - **Target-Level Mutex**: 認証更新や破壊的変更を伴うタスクは、ターゲットごとの排他ロック（Stateful Worker Lane）内で実行し、同一ターゲットへの他タスクを一時待機させる。
- [ ] [重要度:高] timeout が階層化されず、親 task budget を超過する - `session_budget -> batch_timeout -> task_deadline -> specialist_timeout -> request_timeout` の deadline 伝播ルールを定義する。
- [ ] [重要度:高] retry が副作用付き task を重複実行する - lane ごとに retry / idempotency matrix を定義し、`mutating` / `aggressive_exclusive` は自動 retry を抑制する。
- [ ] [重要度:高] 並列レーンの一系統が全体スループットを巻き込んで止める - LLM、network I/O、external tool、aggressive task を別 bulkhead として隔離する。
- [ ] [重要度:高] target単位 rate limit だけでは socket / connection が枯渇する - global / per-host connection budget、DNS concurrency cap、keepalive policy を定義する。
- [ ] [重要度:中] EventBus queue full 時に重要イベントが落ちる - event を `critical`、`important`、`best_effort` に分類し、drop 可否と dead-letter 指標を明示する。
- [ ] [重要度:中] ログが読めなくなる - correlation id と execution trail に加え、lane、mutex key、queue wait、retry count、version 情報を structured logging で残す。
- [ ] [重要度:中] fairness がなく、特定 target や aggressive task が worker を占有する - per-target round robin、priority aging、lane ごとの予約スロットを導入する。
- [ ] [重要度:中] feature flag なしで広げると rollback が困難 - per-lane / per-swarm / per-target の flag、shadow mode、canary target、kill switch を先に入れる。
- [ ] [重要度:中] resume / checkpoint 復元時に running task と mutex ownership が不整合になる - 再開時は orphan task を再評価し、mutex は復元せず再計算する。
- [ ] [重要度:中] CPU / memory だけ見た制御では外部依存の飽和を見逃す - queue wait、429、timeout、connection pool usage、LLM latency、event queue depth を含む multi-dimensional backpressure を設計する。
- [ ] [重要度:中] コメント上の「並列」と実装が食い違っている箇所がある - 実装前に実際の `await` / `for` / `gather` / semaphore を基準に棚卸しし、文書とコードの差分を解消する。
- [ ] [重要度:中] 検証計画が性能比較中心で、障害注入が不足する - 429 連発、EventBus queue full、connection 枯渇、reauth 競合、stale task invalidation などの fault injection を必須試験にする。

### 5.2 ソフトウェアアーキテクト観点
- [ ] [重要度:高] `MasterConductor`、`ParallelOrchestrator`、`ResourceManager`、`SwarmDispatcher` の責務境界が曖昧 - `task generation`、`admission`、`scheduling`、`execution`、`observation` の責務分担表を作り、所有境界を明文化する。
- [ ] [重要度:高] 並列化ポリシーがコード内に分散しやすい - `LanePolicy`、`BudgetPolicy`、`RetryPolicy`、`InvalidationPolicy` を cross-cutting policy layer として定義する。
- [ ] [重要度:高] 共有可変状態の取り扱い原則が弱い - dispatch-scope state と shared immutable service の区別を定義し、manager / swarm の mutable state inventory を作る。
- [ ] [重要度:高] task モデルが依存・無効化・比較の契約として薄い - `requires`、`invalidated_by`、`generation_reason`、`evidence_key`、`supersedes` を含む task schema contract を計画書に追加する。
- [ ] [重要度:高] task lifecycle の状態機械が未定義 - `pending`、`waiting_dependency`、`admitted`、`running`、`invalidated`、`skipped`、`failed`、`replanned`、`success` の state machine を定義する。
- [ ] [重要度:高] event が実装依存で、公開契約として扱われていない - producer / consumer / payload schema / reliability class / versioning を含む event contract table を追加する。
- [ ] [重要度:高] recon / auth / target context が mutable global 参照に寄る - task は versioned snapshot を受け取る immutable handoff 方式に統一する。
- [ ] [重要度:中] scheduler と executor の責務が混線し、差し替え余地が弱い - task selection と task execution を別 interface に分離し、serial / parallel 両方を同じ抽象で扱う。
- [ ] [重要度:中] 並列化後の結果比較のための共通 outcome schema が不足する - `finding_origin`、`decision_trace`、`queue_wait_ms`、`version_snapshot` を含む normalized outcome schema を定義する。
- [ ] [重要度:中] 互換アーキテクチャがないまま parallel runtime を入れると rollback が難しい - serial executor と parallel executor を切り替えられる runtime compatibility mode を計画に含める。
- [ ] [重要度:中] timeout / retry / rate limit / mutex が各層に散って局所最適化される - policy 集約層を先に定義し、specialist 個別実装へ降ろす順序を実装ステップに組み込む。
- [ ] [重要度:中] 検証計画が test の層構造を持たず、アーキテクチャ回帰を見逃しやすい - `unit`、`simulation`、`replay`、`shadow compare`、`fault injection` の5層検証構造を明記する。

### 5.3 デバッガー観点
- [ ] [重要度:高] task 実行時の環境差分が記録されず、再現条件が失われる - `version_snapshot`、`lane`、`mutex_key`、`auth_context_version`、`recon_snapshot_version` を task 実行記録へ必須追加する。
- [ ] [重要度:高] 並列順序の非決定性によりバグの再現性が低下する - seed 固定、固定順 scheduler、record / replay を含む deterministic replay mode を計画書へ追加する。
- [ ] [重要度:高] `invalidated` / `skipped` の理由が粗く、原因追跡が困難になる - `skip_reason`、`invalidate_reason` の正規 reason code 一覧を定義する。
- [ ] [重要度:高] state mutation の発生点が観測できず、race condition の切り分けが難しい - auth 更新、queue 変更、task invalidation、mutex acquisition / release で before / after 差分を structured に残す。
- [ ] [重要度:高] timeout の根本原因が `network`、`lock wait`、`queue wait`、`llm`、`tool` で混ざる - `timeout_stage` と `timeout_owner` を記録し、timeout taxonomy を定義する。
- [ ] [重要度:中] EventBus 経由の不具合が未達なのか handler 失敗なのか区別できない - `event enqueue`、`event dequeue`、`handler start/end`、`handler error` を監査点として追加する。
- [ ] [重要度:中] task invalidation の根拠が残らず pruning の正当性を検証できない - invalidation 時に `evidence_key` と `trigger_event_id` を保存する。
- [ ] [重要度:中] specialist 内局所並列の失敗が swarm 全体ログに埋もれる - specialist sub-result を標準化し、partial failure と retry 履歴を個別記録する。
- [ ] [重要度:中] resume 後の不具合が復元処理由来か元タスク由来か判別しづらい - `resumed_from_checkpoint`、`orphan_recovered`、`rehydrated_versions` を task 実行記録へ追加する。
- [ ] [重要度:中] feature flag 切り替え時の挙動差分が追えない - 全 task 実行で `active_flag_set` を保存し、flag ごとの結果比較を可能にする。
- [ ] [重要度:中] `parallel_safe` 分類ミスが latent bug として残りやすい - 各 specialist に concurrency safety note を持たせ、分類根拠をテスト / 文書に残す。
- [ ] [重要度:中] 調査用 artifact が散在し、再現作業に時間がかかる - task queue snapshot、event trace、mutex state、selected logs をまとめた debug bundle 出力を標準化する。

### 5.4 コーディングが得意なハッカー観点
- [ ] [重要度:高] payload / header / encoding variation の責務が specialist ごとに分散すると、並列化時に mutation の整合性と再現性が崩れる - `PayloadStrategy` / `MutationPlan` を独立層として定義し、variation 生成を中央集約する。
- [ ] [重要度:高] WAF / anti-automation / 403 / 406 / 429 検知時の保護動作が未定義だと、並列化でノイズを増やして有効シグナルを壊す - blocking signal を検知したら攻撃を強めるのではなく、request volume と variation を抑える `protective_degrade_mode` へ移行する。
- [ ] [重要度:高] request 単位の指紋がないと、どの variation が有効だったか追跡できない - `request_fingerprint`、`payload_fingerprint`、`mutation_chain_id` を outcome と replay artifact に必須追加する。
- [ ] [重要度:高] path / query / body / header / cookie の mutation surface が混在すると、危険度もコストも異なる試行を同列に扱ってしまう - surface ごとに queue、budget、retry、comparison rule を分ける。
- [ ] [重要度:中] target ごとに有効だった request shaping が再利用されないと、毎回同じ探索コストを払う - target-safe な compatibility profile を保持し、再試行時に再利用条件を明示する。
- [ ] [重要度:高] specialist 間で「何を検証しているか」の仮説共有が薄いと、並列化で文脈が切れて False Negative が増える - `attack_hypothesis_id`、`preconditions`、`expected_observable` を specialist handoff 契約に含める。
- [ ] [重要度:高] endpoint の正規化がないと、同一 endpoint に対する重複試行や結果分断が発生する - `canonical_endpoint_key` を導入し、dedupe / mutex / comparison / invalidation の基準を統一する。
- [ ] [重要度:高] cache / cookie / token / temp artifact を共有すると、自分の別タスクが観測結果を汚染する - dispatch 単位 namespace と scenario 単位 cleanup 規約を定義する。
- [ ] [重要度:中] timing / blind 系の検証を通常レーンへ混ぜると、並列ノイズで差分が埋もれる - low-noise execution profile または専用実行枠を設け、同時間帯の競合 traffic を抑制する。
- [ ] [重要度:高] mutating task の成功 / 失敗判定が曖昧だと、並列化後に「変更できたのか壊したのか」が判別できない - precondition / postcondition の state assertion を標準契約にする。
- [ ] [重要度:中] response 比較軸が弱いと、status code 以外の差分を見落とす - `status`、`body length`、`JSON shape`、`DOM marker`、`redirect chain`、`cache header`、`timing delta` を標準比較軸に追加する。
- [ ] [重要度:中] tool-backed specialist と native specialist の tactic 差異が放置されると、並列化後の coverage gap に気づけない - 同一仮説に対する parity 比較を検証計画へ組み込む。

### 5.5 CTO観点
- [ ] [発生確率:高 / 影響度:大] 成功判定と撤退条件が未定義 - runtime短縮率、Finding parity、許容 request 増加率、rollback trigger、shadow compare 合格条件を定義し、go / no-go の基準を計画書に追加する。
- [ ] [発生確率:高 / 影響度:大] target の事業リスク階層がない - `public / authenticated / admin / mutating-heavy` などの target risk tier を定義し、lane、budget、aggressive 可否、shadow 必須条件を tier ごとに切り替える。
- [ ] [発生確率:高 / 影響度:大] `SGK-2026-0278` との依存関係が明文化されていない - task pruning / invalidation / recon bundle との責務境界を related docs と実装ステップに明示する。
- [ ] [発生確率:高 / 影響度:大] 「未実施だが不要になった task」の意味論が弱い - `retired`、`superseded`、`skipped`、`invalidated` を区別し、レポート上で失敗と不要化を混同しない state machine と outcome schema を追加する。
- [ ] [発生確率:中 / 影響度:大] 人間オペレータ向けの control plane 要件が不足している - lane pause、queue drain、aggressive lane suppress、invalidation summary 表示などの operator control を要件として追加する。
- [ ] [発生確率:高 / 影響度:中] 設定ガバナンスの正本が未定義 - parallelism 関連設定の正本を `config/shigoku.yaml` に集約し、config schema validation と fail-closed startup を計画へ追加する。
- [ ] [発生確率:中 / 影響度:大] specialist の成熟度別公開戦略がない - `ga / beta / experimental` を定義し、parallel 実行可否と default flag を成熟度ごとに分ける。
- [ ] [発生確率:中 / 影響度:大] report / session / debug bundle の下流互換性の扱いが弱い - `schema_version`、`compatibility window`、reader impact check を定義し、downstream reader 互換性確認を検証ステップへ組み込む。
- [ ] [発生確率:高 / 影響度:大] 部分成功と品質低下の表現がない - `partial_success`、`confidence`、`deferred_reason`、`serial_gap_summary` を outcome schema に追加し、速度向上と信頼性低下を同時に見える化する。
- [ ] [発生確率:中 / 影響度:中] 並列化ルールの学習 / 昇格プロセスがない - shadow compare の結果から lane policy、compatibility profile、specialist maturity を昇格 / 降格するフローを追加する。
- [ ] [発生確率:中 / 影響度:大] 外部依存のドリフト管理が不足している - tool version、adapter version、LLM profile、prompt version を replay artifact に保存し、並列化前後の drift を比較できるようにする。
- [ ] [発生確率:中 / 影響度:大] mutating / aggressive 操作の admission gate が弱い - allowlist、explicit flag、audit trail、default deny を前提にした admission policy を追加する。

### 5.6 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0291-D01
    title: "継続監視: Swarm並列化フェーズ実装のGo/No-Go判断"
    reason: "本タスクは実装可能な計画までを対象とし、実コード変更はGo判断後にフェーズ単位で実施する"
    impact: medium
    tracking_task_id: SGK-2026-0291
    recommended_next_action: "Phase 0-1 の実装サブタスクを起票し、挙動変更なしの観測・metadata基盤から開始する"
```

## 6. 完了クローズ（2026-06-30）

### 6.1 完了判定
- **判定:** done。
- **理由:** SGK-2026-0309 から SGK-2026-0318 までの Phase 0-9 がすべて `done` 化され、計画書は `docs/shigoku/subtasks/done/` 配下へ集約済み。Phase 9 release gate / rollback / promotion matrix / operator runbook の完了判定レビューで Blocker 0 を確認した。
- **残存監視:** operator dashboard / 長期可視化は SGK-2026-0320、EventBus runtime の継続可視化は SGK-2026-0322 で別タスクとして追跡する。本親タスクの完了条件は壊さない。

### 6.2 完了時検証
- `.venv/bin/pytest -q tests/core/engine/test_master_conductor_phase5_parallelism.py tests/unit/config/test_parallelism_settings.py tests/unit/engine/test_budget_policy.py tests/unit/engine/test_lane_policy.py` -> 101 passed。
- `.venv/bin/pytest -q tests/unit/reporting/ tests/unit/engine/test_phase9_injection_budget.py` -> 373 passed。
- `.venv/bin/pytest -q tests/unit/config/test_parallelism_settings.py tests/core/domain/model/test_task_execution_contract_metadata.py tests/unit/engine/test_budget_policy.py tests/unit/engine/test_lane_policy.py tests/unit/engine/test_mutex_policy.py tests/unit/engine/test_phase8_serial_baseline.py tests/unit/engine/test_phase8_gate.py tests/unit/engine/test_phase8_limited_parallel_a.py tests/unit/engine/test_phase8_shadow_decisions.py tests/unit/engine/test_phase9_injection_budget.py tests/unit/reporting/test_runtime_control_release_gate.py tests/unit/reporting/test_shigoku_ops_phase9_route.py tests/unit/reporting/test_parity_comparator.py tests/unit/reporting/test_rollback_drill.py tests/unit/reporting/test_reader_compatibility.py tests/unit/reporting/test_promotion_matrix.py` -> 287 passed。
- `python3 scripts/validate_shigoku_docs.py` -> 0 issue。

### 6.3 クローズ成果物
- Work report: `docs/shigoku/reports/2026-06-30_sgk-2026-0291_work_report.md`
- Work log: `docs/shigoku/worklogs/2026-06-30_sgk-2026-0291_work_log.md`
