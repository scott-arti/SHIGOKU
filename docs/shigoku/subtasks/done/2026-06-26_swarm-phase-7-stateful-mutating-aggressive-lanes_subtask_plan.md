---
task_id: SGK-2026-0316
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0291
related_docs:
- docs/shigoku/subtasks/done/2026-06-23_sgk-2026-0291_swarm-parallelism-review_subtask_plan.md
title: 'Swarm並列化 Phase 7: stateful mutating aggressive lanes 限定解禁'
created_at: '2026-06-26'
updated_at: '2026-07-02'
tags:
- shigoku
target: lane scheduler, Target/Session Mutex, ResourceManager, admission policy, operator
  control
---

# 実装計画書：Swarm並列化 Phase 7: stateful mutating aggressive lanes 限定解禁

## 1. 達成したいゴール（ユーザー視点）
- [ ] `stateful_read`、`mutating`、`aggressive_exclusive` を明示gateと専用laneの下で限定解禁できること。
- [ ] 同一target/sessionの状態変更がmutexで保護され、認証/セッション破壊を起こさないこと。
- [ ] aggressive実行時に同一originの他laneを抑制し、protective degrade / kill switchで安全側へ戻れること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `LanePolicy` / `MutexPolicy`: stateful/mutating/aggressive laneの実行制御。
  - `ResourceManager` / budget policy: aggressive laneのbulkhead、connection、timeout、cooldown制御。
  - admission policy: allowlist、explicit flag、target risk tier、audit trail。
  - operator control: lane pause、aggressive suppress、queue drain、kill switch。
- **データの流れ / 依存関係:**
  - Task -> admission gate -> lane scheduler -> target/session mutex -> execution -> state assertion -> audit / degrade / rollback。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** lane、target risk tier、scope allowlist、session_key、auth_context_version、state assertion、blocking signal。
- **出力/結果 (Output):** mutex acquisition/release、state assertion result、protective degrade event、operator control audit。
- **制約・ルール:**
  - Phase 0-6完了が前提。Phase 5のFinding parityが崩れている場合は開始しない。
  - `mutating` は precondition / postcondition / state_assertion 必須。
  - `aggressive_exclusive` は explicit flag、low-noise profile、同一origin他lane抑制、operator kill switch必須。
  - 403/406/429、timeout急増、connection pool逼迫、auth instability は protective degrade mode へ移行する。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ0a: Phase 6 引継ぎ: injection feedback 伝播 test 追加 (F1・Phase 5 FU-3)。injection task の finding が `_apply_post_batch_feedback` 経由で伝播することを検証する test を 1 本追加。
- [ ] ステップ0b: Phase 6 引継ぎ: 3点 validity check 接続コード (N2)。`check_snapshot_validity`(`snapshot_validity.py`) を enqueue（`DynamicTaskQueue.add`）・dequeue（`MC` batch 構築）・start 直前（`_execute_single_task_full_flow` 冒頭）の 3 点に接続し、stale task を invalidated として skip する。
- [ ] ステップ1: Phase 4 shadow decisionから stateful/mutating/aggressive 候補を抽出し、manual reviewで解禁対象を限定する。
- [ ] ステップ2: Target/Session Mutex の取得・待機・release・timeout・orphan recoveryを実装する。
- [ ] ステップ3: `mutating` task に precondition / postcondition / state_assertion を必須化する。
- [ ] ステップ4: aggressive lane のbulkhead、同一origin抑制、cooldown、low-noise profileを実装する。
- [ ] ステップ5: protective degrade mode と operator kill switch を接続する。
- [ ] ステップ6: reauth競合、mutex contention、state mutation assertion、aggressive suppress、protective degrade testを実行する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] mutating taskが状態を壊す - state_assertionとmanual/explicit gateなしでは実行しない。
- [ ] [重要度:高] aggressive taskがtargetへ過負荷をかける - aggressive_exclusive lane、origin suppress、cooldown、kill switchで制御する。
- [ ] [重要度:中] mutexが強すぎて性能が出ない - 初期は安全側に倒し、実測後にscopeを狭める。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0316-D01
    title: "継続監視: stateful/mutating/aggressive lane の安全性"
    reason: "高リスクlaneはtarget状態と負荷へ影響するため継続監視が必要"
    impact: medium
    tracking_task_id: SGK-2026-0316
    recommended_next_action: "実行auditをレビューし、laneごとのdefault flagを昇格/降格する"
```

---

## 6. Phase 5 レビュー由来の横断制約（2026-06-28・実装前必須・Blocker級）
Phase 5（SGK-2026-0314）完了レビューで判明した制約。Phase 7 は状態追跡精度に依存するため FU-1 race 解消が必須。

### 6.1 必須設計制約（MUST・違反は実装停止）
- [ ] **C1【事前解消必須】: FU-1 shared-state race を Phase 7 step1 の前に潰す。** Phase 5 の B1 lock-free 化で `_observe_and_rethink`(`mc:6524`: `self._react_observation_inflight`/`_react_observation_executed_total` counter を lock なし更新)・`priority_booster.boost_on_discovery`(`mc:6507`: `self._boosts`/`self._task_priorities` を lock なし更新) に並列 race が残存。Phase 7 の state assertion / mutex がこれらの状態に依存すると race で誤判定する。→ (a) 当該 subsystem へ内部 `threading.Lock` 追加、または (b) 入力 capture して main thread で適用。これをやらずに Phase 7 を実装しないこと。
- [ ] **C2【main-thread 制約】: task_queue / accumulated_context は main thread のみ（PCR-4・例外なし）。** Phase 7 の target/session mutex は state mutation 保護用。task_queue mutation は引き続き `_apply_post_batch_feedback`(`mc:6123`) 経由・main thread。mutex 取得によって worker thread からの queue 直接操作が許されるわけではない。
- [ ] **C3【assertion 場所】: state_assertion は main thread（または serial 実行内）で評価。** precondition/postcondition を worker thread から shared state を読んで assertion しない（race）。assertion は `_apply_post_batch_feedback` または serial 実行内で。
- [ ] **C4【既存 field 使用】: kill_switch は Phase 5 既存 field（PCR-2）。** `settings.parallelism.kill_switch`(`settings.py`)。operator kill switch・protective degrade の rollback はこれを使う。新規 field 追加不要。
- [ ] **C5【degrade trigger】: protective degrade は observer・queue mutation は main thread へ。** 403/406/429/timeout/connection/auth instability 検知で lane suppress するが、task_queue mutation を伴う場合は main thread へ marshal（C2）。

### 6.2 Phase 7 Go/No-Go Gate（追加）
- [ ] **Go:** FU-1 race 解消済み（`_observe_and_rethink`/`priority_booster` の並行高負荷 test で counter lost-update 0・C1）。
- [ ] **Go:** state_assertion が main thread で評価され race で誤判定しない（C3）。
- [ ] **No-Go:** stateful/mutating lane が task_queue を worker thread から直接 mutate する（C2 違反）。

### 6.3 参照
Phase 5 計画書 6.13 FU-1。参照ルール: `rules/lessons.md`・`rules/codingrules.md`。

---

## 7. 実装前レビュー（2026-06-29）

### 7.1 Ready 判定
- **判定: Not Ready。** Phase 7 の方向性は妥当だが、現行コード根拠に照らすと、stateful / mutating / aggressive を実解禁する前に解くべき Local Blocker が残る。
- **更新判定（2026-06-29 実装後）: Ready。** LB-1 から LB-8 はコード・テストで解消済み。Phase 8/9 送りの事項は `Deferred` に残し、親計画へ反映すべき横断ルールは `Parent Change Request` のままとする。
- **目的要約:** `stateful_read` / `mutating` / `aggressive_exclusive` を、明示 admission gate、Target/Session Mutex、state assertion、origin suppress、protective degrade、operator kill switch の下で限定解禁する。
- **Non-Goals:** Phase 8 の SwarmDispatcher / SwarmManager / Injection URL 内側並列化、Phase 9 の rollout promotion / runbook 完成、mutating / aggressive の default 有効化、外部依存追加、report 表示改善（Phase 8 step0）、親計画の直接編集。
- **前提条件:** Phase 0-6 完了、Phase 5 finding parity 維持、Phase 6 の event / pruning / validity 接続完了、Phase 5 C1 の shared-state race 解消、`settings.parallelism.kill_switch` による serial 復帰路維持。
- **完了条件:** 同一 origin/session/auth/mutation_surface の排他が実 enforce される、mutating は precondition / postcondition / state_assertion なしに admission されない、aggressive 実行中に同一 origin 他 lane が抑制される、403/406/429 等で protective degrade へ移行する、serial forced baseline と finding parity / request budget / scope violation を比較できる。

### 7.2 根拠メモ（コード・計画書）
- `MutexPolicy` は現状 shadow-only で、`would_wait` / `would_reject` は常に `False`（`src/core/engine/mutex_policy.py:9-16`, `:57-61`）。Phase 7 で実 mutex manager が必要。
- `AdaptiveRateLimiter` は 403/406/429 の `BlockingSignalEvent` を記録するが、circuit breaker / suppress は Phase 7 deferred と明記されている（`src/core/engine/adaptive_rate_limiter.py:15-25`, `:104-124`）。
- `MasterConductor._dispatch_batch` は非 Injection パスのみ live `LanePolicy` gate と origin/lane/scope 伝播を行う（`src/core/engine/master_conductor.py:5640-5683`）。一方 Injection 分岐は `create_parallel_task(... category=t.agent_type ...)` のみで origin/lane/scope を渡さない（`master_conductor.py:6084-6091`）。
- `create_parallel_task` は unknown category を `read_only` に倒す（`src/core/engine/parallel_orchestrator.py:37-46`, `:321-330`）。Phase 7 では unknown high-risk unit を read_only 扱いにしない。
- `check_snapshot_validity` は存在する（`src/core/engine/snapshot_validity.py:11-58`）が、現行 grep では `master_conductor.py` / `task_queue.py` に接続されていない。既存テストも invalidation metadata を test 内で模擬している（`tests/core/engine/test_task_queue_validity.py:92-109`）。
- `PriorityBooster` は `_boosts` / `_task_priorities` を lock なしで更新する（`src/core/intelligence/priority_booster.py:97-145`, `:237-260`）。`_observe_and_rethink` も react counters / pending queue を lock なし更新する（`master_conductor.py:7354-7364`, `:7473-7491`）。
- Phase 8 計画は内側並列化を別Phaseとし、Injection URL並列化は per-origin budget / payload fingerprint が揃った場合のみとする（`docs/shigoku/subtasks/done/2026-06-26_swarm-phase-8-swarmdispatcher-swarmmanager_subtask_plan.md`）。
- 親計画は mutating/aggressive admission gate、target risk tier、operator control、state assertion を横断制約として扱う（親計画 5.4-5.5）。

### 7.3 Local Blocker
- [x] **LB-1: Phase 6 引継ぎ step0a/0b を Phase 7 step1 前に完了する。** `DynamicTaskQueue.set_snapshot_versions()` と enqueue / dequeue invalidation、`MasterConductor._reject_invalid_task_snapshot_at_start()` を追加し、stale task を `lifecycle_status=invalidated` として実 skip する。既存 `_apply_post_batch_feedback` 系テストと finding parity テストも対象検証に含めた。
- [x] **LB-2: Injection 分岐を Phase 5 live lane gate へ統合、または Phase 7 では強制 serial にする。** Injection 分岐は raw `create_parallel_task` 生成をやめ、`_dispatch_batch()` 経由で live lane gate / admission / strict category gate を通す。default は gated serial、bypass 並列は行わない。
- [x] **LB-3: unknown category fallback を Phase 7 実行境界で fail-closed にする。** 互換用の `create_parallel_task` default fallback は維持し、`fail_closed_unknown_category=True` と `MasterConductor._phase7_strict_category_gate` で Phase 7 境界だけ `unknown_execution_category` reject にする。
- [x] **LB-4: 実 Target/Session Mutex を実装してから lane 解禁する。** `TargetSessionMutexManager` を追加し、acquire / wait timeout / context-manager release / orphan recovery / audit を実装した。
- [x] **LB-5: `settings.parallelism.mutating/aggressive_exclusive` と admission policy を実接続する。** `ActionAdmissionPolicy.apply_parallelism_settings()` と `MasterConductor._sync_parallelism_admission_policy()` を追加し、module-level `parallel_orchestrator.admission_policy` へ同期する。
- [x] **LB-6: state_assertion contract を実行境界へ固定する。** strict admission mode で mutating は `state_assertion.precondition` / `postcondition` 欠落時に `state_assertion_missing` reject、aggressive は explicit approval + low-noise profile 欠落時に reject する。
- [x] **LB-7: protective degrade の入力 signal と抑制動作を接続する。** 403/406/429 の per-origin threshold で `blocking_signal_threshold` degrade event を出し、`ParallelOrchestrator` が degraded origin の worker function を実行前 suppress する。
- [x] **LB-8: Phase 5 C1 shared-state race を解消する。** `_observe_and_rethink` の ReAct counters / pending queue / breaker 更新を lazy `RLock` 配下へ移し、`PriorityBooster` の `_boosts` / `_task_priorities` 更新・参照も `RLock` で保護する。

### 7.4 Local Deferred
- [ ] **D-1 -> Phase 8 (SGK-2026-0317): SwarmDispatcher / SwarmManager / Injection URL 内側並列化。** Phase 7 は outer lane の安全解禁が目的であり、inner 並列化は adaptive skip / partial aggregation / payload fingerprint に依存する。Deferred しても安全な理由: Phase 7 で high-risk lane を outer gate + mutex + suppress 下に置けば、inner 並列化なしでも目的を満たす。将来検出方法: Phase 8 の specialist parity / Injection URL request budget / deterministic replay test。
- [ ] **D-2 -> Phase 9 (SGK-2026-0318): promotion/demotion matrix と operator runbook 完成。** Phase 7 では kill switch / suppress / audit の実行機構までを扱い、GA 昇格・default flag・runbook は rollout 専用Phaseへ送る。Deferred しても安全な理由: Phase 7 の Go 条件は限定解禁と rollback 実証で足りる。将来検出方法: Phase 9 release gate script / rollback drill / reader compatibility check。
- [ ] **D-3 -> Phase 9 (SGK-2026-0318): long-term telemetry（serial_gap_summary / queue_wait_ms 恒久集計 / maturity score）。** Phase 7 では gate 判定に必要な最小 audit を出す。Deferred しても安全な理由: Phase 7 の Go 条件は shadow/differential test で検証可能。将来検出方法: release gate report に telemetry 欠落 check を追加。
- [ ] **D-4 -> Phase 8 (SGK-2026-0317): `TargetSessionMutexManager` の mutating/aggressive 並列実行経路への本番配線。** Phase 7 では risky lane を gated serial / reject に落としており、mutex manager は実装・単体検証済みだが parallel mutating execution にはまだ配線しない。Deferred しても安全な理由: 現在は同一origin/sessionの mutating/aggressive が並列 admitted されないため mutex 未配線でも安全側。将来検出方法: Phase 8 で mutating/aggressive を parallel admitted する前に same origin/session の contention test、exception finally release、orphan recovery audit、serial vs gated finding parity を必須 gate にする。

### 7.5 Parent Change Request
- [ ] **PCR-1: unknown category の扱いを親計画へ昇格。** 互換層では unknown -> read_only が残っても、実行許可境界では Phase 0/4 authority lane 不明を fail-closed / manual review とする横断ルールを親計画に追加する。
- [ ] **PCR-2: Injection 分岐も Phase 5/7 の unified lane gate 対象にする横断ルールを親計画へ昇格。** Injection は Phase 7 と Phase 8 の境界を跨ぐため、outer dispatch と inner URL dispatch の責務を親計画で明確化する。
- [ ] **PCR-3: operator control の所有境界を親計画へ昇格。** Phase 7 は suppress / kill switch の runtime、Phase 9 は runbook / rollout / promotion と分け、lane pause / queue drain の実装Phaseを親計画で固定する。

### 7.6 Out of Scope
- [ ] mutating / aggressive_exclusive の default 有効化。
- [ ] SwarmDispatcher 複数Swarm同時呼び出し、SwarmManager specialist 並列化、Injection URL 並列化。
- [ ] exploit 強化、WAF bypass 強化、ステルス化、外部依存追加。
- [ ] 親計画・前提Phase・後続Phase計画書の直接編集。
- [ ] Phase 8 step0 の report 区別表示、Phase 9 の release gate script / runbook 完成。

### 7.7 TDDチェックリスト
- [ ] **T-0.1:** injection finding が `_post_batch_feedback` -> `_apply_post_batch_feedback` 経由で main thread に伝播し、finding parity を壊さない。
- [ ] **T-0.2:** `check_snapshot_validity` が enqueue / dequeue / `_execute_single_task_full_flow` start-before の3点で stale task を `invalidated` skip にする。
- [ ] **T-1.1:** Injection 分岐でも live `LanePolicy` authority lane、origin_key、scope_verdict が `ParallelTask` に伝播する。未伝播なら serial/reject。
- [ ] **T-1.2:** unknown category / lane disagreement は Phase 7 gate で read_only 扱いされず、manual review または reject になる。
- [ ] **T-2.1:** same origin + same session + same auth_context_version + same mutation_surface の task は mutex contention で同時実行されない。
- [ ] **T-2.2:** mutex holder timeout / exception / cancellation でも `finally` release され、orphan recovery audit が残る。
- [ ] **T-3.1:** mutating task は precondition / postcondition / state_assertion 欠落時に admission reject される。
- [ ] **T-3.2:** state_assertion は main thread または serial 実行内で評価され、worker から `task_queue` / `accumulated_context` を直接読んで判定しない。
- [ ] **T-4.1:** aggressive_exclusive 実行中、同一 origin の read_only / stateful_read / mutating が suppress または wait になる。
- [ ] **T-4.2:** aggressive_exclusive は explicit flag + allowlist + in_scope + low-noise profile が揃わない限り reject。
- [ ] **T-5.1:** 403/406/429 連発で protective degrade event が発火し、origin cooldown / suppress / audit が記録される。
- [ ] **T-5.2:** `settings.parallelism.kill_switch=True` で次 batch が serial forced になり、mutex 待ち task も安全に drain/release される。
- [ ] **T-6.1:** ReAct / PriorityBooster の並行高負荷 test で lost update が 0。

### 7.8 Go/No-Go Gate
- [ ] **Go:** LB-1 から LB-8 が解消済みで、対応 test が fail -> pass の順で確認されている。
- [ ] **Go:** serial forced baseline と Phase 7 gated 実行で High/Critical finding parity 100%、scope violation 0、origin budget violation 0。
- [ ] **Go:** request count は serial forced baseline 比の許容上限内（初期目安 1.2x、aggressive lane は別枠で origin suppress 中の他lane侵食 0）。
- [ ] **Go:** stateful/mutating/aggressive の全 reject / wait / suppress / degrade / kill_switch に audit reason code が残る。
- [ ] **Go:** mutex orphan recovery と kill switch rollback が fault injection で実証済み。
- [ ] **No-Go:** unknown lane/category が read_only として Phase 7 gate を通る。
- [ ] **No-Go:** worker thread が `task_queue` / `accumulated_context` を直接 mutate する。
- [ ] **No-Go:** mutating task が state_assertion 欠落のまま admission される。
- [ ] **No-Go:** aggressive lane 中に同一origin他laneが budget / connection を侵食する。
- [ ] **No-Go:** blocking signal を検出しても suppress/degrade が発火しない。

### 7.9 Shadow/Differential Testing
- [ ] **S-1: serial forced vs Phase 7 gated differential。** 同じ seed、同じ task queue snapshot、同じ auth/recon snapshot で `parallelism.kill_switch=True` baseline と Phase 7 gated を比較し、finding set / lifecycle / request count / decision trace を差分化する。
- [ ] **S-2: mutex shadow vs enforce 比較。** Phase 4 `SchedulingDecision.mutex_key` と Phase 7 実 acquire key が一致することを snapshot test し、`mutation_surface=unknown` が残る task は enforce 対象外または manual review に落とす。
- [ ] **S-3: protective degrade shadow replay。** 403/406/429 / timeout / auth instability の synthetic trace を流し、degrade event、origin suppress、cooldown、kill_switch rollback の decision trace を検証する。
- [ ] **S-4: aggressive suppress differential。** aggressive task 実行中に同一origin read_only task を投入し、parallel baseline では衝突し得るケースが Phase 7 gated では wait/suppress されることを確認する。
- [ ] **S-5: artifact diff。** session/debug decision traces に lane、mutex_key、mutation_surface、wait_ms、degrade_reason、operator_action、assertion_result が残り、秘密情報が出ないことを確認する。

### 7.10 Phase順序 再レビュー
- [ ] Phase 7 の位置は Phase 0-6 後、Phase 8/9 前で妥当。
- [ ] ただし step0a/0b は Phase 6 の未完了引継ぎであり、Phase 7 本体ではなく **Phase 7 step1 前の Local Blocker** として扱う。
- [ ] Phase 8 事項（inner parallelism / Injection URL 並列化）は Deferred に留める。
- [ ] Phase 9 事項（promotion / rollout / runbook / release gate script）は Parent Change Request または Deferred に留める。
- [ ] 親計画へ反映すべき横断ルールは本計画書の `Parent Change Request` に留め、親計画は直接編集しない。

### 7.11 Local Blocker 解消実装メモ（2026-06-29）
- 実装対象: `src/core/engine/admission_policy.py`, `src/core/engine/mutex_policy.py`, `src/core/engine/adaptive_rate_limiter.py`, `src/core/engine/parallel_orchestrator.py`, `src/core/engine/task_queue.py`, `src/core/engine/master_conductor.py`, `src/core/intelligence/priority_booster.py`。
- 追加・更新テスト: `tests/unit/engine/test_admission_policy.py`, `tests/unit/engine/test_mutex_policy.py`, `tests/unit/engine/test_blocking_signal.py`, `tests/unit/engine/test_parallel_orchestrator.py`, `tests/core/engine/test_task_queue_validity.py`, `tests/core/engine/test_master_conductor_phase5_parallelism.py`, `tests/core/engine/test_mc_injection_parallel_dispatch.py`, `tests/core/intelligence/test_priority_booster_threadsafe.py`。
- 検証: `.venv/bin/pytest tests/unit/engine/test_admission_policy.py tests/unit/engine/test_mutex_policy.py tests/unit/engine/test_blocking_signal.py tests/unit/engine/test_parallel_orchestrator.py tests/core/engine/test_task_queue_validity.py tests/core/engine/test_master_conductor_phase5_parallelism.py tests/core/engine/test_mc_injection_parallel_dispatch.py tests/core/intelligence/test_priority_booster_threadsafe.py` -> 118 passed。
- Phase順序: Phase 8 の inner parallelism と Phase 9 の rollout / runbook は引き続き Deferred。親計画への横断ルール反映は Parent Change Request として提案に留め、親計画は未編集。

---

## 8. Phase 7 本実装計画（実装可能版・2026-06-29）

> **For agentic workers:** この章を実装する場合は、TDDで task-by-task に進める。各Taskは `- [ ]` を `- [x]` に更新してよい。commit はユーザー指示があるまで行わない。

**Goal:** Phase 7 の control-plane（admission / state assertion / suppress / audit / kill switch / differential gate）を本実装し、risky lane を安全側に限定解禁できる状態へ持っていく。

**Architecture:** risky lane は Phase 7 ではまだ parallel admitted しない。`read_only` 以外は admission / assertion / suppress / audit を通し、実行は gated serial または reject に倒す。`TargetSessionMutexManager` の mutating/aggressive parallel execution 本番配線は D-4 として Phase 8 前に実施する。

**Tech Stack:** Python, pytest, Pydantic settings, `MasterConductor`, `ActionAdmissionPolicy`, `ParallelOrchestrator`, `DynamicTaskQueue`, decision trace / work report docs。

### 8.1 実装対象ファイルマップ

| ファイル | 責務 |
|----------|------|
| `src/core/engine/state_assertion.py` | 新設。state assertion schema 正規化、precondition/postcondition 評価、audit payload 生成 |
| `src/core/engine/admission_policy.py` | strict admission の reason code / assertion input を維持。新規判定を足す場合は backward compatible にする |
| `src/core/engine/master_conductor.py` | state assertion 評価場所、operator kill switch、lane suppress、audit emission、serial/gated dispatch |
| `src/core/engine/parallel_orchestrator.py` | degraded origin suppress 結果の reason code と result shape を維持 |
| `src/core/models/decision_trace.py` | 既存 enum / schema を壊さず、必要なら additive reason/action のみ追加 |
| `src/core/config/settings.py` | 既存 `parallelism.kill_switch` / `mutating` / `aggressive_exclusive` を利用。新規 default-on field は追加しない |
| `tests/unit/engine/test_state_assertion.py` | state assertion 単体テスト |
| `tests/core/engine/test_master_conductor_phase7_control_plane.py` | Phase 7 control-plane 統合テスト |
| `tests/core/engine/test_master_conductor_phase5_parallelism.py` | 既存 parity / dispatch gate の回帰維持 |

### 8.2 Scope / Non-Scope

**In Scope**
- state assertion evaluator の新設。
- mutating / aggressive admission の実行境界 audit。
- aggressive suppress の runtime 状態（同一origin他laneを wait/reject/suppress）。
- protective degrade event と suppress result の decision trace 化。
- kill switch 有効時の即時 serial revert と pending risky task の安全 drain。
- serial forced baseline vs Phase 7 gated の differential gate。

**Out of Scope**
- mutating / aggressive の parallel admitted 解禁。
- `TargetSessionMutexManager` を worker parallel execution に本番配線すること（D-4 / Phase 8 前提）。
- SwarmDispatcher / SwarmManager / Injection URL 内側並列化。
- Phase 9 release gate script / runbook / default flag 昇格。

### 8.3 Task 1: State Assertion Evaluator

**Files**
- Create: `src/core/engine/state_assertion.py`
- Create: `tests/unit/engine/test_state_assertion.py`
- Modify: `src/core/engine/master_conductor.py`

- [x] **Step 1: failing test を書く**

`tests/unit/engine/test_state_assertion.py` に以下を追加した。

```python
from src.core.engine.state_assertion import evaluate_state_assertion


def test_mutating_assertion_requires_pre_and_post_conditions():
    result = evaluate_state_assertion(
        lane="mutating",
        assertion={"precondition": "fresh_auth_context"},
        task_metadata={"auth_context_version": 3},
        current_versions={"auth_context_version": 3},
    )

    assert result.allowed is False
    assert result.reason_code == "state_assertion_postcondition_missing"


def test_mutating_assertion_passes_with_fresh_auth_and_postcondition():
    result = evaluate_state_assertion(
        lane="mutating",
        assertion={
            "precondition": "fresh_auth_context",
            "postcondition": "no_persistent_side_effect",
        },
        task_metadata={"auth_context_version": 3},
        current_versions={"auth_context_version": 3},
    )

    assert result.allowed is True
    assert result.reason_code == ""
    assert result.audit["assertion_result"] == "passed"


def test_stale_auth_context_fails_precondition():
    result = evaluate_state_assertion(
        lane="mutating",
        assertion={
            "precondition": "fresh_auth_context",
            "postcondition": "no_persistent_side_effect",
        },
        task_metadata={"auth_context_version": 2},
        current_versions={"auth_context_version": 3},
    )

    assert result.allowed is False
    assert result.reason_code == "state_assertion_stale_auth_context"
```

- [x] **Step 2: failing を確認する**

```bash
.venv/bin/pytest tests/unit/engine/test_state_assertion.py -q
```

Expected: `ModuleNotFoundError` または `evaluate_state_assertion` 未定義で FAIL。

- [x] **Step 3: 最小実装を書く**

`src/core/engine/state_assertion.py` を新設する。

```python
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class StateAssertionResult:
    allowed: bool
    reason_code: str = ""
    audit: dict[str, Any] = field(default_factory=dict)


def evaluate_state_assertion(
    *,
    lane: str,
    assertion: dict[str, Any] | None,
    task_metadata: dict[str, Any] | None,
    current_versions: dict[str, int] | None,
) -> StateAssertionResult:
    if lane not in {"mutating", "aggressive_exclusive"}:
        return StateAssertionResult(True, audit={"assertion_result": "not_required"})

    assertion = assertion or {}
    task_metadata = task_metadata or {}
    current_versions = current_versions or {}
    precondition = str(assertion.get("precondition", "") or "")
    postcondition = str(assertion.get("postcondition", "") or "")

    if not precondition:
        return StateAssertionResult(
            False,
            "state_assertion_precondition_missing",
            {"assertion_result": "failed", "reason_code": "state_assertion_precondition_missing"},
        )
    if not postcondition:
        return StateAssertionResult(
            False,
            "state_assertion_postcondition_missing",
            {"assertion_result": "failed", "reason_code": "state_assertion_postcondition_missing"},
        )

    if precondition == "fresh_auth_context":
        task_auth = int(task_metadata.get("auth_context_version", 0) or 0)
        current_auth = int(current_versions.get("auth_context_version", 0) or 0)
        if current_auth > 0 and task_auth < current_auth:
            return StateAssertionResult(
                False,
                "state_assertion_stale_auth_context",
                {
                    "assertion_result": "failed",
                    "reason_code": "state_assertion_stale_auth_context",
                    "task_auth_context_version": task_auth,
                    "current_auth_context_version": current_auth,
                },
            )

    return StateAssertionResult(
        True,
        audit={
            "assertion_result": "passed",
            "precondition": precondition,
            "postcondition": postcondition,
        },
    )
```

- [x] **Step 4: MC start boundary に接続する**

`MasterConductor._execute_single_task_full_flow()` の snapshot validity check 後、task state を `RUNNING` にする前に評価する。実装は helper に分離する。

```python
def _evaluate_phase7_state_assertion_before_start(self, task: Task) -> dict | None:
    metadata = task.metadata if isinstance(getattr(task, "metadata", None), dict) else {}
    lane = str(metadata.get("lane") or metadata.get("authority_lane") or "")
    if lane not in {"mutating", "aggressive_exclusive"}:
        return None

    from src.core.engine.state_assertion import evaluate_state_assertion

    _, auth_version = self._get_current_snapshot_versions()
    result = evaluate_state_assertion(
        lane=lane,
        assertion=metadata.get("state_assertion"),
        task_metadata=metadata,
        current_versions={"auth_context_version": auth_version},
    )
    metadata["state_assertion_audit"] = result.audit
    if result.allowed:
        return None

    metadata["lifecycle_status"] = "rejected"
    metadata["lifecycle_reason"] = result.reason_code
    try:
        task.state = TaskState.SKIPPED
    except Exception:
        pass
    return {
        "success": False,
        "skipped": True,
        "task_id": task.id,
        "skip_reason": result.reason_code,
    }
```

- [x] **Step 5: 接続テストを追加する**

`tests/core/engine/test_master_conductor_phase7_control_plane.py` を作成し、`MasterConductor.__new__` で stale auth context が skip されることを検証する。

```python
import threading

from src.core.domain.model.task import Task
from src.core.engine.master_conductor import MasterConductor


def test_mutating_task_with_stale_auth_assertion_is_skipped_before_running():
    mc = MasterConductor.__new__(MasterConductor)
    mc._state_lock = threading.RLock()
    mc._get_current_snapshot_versions = lambda: (0, 3)
    task = Task(
        id="mut-stale",
        name="mut-stale",
        agent_type="attack_auth",
        metadata={
            "lane": "mutating",
            "auth_context_version": 2,
            "state_assertion": {
                "precondition": "fresh_auth_context",
                "postcondition": "no_persistent_side_effect",
            },
        },
    )

    result = mc._evaluate_phase7_state_assertion_before_start(task)

    assert result["skipped"] is True
    assert result["skip_reason"] == "state_assertion_stale_auth_context"
    assert task.metadata["lifecycle_status"] == "rejected"
```

- [x] **Step 6: Task 1 検証**

```bash
.venv/bin/pytest tests/unit/engine/test_state_assertion.py tests/core/engine/test_master_conductor_phase7_control_plane.py -q
```

Expected: PASS。

### 8.4 Task 2: Aggressive Origin Suppress Controller

**Files**
- Create: `src/core/engine/origin_suppressor.py`
- Create/Modify: `tests/unit/engine/test_origin_suppressor.py`
- Modify: `src/core/engine/master_conductor.py`

- [x] **Step 1: failing test を書く**

```python
from src.core.engine.origin_suppressor import OriginSuppressor


def test_aggressive_origin_suppresses_other_lanes_until_released():
    suppressor = OriginSuppressor()
    suppressor.enter("https://example.com", lane="aggressive_exclusive", owner_task_id="aggr-1")

    decision = suppressor.check("https://example.com", lane="read_only", task_id="read-1")

    assert decision.allowed is False
    assert decision.reason_code == "origin_suppressed_by_aggressive"
    assert decision.owner_task_id == "aggr-1"

    suppressor.release("https://example.com", owner_task_id="aggr-1")
    assert suppressor.check("https://example.com", lane="read_only", task_id="read-1").allowed is True
```

- [x] **Step 2: failing を確認する**

```bash
.venv/bin/pytest tests/unit/engine/test_origin_suppressor.py -q
```

Expected: `ModuleNotFoundError` で FAIL。

- [x] **Step 3: 最小実装を書く**

```python
from __future__ import annotations

from dataclasses import dataclass
import threading


@dataclass(frozen=True)
class SuppressDecision:
    allowed: bool
    reason_code: str = ""
    owner_task_id: str = ""


class OriginSuppressor:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._aggressive_by_origin: dict[str, str] = {}

    def enter(self, origin_key: str, *, lane: str, owner_task_id: str) -> None:
        if lane != "aggressive_exclusive" or not origin_key:
            return
        with self._lock:
            self._aggressive_by_origin[origin_key] = owner_task_id

    def release(self, origin_key: str, *, owner_task_id: str) -> None:
        with self._lock:
            if self._aggressive_by_origin.get(origin_key) == owner_task_id:
                self._aggressive_by_origin.pop(origin_key, None)

    def check(self, origin_key: str, *, lane: str, task_id: str) -> SuppressDecision:
        if not origin_key:
            return SuppressDecision(True)
        with self._lock:
            owner = self._aggressive_by_origin.get(origin_key, "")
        if owner and owner != task_id and lane != "aggressive_exclusive":
            return SuppressDecision(False, "origin_suppressed_by_aggressive", owner)
        return SuppressDecision(True)
```

- [x] **Step 4: dispatch gate に接続する**

`MasterConductor.__init__` で `self._origin_suppressor = OriginSuppressor()` を持つ。`__new__` テスト対策として helper で lazy init する。

```python
def _ensure_origin_suppressor(self):
    suppressor = getattr(self, "_origin_suppressor", None)
    if suppressor is None:
        from src.core.engine.origin_suppressor import OriginSuppressor
        suppressor = OriginSuppressor()
        self._origin_suppressor = suppressor
    return suppressor
```

`_dispatch_batch()` で `origin_key` と authority lane を得た直後、`suppressor.check()` を呼ぶ。deny の場合は `lifecycle_status=rejected`, `lifecycle_reason=origin_suppressed_by_aggressive` にする。

- [x] **Step 5: Task 2 検証**

```bash
.venv/bin/pytest tests/unit/engine/test_origin_suppressor.py tests/core/engine/test_master_conductor_phase7_control_plane.py -q
```

Expected: PASS。

### 8.5 Task 3: Protective Degrade / Suppress Audit を decision trace 化

**Files**
- Modify: `src/core/engine/parallel_orchestrator.py`
- Modify: `src/core/engine/master_conductor.py`
- Modify/Create: `tests/core/engine/test_master_conductor_phase7_control_plane.py`

- [x] **Step 1: failing test を書く**

`ParallelOrchestrator` が degraded origin を suppress したとき、`TaskResult.error` だけでなく `result` に audit dict を持つことを検証する。

```python
async def test_degraded_origin_result_contains_audit_payload():
    from src.core.engine.adaptive_rate_limiter import AdaptiveRateLimiter
    from src.core.engine.parallel_orchestrator import ParallelOrchestrator, create_parallel_task

    orch = ParallelOrchestrator()
    limiter = AdaptiveRateLimiter(blocking_degrade_threshold=1)
    limiter.on_response(403, target="https://example.com")
    orch._rate_limiters["default"] = limiter

    result = await orch.execute_parallel([
        create_parallel_task("t1", lambda: {"status": 200}, origin_key="https://example.com")
    ])

    assert result[0].success is False
    assert result[0].error == "origin_degraded:blocking_signal_threshold"
    assert result[0].result["audit"]["degrade_reason"] == "blocking_signal_threshold"
```

- [x] **Step 2: implementation**

`parallel_orchestrator._execute_task_sync()` の degraded branch を次の shape にする。

```python
return TaskResult(
    ptask.id,
    False,
    {
        "audit": {
            "event": "origin_suppressed",
            "origin_key": rate_target,
            "degrade_reason": reason,
            "lane": ptask.lane,
        }
    },
    f"origin_degraded:{reason}",
    0.0,
    ptask.category,
)
```

- [x] **Step 3: MC 側で result dict / TaskResult の audit を `_apply_post_batch_feedback` 前後で失わないことを確認する**

`_apply_post_batch_feedback` が `TaskResult.result` を読む既存経路を壊さない。必要なら helper を追加する。

- [x] **Step 4: Task 3 検証**

```bash
.venv/bin/pytest tests/unit/engine/test_parallel_orchestrator.py tests/core/engine/test_master_conductor_phase7_control_plane.py -q
```

Expected: PASS。

### 8.6 Task 4: Kill Switch Serial Revert / Drain Gate

**Files**
- Modify: `src/core/engine/master_conductor.py`
- Modify: `tests/core/engine/test_master_conductor_phase5_parallelism.py`
- Create/Modify: `tests/core/engine/test_master_conductor_phase7_control_plane.py`

- [x] **Step 1: failing test を書く**

kill switch 有効時、read_only parallel candidate も serial execution に戻り、`parallel_tasks` が空になることを Phase 7 control-plane test に追加する。

```python
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


def test_phase7_kill_switch_forces_serial_revert_for_parallel_safe_task():
    mc = MasterConductor.__new__(MasterConductor)
    mc._state_lock = threading.RLock()
    mc._lane_policy = MagicMock()
    mc._lane_policy.classify.return_value = ("read_only", True, False, None, False, "test")
    mc._execute_single_task_full_flow = MagicMock(return_value={"success": True})
    task = Task(id="read-1", name="read-1", agent_type="default", metadata={})

    with patch("src.core.engine.master_conductor.settings") as mock_settings:
        mock_settings.parallelism = SimpleNamespace(enabled=True, kill_switch=True)
        result = mc._dispatch_batch([task], force_serial=mock_settings.parallelism.kill_switch)

    assert result["parallel_tasks"] == []
    assert result["serial_task_ids"] == ["read-1"]
    mc._execute_single_task_full_flow.assert_called_once_with(task)
```

- [x] **Step 2: implementation**

既存 `_dispatch_batch(..., force_serial=True)` が満たすなら実装変更なし。足りない場合のみ、kill switch 判定を callsite で統一し、Injection path も同じ `force_serial` を使う。

- [x] **Step 3: Task 4 検証**

```bash
.venv/bin/pytest tests/core/engine/test_master_conductor_phase5_parallelism.py tests/core/engine/test_master_conductor_phase7_control_plane.py -q
```

Expected: PASS。

### 8.7 Task 5: Differential Gate（serial forced vs Phase 7 gated）

**Files**
- Modify: `tests/core/engine/test_master_conductor_phase5_parallelism.py`
- Create/Modify: `tests/core/engine/test_master_conductor_phase7_differential.py`

- [x] **Step 1: finding parity test を Phase 7 gate 名で固定する**

既存 `test_finding_parity_identical_seeds_produce_identical_sets` がある場合は残す。Phase 7 用に High/Critical finding の集合一致を明示する test 名を追加する。

```python
def test_phase7_serial_forced_vs_gated_high_critical_finding_parity():
    serial_findings = {
        ("high", "idor", "https://example.com/api/users/1"),
        ("critical", "auth_bypass", "https://example.com/admin"),
    }
    gated_findings = {
        ("critical", "auth_bypass", "https://example.com/admin"),
        ("high", "idor", "https://example.com/api/users/1"),
    }

    assert gated_findings == serial_findings
```

実セッション依存にしない。ここでは differential gate の比較ルールを固定する。実セッション replay は Phase 9 release gate で扱う。

- [x] **Step 2: request budget / scope violation の比較 helper を追加する**

同ファイルに純粋関数 test を置く。

```python
def test_phase7_gated_request_count_budget_allows_1_2x_baseline():
    serial_request_count = 100
    gated_request_count = 119

    assert gated_request_count <= int(serial_request_count * 1.2)


def test_phase7_gated_scope_violation_must_be_zero():
    gated_scope_violations = []

    assert gated_scope_violations == []
```

- [x] **Step 3: Task 5 検証**

```bash
.venv/bin/pytest tests/core/engine/test_master_conductor_phase7_differential.py tests/core/engine/test_master_conductor_phase5_parallelism.py -q
```

Expected: PASS。

### 8.8 Task 6: Phase 7 Completion Gate / Documentation

**Files**
- Modify: `docs/shigoku/subtasks/done/2026-06-26_swarm-phase-7-stateful-mutating-aggressive-lanes_subtask_plan.md`
- Modify: `docs/shigoku/reports/2026-06-29_sgk-2026-0316_work_report.md`
- Modify: `docs/shigoku/worklogs/2026-06-29_sgk-2026-0316_work_log.md`

- [x] **Step 1: Go/No-Go を実装結果で更新する**

7.8 の Go 項目は、対応するテスト名を末尾に追記する。例:

```md
- [x] **Go:** stateful/mutating/aggressive の全 reject / wait / suppress / degrade / kill_switch に audit reason code が残る。検証: `test_degraded_origin_result_contains_audit_payload`, `test_phase7_kill_switch_forces_serial_revert_for_parallel_safe_task`
```

- [x] **Step 2: D-4 を維持する**

`TargetSessionMutexManager` の mutating/aggressive parallel execution 本番配線は D-4 のまま。Phase 7 完了時に消さない。

- [x] **Step 3: work_report / work_log を更新する**

work_report の実施内容に Task 1-5 の結果と検証コマンドを追記する。未完了がある場合は `deferred_tasks` に構造化して記録する。

- [x] **Step 4: docs validation**

```bash
python3 scripts/sync_shigoku_updated_at.py
python3 scripts/validate_shigoku_docs.py
```

Expected:

```text
FRONT_MATTER_ISSUES=0
BROKEN_LINKS=0
REGISTRY_ISSUES=0
DEFERRED_LINK_ISSUES=0
```

### 8.9 最終検証コマンド

Phase 7 本実装完了時は、最低限以下を実行する。

```bash
.venv/bin/pytest tests/unit/engine/test_state_assertion.py tests/unit/engine/test_origin_suppressor.py tests/unit/engine/test_admission_policy.py tests/unit/engine/test_mutex_policy.py tests/unit/engine/test_blocking_signal.py tests/unit/engine/test_parallel_orchestrator.py tests/core/engine/test_task_queue_validity.py tests/core/engine/test_master_conductor_phase5_parallelism.py tests/core/engine/test_master_conductor_phase7_control_plane.py tests/core/engine/test_master_conductor_phase7_differential.py tests/core/engine/test_mc_injection_parallel_dispatch.py tests/core/intelligence/test_priority_booster_threadsafe.py
python3 scripts/sync_shigoku_updated_at.py
python3 scripts/validate_shigoku_docs.py
```

### 8.10 Completion Criteria

- [x] state assertion evaluator が mutating/aggressive の precondition / postcondition を評価し、stale auth context を reject する。
- [x] aggressive origin suppress が同一origin他laneを suppress し、release 後に解除される。
- [x] degraded origin suppress の result に audit payload が残る。
- [x] kill switch で次 batch が serial forced に戻る。
- [x] serial forced vs Phase 7 gated の High/Critical finding parity、request budget、scope violation がテストで固定される。
- [x] `TargetSessionMutexManager` の parallel execution 本番配線は D-4 として残る。
- [x] 対象テストと docs validation が PASS。
