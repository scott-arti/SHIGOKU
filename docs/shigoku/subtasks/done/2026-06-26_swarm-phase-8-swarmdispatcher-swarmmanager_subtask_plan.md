---
task_id: SGK-2026-0317
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0291
related_docs:
- docs/shigoku/subtasks/2026-06-23_sgk-2026-0291_swarm-parallelism-review_subtask_plan.md
- docs/shigoku/reports/2026-06-30_sgk-2026-0317_work_report.md
- docs/shigoku/worklogs/2026-06-30_sgk-2026-0317_work_log.md
title: 'Swarm並列化 Phase 8: SwarmDispatcher SwarmManager 内側並列化評価'
created_at: '2026-06-26'
updated_at: '2026-06-30'
tags:
- shigoku
target: SwarmDispatcher.dispatch, SwarmManager.dispatch, InjectionManager.dispatch,
  specialist safety notes
---

# 実装計画書：Swarm並列化 Phase 8: SwarmDispatcher SwarmManager 内側並列化評価

## 1. 達成したいゴール（ユーザー視点）
- [ ] 外側並列化が安定した後に、SwarmDispatcher / SwarmManager / InjectionManager 内側並列化を個別評価できること。
- [ ] SwarmManager specialist直列実行とHigh/Critical adaptive skipの意味論を壊さないこと。
- [ ] Injection URL並列化は per-origin budget、payload fingerprint、context isolation が揃った範囲だけに限定すること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/swarm_dispatcher.py`: 複数Swarm候補の並列評価可否。
  - `src/core/agents/swarm/base.py`: specialist実行順序とadaptive skip保護。
  - `src/core/agents/swarm/injection/manager.py`: Injection URL処理の限定並列化評価。
  - specialistごとの concurrency safety note: `parallel_safe` / `sequential_required` 根拠。
- **データの流れ / 依存関係:**
  - SwarmDispatcher -> Swarm candidates -> SwarmManager -> specialists -> sub-results -> aggregation / adaptive skip / replay。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** state isolation result、lane decision、specialist safety note、payload/request fingerprint、baseline parity result。
- **出力/結果 (Output):** inner parallelism decision、partial failure aggregation、specialist parity result、replay artifact。
- **制約・ルール:**
  - Phase 3のcontext isolation完了が必須。
  - Phase 5のouter parallelismが安定していない場合は開始しない。
  - High/Critical finding時のadaptive skipを再現できない並列化は採用しない。
  - SwarmDispatcher / SwarmManager / InjectionManager を一括で並列化しない。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ0: Phase 6 引継ぎ: report 区別表示 (F2) を **pre-flight 独立 patch** として先に完了する。`run_narrative_formatter.py` の decision_traces 描画部で `decision_type in {task_retired, task_superseded, task_invalidated}` を抽出し、"未実施（不要化）" セクションへ集計。`_DECISION_TYPE_JA` mapping へ TASK_RETIRED→"退役"・TASK_SUPERSEDED→"差替"・TASK_INVALIDATED→"無効化" を追加。内側並列化のコード変更とは同一 patch にしない。
- [ ] ステップ1: SwarmDispatcher、SwarmManager、InjectionManagerを別々に評価し、内側並列化候補を分類する。
- [ ] ステップ2: specialistごとの concurrency safety note と adaptive skip影響を記録する。
- [ ] ステップ3: SwarmDispatcherは state isolation 済み read_only/stateless Swarm のみ限定候補にし、serial baseline と stable merge order を先に固定する。
- [ ] ステップ4: SwarmManager specialist並列化は Phase 8 では **shadow 評価のみ** とする。adaptive skipを保てる設計が未実装なら実並列へ昇格しない。
- [ ] ステップ5: Injection URL並列化は per-url sub-result schema、per-origin budget、payload/request fingerprint、request budget assertion が揃った場合だけ限定解禁する。URL worker は共有 `current_context` を直接 mutate しない。
- [ ] ステップ6: specialist parity、partial failure aggregation、Injection URL request budget、deterministic replay testを実行する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] adaptive skipが崩れると無駄撃ちやFalse Negativeが増える - specialist並列化はskip意味論を再現できるまで保留する。
- [ ] [重要度:高] Injection URL並列化がtarget負荷を増やす - per-origin budgetとrequest fingerprintを必須にする。
- [ ] [重要度:中] partial failureの集約でfindingが欠落する - specialist sub-result schemaを標準化する。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0317-D01
    title: "継続監視: Swarm内側並列化のparity"
    reason: "内側並列化はfinding aggregationとadaptive skipへ影響する"
    impact: medium
    tracking_task_id: SGK-2026-0317
    recommended_next_action: "specialistごとのparity結果をレビューし、安全なものだけ昇格する"
```

---

## 6. Phase 5 レビュー由来の横断制約（2026-06-28・実装前必須・Blocker級）
Phase 5（SGK-2026-0314）完了レビューで判明した制約。Phase 8 は内側並列で最も shared state に触るため最重要。

### 6.1 必須設計制約（MUST・違反は実装停止）
- [ ] **C1【main-thread 制約・例外なし】: task_queue / accumulated_context mutation は main thread のみ（PCR-4）。** specialist が並列実行されても shared state mutation は dispatch 終了後（outer の `_apply_post_batch_feedback`(`mc:6123`)）へ集約。specialist 内で直接 `task_queue.add/boost_priority/inject_context`・`accumulated_context.merge` を呼んではいけない。`DynamicTaskQueue` は内部 lock なし。
- [ ] **C2【DispatchContext threading 必須】: Phase 3 D-1 の完全 threading を導入。** Phase 3 は per-dispatch instance で外側汚染を防いだが、Phase 8 は同一 instance 内の specialist 並列。`current_context`/`history`/`url_results` 等の mutable instance state を ContextVar/DispatchContext で specialist 単位に thread-safe 分離することが必須。per-dispatch instance だけでは不十分（Phase 3 計画書 6.7 D-1 参照）。
- [ ] **C3【adaptive skip 保護】: High/Critical finding で後続 specialist を skip する意味論（`base.py:356-357`）を壊さない。** 内側並列化で skip 伝播が再現できる設計ができるまで shadow 評価に留める（step4 どおり）。再現できない並列化は採用しない。
- [ ] **C4【pool 復活は stateless のみ】: pool 再利用復活は stateless Swarm のみ（Phase 5 D-2）。** per-dispatch instance は外側正確性の基盤として維持。pool 復活は stateless（plain `SwarmManager` 継承）Swarm のみ評価。stateful（`BaseManagerAgent` 継承: injection/auth/logic/discovery）は引き続き per-dispatch。
- [ ] **C5【Injection URL】: per-origin budget + payload fingerprint 揃ってから（step5 どおり）。** specialist 内の局所並列も task_queue 直接操作禁止（C1）。

### 6.2 Phase 8 Go/No-Go Gate（追加）
- [ ] **Go:** 内側並列でも task_queue mutation が main thread 集約・`threading.main_thread()` assert 付き（C1）。
- [ ] **Go:** DispatchContext threading で同一 Swarm instance の specialist 並列で context/history/url_results が混ざらない（C2・Phase 3 isolation test の内側版）。
- [ ] **No-Go:** adaptive skip 意味論が再現できない並列化を採用する（C3）。
- [ ] **No-Go:** specialist が task_queue を直接 mutate する（C1 違反）。

### 6.3 参照
Phase 3 計画書 6.7 D-1（DispatchContext threading）・Phase 5 計画書 D-2（pool 復活）・PCR-4。参照ルール: `rules/lessons.md`・`rules/codingrules.md`。

---

## 7. 実装前レビュー更新（2026-06-30）

### 7.1 Ready / Not Ready 判定
- **判定: Ready（実装着手可）。**
- **理由:** 前回レビューで Not Ready とした未決事項（Step 0 scope、DispatchContext threading、adaptive skip、deterministic aggregation、Injection per-url schema、mutating/aggressive扱い）は 7.4 で実装上の固定決定として解消済み。Phase 8 は「pre-flight cleanup -> serial baseline -> shadow decision -> read_only/stateless limited execution -> Injection URL limited execution -> replay/parity gate」の順にTDDで進められる。
- **Ready条件:** 実装者は 7.8 の TDD 順序と 7.9 の Go/No-Go Gate を必ず守ること。これを外れる変更は Phase 8 の範囲外または No-Go とする。

### 7.2 対象Phaseの要約
- **目的:** 外側並列化が Phase 5/7 の gate 下で安定した後、内側並列化候補を SwarmDispatcher / SwarmManager / InjectionManager に分けて評価する。実行可能な候補は `read_only` / `parallel_safe` / `rate_limited` かつ per-origin budget 下に限定する。
- **Non-Goals:** SwarmDispatcher / SwarmManager / InjectionManager の一括並列化、adaptive skip の意味論変更、scope unknown の active/mutating/aggressive 実行、秘密情報を含む replay/debug artifact、親計画・他Phase計画書の直接編集。
- **前提条件:** Phase 3 の per-dispatch instance 隔離、Phase 5 の gated outer parallelism / kill switch / origin_key 伝播、Phase 6 の decision trace / pruning lifecycle、Phase 7 の risky lane gate / suppress / mutex manager 単体検証が利用可能であること。
- **完了条件:** 内側並列を有効化した候補について、High/Critical finding parity 100%、adaptive skip 互換、scope violation 0、origin/request budget violation 0、partial failure aggregation 欠落 0、deterministic replay 可能、kill switch で serial 互換へ戻せること。

### 7.3 根拠コード / 既存テスト
- `SwarmDispatcher.dispatch()` は `for swarm_name in swarm_names` で直列実行し、結果を `all_findings` / `all_execution_logs` / `statuses` に順序集約する（`src/core/engine/swarm_dispatcher.py:245-320`）。内側並列化時は deterministic merge order と partial failure semantics が必須。
- `_get_or_create_swarm()` は Phase 3 で per-dispatch instance に固定され、pool へ保存しない（`src/core/engine/swarm_dispatcher.py:94-138`）。pool 復活は stateless Swarm 限定で別 gate が必要。
- `SwarmManager.dispatch()` は specialist を直列に実行し、High/Critical finding 後に後続 specialist を `skipped` として記録して `break` する（`src/core/agents/swarm/base.py:332-369`）。既存テスト `tests/unit/test_tier4_intelligence.py:57-98` が後続 specialist 未実行を固定している。
- `BaseManagerAgent` は `self.current_context` / `self.history` を dispatch 中に上書き・append し、`report_finding()` も `current_context["findings"]` へ直接 append する（`src/core/agents/swarm/base_manager.py:62-66`, `178-199`, `220-304`, `495-504`）。同一 instance 内の specialist 並列は DispatchContext threading なしでは不可。
- `InjectionManagerAgent.dispatch()` は `current_context["findings"]` と `current_context["url_results"]` を URL loop 内で直接 append / extend する（`src/core/agents/swarm/injection/manager.py:1863-1869`, `1942-2055`, `2267-2368`, `2807-2808`, `3058-3059`）。URL 並列化は per-url sub-result 化と post-join deterministic merge が先。
- per-origin budget は thread-safe 実装済み（`src/core/engine/budget_policy.py:67-78`, `103-115`）で、競合テストもある（`tests/unit/engine/test_budget_policy.py:100-130`）。
- Phase 7 の risky lane 実行 mutex は `TargetSessionMutexManager` として単体実装済みだが、実行経路への本番配線は Phase 7 D-4 のまま（`src/core/engine/mutex_policy.py:67-162`, `tests/unit/engine/test_mutex_policy.py:147-191`）。
- Step 0 の report 表示引継ぎは一部未完。`DecisionType` enum には `TASK_RETIRED` / `TASK_SUPERSEDED` / `TASK_INVALIDATED` が存在するが、`run_narrative_formatter.py` の `_DECISION_TYPE_JA` mapping は未対応で、decision_traces から「未実施（不要化）」セクションへ分離集計する処理も未実装（`src/core/models/decision_trace.py:12-25`, `src/reporting/run_narrative_formatter.py:49-58`, `306-345`）。

### 7.4 Local Blocker（解消済み設計決定）
- [x] **LB-1 解消: Step 0 は pre-flight 独立 patch に固定。** report formatting は内側並列化の実装 patch と混ぜない。Step 0 を完了してから Step 1 へ進む。もし実装時に Step 0 が想定以上に膨らむ場合は D-3 として Phase 9 へ切り出し、Phase 8 の inner parallelism patch には含めない。
- [x] **LB-2 解消: DispatchContext は explicit context/result object 優先。** Phase 8 の parallel path では `current_context` / `history` / `url_results` / `_phase2_detection_mode` を worker から直接 mutate しない。残存 `self.current_context` mutation は grep で検出し、worker は per-worker local result のみ返す。
- [x] **LB-3 解消: SwarmManager specialist 実並列化は Phase 8 では shadow-only。** High/Critical 発見後に後続を未実行扱いにする serial 意味論を保持する。全面 `asyncio.gather()` は No-Go として固定する。
- [x] **LB-4 解消: deterministic aggregation contract を固定。** SwarmDispatcher / Injection URL の結果は入力順・swarm order・URL priority order に従って stable merge し、partial failure は finding 欠落ではなく sub-result failure として `execution_log` / replay artifact に残す。
- [x] **LB-5 解消: Injection URL は per-url sub-result schema 先行。** URL worker は `findings`, `url_result`, `tested_params`, `request_fingerprint`, `payload_fingerprint`, `error`, `budget_decision` を返し、共有 `current_context` へ直接 append しない。post-join でのみ `current_context` を更新する。
- [x] **LB-6 解消: mutating/aggressive inner execution は Phase 8 limited execution から除外。** Phase 8 の実行対象は `read_only` / `parallel_safe` / `rate_limited` のみ。mutating/aggressive は `TargetSessionMutexManager` 本番配線、exception finally release、orphan recovery audit、same origin/session contention test が揃うまで No-Go。
- **未解決 Local Blocker:** なし。

### 7.5 Local Deferred
| # | 項目 | Deferred先Phase | Deferredしても安全な理由 | 将来の検出方法 |
|---|---|---|---|---|
| D-1 | rich telemetry の恒久化（`serial_gap_summary` / `queue_wait_ms` / long-term maturity score） | Phase 9 (SGK-2026-0318) | Phase 8 の Go は test artifact と replay artifact の最小 parity で判定できる。恒久レポート化は rollout / promotion gate の責務 | Phase 9 release gate script / shadow compare report で telemetry 欠落 check |
| D-2 | mutating/aggressive inner parallelism の default 有効化 | Phase 9 (SGK-2026-0318) | Phase 8 は read_only/rate_limited 限定評価で目的を満たせる。mutating/aggressive は serial/reject のままならこのPhaseの Go 条件を壊さない | Phase 9 promotion matrix で risky lane default flag が false であること、mutex contention / rollback drill |
| D-3 | report 「未実施（不要化）」表示のリッチ化（summary grouping / operator dashboard 表示） | Phase 9 (SGK-2026-0318) | Phase 8 Step 0 は最小表示と翻訳 mapping までを pre-flight で扱う。恒久ダッシュボードや詳細 grouping は inner parallelism の Go 条件に不要 | `tests/unit/reporting/test_run_narrative_formatter.py` と Phase 9 release gate report で task_retired/superseded/invalidated 表示を確認 |
| D-4 | EventBus thread model の根本変更（SharedLoopManager -> main-loop 統合） | Phase 9 (SGK-2026-0318) | Phase 8 は event emission を main-thread post-join 集約に限定すれば安全に評価できる。EventBus runtime の根本変更は rollout / recovery 設計と合わせるべき | event enqueue/dequeue/handler audit と queue full fault injection |
| D-5 | Injection URL actual parallel execution（T-5.2 request budget enforcement） | Phase 9 (SGK-2026-0318) | Phase 8 では PerUrlSubResult schema と Dispatcher limited parallel A までを完了。Injection URL actual parallel の budget enforcement は有効化していないため request budget violation は発生しない。schema (`PerUrlSubResult`) は Phase 8 で完了済み | Phase 9 で `ExecutionBudgetPolicy` 超過時に skipped/rejected `PerUrlSubResult` が残るテストを追加 |

### 7.6 Parent Change Request
- [ ] **PCR-1: inner parallelism は3層を別 gate にする横断ルール。** `SwarmDispatcher parallel`, `SwarmManager specialist shadow`, `Injection URL limited parallel` を同一 feature flag で有効化しない。親計画 4.1 / 4.4 に「層別 flag・層別 Go/No-Go・層別 rollback」を追加候補とする。
- [ ] **PCR-2: partial failure aggregation schema の親計画昇格。** 複数 Phase（Phase 6/8/9）で使うため、`sub_result.status`, `source_layer`, `source_unit`, `reason_code`, `error_class`, `finding_count`, `request_count`, `fingerprint` を共通 outcome schema として親計画へ反映候補にする。
- [ ] **PCR-3: `BaseManagerAgent` 系 stateful manager は shared mutable state を直接並列 worker に渡さない横断ルール。** `current_context` 互換 shim ではなく explicit context/result object を優先し、残存 mutable state は grep とテストで検出する。
- [ ] **PCR-4: Step 0 のような report formatting backlog は Phase 9 または dedicated cleanup に集約する運用ルール。** 安全評価PhaseにUI/report cleanupを混ぜる場合は pre-flight として独立完了させ、inner parallelism 実装と同時 patch にしない。

### 7.7 Out of Scope
- [ ] SwarmDispatcher / SwarmManager / InjectionManager の全面同時並列化。
- [ ] SwarmManager specialist の実並列化を adaptive skip 互換設計なしで採用すること。
- [ ] stateful manager（`BaseManagerAgent` 継承: injection/auth/logic/discovery）の pool 再利用復活。
- [ ] mutating/aggressive inner parallelism の default 有効化。
- [ ] target allowlist / scope verdict なしの active/mutating/aggressive 実行。
- [ ] Phase 9 release gate / rollout runbook / operator dashboard の完成。
- [ ] 親計画・前提Phase・後続Phase計画書の直接編集。

### 7.7.1 Ready 実装順序（固定）
1. **Pre-flight:** Step 0 report cleanup を単独 patch + `tests/unit/reporting/test_run_narrative_formatter.py` で完了する。
2. **Baseline:** `SwarmDispatcher.dispatch()` / `SwarmManager.dispatch()` の serial behavior、adaptive skip、execution_log shape を snapshot 固定する。
3. **Shadow:** SwarmDispatcher / SwarmManager / Injection URL の candidate decision を記録するが、実行順序は変えない。
4. **Limited execution A:** SwarmDispatcher は read_only/stateless Swarm のみ limited parallel を許可し、stable merge と partial failure aggregation を検証する。
5. **Limited execution B:** Injection URL は per-url sub-result + budget/fingerprint が揃った候補のみ limited parallel を許可する。
6. **Gate:** deterministic replay / High-Critical parity / request budget / kill switch rollback を通過した候補だけを Phase 8 完了範囲とする。

### 7.8 TDDチェックリスト
- [ ] **T-0.1 Step 0 pre-flight test:** `task_retired` / `task_superseded` / `task_invalidated` が `_DECISION_TYPE_JA` で和訳され、必要なら「未実施（不要化）」セクションへ分離表示される。Step 0 を Phase 8 で実施しない場合は D-3 へ移す。
- [ ] **T-1.1 serial baseline lock:** 既存 `SwarmDispatcher.dispatch()` と `SwarmManager.dispatch()` の serial result order / execution_log shape / adaptive skip を snapshot 固定する。
- [ ] **T-2.1 Dispatcher shadow:** 複数 Swarm 候補を shadow schedule しても実実行順は変えず、parallel candidate / reject reason / state isolation status を記録する。
- [ ] **T-2.2 Dispatcher limited parallel:** `read_only` かつ stateless Swarm のみ、parallel execution の finding set が serial と一致し、execution_log は deterministic merge order になる。
- [ ] **T-3.1 Specialist shadow:** specialist 候補ごとに `parallel_safe`, `rate_limited`, `stateful`, `aggressive_exclusive`, `adaptive_skip_sensitive` を記録し、High/Critical を返す specialist がある場合は実並列化しない。
- [ ] **T-3.2 adaptive skip regression:** `tests/unit/test_tier4_intelligence.py` 相当で、High/Critical 発見後の後続 specialist 未実行 / skipped log が維持される。
- [ ] **T-4.1 DispatchContext isolation:** （Phase 9 Deferred: Phase 3 D-1 の完全 threading 導入は inner parallelism rollout 時に実施）同一 manager instance 内で2つの worker context を走らせても `current_context`, `history`, `url_results`, `findings`, `_phase2_detection_mode` が混ざらない。
- [x] **T-5.1 Injection per-url sub-result:** URL worker は共有 context を mutate せず、per-url result を返す（Phase 8: `PerUrlSubResult` schema 完了）。post-join merge は Phase 9 で実施。
- [ ] **T-5.2 Injection request budget:** 同一 origin への URL 並列で `ExecutionBudgetPolicy` の burst を超えず、超過分は skipped/rejected sub-result として残る → **Phase 9 Deferred (D-5)**。Phase 8 では schema (`PerUrlSubResult`) が ready、actual parallel と budget enforcement は Phase 9 で実施。
- [ ] **T-6.1 partial failure aggregation:** 1つの Swarm / specialist / URL worker が失敗しても他結果は保持され、失敗は `execution_log` と replay artifact に source unit 付きで残る。
- [ ] **T-7.1 deterministic replay:** seed、swarm order、specialist order、URL priority order、request/payload fingerprint を保存し、serial baseline と limited parallel の High/Critical finding parity を再現できる。
- [ ] **T-8.1 kill switch rollback:** `parallelism.enabled=false` または `kill_switch=true` で Phase 8 inner parallel candidate も serial path に戻る。

### 7.9 Go/No-Go Gate
- [ ] **Go:** 7.4 の解消済み設計決定と 7.7.1 の実装順序を守っている。
- [ ] **Go:** Phase 8 limited execution は `read_only` / `parallel_safe` / `rate_limited` + per-origin budget + request/payload fingerprint が揃う候補だけ。
- [ ] **Go:** High/Critical finding parity 100%、scope violation 0、origin/request budget violation 0、secret leak 0。
- [ ] **Go:** adaptive skip sensitive な SwarmManager specialist 実並列化は shadow-only のまま。
- [ ] **Go:** `current_context` / `history` / `url_results` は parallel worker から直接 mutate されず、post-join deterministic merge に限定される。
- [ ] **Go:** partial failure は finding 欠落ではなく source unit 付き sub-result failure として追跡できる。
- [ ] **Go:** kill switch / `parallelism.enabled=false` で即 serial 互換に戻る。
- [ ] **No-Go:** Step 0 report cleanup と inner parallelism の実装を同一 patch に混ぜる。
- [ ] **No-Go:** `asyncio.gather()` で specialist を全面実行し、High/Critical adaptive skip の未実行意味論を失う。
- [ ] **No-Go:** stateful manager pool を復活させる。
- [ ] **No-Go:** mutating/aggressive inner parallelism を default 有効化する。
- [ ] **No-Go:** worker が task_queue / accumulated_context / EventBus critical mutation を直接実行する。

### 7.10 Shadow / Differential Testing
- [ ] **Shadow-1:** serial baseline 実行時に、同じ入力から inner parallel candidate decision だけを記録し、実行順序は変えない。
- [ ] **Shadow-2:** SwarmDispatcher は swarm order ごとの predicted parallel groups と reject reason を出すが、serial result と比較するまでは limited parallel を有効にしない。
- [ ] **Shadow-3:** SwarmManager は specialist order、adaptive skip sensitivity、predicted cancellation point を記録する。High/Critical 発見候補がある場合は実並列化しない。
- [ ] **Shadow-4:** Injection URL は URL priority order、origin_key、request_fingerprint、payload_fingerprint、budget decision を記録し、parallel candidate count と skipped/rejected count を比較する。
- [ ] **Differential-1:** 同一 task queue snapshot を forced serial と Phase 8 limited parallel で実行し、High/Critical finding set（severity + vuln type + canonical target + evidence key）を集合比較する。
- [ ] **Differential-2:** request count は serial baseline 比 1.2x 以下を初期上限とし、超過時は No-Go。
- [ ] **Differential-3:** execution_log / decision_traces / replay artifact で、serial と limited parallel の差分を `ordering_only`, `skipped`, `rejected`, `failed`, `finding_delta` に分類する。
- [ ] **Differential-4:** 429/403/406/timeout 注入時に protective degrade / budget reject / partial failure が観測でき、finding 欠落として扱われない。

### 7.11 Phase順序再レビュー
- [ ] **Phase 0-4 -> Phase 8:** 妥当。specialist分類、metadata、origin/lane/mutex shadow が Phase 8 の入力になる。
- [ ] **Phase 5 -> Phase 8:** 妥当。ただし Phase 5 が未完または kill switch / serial fallback が壊れている場合、Phase 8 は開始しない。
- [ ] **Phase 6 -> Phase 8:** 妥当。Phase 8 の partial failure / post-join feedback / report 表示は Phase 6 の decision trace と lifecycle 表現に依存する。
- [ ] **Phase 7 -> Phase 8:** 妥当。Phase 7 は risky lane を gated serial / reject / suppress に置き、Phase 8 は inner parallelism を read_only/rate_limited に限定して評価する。Phase 7 D-4 の mutating/aggressive mutex 本番配線は Phase 8 で評価対象だが、default 有効化は Phase 9 送り。
- [ ] **Phase 8 -> Phase 9:** 妥当。Phase 8 は candidate 評価と limited execution の parity 証明まで。promotion/demotion、default flag、operator runbook、恒久 telemetry は Phase 9。
- [ ] **結論:** Phase順序は壊れていない。Step 0 は pre-flight 独立 patch、SwarmManager specialist は shadow-only、limited execution は read_only/stateless と Injection per-url sub-result に限定する方針で固定済みのため、Phase 8 は実装 Ready。
