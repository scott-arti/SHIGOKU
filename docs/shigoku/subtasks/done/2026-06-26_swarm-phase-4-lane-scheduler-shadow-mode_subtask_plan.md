---
task_id: SGK-2026-0313
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0291
related_docs:
- docs/shigoku/subtasks/done/2026-06-23_sgk-2026-0291_swarm-parallelism-review_subtask_plan.md
- docs/shigoku/subtasks/2026-06-27_sgk-2026-0313_phase4-implementation-instruction_manual.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-0_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-1-additive-execution-contract-debug-metadata_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-2-scope-admission-per-origin-budget-policy_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-3-dispatch-context-isolation-swarm-pool_subtask_plan.md
- docs/shigoku/reports/2026-06-26_sgk-2026-0309_work_report.md
title: 'Swarm並列化 Phase 4: Lane Scheduler shadow mode'
created_at: '2026-06-26'
updated_at: '2026-06-30'
tags:
- shigoku
target: LanePolicy, MutexPolicy, SchedulingDecision, MasterConductor task dequeue
---

# 実装計画書：Swarm並列化 Phase 4: Lane Scheduler shadow mode

## 1. 達成したいゴール（ユーザー視点）
- [ ] 実行順序を変えずに、各taskのlane / mutex / admission / budget判断をshadow記録できること。
- [ ] `read_only`、`stateful_read`、`mutating`、`aggressive_exclusive` の分類根拠をreason code付きで説明できること。
- [ ] Phase 5の限定並列化へ進む前に、分類ミスを観測できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `LanePolicy`（新規候補）: task/specialist/lane分類。
  - `MutexPolicy`（新規候補）: target/session/mutation surfaceの排他key判定。
  - `SchedulingDecision`（新規候補）: shadow decisionの記録形式。
  - `src/core/engine/master_conductor.py`: dequeue前後のshadow decision接続候補。
  - session/debug event保存箇所: shadow decisionの監査出力。
- **データの流れ / 依存関係:**
  - Task metadata -> LanePolicy -> MutexPolicy -> SchedulingDecision -> serial executor（実行順は変更しない） -> session/debug audit。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** Task metadata、specialist分類、target/session/origin、auth context version、mutation surface、admission/budget decision。
- **出力/結果 (Output):** lane、mutex_key、would_wait、would_reject、reason_code、shadow_only flag。
- **制約・ルール:**
  - 本フェーズでは実スケジュールを変更しない。
  - `mutating` / `aggressive_exclusive` はshadow decisionのみで実並列化しない。
  - mutex key は `origin_key + session_key + auth_context_version + mutation surface` を基準にする。
  - decisionはreplay/debug可能な形でsessionまたはdebug bundleに残す。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `LanePolicy` / `MutexPolicy` / `SchedulingDecision` の最小schemaを定義する。
- [ ] ステップ2: specialist / task分類表をPhase 0成果物から取り込み、default unknownは安全側へ倒す。
- [ ] ステップ3: MasterConductorのdequeue前後でshadow decisionを計算し、実行順序はserial/既存のまま維持する。
- [ ] ステップ4: session/debug auditにlane、mutex_key、reason_code、shadow_onlyを出力する。
- [ ] ステップ5: lane classification、mutex key normalization、shadow decision snapshotのテストを追加する。
- [ ] ステップ6: Phase 5 Go条件として、shadow decisionが全taskに付いていることを確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] 分類ミスがPhase 5で事故につながる - unknownはparallel_safeにせずsequential_requiredへ倒す。
- [ ] [重要度:中] shadow decisionが多すぎてログが読みにくい - 通常ログは要約、debug bundleは詳細に分ける。
- [ ] [重要度:中] mutex keyが粗いと不要に直列化される - 初期は安全側に倒し、実測後に緩める。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0313-D01
    title: "継続監視: lane / mutex shadow decision の分類精度"
    reason: "初期分類は保守的であり、実測に基づく昇格/降格が必要"
    impact: medium
    tracking_task_id: SGK-2026-0313
    recommended_next_action: "Phase 5前にshadow decisionのサンプルをレビューし、read_only候補だけを解禁する"
```

---

## 6. 実装前レビュー結果（2026-06-27）

### 6.1 Phase要約（コード根拠ベース）
- **目的:** 実行順序を変えずに各 task の lane / mutex / admission / budget 判断を shadow 記録し、Phase 5 の限定並列化へ進む前に分類の妥当性を観測可能にする。
- **Non-Goals:** 実スケジュール変更・実 mutex 取得（Phase 5/7）、pool 再利用復活（Phase 5）、SwarmDispatcher/SwarmManager 内側並列化（Phase 8）、protective degrade mode（Phase 7）、TaskState enum 変更（Phase 1 deferred 済み）。
- **前提条件（実コードで確認済み）:**
  - Phase 2 成果物実在: `src/core/engine/admission_policy.py:46`（`ActionAdmissionPolicy`）/ `src/core/engine/budget_policy.py:43`（`ExecutionBudgetPolicy`）/ `src/core/engine/origin_normalizer.py:21`（`normalize_origin_key`）/ `src/core/config/settings.py:247-259`（`ParallelismSettings`, `shadow_mode=True` あり）/ `src/core/engine/adaptive_rate_limiter.py:20`（`BlockingSignalEvent`）。
  - Phase 0 分類表実在: `src/core/agents/swarm/phase0/concurrency_map.yaml:509-678`（22 specialist を parallel_safe/rate_limited/stateful/aggressive_exclusive 等に分類、分類規則 L909-961）。
  - Phase 1 metadata 実在: `Task.metadata`（`src/core/domain/model/task.py:93`）に origin_key/session_key/auth_context_version/canonical_endpoint_key を保持（契約 field 集合 `tests/core/domain/model/test_task_execution_contract_metadata.py:448-463`）。
  - Phase 3（per-dispatch instance）は独立して done。Phase 4 は実行順を変えないため Phase 3 未完でも shadow 記録可能だが、既に done。
- **完了条件:** serial 実行結果（findings・実行順・request 数）を一切変えずに、全 task へ lane / mutex / admission / budget の shadow decision が reason code 付きで付与され、再現可能な形で既存 session payload sink へ永続化されること。

### 6.2 Ready / Not Ready
- **判定（2026-06-27 更新）: Ready（Conditional）— 4 件の Local Blocker をすべて Phase 4 内部の設計決定で解消済み（他 Phase のコード・計画書は未変更）。解決設計は 6.3 / 6.3.1。**
- 本来の核心リスクは **LB-1（分類語彙の不整合）** だった。Phase 0 specialist 分類（parallel_safe/sequential_required/rate_limited/stateful/aggressive_exclusive/unknown）、Phase 4 lane（read_only/stateful_read/mutating/aggressive_exclusive）、Phase 2 `CATEGORY_TO_LANE`（read_only/mutating のみ生成）の 3 語彙が整合せず、かつ Phase 2 は unknown → read_only へ倒れる（並列化に対し危険側）。これを 6.3.1 の `PHASE0_CLASS_TO_LANE` 対応表と直交軸分離（`parallel_safe`/`rate_limited`）で解決し、unknown は安全側（`sequential_required`）へ倒した。
- 前提 Phase 成果物は実コードで確認済み（6.1 参照）。`Task.metadata` に origin_key/session_key/auth_context_version あり。`auth_context_version` は `src/core/agents/swarm/auth/reauth_contracts.py:76` に concrete model がある。
- 解決の最小性（他 Phase 影響ゼロ）: LB-1 は新規 `LanePolicy` モジュール内の対応表で解決（Phase 2 `CATEGORY_TO_LANE` は serial 互換として未変更）。LB-2 は既存 `decision_traces` sink へ固定。LB-3 は mutation_surface enum 追加。LB-4 は SchedulingDecision の safe-by-construction。いずれも Phase 2/3/5/7 のコード・計画書を変更しない。Phase 5 が読む `read_only`+`parallel_safe` は本設計が生成するため Phase 5 計画書の編集も不要。実装時は TDD を厳守し T-0.1（shadow off baseline 固定）を最初に置くこと。
- 残リスク（実装中に No-Go に戻す条件）: shadow 計算が実行順・findings・request 数に副作用を持つ、または Phase 0 で stateful/aggressive_exclusive の specialist が read_only に分類される回帰が見つかった場合は実装を止めて再評価する。

### 6.3 Local Blocker（すべて Phase 4 内部設計で解決済み・他 Phase コード変更不要）
- [x] **LB-1: specialist 分類 → lane の対応表が未定義 → 解決（6.3.1）。** Phase 4 専用の新規 `LanePolicy` モジュールに `PHASE0_CLASS_TO_LANE` 対応表を実装し、`concurrency_map.yaml`（Phase 0 成果物）を読み込んで権威分類する。Phase 2 の `CATEGORY_TO_LANE`（`parallel_orchestrator.py:39-46`）は serial 互換 auto-inference として**未変更**。直交軸は `lane` / `parallel_safe` / `rate_limited` の 3 field に分離し、unknown は安全側（`sequential_required`, `parallel_safe=false`）へ倒す。
- [x] **LB-2: shadow decision の永続化先 → 解決。** sink を既存 `build_async_session_payload(decision_traces=...)`（`master_conductor_session_service.py:82-84,141-142`, None-safe 接続済み）に固定。あわせて `RunLedgerEvent.DECISION_MADE`（`run_ledger.py:45`, 定義済み未使用）を emit し Phase 4 が最初の消費者となる。**debug bundle には依存しない。**
- [x] **LB-3: `mutation_surface` 未定義 → 解決。** Section 4 step1 schema で値域 `{path, query, body, header, cookie, unknown}` を定義。shadow は既定値 `unknown` で記録（正確な導出は Phase 7 D-1）。mutex_key は `unknown` を含めて構成する。
- [x] **LB-4: SchedulingDecision の秘密情報境界 → 解決（safe-by-construction）。** `build_async_session_payload` の `decision_traces` は deep-copy のみで `_sanitize` 対象外（`master_conductor_session_service.py:141-142` 実コード確認）。よって SchedulingDecision は**構造的に秘密を含まない**（6.3.1 schema 参照: lane/parallel_safe/rate_limited/reason_code/mutex_key(hash)/mutation_surface(enum)/would_wait/would_reject/shadow_only/origin_key(正規化済)/auth_context_version(int) のみ）。cookie/token/header 実値は持たない。T-3.5 で「秘密 field が存在しないこと」を固定。

### 6.3.1 解決設計: 分類対応表と SchedulingDecision schema（Phase 4 内部完結）
**`PHASE0_CLASS_TO_LANE` 対応表（`LanePolicy` が `concurrency_map.yaml` を読んで適用）:**

| Phase 0 class | lane | parallel_safe | rate_limited | reason_code |
|---|---|---|---|---|
| `parallel_safe` | `read_only` | true | false | `class_parallel_safe` |
| `rate_limited` | `read_only` | true | true | `class_rate_limited_budget_required` |
| `stateful` | `stateful_read` | false | false | `class_stateful_session_order` |
| `aggressive_exclusive` | `aggressive_exclusive` | false | false | `class_aggressive_exclusive` |
| `sequential_required` | `sequential_required` | false | false | `class_sequential_required` |
| `unknown` / 欠落 | `sequential_required` | false | false | `unclassified_safety_default` |

- **lane 値域（5種・元の4種に安全 bucket を add）:** `read_only` / `stateful_read` / `mutating` / `aggressive_exclusive` / `sequential_required`（安全 bucket・未分類と順序依存を収容）。Phase 5 は `read_only` かつ `parallel_safe=true` のみ抽出、Phase 7 は `stateful_read`/`mutating`/`aggressive_exclusive` を扱うため、`sequential_required` はどちらにも消費されず安全（Phase 5/7 計画書の変更不要）。
- **直交軸の分離（核心）:** `parallel_safe`（並列安全性＝共有状態なし・順序依存なし）と `rate_limited`（流量制御要否）は別軸。`rate_limited` specialist は read-only 性質（`parallel_safe=true`）だが流量制御要（`rate_limited=true`）。誤って `parallel_safe=false` にすると Phase 5 で過剰直列化されるため、この分離が分類ミス事故の主要な防止策。流量そのものは Phase 2 の per-origin budget が処理（第三-party API rate は Phase 5 で別途観測: D-2/D-4）。
- **SchedulingDecision schema（秘密を含まない構造）:** `lane: str`, `parallel_safe: bool`, `rate_limited: bool`, `reason_code: str`, `mutex_key: str`（`normalize_origin_key + session_key + auth_context_version + mutation_surface` の hash・実 URL/header 非含）, `mutation_surface: str`, `would_wait: bool`, `would_reject: bool`, `shadow_only: bool = True`, `origin_key: str`（正規化済）, `auth_context_version: int`。cookie/token/header 実値は**一切持たない**。
- **Phase 2 decision の再利用:** admission / budget の reject/allow 判定は Phase 2 の `ActionAdmissionPolicy`/`ExecutionBudgetPolicy` の既存 decision を再計算せず再利用（二重判定排除: T-4.1）。**lane は Phase 2 category ではなく Phase 0 specialist 分類から LanePolicy が計算する（6.3.2 権威ソース）。**

### 6.3.2 実装構造の固定（粒度・権威ソース・mutating扱い）
- **粒度（Swarm level shadow）:** 分類ソース（`specialist_classification`）は specialist 名単位だが、MasterConductor dequeue 時点では `task.agent_type → Swarm` までしか分からず、どの specialist が走るか未確定（BaseManagerAgent 系は LLM が specialist を動的選択）。よって Phase 4 shadow decision は **Swarm 粒度（coarse）** とする: Swarm の lane = その Swarm に属する specialist の中最も制約の強い分類から導出（強さ順: `read_only` < `rate_limited` < `stateful` < `aggressive_exclusive` < `sequential_required`/`unknown`）。swarm→specialist 所属が解決できない場合は安全側 `sequential_required`。per-specialist 精緻化は Phase 8 内側並列化評価時へ deferred（D-6）。
- **権威ソース（Phase 0 specialist 分類が Phase 2 category より優先）:** Phase 2 `CATEGORY_TO_LANE` は `attack_auth`/`attack_inject` → `mutating` とするが、Phase 0 はこれらの specialist を `rate_limited`（read-only 性質）に分類する。**Phase 4 shadow は Phase 0 specialist 分類を権威 lane とし、Phase 2 category lane は `compat_lane` として併記**し、両者が不一致なら `lane_disagreement=true` flag を記録する（T-1.5）。Phase 5 は Phase 4 権威 lane（`read_only`+`parallel_safe`）を読む。injection 系は read-only 候補として観測されるが、state mutation リスクは Phase 5 Go 前の個別レビューで確認する（shadow の観測価値）。
- **mutating lane の取り扱い:** Phase 0 の 6 class には `mutating` がなく、FileUploadSpecialist 等の mutating 操作は `aggressive_exclusive` に畳まれている。よって Phase 4 shadow が `mutating` lane を生成することはなく、これらは `aggressive_exclusive` で記録される。`mutating` と `aggressive_exclusive` の厳密な切り分け（state assertion 要否 vs low-noise profile 要否）は Phase 7 へ deferred（D-7）。Phase 5 の安全性は影響しない（いずれも read_only ではないため並列対象外）。
- **unknown の取り扱い:** LanePolicy は inventory の `classification_rules` 中 `unknown.default_treatment` を尊重し、ハードコードしないこと（実装時に同欄が sequential_required 系を指示していることを確認する）。

### 6.4 TDDチェックリスト
- [ ] **T-0.1: `test_shadow_off_baseline`** — shadow decision 計算を無効化した状態の MC 実行結果（findings/実行順/request 数）を characterization として固定。コード変更前に追加し、変更後も shadow off で同一であることを回帰で使う。
- [ ] **T-1.1: `test_specialist_class_to_lane_mapping`** — Phase 0 class（parallel_safe/rate_limited/stateful/aggressive_exclusive/unknown）→ Phase 4 lane の対応表を固定（LB-1 の成果物）。
- [ ] **T-1.2: `test_unknown_defaults_sequential_required`** — 未知 specialist / metadata 欠落 task は lane=`sequential_required` で記録され、`read_only` にならない（Phase 2 の `CATEGORY_TO_LANE` default との差分を shadow が正す）。
- [ ] **T-1.3: `test_lane_decision_reason_code_required`** — 全 lane decision に空でない reason_code が付く。
- [ ] **T-1.4: `test_lane_classification_deterministic`** — 同一入力（specialist + metadata）は同一 lane（replay 可能）。
- [ ] **T-1.5: `test_phase2_category_vs_phase0_specialist_disagreement_flagged`** — `attack_inject` task で Phase2 compat_lane=`mutating` / Phase0 権威 lane=`read_only`+`rate_limited` の不一致が `lane_disagreement=true` で記録される（6.3.2 権威ソース）。
- [ ] **T-1.6: `test_swarm_level_lane_most_restrictive`** — Swarm 内に read_only と stateful が混在する場合、Swarm lane は制約の強い側（stateful）になる（6.3.2 粒度）。
- [ ] **T-2.1: `test_mutex_key_composition`** — mutex_key = `normalize_origin_key` + session_key + auth_context_version + mutation_surface の順序付き結合で決定的。
- [ ] **T-2.2: `test_mutex_key_auth_version_isolation`** — auth_context_version が異なれば mutex_key が異なる（reauth 分離）。
- [ ] **T-2.3: `test_mutation_surface_unknown_recorded`** — mutation_surface 未導出時は `unknown` で記録され crash しない（LB-3）。
- [ ] **T-2.4: `test_session_key_absent_coarse_key`** — session_key 欠落時は coarse な key になることを記録（観測）。
- [ ] **T-3.1: `test_shadow_decision_coverage`** — 1 run の全 task に SchedulingDecision が付く（coverage 100%）。
- [ ] **T-3.2: `test_shadow_on_off_finding_parity`** — shadow on/off で findings・実行順・request 数が完全一致（副作用ゼロ）。
- [ ] **T-3.3: `test_shadow_decision_state_isolated`** — shadow MutexPolicy/BudgetPolicy の状態が実 executor へ逆流しない（観測専用）。
- [ ] **T-3.4: `test_shadow_decision_persisted_to_session`** — SchedulingDecision が `decision_traces`（`build_async_session_payload`）へ永続化され、`RunLedgerEvent.DECISION_MADE` も emit される（LB-2 解決）。
- [ ] **T-3.5: `test_shadow_decision_redacts_secrets`** — snapshot に cookie/token/header 実値が含まれない（LB-4）。
- [ ] **T-4.1: `test_phase2_admission_budget_reuse`** — shadow decision が Phase 2 の `ActionAdmissionPolicy`/`ExecutionBudgetPolicy` の decision を再計算せず再利用（二重判定の排除）。
- [ ] **T-4.2: `test_phase1_metadata_regression`** — Phase 1 metadata serialization / session reader / report reader が壊れない。

### 6.5 Go/No-Go Gate
- [ ] **Go:** 1 run の全 task に lane + reason_code 付き SchedulingDecision が付く（T-3.1, T-1.3）。
- [ ] **Go:** unknown / metadata 欠落 task は `sequential_required` で記録され `read_only` にならない（T-1.2）。`PHASE0_CLASS_TO_LANE` 対応表が実装済みで、`rate_limited` は `read_only`+`parallel_safe=true`+`rate_limited=true` に分類される（T-1.1, LB-1 解決）。
- [ ] **Go:** Phase 2 category lane と Phase 0 権威 lane の不一致が `lane_disagreement` flag で記録される（injection 系の mutating vs read_only 衝突を観測可能: T-1.5, 6.3.2）。
- [ ] **Go:** shadow on/off で findings・実行順・request 数が完全一致（T-3.2）。
- [ ] **Go:** SchedulingDecision が `decision_traces` sink へ永続化され、`DECISION_MADE` event も emit される。かつ safe-by-construction で秘密 field が存在しない（T-3.4, T-3.5, LB-2/LB-4 解決）。
- [ ] **Go:** shadow decision が Phase 2 の admission/budget decision を再利用し二重判定しない（T-4.1）。
- [ ] **Go:** Phase 1 回帰全 PASS（T-4.2）、`python3 scripts/sync_shigoku_updated_at.py` 後に `python3 scripts/validate_shigoku_docs.py` が 0 エラー。
- [ ] **No-Go（未該当確認）:** shadow 計算が実行順・findings・request 数を変える（T-3.2 fail）。
- [ ] **No-Go（未該当確認）:** Phase 0 で stateful / aggressive_exclusive の specialist が read_only lane に分類される（分類回帰: T-1.1/T-1.2 fail）。
- [ ] **No-Go（未該当確認）:** SchedulingDecision に秘密情報が漏れる（T-3.5 fail）。
- [ ] **No-Go（未該当確認）:** SchedulingDecision の永続化先が未実装の debug bundle に依存する（LB-2 解決済み・debug bundle 不使用）。

### 6.6 Shadow / Differential Testing
- [ ] **S-1: shadow on/off differential** — 同一 task queue snapshot で findings/実行順/request 数が完全一致する。
- [ ] **S-2: classification replay determinism** — seed/task queue snapshot 固定で shadow decision が再現可能。
- [ ] **S-3: would_wait/would_reject 非消費検証** — shadow MutexPolicy/BudgetPolicy が実 mutex/実 budget を消費しない。serial 実行では lock contention は概ね空のため、shadow の主眼は分類・admission・budget の妥当性と mutex key 構造の検証である（mutex contention の実観測は Phase 5+ へ deferred: D-4）。
- [ ] **S-4: classification source-of-truth differential** — Phase 0 `concurrency_map.yaml` を読み込んだ結果と、本 Phase の対応表が一致する（分類表の drift 検出）。

### 6.7 Local Deferred（後続Phaseへ送る）
| # | 項目 | Deferred先 | 安全な理由 | 検出方法 |
|---|---|---|---|---|
| D-1 | mutation_surface の正確な導出・propagation（specialist ごとの表面特定） | Phase 7 (SGK-2026-0316) | Phase 4 は値域定義と `unknown` 記録のみ。serial 実行で mutation 衝突は起きない | Phase 7 で state mutation assertion / mutation surface test |
| D-2 | Task→ParallelTask 変換での origin_key/target_key/lane/scope_verdict 伝播（`master_conductor.py:5778-5781`） | Phase 5 (SGK-2026-0314) | Phase 4 shadow は Task.metadata から直接読むため ParallelTask wiring 不要 | Phase 5 で origin budget / parity test |
| D-3 | `ParallelismSettings.kill_switch` field の追加 | Phase 5 (SGK-2026-0314) | Phase 4 は shadow_mode + enabled=false で十分。実並列化しないので kill switch 不要 | Phase 5 rollback / kill switch test（PCR-2 経由で親へも反映提案） |
| D-4 | mutex contention の実観測（同時 dispatch での待機・排他） | Phase 5+ (SGK-2026-0314/0316) | serial shadow では lock contention は概ね空。shadow は分類・admission・budget 妥当性と mutex key 構造の検証が主眼 | Phase 5/7 で mutex contention simulation / reauth 競合 test |
| D-5 | session_key の正規化・検証 | Phase 7 (SGK-2026-0316) | Phase 4 は free-form metadata をそのまま記録。serial で衝突しない | Phase 7 で mutex contention / session 競合 test |
| D-6 | per-specialist 精緻化（Swarm 粒度→specialist 粒度の shadow decision） | Phase 8 (SGK-2026-0317) | Phase 4 は Swarm 粒度の coarse shadow で十分（Phase 5 は task/swarm 単位で判定）。specialist 個別の並列安全性は内側並列化評価時に必要 | Phase 8 で specialist parity / partial failure aggregation test |
| D-7 | `mutating` と `aggressive_exclusive` の厳密切り分け（state assertion vs low-noise profile） | Phase 7 (SGK-2026-0316) | Phase 0 が両者を `aggressive_exclusive` に畳んでおり、Phase 4 shadow は観測のみ。Phase 5 はいずれも read_only ではなく並列対象外なので安全 | Phase 7 で state mutation assertion / aggressive lane suppress test |

### 6.8 Parent Change Request（親計画へ反映提案・本Phaseでは適用しない）
- [ ] **PCR-1: Lane 語彙契約の正本化（親計画 4.1 へ反映提案）。※LB-1 は Phase 4 内部の `PHASE0_CLASS_TO_LANE`（6.3.1）で解決済み。本 PCR は Phase 2 `CATEGORY_TO_LANE` との二重管理解消・直交軸の親レベル正規化として残存。** Phase 0 specialist 分類（parallel_safe/sequential_required/rate_limited/stateful/aggressive_exclusive/unknown）、Phase 4 lane（read_only/stateful_read/mutating/aggressive_exclusive）、Phase 2 `CATEGORY_TO_LANE`（read_only/mutating）の 3 語彙を、(a) 直交軸の分離（mutation safety / statefulness / rate-limit / exclusivity は別軸）、(b) Phase 0 class → Phase 4 lane の公式対応表、(c) 安全側 default（unknown → sequential_required）として親計画へ集約すべき。Phase 2/4/5/7 共通。現状 `CATEGORY_TO_LANE.get(category,"read_only")`（`parallel_orchestrator.py:39-46,301-344`）は unknown を read_only に倒し並列化に危険。
- [ ] **PCR-2: `kill_switch` field（親計画 4.1/4.4 へ反映提案）。** 親計画 4.4 Go 条件と 4.1 が「kill switch」を参照するが、`ParallelismSettings`（`settings.py:247-259`）に kill_switch field がない（enabled/shadow_mode のみ）。Phase 5/7/9 rollback に影響。
- [ ] **PCR-3: decision 永続化 sink の正規化（親計画 4.3/4.4 へ反映提案）。** scheduling/admission/budget decision の単一 canonical sink を定義（`decision_traces` vs `RunLedgerEvent.DECISION_MADE` vs `TaskExecutionRecord.metadata`）。各 Phase 計画書が「debug bundle」を参照するが未実装（grep zero hit）。Phase 2/4/6/9 共通。

### 6.9 Out of Scope（本Phaseでは実装しない）
- [ ] 実スケジュール変更・実並列実行（Phase 5）
- [ ] 実 mutex 取得・lock contention 強制（Phase 5/7）
- [ ] pool 再利用復活（Phase 5）
- [ ] SwarmDispatcher / SwarmManager 内側並列化（Phase 8）
- [ ] protective degrade mode 回路遮断（Phase 7）
- [ ] mutation_surface の正確な specialist ごと導出（Phase 7: D-1）
- [ ] TaskState enum 変更（Phase 1 で deferred 済み）
- [ ] 外部依存ライブラリの追加

### 6.10 Phase順序再レビュー
- **Phase 0 → Phase 1 → Phase 2 → Phase 3:** ✅ 全 done。Phase 4 の入力（分類表・metadata・admission/budget）は実コードで存在確認済み。
- **Phase 2 → Phase 4:** ✅ Phase 4 shadow は Phase 2 の `AdmissionDecision`（`admission_policy.py:26-31`）/`BudgetDecision`（`budget_policy.py:20-25`）/`origin_key` に依存し、実コードで存在。順序正当。
- **Phase 3 → Phase 4:** ✅ Phase 3（per-dispatch instance）は Phase 4 と独立。Phase 4 は実行順を変えないため Phase 3 未完でも shadow 記録可能だが、Phase 3 は既に done。
- **Phase 4 → Phase 5:** ✅✅ Phase 5 は Phase 4 shadow decision から `read_only` 候補だけを抽出する**硬依存**（Phase 5 plan step1）。**LB-1（分類対応表）未解決のまま Phase 4 を出すと、Phase 5 で分類ミスが事故化する。** これが Phase 4 を Not Ready とする主因。
- **結論:** Phase 順序は壊れていない。実際の依存関係にも適合している。ただし LB-1 は Phase 5 Go を直接脅かすため、Phase 4 実装前に必ず解消すること。
