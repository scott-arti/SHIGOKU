---
task_id: SGK-2026-0313
doc_type: manual
status: active
parent_task_id: SGK-2026-0291
related_docs:
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-4-lane-scheduler-shadow-mode_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-23_sgk-2026-0291_swarm-parallelism-review_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-0_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-1-additive-execution-contract-debug-metadata_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-2-scope-admission-per-origin-budget-policy_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-3-dispatch-context-isolation-swarm-pool_subtask_plan.md
- docs/shigoku/reports/2026-06-26_sgk-2026-0309_work_report.md
title: 'SGK-2026-0313 Phase 4 実装指示書（Lane Scheduler shadow mode）'
created_at: '2026-06-27'
updated_at: '2026-06-30'
tags:
- shigoku
target: src/core/engine/lane_policy.py, src/core/engine/mutex_policy.py, src/core/engine/scheduling_decision.py,
  src/core/engine/master_conductor.py, src/core/engine/master_conductor_session_service.py
---

# 実装指示書: Phase 4 Lane Scheduler shadow mode（SGK-2026-0313）

> この文書は別エージェントが実装するための実行指示である。計画書 `2026-06-26_swarm-phase-4-lane-scheduler-shadow-mode_subtask_plan.md` Section 6（6.1〜6.10）と本指示書の両方を守ること。矛盾時は本指示書の「不変条件」と「設計固定事項」を優先し、即報告すること。

## 0. 一言でいうと
Phase 4 は **shadow mode（観測専用・実行順不改）** を実装する。各 task の lane / mutex / admission / budget 判断を記録するだけで、**実行を一切変えない**。製品を壊すことはないが、観測データの正確さが Phase 5（実並列化）の安全の前提になる。

## 1. 必読（この順）
1. 本指示書（全文）
2. 計画書 `docs/shigoku/subtasks/done/2026-06-26_swarm-phase-4-lane-scheduler-shadow-mode_subtask_plan.md` の Section 6（特に 6.3.1 対応表・6.3.2 実装構造）
3. `rules/codingrules.md`（品質・秘密情報・サブプロセス・async）
4. `rules/lessons.md`（[2026-06] secret 境界 CRITICAL、[2026-06] docs validation 厳格）
5. `AGENTS.md` §9（`.venv/bin/python` / `.venv/bin/pytest`）、§15（台帳ワークフロー）、§17（ルール動的ロード）

## 2. 不変条件（違反 = 即中止・報告）
- **実行順・findings・request 数を一切変えない。** shadow 計算は観測専用で、実 executor への逆流禁止。
- **変更禁止ファイル:** `src/core/engine/parallel_orchestrator.py` の `CATEGORY_TO_LANE`・`create_parallel_task`、`src/core/security/ethics_guard.py`・`enhanced_ethics_guard.py`、Phase 2/3/5/7/8/9 の計画書・コード、`TaskState` enum、既存 session/report schema field。
- **外部依存ライブラリを追加しない。**（PyYAML・pydantic は既存利用可）
- **秘密情報（cookie/token/header/API key/password 実値）を `SchedulingDecision`・`decision_traces`・`DECISION_MADE` event・ログのいずれにも書き込まない。**

## 3. 設計固定事項（計画書 6.3.1 / 6.3.2 から変更禁止）

### 3.1 `PHASE0_CLASS_TO_LANE` 対応表（`LanePolicy` に verbatim 実装）
| Phase 0 class | lane | parallel_safe | rate_limited | reason_code |
|---|---|---|---|---|
| `parallel_safe` | `read_only` | true | false | `class_parallel_safe` |
| `rate_limited` | `read_only` | true | true | `class_rate_limited_budget_required` |
| `stateful` | `stateful_read` | false | false | `class_stateful_session_order` |
| `aggressive_exclusive` | `aggressive_exclusive` | false | false | `class_aggressive_exclusive` |
| `sequential_required` | `sequential_required` | false | false | `class_sequential_required` |
| `unknown` / 欠落 | `sequential_required` | false | false | `unclassified_safety_default` |

- **lane 値域は5種:** `read_only` / `stateful_read` / `mutating` / `aggressive_exclusive` / `sequential_required`（`mutating` は Phase 4 shadow では生成されない: 6.3.2 参照）。
- **直交軸:** `parallel_safe`（並列安全性）と `rate_limited`（流量制御要否）は `lane` とは別 field。`rate_limited` specialist は `parallel_safe=true`（read-only 性質）＋ `rate_limited=true`。
- **権威ソース:** Phase 0 specialist 分類（`load_inventory()["specialist_classification"]`）が Phase 2 `CATEGORY_TO_LANE` より優先。Phase 2 category lane は `compat_lane` として併記し、不一致は `lane_disagreement: bool = True` を立てる。
- **粒度:** shadow decision は **Swarm 単位（coarse）**。Swarm lane = 所属 specialist の中最も制約の強い分類（強さ: `read_only` < `rate_limited` < `stateful` < `aggressive_exclusive` < `sequential_required`/`unknown`）。swarm→specialist 所属が解決できない Swarm は安全側 `sequential_required`。
- **unknown:** `load_inventory()["classification_rules"]` 中 `unknown.default_treatment` を尊重しハードコードしない（実装時に同欄が sequential_required 系を指示していることを確認。異なれば報告）。

### 3.2 `SchedulingDecision` schema（safe-by-construction・秘密 field なし）
```
lane: str                      # 5値のいずれか
parallel_safe: bool
rate_limited: bool
compat_lane: str | None        # Phase 2 CATEGORY_TO_LANE 由来（disagreement 比較用）
lane_disagreement: bool
reason_code: str               # 空文字禁止
mutex_key: str                 # hash(normalize_origin_key + session_key + auth_context_version + mutation_surface)
mutation_surface: str          # {path,query,body,header,cookie,unknown}・既定 unknown
would_wait: bool
would_reject: bool
shadow_only: bool = True       # Phase 4 では常に True
origin_key: str                # normalize_origin_key 済
auth_context_version: int
```
cookie/token/header 実値は**一切持たない**。`mutex_key` は hash 文字列のみ（実 URL/header 非含）。

### 3.3 永続化先（sink・変更不可）
- 主: `build_async_session_payload(decision_traces=[...])`（`src/core/engine/master_conductor_session_service.py:82-84,141-142`・None-safe 接続済み）。
- 副: `RunLedgerEvent.DECISION_MADE`（`src/core/models/run_ledger.py:45`・定義済み未使用→Phase 4 が最初の消費者）を emit。
- **`debug bundle` には依存しない**（未実装のため）。
- `decision_traces` は `copy.deepcopy` のみで `_sanitize` 対象外（`master_conductor_session_service.py:141-142` 実確認）。よって 3.2 の safe-by-construction が秘密防御の主で、追加 redaction は不要。

## 4. 作るもの（新規ファイル）
- `src/core/engine/scheduling_decision.py`
  - `MutationSurface` enum（`PATH|QUERY|BODY|HEADER|COOKIE|UNKNOWN`）
  - `SchedulingDecision` dataclass（3.2）
- `src/core/engine/lane_policy.py`
  - `PHASE0_CLASS_TO_LANE` 表（3.1）
  - `LanePolicy` クラス: `load_inventory()`（`src/core/agents/swarm/phase0/__init__.py:21`）を読み `specialist_classification` を取り込む。`classify(swarm_name, task_metadata) -> (lane, parallel_safe, rate_limited, compat_lane, lane_disagreement, reason_code)`。Swarm→specialist 所属の導出（8 Swarm・Phase 3 inventory 参照: BaseManagerAgent 継承=injection/auth/logic/discovery、plain SwarmManager 継承=secret/scanner/intelligence/fuzzing）。所属未解決は `sequential_required`。
- `src/core/engine/mutex_policy.py`
  - `MutexPolicy` クラス: `decide(task_metadata) -> (mutex_key, mutation_surface, would_wait, would_reject)`。`normalize_origin_key`（`src/core/engine/origin_normalizer.py:21`）を再利用。`mutation_surface` は Phase 4 では常に `UNKNOWN`（導出は Phase 7 D-1）。`would_wait`/`would_reject` は shadow 計算（実 mutex/budget は消費しない）。
- テスト（`tests/unit/engine/`）: `test_scheduling_decision.py`, `test_lane_policy.py`, `test_mutex_policy.py`, `test_shadow_decision_integration.py`

## 5. 修正するもの（最小・既存ファイル）
- `src/core/engine/master_conductor.py`: dequeue 〜 dispatch 経路に shadow decision 計算を接続。参考行: batch 生成 `5762-5781`、`_execute_single_task_full_flow` の hook（`5976` pre-dispatch / `6094` dispatch / `6114` post-result）。**Task.metadata から origin_key/session_key/auth_context_version を読む**（`src/core/domain/model/task.py:93`）。`shadow_only=True` で実行経路には影響させない。接続は `ParallelismSettings.shadow_mode`（`src/core/config/settings.py:247-259`）が True の時のみ有効。
- shadow decision を session 保存経路へ渡す: `build_async_session_payload` の呼び出し箇所で `decision_traces=[...]` を渡す（既存 None-safe）。

## 6. 実装順序（TDD 厳守・この順）
1. **T-0.1 `test_shadow_off_baseline`** — shadow 計算無効化状態の MC 実行結果（findings/実行順/request 数）を characterization として固定。**コード変更前に最初に置く。**
2. **★ T-1.1 + S-4（最初の硬ゲート）** — `PHASE0_CLASS_TO_LANE` と `load_inventory()["specialist_classification"]` の22 specialist を全件突合。全て6値に収まり、対応表が drift ないことを確認。**収まらなければ即 STOP（§7）。**
3. T-1.2 / T-1.3 / T-1.4 / T-1.5 / T-1.6（lane 分類・unknown 安全側・reason_code 必須・決定性・disagreement flag・Swarm 最制約導出）
4. T-2.1〜T-2.4（mutex_key 構成・auth_version 分離・mutation_surface=unknown 記録・session_key 欠落 coarse 観測）
5. T-3.1〜T-3.5（全 task coverage・**shadow on/off parity★**・状態非逆流・sink 永続化・秘密 field 非存在）
6. T-4.1 / T-4.2（Phase 2 admission/budget decision 再利用・Phase 1 回帰）

★ = 必須硬ゲート。失敗時は即中止。

## 7. STOP 条件（即中止・報告。継続しない）
- 22 specialist のいずれかが `PHASE0_CLASS_TO_LANE` に収まらない、または classification が6値外（T-1.1/S-4 fail）。
- 8 Swarm のいずれかで swarm→specialist 所属が解決できない（安易に default で継続せず報告）。
- **T-3.2 shadow on/off parity が失敗** = 実行に副作用あり（最重大）。
- 秘密情報が snapshot・永続化先・ログに漏れる（T-3.5 fail）。
- Phase 1/2 既存テストが壊れる（T-4.1/T-4.2 fail）。
- `unknown.default_treatment` が sequential_required 系でない（3.1）。

## 8. 変更禁止の再掲（事故防止）
- `parallel_orchestrator.py` の `CATEGORY_TO_LANE`・`create_parallel_task`（serial 互換 auto-inference として維持）
- `ethics_guard.py` / `enhanced_ethics_guard.py`
- Phase 2 の `admission_policy.py` / `budget_policy.py` / `origin_normalizer.py`（**再利用のみ・変更不可**）
- `TaskState` enum・既存 session/report schema field
- 他 Phase 計画書（Phase 0/1/2/3/5/6/7/8/9）
- 実行順を変えるいかなる変更

## 9. 検証コマンド（完了定義・全 PASS で完了）
```sh
# 新規テスト
.venv/bin/pytest tests/unit/engine/test_scheduling_decision.py tests/unit/engine/test_lane_policy.py tests/unit/engine/test_mutex_policy.py tests/unit/engine/test_shadow_decision_integration.py

# Phase 2 回帰（変更していないが念のため）
.venv/bin/pytest tests/unit/engine/test_admission_policy.py tests/unit/engine/test_budget_policy.py tests/unit/engine/test_origin_normalizer.py tests/unit/engine/test_parallel_orchestrator.py tests/unit/config/test_parallelism_settings.py

# Phase 1 回帰
.venv/bin/pytest tests/core/domain/model/test_task_execution_contract_metadata.py

# docs 検証
python3 scripts/sync_shigoku_updated_at.py && python3 scripts/validate_shigoku_docs.py
# → FRONT_MATTER_ISSUES=0 BROKEN_LINKS=0 REGISTRY_ISSUES=0 DEFERRED_LINK_ISSUES=0
```
※ shadow on/off parity（T-3.2）はテスト内で検証（手動比較ではない）。

## 10. Go/No-Go Gate（計画書 6.5 準拠・全 Go 成立で完了）
- 全 task に lane + reason_code 付き SchedulingDecision が付く（T-3.1/T-1.3）
- unknown は `sequential_required`（T-1.2）。`rate_limited` は `read_only`+`parallel_safe=true`+`rate_limited=true`（T-1.1）
- Phase 2 category と Phase 0 権威 lane の不一致が `lane_disagreement` で記録される（T-1.5）
- shadow on/off で findings・実行順・request 数が完全一致（T-3.2）
- `decision_traces` へ永続化・`DECISION_MADE` emit・秘密 field 非存在（T-3.4/T-3.5）
- Phase 2 admission/budget decision 再利用（T-4.1）・Phase 1 回帰 PASS（T-4.2）
- docs validate 0 エラー

## 11. 報告フォーマット（作業完了時・AGENTS.md §15 準拠）
1. 変更ファイル一覧・新規ファイル一覧（行数概算）
2. T-0.1〜T-4.2・S-1〜S-4 の各結果（PASS/FAIL・実行コマンド）
3. STOP 条件（§7）への抵触有無
4. 残リスク・気づき（特に injection 系 read_only 化の観測結果・disagreement 件数）
5. `docs/shigoku/reports/2026-06-XX_sgk-2026-0313_work_report.md` と `docs/shigoku/worklogs/2026-06-XX_sgk-2026-0313_work_log.md` を作成
6. 計画書の status を `done` にし `done/` へ移動（AGENTS.md §14/§15）。台帳 `task_registry.yaml` / `task_ledger.md` / `task_ledger.csv` 更新
7. 変更後に必ず `python3 scripts/sync_shigoku_updated_at.py` → `python3 scripts/validate_shigoku_docs.py` を実行し 0 エラーを確認

## 12. 実装しないこと（Out of Scope・計画書 6.9 準拠）
実スケジュール変更・実並列（Phase 5）/ 実 mutex 取得・lock contention（Phase 5/7）/ pool 再利用復活（Phase 5）/ SwarmDispatcher・SwarmManager 内側並列（Phase 8）/ protective degrade mode（Phase 7）/ mutation_surface の specialist 別導出（Phase 7 D-1）/ per-specialist 精緻化（Phase 8 D-6）/ `mutating` vs `aggressive_exclusive` 切り分け（Phase 7 D-7）/ TaskState enum 変更 / 外部依存追加
