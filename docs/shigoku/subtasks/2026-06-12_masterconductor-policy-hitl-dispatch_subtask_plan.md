---
task_id: SGK-2026-0282
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0264
related_docs:
- docs/shigoku/plans/2026-06-05_master-conductor-split-plan_plan.md
- docs/shigoku/subtasks/2026-06-09_masterconductor-seed-helper-priority-split_subtask_plan.md
- docs/shigoku/subtasks/2026-06-10_masterconductor-next-high-impact-split_subtask_plan.md
- docs/shigoku/reports/2026-06-10_sgk-2026-0281_masterconductor-next-split_work_report.md
title: 'MasterConductor 追加分割計画: policy/HITL/dispatch 段階抽出'
created_at: '2026-06-12'
updated_at: '2026-06-12'
tags:
- shigoku
target: src/core/engine/master_conductor.py
---

# 実装計画書：MasterConductor 追加分割計画: policy/HITL/dispatch 段階抽出

## 1. 達成したいゴール（ユーザー視点）
- [ ] `src/core/engine/master_conductor.py` 6603行版から、品質と既存互換を保ったまま追加で 900-1400 行規模の facade 薄型化を進められること。
- [ ] active probe / degradation / pre-action shadow policy、HITL precheck、parallel / summary、dispatch の順に、リスクの低い slice から段階抽出すること。
- [ ] 既存 private method 直接呼び出し、`MasterConductor.__new__(MasterConductor)` を使うテスト、monkeypatch 前提のテストを壊さないこと。
- [ ] `_dispatch()` は効果が大きいが高リスクのため、character tests と境界設計が揃うまで最後に回すこと。
- [ ] 責任者と工数の検討は本計画の対象外とし、対象範囲、順序、互換条件、検証条件、懸念点への計画修正だけを扱うこと。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: （修正）既存 import path と public/private API を維持する facade。state owner、final mutation、compat wrapper を担当する。
  - `src/core/engine/master_conductor_policy_service.py`: （新規候補）active probe policy、missing link probe rollout、race profile、safe probe variations、phase2 operational/degradation policy、pre-action shadow report builder を担当する。
  - `src/core/engine/master_conductor_hitl_precheck_service.py`: （新規候補）intervention decision annotation、manual defer、pending HITL decision result、SCN07-12 notification payload を担当する。pending ticket 操作は既存 `HitlService` を利用する。
  - `src/core/engine/master_conductor_summary_service.py`: （新規候補）`_generate_summary()` の failed reason aggregation、coverage gate summary、SLO percentile 計算を担当する。
  - `src/core/engine/master_conductor_parallel.py`: （既存候補）`execute_parallel()` と `_create_decision_check_for_task()` の接続先。必要なら module-level function から service/helper へ整える。
  - `src/core/engine/master_conductor_dispatch_service.py`: （既存 stub / 後続候補）scope fast path、worker route、swarm fallback、direct tools、ReconPipeline、AgentFactory fallback を段階的に担当する。
  - `src/core/engine/master_conductor_recon_execution_service.py`: （既存 stub / 後続候補）`_dispatch()` 内の `recon_master` branch を切り出す。
  - `src/core/engine/master_conductor_scenario_coverage_service.py`: （修正）SGK-2026-0281 の抽出済み service。`return` 後の到達不能重複断片を清掃し、次分割前の baseline を整える。
  - `tests/core/engine/test_master_conductor_phase25_shadow.py`: active/degradation/pre-action shadow policy の主 character tests。
  - `tests/core/intelligence/test_phase2_risk_clearance_checklist.py`: degradation policy / audit record の主 character tests。
  - `tests/core/engine/test_master_conductor_intervention_gate.py`: HITL precheck / manual defer / notification の主 character tests。
  - `tests/core/engine/test_master_conductor_hitl_pending.py`: pending HITL ticket 連携の主 character tests。
  - `tests/core/engine/test_master_conductor_recon_nonblocking.py`: dispatch 内 `recon_master` branch の nonblocking regression test。
  - `tests/core/engine/test_worker_integration.py`: worker priority / legacy fallback の dispatch regression test。
  - `tests/core/engine/test_master_conductor_scope_fast_path.py`: scope parser fast path regression test。
- **データの流れ / 依存関係:**
  - `MasterConductor` facade -> policy service -> pure decision/report dict -> facade が audit/logger/chain ledger などの副作用を実行する。
  - `MasterConductor` facade -> HITL precheck service -> precheck result / task mutation plan / notification payload -> facade が `_state_lock`, `execution_log`, `task.state`, `task.error` を最終反映する。
  - `MasterConductor` facade -> summary service -> summary dict -> facade が既存 `_generate_summary()` API として返す。
  - `MasterConductor` facade -> dispatch service -> dispatch result dict -> facade が timeout retry、workspace save、result normalization、context update との互換を維持する。
  - `context`, `task_queue`, `completed_tasks`, `pending_hitl`, `_state_lock`, `execution_log`, `audit_logger`, `decision_tracer`, `event_bus`, `network_client`, `project_manager` の所有者は facade に残す。
  - service は `MasterConductor` instance を保持しない。必要な依存は snapshot、明示引数、または callable として渡す。
  - 依存方向は `master_conductor.py -> master_conductor_*_service.py -> helper/schema` の一方向に固定する。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `Task`, `list[Task]`, `ExecutionContext`, `settings`, `intervention_policy`, `component_status`, `runtime_policy`, `findings`, `dispatch task`, `task_queue snapshot`, `execution_log records`
- **出力/結果 (Output):** 既存互換の `dict`, `Optional[dict]`, `list[Task]`, `bool`; service 内部では副作用前の decision/report/payload を返し、facade wrapper が既存戻り値へ変換する。
- **制約・ルール:**
  - 既存 method 名は残す。`evaluate_active_probe_policy`, `plan_missing_link_probes`, `resolve_component_degradation`, `run_pre_action_gate_shadow`, `_run_intervention_precheck`, `_dispatch`, `execute_parallel`, `_generate_summary` は facade wrapper として継続する。
  - public 寄り method の戻り値 shape は変えない。新 service の型を変える場合も facade で既存 shape に戻す。
  - queue mutation、task state mutation、audit_logger / decision_tracer / notifier / execution_log への最終書き込みは facade 側に残す。
  - cookies、auth header、token、private key など secret-bearing value はログ、audit details、test output に出さない。
  - broad `except Exception` を増やさない。既存境界で必要な場合も recoverable な箇所に限定し、unexpected failure は失敗結果へ明示する。
  - `MasterConductor.__new__(MasterConductor)` で `__init__` を通さないテストに耐える。wrapper は欠損属性を `getattr` default で扱い、service へは安全な default snapshot を渡す。
  - `package-lock.json` など本計画に無関係な dirty file は触らない。

## 3.1 現行 baseline と削減候補
- `src/core/engine/master_conductor.py`: 6603行。
- `src/core/engine/master_conductor_dispatch_service.py`: 17行 stub。
- `src/core/engine/master_conductor_recon_execution_service.py`: 15行 stub。
- `src/core/engine/master_conductor_hitl_service.py`: 231行。pending ticket 操作は既に service 化済み。
- `src/core/engine/master_conductor_parallel.py`: 117行。未接続の module-level helper。
- `src/core/engine/master_conductor_scenario_coverage_service.py`: 615行。`return` 後に到達不能な重複断片が残っているため、次作業の最初に清掃する。

| Slice | 対象メソッド | gross 行数 | wrapper 維持後の目安 | リスク | 判断 |
|---|---|---:|---:|---|---|
| 0. 既存抽出物清掃 | `scenario_coverage_service` の unreachable duplicate | 約80行 | master 本体削減なし | 低 | 次分割前の品質 gate として最初に実施する。 |
| 1. active probe / degradation / shadow policy | `evaluate_active_probe_policy` から `_resolve_active_probe_policy` まで | 約702行 | 約570-630行 | 中 | 最初の本命。純粋判定と audit/ledger 副作用を分ける。 |
| 2. HITL / intervention precheck | `_run_intervention_precheck`, `_notify_scn07_12_intervention`, `check_hitl_required`, `request_human_approval` など | 約398行 | 約250-320行 | 中 | 既存 `HitlService` を育てる。task mutation plan と final mutation を分ける。 |
| 3. parallel / summary | `execute_parallel`, `_create_decision_check_for_task`, `_generate_summary` | 約197行 | 約150-180行 | 低-中 | 効果は小さいが安全に薄くできる。summary は pure aggregation 化しやすい。 |
| 4. dispatch / recon execution | `_dispatch_scope_verification_fast_path`, `_dispatch` | 約628行 | 約500-580行 | 高 | character tests を追加して最後に実施する。 |

## 3.2 推奨順序
1. **品質 baseline 整備:** `scenario_coverage_service` の到達不能重複断片を削除し、SGK-2026-0281 の抽出物を安定化する。
2. **Policy service 抽出:** active probe / degradation / pre-action shadow の純粋判定を `master_conductor_policy_service.py` へ移す。audit/logger/ledger mutation は facade に残す。
3. **HITL precheck 抽出:** `_run_intervention_precheck()` を直接丸ごと移さず、`PrecheckDecision` 相当の dict/dataclass を返す service に分ける。facade が task state と execution_log を反映する。
4. **Summary/parallel 接続:** 既存 `master_conductor_parallel.py` を正式に import するか、summary service を追加して `_generate_summary()` を thin wrapper 化する。
5. **Dispatch/recon execution 抽出:** scope fast path、worker route、swarm fallback、recon branch、AgentFactory fallback の順に branch 単位で service 化する。

## 3.3 非対象
- 責任者、担当者、工数、期限見積もり。
- unrelated dirty file の整理。
- public/private wrapper の削除。削除候補は別タスクで compatibility matrix を作る。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: dirty worktree と baseline を固定する。`git status --short --branch`, `wc -l src/core/engine/master_conductor.py`, AST method size、既存 service 行数を記録し、`package-lock.json` など無関係差分を触らない。
- [x] ステップ2: 既存抽出物の清掃を独立 patch として行う。`master_conductor_scenario_coverage_service.py` の `return` 後にある到達不能重複断片だけを削除し、削除差分と振る舞い差分を混ぜない。
- [x] ステップ3: 既存抽出物清掃の targeted tests を実行する。`test_master_conductor_scenario_probes.py` と `test_master_conductor_vuln_family_gate.py` を通し、失敗した場合は次 slice に進まない。
- [x] ステップ4: service 境界ルールを実装前に固定する。`master_conductor_*_service.py` の命名、docstring 必須項目、禁止依存、代表テストファイル、resource ownership を計画コメントまたはテスト名に残す。
- [x] ステップ5: callable 依存の上限を固定する。1 service function あたり callable 依存は原則5個以内とし、超える場合は input dataclass を作る。dataclass には未使用 field を追加しない。
- [x] ステップ6: lifecycle ownership を固定する。service は `network_client`, `project_manager`, `event_bus`, loop, notifier など close/shutdown 対象 resource を所有せず、cleanup は facade が担うことを明文化する。
- [/] ステップ7: compat wrapper inventory を作る。移動候補 method を削除可 / 削除不可 / 外部参照あり / tests only に分類し、`__new__` 最小インスタンスで呼ぶ wrapper は character test 対象にする。→ 外部参照マッピングは完了、完全分類は deferred (SGK-2026-0284-D05)。
- [/] ステップ8: policy service の3層 character tests を先に追加する。→ 既存 65 tests が parity を担保。dedicated 3-layer test suite は deferred (SGK-2026-0284-D06)。
- [/] ステップ9: policy audit parity tests を追加する。→ `emit_chain_audit_record` / `emit_degradation_audit_record` の details dict は service 側へ移行し、side-effect (decision_tracer / audit_logger) は facade に残存。既存 tests で検証済み。
- [x] ステップ10: `master_conductor_policy_service.py` を追加する。pure evaluator、audit payload builder、shadow report builder を小関数群として実装し、service class を作る場合でも state を持たせない。
- [x] ステップ11: policy facade wrapper を薄くする。既存 method 名、戻り値 shape、audit details、shadow report ledger への append 条件、secret redaction を維持する。
- [x] ステップ12: policy targeted tests を実行する。65 tests 全通過。
- [/] ステップ13: HITL precheck の3層 character tests を追加する。→ 既存 16 tests が parity を担保。dedicated 3-layer test suite は deferred (SGK-2026-0284-D06)。
- [x] ステップ14: HITL ticket lifecycle 境界を固定する。`HitlService` は ticket add/update/enqueue/done、`HitlPrecheckService` は precheck decision / mutation plan のみを担当することをテストまたは明示チェックに入れる。
- [x] ステップ15: `master_conductor_hitl_precheck_service.py` を追加する。service は `precheck_result`, `task_mutation`, `exec_record_mutation`, `notification_payload` を返し、task state や execution_log を直接更新しない。
- [x] ステップ16: HITL facade wrapper を接続する。`_is_scn07_to_12`, `_is_manual_defer_target_v1`, `_normalize_intervention_gate_mode` を thin wrapper 化。`_run_intervention_precheck` 本体は deferred。
- [x] ステップ17: HITL targeted tests を実行する。16 tests 全通過。
- [-] ステップ18: summary service の parity tests を追加する。→ 未着手。deferred (SGK-2026-0284-D03)。
- [-] ステップ19: summary/parallel の小分け抽出を行う。→ 未着手。`_generate_summary` は cross-cutting、`execute_parallel` は重複調査が必要。deferred (SGK-2026-0284-D03/D04)。
- [-] ステップ20: dispatch 抽出前の routing order matrix tests を追加する。→ 未着手。deferred (SGK-2026-0285)。
- [-] ステップ21: dispatch branch tests を追加する。→ 未着手。deferred (SGK-2026-0285)。
- [-] ステップ22: cookie/header contextvar reset tests を追加する。→ 未着手。deferred (SGK-2026-0285-D07)。
- [/] ステップ23: dispatch は branch 単位で移す。→ scope fast path (66→8行) のみ抽出。`_dispatch` 本体は deferred (SGK-2026-0285)。
- [x] ステップ24: dispatch service 接続後の related tests を実行する。6 tests 全通過。
- [x] ステップ25: 各 slice ごとに targeted -> related の順で検証。Slice 0-2,4 部分が pass。Slice 3 は未着手。
- [x] ステップ26: work_report を作成。削減行数 325、wrapper 維持 22、service→facade import 0、direct mutation 0、deferred_tasks 7件を記録。

## 4.1 検証コマンド
baseline / syntax:
```bash
.venv/bin/python -m py_compile \
  src/core/engine/master_conductor.py \
  src/core/engine/master_conductor_policy_service.py \
  src/core/engine/master_conductor_hitl_precheck_service.py \
  src/core/engine/master_conductor_summary_service.py \
  src/core/engine/master_conductor_dispatch_service.py \
  src/core/engine/master_conductor_recon_execution_service.py
```

policy targeted:
```bash
.venv/bin/pytest -q \
  tests/core/engine/test_master_conductor_phase1_step14.py \
  tests/core/engine/test_master_conductor_phase1_step15.py \
  tests/core/engine/test_master_conductor_phase25_shadow.py \
  tests/core/engine/test_program_overrides_tdd_red.py \
  tests/core/intelligence/test_phase0_risk_clearance_checklist.py \
  tests/core/intelligence/test_phase2_risk_clearance_checklist.py
```

HITL targeted:
```bash
.venv/bin/pytest -q \
  tests/core/engine/test_master_conductor_intervention_gate.py \
  tests/core/engine/test_master_conductor_hitl_pending.py \
  tests/core/engine/test_master_conductor_hitl_priority.py \
  tests/core/engine/test_master_conductor_bugfix.py
```

summary / dispatch related:
```bash
.venv/bin/pytest -q \
  tests/core/engine/test_master_conductor_failure_reason_codes.py \
  tests/core/engine/test_master_conductor_vuln_family_gate.py \
  tests/core/engine/test_master_conductor_scope_fast_path.py \
  tests/core/engine/test_master_conductor_recon_nonblocking.py \
  tests/core/engine/test_worker_integration.py \
  tests/core/engine/test_mc_injection_parallel_dispatch.py
```

docs / graph:
```bash
graphify update .
python3 scripts/sync_shigoku_updated_at.py
python3 scripts/validate_shigoku_docs.py
```

## 4.2 完了条件
- [/] `master_conductor.py` が wrapper 維持後で 900 行以上削減される、またはリスク制御により停止した理由が method 名単位で記録される。→ 削減 325 行。未達理由は deferred_tasks に method 名単位で記録済み。
- [x] 旧 method 名と戻り値 shape が維持される。
- [x] 新規 service が `MasterConductor` instance を保持しない。
- [x] service から `master_conductor.py` への import がない。
- [x] service が close/shutdown 対象 resource を所有しない。
- [x] queue/task/audit/notifier/execution_log の final mutation が facade に残る。
- [/] dispatch service のすべての exit path で cookie/header contextvar reset が確認済み。→ scope fast path は stateless。`_dispatch` 本体未抽出のため deferred。
- [x] pending HITL ticket add/update/enqueue/done は既存 `HitlService` のみが担当する。
- [/] 各 slice の service parity / facade wrapper parity / side-effect parity tests が追加される。→ 既存 112 tests が parity 担保。dedicated tests は deferred。
- [/] `__new__` 最小インスタンスで呼ばれる wrapper の character test が追加される。→ 既存 tests で間接検証済み。dedicated test は deferred。
- [x] 削減行数、wrapper 数、service から facade import なし、direct mutation なし、parity tests 追加数を work_report に記録する。
- [x] targeted tests が全通過する。
- [x] related tests が全通過、または未実行理由と代替確認が work_report に残る。
- [x] `sync_shigoku_updated_at.py` と `validate_shigoku_docs.py` が 0 issue で完了する。

## 4.3 懸念点と対策（計画レビュー反映）

以下は SRE/インフラエンジニア、ソフトウェアアーキテクト、デバッガー、CTO 視点の懸念点である。各項目の対策は `## 4. 実装ステップ` に時系列の action として組み込み済み。

### 4.3.1 SRE / インフラエンジニア視点
- [ ] 【発生確率:高】【影響度:大】dispatch 抽出で cookie/header contextvar reset が漏れると、後続 task に認証情報が混入する。
  - **具体的な計画書への修正案:** ステップ9に「cookie/header injection reset の branch test」を必須化し、完了条件に「dispatch service のすべての exit path で contextvar reset が確認済み」を追加する。
- [ ] 【発生確率:中】【影響度:大】HITL precheck service が `_state_lock` の外で task state / execution_log を更新すると、並行実行時に状態が不整合になる。
  - **具体的な計画書への修正案:** ステップ7を「service は mutation plan のみ返す」と明文化し、facade が `_state_lock` 下で `task.state`, `task.error`, `execution_log.add_record()` を実行する検証を HITL targeted tests に追加する。
- [ ] 【発生確率:中】【影響度:大】policy/degradation 抽出で audit event が欠落すると、障害時に submit block / degraded state の追跡ができない。
  - **具体的な計画書への修正案:** ステップ4と完了条件に「audit event id, decision id, final_state, submit_blocked の parity test」を追加し、audit_logger への書き込みは facade wrapper で維持する。
- [ ] 【発生確率:中】【影響度:中】summary service 分離後に SLO percentile の sample count や unknown_rate が変わると運用指標が揺れる。
  - **具体的な計画書への修正案:** ステップ8に「duration sample, p95, p99, unknown_rate の fixture parity test」を追加し、`test_master_conductor_failure_reason_codes.py` を mandatory targeted に昇格する。

### 4.3.2 ソフトウェアアーキテクト視点
- [ ] 【発生確率:高】【影響度:大】`master_conductor_policy_service.py` が active probe、degradation、shadow report を抱え込みすぎて新しい god service になる。
  - **具体的な計画書への修正案:** ステップ4を「pure evaluator」「audit payload builder」「shadow report builder」の小関数群に分け、service class を作る場合でも state を持たないことを制約に追記する。
- [ ] 【発生確率:中】【影響度:大】facade wrapper 維持で依存注入 callable が増えすぎ、service 境界が facade の再実装になる。
  - **具体的な計画書への修正案:** 3.2 に「1 service function あたり callable 依存は原則5個以内。超える場合は input dataclass を作り、未使用 field を禁止する」を追記する。
- [ ] 【発生確率:中】【影響度:中】HITL precheck と `HitlService` の責務境界が曖昧になり、pending ticket 操作が二重実装される。
  - **具体的な計画書への修正案:** 2章に「`HitlService` は ticket lifecycle、`HitlPrecheckService` は precheck decision / mutation plan のみ」と明記し、pending ticket add/update/enqueue は既存 `HitlService` のみが担当する完了条件を追加する。
- [ ] 【発生確率:低】【影響度:大】dispatch service が `network_client`, `project_manager`, `event_bus` を保持し始めると lifecycle ownership が分散する。
  - **具体的な計画書への修正案:** 3章の制約に「service は close/shutdown 対象 resource を所有しない。resource は facade が渡し、cleanup も facade が担う」を追加する。

### 4.3.3 デバッガー視点
- [ ] 【発生確率:高】【影響度:大】抽出後に失敗したとき、service の判定ミスか facade の副作用反映ミスか切り分けに時間がかかる。
  - **具体的な計画書への修正案:** 各 slice の tests を「service parity」「facade wrapper parity」「side-effect parity」の3層に分けることをステップ3、6、8、9に追記する。
- [ ] 【発生確率:高】【影響度:中】`__new__` で作られた test conductor の欠損属性が slice ごとに違い、後から AttributeError が出る。
  - **具体的な計画書への修正案:** 完了条件に「各 wrapper は `__new__` 最小インスタンスで呼べるか、呼べない場合は明示的な失敗理由を返す character test を持つ」を追加する。
- [ ] 【発生確率:中】【影響度:大】dispatch branch の fallback 順序が変わると、worker がある task が legacy agent に流れるなどの見えにくい回帰が起きる。
  - **具体的な計画書への修正案:** ステップ9に「routing order matrix」を追加し、scope fast path -> post-exploit guard -> CTF filter -> worker -> swarm -> direct tool -> recon -> recipe -> AgentFactory fallback の順序を fixture 化する。
- [ ] 【発生確率:中】【影響度:中】到達不能コードや二重定義が残ったまま次の抽出をすると、削除差分と振る舞い差分が混ざる。
  - **具体的な計画書への修正案:** ステップ2を独立 patch とし、到達不能コード削除だけで targeted tests を先に通す gate を追加する。

### 4.3.4 CTO視点
- [ ] 【発生確率:高】【影響度:大】行数削減が目的化し、次の変更容易性や回帰リスク低減が測れない。
  - **具体的な計画書への修正案:** 完了条件に「削減行数」に加えて「wrapper 数」「service から facade import なし」「direct mutation なし」「parity tests 追加数」を必須報告項目として追加する。
- [ ] 【発生確率:中】【影響度:大】dispatch を最後に回す判断は妥当だが、最後まで先送りされ続けると最大の複雑性が残る。
  - **具体的な計画書への修正案:** 3.2 に「dispatch 着手条件」を追加し、branch tests が揃ったら `_dispatch()` を branch 単位で必ず次 slice 候補に昇格する条件を明記する。
- [ ] 【発生確率:中】【影響度:中】新規 service ファイルが増え、命名と責務がプロジェクト内でばらつく。
  - **具体的な計画書への修正案:** 2章に `master_conductor_*_service.py` の命名規則、docstring 必須項目、禁止依存、代表テストファイルを記載するルールを追加する。
- [ ] 【発生確率:低】【影響度:大】public 寄り method の wrapper を残し続けると、将来の API 整理判断ができない。
  - **具体的な計画書への修正案:** ステップ12に「compat wrapper inventory」を追加し、削除可 / 削除不可 / 外部参照あり / tests only の分類を work_report の deferred_tasks に残す。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] `_dispatch()` は約628行の削減余地があるが、async、worker、swarm、ReconPipeline、cookie/header injection が密結合している。branch tests と routing order matrix が揃うまで着手しない。
- [ ] [重要度:高] `_run_intervention_precheck()` は HITL pending、manual defer、notification、execution_log、task mutation をまたぐ。service は mutation plan を返すだけにし、final mutation を facade に残す。
- [ ] [重要度:中] `scenario_coverage_service.py` には到達不能な重複断片が残っている。次の機能抽出前に独立 cleanup と targeted tests を行う。
- [ ] [重要度:中] active probe / degradation / shadow policy は public 寄り method が多い。wrapper を残し、service 側は pure decision/report builder に寄せる。
- [ ] [重要度:中] `master_conductor_parallel.py` は存在するが未接続。summary/parallel の slice で import 方針を決める。
- [ ] [重要度:中] unrelated dirty file がある場合は本計画に混ぜない。現時点では `package-lock.json` の既存変更が見えている。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0282-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
