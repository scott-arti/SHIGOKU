---
task_id: SGK-2026-0286
doc_type: subtask_plan
doc_usage: execution_plan
status: done
parent_task_id: SGK-2026-0264
related_docs:
- docs/shigoku/plans/2026-06-05_master-conductor-split-plan_plan.md
- docs/shigoku/reports/2026-06-12_sgk-2026-0282_masterconductor-policy-hitl-dispatch_work_report.md
- docs/shigoku/subtasks/2026-06-12_sgk-2026-0284_mc-policy-hitl-followup_subtask_plan.md
- docs/shigoku/subtasks/2026-06-12_sgk-2026-0285_mc-dispatch-extraction_subtask_plan.md
- docs/shigoku/reports/2026-06-13_sgk-2026-0286_work_report.md
title: 'MasterConductor 大幅行数削減計画: execution loop・dispatch・HITL の三段階抽出'
created_at: '2026-06-12'
updated_at: '2026-06-13'
tags:
- shigoku
target: src/core/engine/master_conductor.py
---

# 実装計画書：MasterConductor 大幅行数削減計画: execution loop・dispatch・HITL の三段階抽出

## 1. 達成したいゴール（ユーザー視点）
- [ ] `src/core/engine/master_conductor.py` の現行 6278 行を、公開挙動と既存テスト互換を保ったまま段階的に 5000 行前後まで圧縮できる実行計画になっていること。
- [ ] 既存の follow-up backlog である `SGK-2026-0284` と `SGK-2026-0285` をばらばらに消化せず、最大削減効果のある `execution loop` を加えた一体計画として進められること。
- [ ] `MasterConductor` の役割を `state owner + orchestration facade + thin wrapper` に寄せ、branch-heavy な実装本体を service / helper へ移す順序が明確であること。
- [ ] `_dispatch`、`_execute_single_task_full_flow`、`execute_with_replan`、`_run_intervention_precheck` のような高リスク中核を、character tests と副作用境界を先に固定してから安全に外出しできること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: （修正）shared state owner。最終的に facade と thin wrapper を主責務とする。
  - `src/core/engine/master_conductor_dispatch_service.py`: （修正）scope fast path に加え、worker / swarm / recon / recipe / agent fallback branch の抽出先とする。
  - `src/core/engine/master_conductor_hitl_precheck_service.py`: （修正）`PrecheckDecision` ベースで intervention / manual defer / pending HITL の mutation plan を返す境界として育てる。
  - `src/core/engine/master_conductor_execution_runner_service.py`: （新規候補）`execute_with_replan` と `_execute_single_task_full_flow` のうち、前処理・dispatch 呼び出し・後処理・失敗時再計画のうち pure / plan 化できる部分を切り出す。
  - `src/core/engine/master_conductor_summary_service.py`: （新規候補）`_generate_summary()` の failure aggregation / percentile / coverage assembly を pure function 化する。
  - `src/core/engine/master_conductor_parallel.py`: （既存候補）`execute_parallel()` の重複先。重複解消または正式接続のどちらかに統一する。
  - `src/core/engine/master_conductor_dependencies.py`: （修正候補）dispatch / execution runner / summary の依存束ね dataclass を追加する。
  - `tests/core/engine/test_master_conductor_intervention_gate.py`: HITL precheck / manual defer / notification の主 character tests。
  - `tests/core/engine/test_master_conductor_hitl_pending.py`: pending HITL ticket lifecycle の主 tests。
  - `tests/core/engine/test_master_conductor_scope_fast_path.py`: dispatch fast path の回帰固定。
  - `tests/core/engine/test_worker_integration.py`: worker route / fallback の回帰固定。
  - `tests/core/engine/test_master_conductor_recon_nonblocking.py`: recon branch の isolated loop / nonblocking 契約の回帰固定。
  - `tests/core/engine/test_mc_intelligence_integration.py`: `_execute_single_task_full_flow` と `execute_with_replan` の主回帰固定。
  - `tests/core/engine/test_master_conductor_failure_reason_codes.py`: summary の failure aggregation 回帰固定。
  - `tests/core/engine/test_master_conductor_vuln_family_gate.py`: coverage / summary integration 回帰固定。
- **データの流れ / 依存関係:**
  - CLI / API / scheduler -> `MasterConductor` facade -> service helper (`dispatch`, `hitl`, `execution_runner`, `summary`) -> facade が `task_queue`, `execution_log`, `pending_hitl`, `phase_gate`, `context` に最終反映
  - `execute_with_replan` -> task selection / batch strategy -> `_execute_single_task_full_flow` -> `_run_intervention_precheck` -> `_dispatch` -> result normalization -> replan / checkpoint / summary
  - `_dispatch` -> scope fast path / post-exploit guard / CTF filter / worker / swarm / recon / recipe / AgentFactory fallback -> cookie/header reset -> normalized result dict
  - summary path -> completed tasks + execution records + coverage evaluators + pending HITL -> summary dict -> report / logger / caller

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `Task`, `TaskExecutionRecord`, `ExecutionContext`, `pending_hitl`, `task_queue`, `execution_log`, `settings`, `network_client`, `project_manager`, `phase_gate`
- **出力/結果 (Output):** 既存互換の `dict` result、`Optional[dict]` precheck result、summary dict、replan task list、pending HITL mutation plan
- **制約・ルール:**
  - `MasterConductor` の既存 method 名と import path は維持する。抽出後も facade wrapper は残し、既存 direct call / monkeypatch / `MasterConductor.__new__(MasterConductor)` ベースのテストを壊さない。
  - `task_queue`, `context`, `phase_gate`, `pending_hitl`, `_state_lock`, `execution_log`, `audit_logger`, `event_bus`, `project_manager` の所有者は facade に残す。service は最終 mutation を持たない。
  - service は `MasterConductor` instance を保持しない。必要な依存は snapshot、明示引数、callable、または `master_conductor_dependencies.py` の dataclass で受け取る。
  - `_ensure_global_*_guard_task` 系の global guard 注入と queue ownership は本タスクでは facade に残す。service 側へ移す場合は、別 slice と専用 parity tests を先に用意する。
  - callable 依存が 1 関数あたり 5 個を超える場合は input dataclass を作る。未使用 field の追加は禁止する。
  - `src/core/engine/master_conductor/` のような同名パッケージ化は行わない。既存 `src.core.engine.master_conductor` import 互換を優先する。
  - cookie、auth header、token、session secret は tests / logs / audit details / plan examples に出さない。
  - `_dispatch` 抽出前に contextvar reset を全 exit path で検証する character tests を必須とする。
  - `package-lock.json` の既存 dirty diff は本タスクと無関係なので触らない。

## 3.1 現行 baseline と削減目標
- `src/core/engine/master_conductor.py`: 6278 行
- 主な残存大物:
  - `execute_with_replan`: 303 行
  - `_execute_single_task_full_flow`: 406 行
  - `_dispatch`: 561 行
  - `_run_intervention_precheck`: 171 行
  - `_notify_scn07_12_intervention`: 65 行
  - `check_hitl_required`: 48 行
  - `request_human_approval`: 19 行
  - `execute_parallel`: 85 行
  - `_generate_summary`: 96 行

| Slice | 主対象 | gross 行数 | facade 純減目安 | リスク | 判断 |
|---|---|---:|---:|---|---|
| A | `_dispatch` branch 抽出 | 約561 | 約400-480 | 高 | 大物。character tests を先に揃えれば高い削減効果がある。 |
| B | `execute_with_replan` + `_execute_single_task_full_flow` | 約709 | 約550-620 | 高 | 最大候補。dispatch/HITL 境界固定後に着手する。 |
| C | HITL / intervention 残部 | 約303 | 約230-280 | 中 | service 下地があるため、execution loop 前の安全化 slice として有効。 |
| D | summary / parallel | 約181-197 | 約140-170 | 低-中 | 効果は小さめだが最後の仕上げに向く。 |

### 3.1.1 この計画の数値目標
- **Primary target:** facade 純減 1100-1350 行
- **Expected landing zone:** `master_conductor.py` を 6278 → 4928-5178 行へ圧縮
- **Stretch target:** wrapper inventory で安全な重複 wrapper をさらに整理し、 4900 行未満を狙う
- **Non-goal:** 1 回の slice で god service を作ること。大幅削減は「大きな 1 ファイルを、複数の小さな god service に置き換えない」条件付きでのみ成功とみなす

## 3.2 推奨順序
1. **Slice C: HITL / intervention 残部を先に閉じる**
   - 理由: `PrecheckDecision` が既にあり、execution loop の前提を安全に固めやすい。
2. **Slice A: `_dispatch` を branch 単位で抽出する**
   - 理由: gross 削減量が大きく、execution loop から一段内側の境界を先に安定化できる。
3. **Slice B: execution loop を execution runner service へ分解する**
   - 理由: dispatch と HITL の境界固定後なら、`_execute_single_task_full_flow` を plan/apply 構造へ落とし込みやすい。
4. **Slice D: summary / parallel / wrapper inventory を仕上げる**
   - 理由: 主幹抽出後に残る cross-cutting 集成と重複を安全に掃除できる。

## 3.3 既存 tracking task との関係
- `SGK-2026-0284`: HITL / summary / parallel / parity / compat inventory の backlog。`0286` では Slice C と Slice D の実行計画として吸収する。
- `SGK-2026-0285`: `_dispatch` 本体抽出の backlog。`0286` では Slice A の実行計画として吸収する。
- `SGK-2026-0286`: 上記に加えて execution loop 抽出を明示し、残存大物をまとめて sequencing する primary active plan とする。

## 3.4 Service Decomposition Guardrails
- `master_conductor_execution_runner_service.py` は新しい god service にしない。`preparation plan`, `dispatch invocation`, `result apply plan`, `failure replan policy` の責務境界を明示し、4 種類以上の state mutation を 1 service に集約しない。
- `_execute_single_task_full_flow` の抽出は、event payload builder / metadata builder / result normalizer / apply decision helper のような小さい helper から始める。`task_queue`, `execution_log`, `pending_hitl`, `_state_lock` への final mutation は facade 側でのみ実行する。
- `_dispatch` の recon branch 抽出前に `ReconExecutionDependencies` または adapter を追加し、抽出先 service から `ReconPipeline(master_conductor=self)` を直接作らない。facade 参照が必要な既存経路は adapter で隔離する。
- `master_conductor_summary_service.py` は pure aggregation を主責務とし、warning log emit や audit/event emission は facade に残す。

## 3.5 Non-Negotiable Behavior Matrix
| 領域 | 維持する挙動 | 固定方法 |
|---|---|---|
| HITL pending | pending ticket lifecycle、manual defer、execution_log 追加、`_state_lock` 下 mutation を維持する。 | HITL 3-layer parity tests と exception-path tests で固定する。 |
| dispatch routing | `scope fast path -> post-exploit guard -> CTF filter -> worker -> swarm -> cartographer -> fingerprinter -> recon -> recipe -> AgentFactory fallback` の順序と duplicate recon skip を維持する。 | routing order matrix と branch return schema matrix を作る。 |
| dispatch cleanup | cookie/header contextvar reset、resource close、workspace save の exit path を維持する。 | success / error / TypeError fallback / unsupported agent / ImportError / recon error で cleanup tests を追加する。 |
| lifecycle events | `TASK_STARTED`, `TASK_COMPLETED`, `TASK_FAILED` の payload shape と emission timing を維持する。 | event payload parity tests で `task_id`, correlation, failure reason/category を確認する。 |
| global guards | global guard 注入、injection batch timeout、checkpoint cadence を維持する。 | baseline metrics と execution loop character tests で固定し、service 側 mutation を禁止する。 |
| summary/report | pending HITL count、failure aggregation、unknown rate、percentile、coverage gate assembly を維持する。 | summary fixture と real artifact または serialized execution_log fixture で検証する。 |
| compatibility | public/private method 名、戻り値 shape、`MasterConductor.__new__(MasterConductor)` 直呼びテスト互換を維持する。 | compat wrapper inventory と wrapper parity tests で固定する。 |

## 4. 実装ステップ（AIに指示する手順）
- [ ] Step 1: baseline を固定する。`wc -l src/core/engine/master_conductor.py`、主要 method の AST 行数、`git status --short --branch`、`rg` による外部参照箇所に加え、batch timeout path、checkpoint cadence、pending_hitl_count、summary p95/p99 相当の測定方法を記録し、`package-lock.json` は非対象であることを明示する。
- [ ] Step 2: compat wrapper inventory と Non-Negotiable Behavior Matrix を更新する。`_dispatch`、`execute_with_replan`、`_execute_single_task_full_flow`、`_run_intervention_precheck`、`_generate_summary`、`execute_parallel` を `external reference / tests only / facade-only` に分類し、削除禁止 wrapper と public behavior を先に確定する。
- [ ] Step 3: dependency / ownership matrix を作る。`task_queue`, `execution_log`, `pending_hitl`, `_state_lock`, `event_bus`, `audit_logger`, `_ensure_global_*_guard_task` の所有者を facade として固定し、service 側へ渡せる snapshot / callable / dataclass 依存を列挙する。
- [ ] Step 4: HITL precheck の 3-layer parity tests を先に追加する。service parity、facade wrapper parity、side-effect parity に分けて `intervention_gate`, `hitl_pending`, `hitl_priority` を増強し、callback crash、pending HITL without exec_record、denied/manual defer、deterministic `time.time` / `uuid.uuid4` fixture を固定する。
- [ ] Step 5: `master_conductor_hitl_precheck_service.py` を拡張し、`evaluate_precheck_decision()` を中心に `_run_intervention_precheck` の decision tree を service 側へ寄せる。facade は `task.state`, `task.error`, `execution_log`, `pending_hitl` への最終反映だけを担う。
- [ ] Step 6: `_notify_scn07_12_intervention`, `check_hitl_required`, `request_human_approval` の副作用境界を整理する。message line builder / hitl info builder は service、notifier callback と fail-closed は facade に残す。
- [ ] Step 7: dispatch の routing order matrix と return schema matrix tests を追加する。対象は `scope fast path -> post-exploit guard -> CTF filter -> worker -> swarm -> cartographer -> fingerprinter -> recon -> recipe -> AgentFactory fallback` で、branch ごとの required keys / optional keys / error keys を snapshot 化する。
- [ ] Step 8: cookie/header contextvar reset tests と recon cleanup tests を追加する。成功・エラー・TypeError fallback・unsupported agent・ImportError・recon error・duplicate recon skip の各 exit path で reset、dangling thread なし、unclosed event loop なしを固定する。
- [ ] Step 9: `ReconExecutionDependencies` または adapter を導入する。dispatch service から `ReconPipeline(master_conductor=self)` を直接生成しないようにし、既存 facade 参照が必要な recon path は adapter 境界へ隔離する。
- [ ] Step 10: `master_conductor_dispatch_service.py` を branch 単位で拡張する。まず `recon_master`、次に `recipe`, `AgentFactory` fallback tail、その後 `worker/swarm/direct tools` を移し、1 patch 1 branch group を原則とする。
- [ ] Step 11: `_dispatch` facade wrapper を薄くする。service が返す normalized result / cleanup plan を受けて、context update・workspace save・resource close・contextvar reset の最終適用を facade に残す。
- [ ] Step 12: execution loop の character tests を追加する。`_execute_single_task_full_flow` と `execute_with_replan` について、intervention precheck、risk predictor block、dispatch success/failure、replan、checkpoint、summary 呼び出し、flaky quarantine、`TASK_STARTED` / `TASK_COMPLETED` / `TASK_FAILED` payload、batch timeout sequential recovery、dispatch exception を fixture 化する。
- [ ] Step 13: `master_conductor_execution_runner_service.py` を新設する。`preparation plan`, `dispatch invocation`, `result apply plan`, `failure replan policy` の責務境界を守り、event payload builder、metadata builder、result normalizer、decision helper の小単位から切り出す。
- [ ] Step 14: `_execute_single_task_full_flow` を段階移行する。event payload builder、exec_record metadata 構築、result normalization、success/failure branch 内の decision helper を service 化し、最終 state mutation と queue mutation は facade に残す。
- [ ] Step 15: `execute_with_replan` を段階移行する。queue selection、parallel injection batch 判定、checkpoint cadence、summary invocation のうち facade から外せる部分を execution runner / helper へ寄せ、global guard 注入と injection batch timeout の ownership は facade 側に維持する。
- [ ] Step 16: `_generate_summary` を `master_conductor_summary_service.py` へ切り出す。failure reason aggregation、unknown rate、percentile、coverage gate assembly を pure function 化し、warning log emit だけ facade に残す。real execution artifact または serialized execution_log fixture で report-facing fields を検証し、tests-only / tests+artifact の別を work_report に書く。
- [ ] Step 17: `execute_parallel` の重複を整理する。`master_conductor_parallel.py` を再利用するか削除前提で統合するかを確定し、重複実装を 1 つに統一する。
- [ ] Step 18: targeted syntax / unit / integration を実行する。失敗した場合は次の slice へ進まず、どの branch/service で parity が崩れたかを修正する。
- [ ] Step 19: Slice Exit Gates を確認し、続行 / 分割 / defer を判定する。Slice C 完了、Slice A 完了、Slice B 着手前、Slice D 着手前の節目で、削減行数・parity・未解決リスクを work_log に残す。
- [ ] Step 20: broad related tests、`graphify update .`、`python3 scripts/sync_shigoku_updated_at.py`、`python3 scripts/validate_shigoku_docs.py` を実行し、削減行数、validation coverage、residual risk を work_report / work_log に残す。

## 4.1 検証コマンド
baseline / syntax:
```bash
wc -l src/core/engine/master_conductor.py

.venv/bin/python -m py_compile \
  src/core/engine/master_conductor.py \
  src/core/engine/master_conductor_dispatch_service.py \
  src/core/engine/master_conductor_hitl_precheck_service.py \
  src/core/engine/master_conductor_execution_runner_service.py \
  src/core/engine/master_conductor_summary_service.py
```

HITL targeted:
```bash
.venv/bin/pytest -q \
  tests/core/engine/test_master_conductor_intervention_gate.py \
  tests/core/engine/test_master_conductor_hitl_pending.py \
  tests/core/engine/test_master_conductor_hitl_priority.py \
  tests/core/engine/test_master_conductor_bugfix.py
```

dispatch targeted:
```bash
.venv/bin/pytest -q \
  tests/core/engine/test_master_conductor_scope_fast_path.py \
  tests/core/engine/test_worker_integration.py \
  tests/core/engine/test_master_conductor_recon_nonblocking.py \
  tests/core/engine/test_mc_injection_parallel_dispatch.py
```

execution loop / summary targeted:
```bash
.venv/bin/pytest -q \
  tests/core/engine/test_mc_intelligence_integration.py \
  tests/core/engine/test_integration_mc_context_designer.py \
  tests/core/engine/test_mc_strategic_upgrade.py \
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
- [ ] `master_conductor.py` が 6278 行から少なくとも 1100 行以上純減し、概ね 5000 行前後まで下がる。
- [ ] `_dispatch`, `execute_with_replan`, `_execute_single_task_full_flow`, `_run_intervention_precheck` の public/private method 名と戻り値 shape が維持される。
- [ ] service が `MasterConductor` instance を保持しない。
- [ ] service から `master_conductor.py` への import が 0 件である。
- [ ] cookie/header contextvar reset が `_dispatch` の全 exit path で確認される。
- [ ] `task_queue`, `execution_log`, `pending_hitl`, `_state_lock`, `audit_logger`, `event_bus` への final mutation が facade に残る。
- [ ] Non-Negotiable Behavior Matrix の全項目が tests / fixtures / work_report evidence のいずれかで確認される。
- [ ] `TASK_STARTED`, `TASK_COMPLETED`, `TASK_FAILED` の event payload parity が確認される。
- [ ] recon branch の error / duplicate skip path で dangling thread と unclosed event loop がないことを確認する。
- [ ] summary / report-facing fields の検証が tests-only か tests+artifact か work_report に明記される。
- [ ] Slice Exit Gates の stop/go 判定と defer 判断が work_log に残る。
- [ ] targeted tests が全通過する。
- [ ] broad related tests が全通過するか、未実行理由と代替確認が work_report に残る。
- [ ] `graphify update .` と SHIGOKU docs validation が通る。

## 4.3 Slice Exit Gates
- **Gate C complete:** HITL 3-layer parity、exception path、pending HITL lifecycle、facade final mutation が通るまで Slice A に進まない。
- **Gate A complete:** dispatch routing order、return schema、contextvar reset、recon cleanup、adapter boundary が通るまで Slice B に進まない。
- **Gate B start:** execution runner service の responsibility boundary と global guard ownership を再確認し、`master_conductor_execution_runner_service.py` が god service 化していないことを確認してから移行する。
- **Gate D start:** Slice A+C の純減が 800 行以上、または Slice B の risk が高すぎる場合は D を先に実施して安全に削減量を積み増す。
- **Gate final:** 1100 行以上の純減、targeted/broad validation、docs validation、work_report / work_log 反映を揃えて完了判定する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。

### 5.1 SRE / インフラエンジニア視点
- [ ] 【発生確率：高】【影響度：大】`_dispatch` 抽出で cookie/header contextvar reset が漏れ、認証状態が後続 task にリークする。
  - 対策: Step 7-11 に routing order matrix、return schema matrix、全 exit path reset tests を組み込み、service では reset plan を返すだけに留める。
- [ ] 【発生確率：中】【影響度：大】task lifecycle event parity が崩れ、`TASK_STARTED` / `TASK_COMPLETED` / `TASK_FAILED` の監視・監査 payload が欠落する。
  - 対策: Step 12 と完了条件に event payload parity を追加し、`task_id`, correlation, failure reason/category を success / failure / pending HITL で確認する。
- [ ] 【発生確率：中】【影響度：大】runtime baseline が行数中心になり、batch timeout、checkpoint cadence、summary 集計の性能劣化を見逃す。
  - 対策: Step 1 に batch timeout path、checkpoint cadence、pending_hitl_count、summary p95/p99 相当の baseline 記録を追加し、work_report に before/after を残す。
- [ ] 【発生確率：中】【影響度：大】recon branch の thread / event loop cleanup が検証されず、長時間実行で dangling thread や unclosed loop が残る。
  - 対策: Step 8 と完了条件に recon error / duplicate skip path の dangling thread なし、unclosed event loop なしの tests を追加する。
- [ ] 【発生確率：中】【影響度：大】HITL precheck の service 化で `_state_lock` 外 mutation が混入し、pending HITL と execution log の整合性が壊れる。
  - 対策: Step 4-6 で `PrecheckDecision` は mutation plan のみ返し、facade が lock 下で final apply する設計を固定する。

### 5.2 ソフトウェアアーキテクト視点
- [ ] 【発生確率：高】【影響度：大】`master_conductor_execution_runner_service.py` や `dispatch_service.py` が新しい god service になる。
  - 対策: `## 3.4 Service Decomposition Guardrails` と Step 13 に responsibility boundary を追加し、`preparation plan`, `dispatch invocation`, `result apply plan`, `failure replan policy` を混在させない。
- [ ] 【発生確率：中】【影響度：大】global guard 注入の ownership が曖昧になり、queue mutation が service に漏れる。
  - 対策: `## 3` の制約と Step 3 / Step 15 に `_ensure_global_*_guard_task` は facade 所有と明記し、service 移行は別 slice + 専用 tests を条件にする。
- [ ] 【発生確率：中】【影響度：大】`ReconPipeline(master_conductor=self)` が抽出先 service に残り、facade 参照禁止ルールと矛盾する。
  - 対策: `## 3.4` と Step 9 に `ReconExecutionDependencies` / adapter 導入を追加し、dispatch service から `master_conductor=self` を直接渡さない。
- [ ] 【発生確率：中】【影響度：大】callable 依存が増えすぎて facade の再実装になる。
  - 対策: Step 3 で dependency / ownership matrix を作り、callable > 5 で dataclass 化し、field ごとに利用箇所と代表テストを明示する。
- [ ] 【発生確率：中】【影響度：中】`master_conductor_parallel.py` の扱いが曖昧なまま並列処理だけ二重実装で残る。
  - 対策: Step 17 で reuse か削除かを明示的に決め、work_report に最終判断を残す。

### 5.3 デバッガー視点
- [ ] 【発生確率：高】【影響度：大】branch-heavy な `_dispatch` をまとめて移すと、どの branch で回帰したか切り分けづらい。
  - 対策: Step 10 を `recon -> recipe/fallback tail -> worker/swarm/direct tools` の branch group 単位に分け、1 patch 1 branch group を守る。
- [ ] 【発生確率：高】【影響度：大】`_dispatch` の return schema matrix が不足し、branch ごとの戻り値 shape 回帰を検出できない。
  - 対策: Step 7 に required keys / optional keys / error keys の snapshot 化を追加し、service 移行前に branch return schema を固定する。
- [ ] 【発生確率：中】【影響度：大】exception-path matrix が薄く、callback crash、pending HITL without exec_record、batch timeout recovery、dispatch exception の原因切り分けが困難になる。
  - 対策: Step 4 と Step 12 に HITL / execution loop の exception-path tests を追加し、Slice Gate C/A/B で次段階へ進む条件にする。
- [ ] 【発生確率：中】【影響度：中】time / uuid / thread state の非決定性により、抽出後の flake が原因不明になる。
  - 対策: Step 4 / Step 8 / Step 12 に `time.time`, `uuid.uuid4`, thread enumeration の patch / freeze fixture を追加する。
- [ ] 【発生確率：中】【影響度：中】`__new__` ベースの軽量 test conductor で AttributeError が出る。
  - 対策: Step 2 に compat wrapper inventory を追加し、wrapper は `getattr` default で欠損属性を扱い、dedicated wrapper parity tests を追加する。

### 5.4 CTO視点
- [ ] 【発生確率：高】【影響度：大】「大幅削減」が行数目標だけに寄り、変更容易性や検証可能性の改善が測れない。
  - 対策: 完了条件に、削減行数に加えて `service->facade import 0`, `final mutation in facade`, `targeted/broad tests`, `contextvar reset coverage`, Non-Negotiable Behavior Matrix の検証を必須化する。
- [ ] 【発生確率：高】【影響度：大】slice stop/go criteria が弱く、高リスク slice に入りすぎて中途半端な service が残る。
  - 対策: `## 4.3 Slice Exit Gates` と Step 19 を追加し、Slice C/A/B/D の節目で続行 / 分割 / defer を判定する。
- [ ] 【発生確率：中】【影響度：大】非交渉の public behavior matrix がないまま進み、互換性を壊しても行数削減で見逃す。
  - 対策: `## 3.5 Non-Negotiable Behavior Matrix` と Step 2 を追加し、pending HITL、recon duplicate skip、global guard、summary fields、`__new__` direct-call compatibility を固定する。
- [ ] 【発生確率：中】【影響度：大】summary / report artifact validation が不足し、unit test は通るが実運用 report-facing fields が崩れる。
  - 対策: Step 16 と完了条件に real artifact または serialized execution_log fixture による検証を追加し、tests-only / tests+artifact の別を work_report に明記する。
- [ ] 【発生確率：中】【影響度：大】既存 backlog `0284/0285` と新計画 `0286` が競合し、どれが正本か分からなくなる。
  - 対策: `0286` を primary active plan、`0284/0285` を related backlog / scope reference として明示し、完了時の work_report でもこの関係を固定する。

### 5.5 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0286-D01
    title: "継続監視: dispatch/execution loop 抽出後の residual branch parity"
    reason: "実装スコープは完了したが、長時間実行と branch edge case の継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
