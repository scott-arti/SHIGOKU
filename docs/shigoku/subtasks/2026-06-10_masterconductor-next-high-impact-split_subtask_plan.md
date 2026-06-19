---
task_id: SGK-2026-0281
doc_type: subtask_plan
doc_usage: execution_plan
status: done
parent_task_id: SGK-2026-0264
related_docs:
- docs/shigoku/plans/2026-06-05_master-conductor-split-plan_plan.md
- docs/shigoku/reports/2026-06-09_master-conductor-split_work_report.md
- docs/shigoku/subtasks/2026-06-09_masterconductor-seed-helper-priority-split_subtask_plan.md
title: 'MasterConductor 追加分割計画: scenario/global guard と実行ループ優先度整理'
created_at: '2026-06-10'
updated_at: '2026-06-11'
tags:
- shigoku
target: src/core/engine/master_conductor.py
---

# 実装計画書：MasterConductor 追加分割計画: scenario/global guard と実行ループ優先度整理

## 1. 達成したいゴール（ユーザー視点）
- [x] `src/core/engine/master_conductor.py` の次の分割対象を、現行 7,406 行版の実測に基づいて決められること。
- [x] 既に完了済みの seed/path helper 分割を重複して扱わず、次に外出し効果が高い領域へ進めること。
- [x] 行数削減だけでなく、既存 private method 呼び出し、`MasterConductor.__new__()` 利用テスト、queue / context / phase_gate 所有権を壊さないこと。
- [x] 実装順序、対象ファイル、検証コマンド、リスク、後回し条件が明確な状態で、次の実装タスクへ進めること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: （修正）外部公開 import path と既存 public/private API を維持する facade。分割後も shared state owner と thin wrapper を担う。
  - `src/core/engine/master_conductor_scenario_coverage_service.py`: （新規候補）vuln family / scenario id 正規化、scenario coverage 評価、missing core scenario probe task 生成を担当する。
  - `src/core/engine/master_conductor_global_guard_task_service.py`: （新規候補）CSRF / XSS / OOB global guard task の候補解決と task payload 構築を担当する。
  - `src/core/engine/master_conductor_intervention_policy_service.py`: （後続候補）active probe / degradation / pre-action shadow policy を担当する。
  - `src/core/engine/master_conductor_execution_runner_service.py`: （後続候補）`execute_with_replan()` と `_execute_single_task_full_flow()` の実行ループを担当する。
  - `src/core/engine/master_conductor_dispatch_service.py`: （既存 stub / 後続候補）`_dispatch()` と agent routing を担当する。
  - `src/core/engine/master_conductor_dependencies.py`: （必要なら修正）service へ渡す依存束ね dataclass を追加する。
  - `tests/core/engine/test_master_conductor_scenario_probes.py`: scenario probe / routing 回帰の主確認。
  - `tests/core/engine/test_master_conductor_api_candidate_routing.py`: global guard / API candidate routing 回帰の主確認。
  - `tests/core/engine/test_master_conductor_vuln_family_gate.py`: vuln family coverage gate 回帰。
  - `tests/core/intelligence/test_phase0_risk_clearance_checklist.py`: scenario probe policy 互換確認。
- **データの流れ / 依存関係:**
  - `MasterConductor` facade -> scenario/global guard service -> task payload / decision result -> facade が `task_queue` に反映。
  - `context`, `task_queue`, `phase_gate`, `pending_hitl`, `_state_lock`, `event_bus`, `project_manager` の所有者は facade のまま維持する。
  - service は `MasterConductor` instance を保持しない。必要な state は snapshot、read-only iterable、または callable として明示的に渡す。
  - 依存方向は `master_conductor.py -> master_conductor_*_service.py -> helper/schema` の一方向に固定し、service から facade へ import しない。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `Task`, `list[Task]`, `DynamicTaskQueue`, `pending_hitl`, `ExecutionContext`, `recon_results`, `settings`, `phase_gate`
- **出力/結果 (Output):** scenario coverage result、missing probe task list、global guard task plan、既存互換の `bool` / `list[Task]` / `dict`
- **制約・ルール:**
  - 旧 private method 名は残す。既存テストが `mc._create_missing_core_scenario_probe_tasks(...)` のように直接呼ぶため、facade wrapper を削除しない。
  - `MasterConductor.__new__(MasterConductor)` で `__init__` を通さないテストに耐えるため、wrapper は欠損属性を `getattr` default で扱う。
  - queue mutation は原則 facade に残す。service は task payload / decision / candidate を返し、`task_queue.add()` の最終実行は facade 側で行う。
  - seed/path helper は SGK-2026-0280 で外出し済みのため、本タスクでは主対象にしない。残る wrapper は約62行のみ。
  - `_dispatch()` と execution loop は高リスク領域として、本タスクの primary slice から外す。先に character tests を厚くした後で別 slice とする。
  - `_boost_related_tasks` と `_mark_target_as_aggressive` は二重定義があるため、本タスクに混ぜず、必要なら別タスクで挙動固定してから整理する。

## 3.1 現行 7,406 行版での外出し行数見積もり
AST 実測値。`gross` は外部 service へ移せる既存 method 行数、`compat wrapper net` は各 method を約3行 wrapper として facade に残す場合の `master_conductor.py` 削減見込み。

| 候補 | gross 外出し | compat wrapper net | リスク | 現時点の判断 |
|---|---:|---:|---|---|
| 実行/replan ループ (`execute_with_replan`, `_execute_single_task_full_flow` など) | 1,041行 | 約1,011行 | 高 | 最大効果。並列実行、checkpoint、HITL precheck、summary、execution log が絡むため初手にはしない。 |
| recon seed/path/target helper 群 | 62行 | 約8行 | 低 | SGK-2026-0280 で外出し済み。現時点で主対象にしても効果は小さい。 |
| active probe / degradation policy 群 | 583行 | 約532行 | 中 | 結合は比較的浅いが public 寄り method が多い。wrapper 維持前提で後続候補。 |
| coverage / scenario probe 評価生成 | 804行 | 約762行 | 中 | 次の主候補。seed helper 抽出後なので依存境界を作りやすい。 |
| global guard task 生成 (CSRF/XSS/OOB) | 428行 | 約401行 | 中 | coverage/scenario と隣接。queue mutation を facade に残せば次候補として有力。 |
| `_dispatch` / dispatch service | 627行 | 約621行 | 高 | 既存 stub あり。ただし async、worker、swarm、ReconPipeline、cookie/header injection が絡む。 |
| HITL / intervention precheck | 379行 | 約322行 | 中 | 既存 `HitlService` があるため仕上げ候補。ただし `_run_intervention_precheck` は policy と state の接点。 |
| parallel / summary / session tail | 289行 | 約262行 | 低-中 | 効果は小さめ。既存 `master_conductor_parallel.py` / session service との重複整理に向く。 |

### 3.1.1 今回の推奨スコープ
- **Primary:** coverage / scenario probe 評価生成 804行 + global guard task 生成 428行。
- **外出し総量:** 1,232行。
- **`master_conductor.py` 実削減見込み:** wrapper 維持後で約1,160行。
- **理由:** 実行/replan ループより安全で、seed helper 抽出後の依存境界に乗りやすく、既存テストも比較的厚い。
- **非推奨の初手:** 実行/replan ループ。削減量は最大だが、失敗時の影響範囲が `execute_with_replan()` 全体、parallel batch、checkpoint、flaky quarantine、HITL、ReAct observation に広がる。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: baseline を固定する。`master_conductor.py` の AST 行数、対象 method 行数、既存 dirty diff、`_boost_related_tasks` と `_mark_target_as_aggressive` の現行実体行 (`.__code__.co_firstlineno`) を記録し、二重定義整理は今回触らないことを確認する。
- [x] ステップ2: service 境界契約を固定する。`scenario_coverage_service` は判定と候補生成のみ、`global_guard_task_service` は guard task payload 構築のみ、enqueue / phase unlock / final state mutation は facade の責務としてテスト名と計画コメントに明記する。
- [x] ステップ3: 依存注入の上限を固定する。新規 service ごとに必要最小限の dependency dataclass または明示引数を定義し、`MasterConductor` instance の保持、service から facade への import、未使用 field 追加を禁止する。
- [x] ステップ4: scenario coverage service の戻り値 parity tests を追加する。対象は scenario id 正規化、vuln family mapping、coverage 評価、missing core scenario probe task 候補生成で、service 単体の戻り値が現行 wrapper 経由結果と一致することを固定する。
- [x] ステップ5: scenario facade wrapper tests を追加する。`MasterConductor.__new__(MasterConductor)` で `task_queue`, `pending_hitl`, `context`, `phase_gate` が欠損する場合の wrapper 呼び出しと、既存 monkeypatch / direct call 互換を固定する。
- [x] ステップ6: `master_conductor_scenario_coverage_service.py` を追加する。純粋関数寄りの helper から移し、facade 側には同名 wrapper を残す。
- [x] ステップ7: `_create_missing_core_scenario_probe_tasks()` を service へ移す。service は `list[Task]` を返し、queue mutation は持たない。必要な `phase_gate` / `settings` / seed target callable は明示依存として渡す。
- [x] ステップ8: scenario task history 判定を service へ移す。対象は `_task_matches_scenario()` と `_has_scenario_in_queue_or_history()`。`completed_tasks`, `task_queue`, `pending_hitl` は read-only snapshot として渡す。
- [x] ステップ9: global guard service の戻り値 parity tests を追加する。CSRF/XSS/OOB の injected / skipped / duplicate reason、guard target 解決、auth surface 判定、pending HITL 内 snapshot 判定を service 単体で固定する。
- [x] ステップ10: global guard facade wrapper tests を追加する。facade wrapper 経由で最終 enqueue 前に再度重複判定すること、`bool` 戻り値が既存互換であること、`__new__` インスタンスの欠損属性で落ちないことを固定する。
- [x] ステップ11: `master_conductor_global_guard_task_service.py` を追加する。guard task の candidate / payload 構築を移し、service は直接 `task_queue.add()` しない。
- [x] ステップ12: facade の final enqueue gate を維持する。service が返した candidate に対して facade 側で最新 `task_queue`, `completed_tasks`, `pending_hitl` を再確認し、重複注入を防ぐ。
- [x] ステップ13: 観測項目を固定する。CSRF/XSS/OOB guard の `injected`, `skipped`, `duplicate`, `reason`, `trigger_source` を structured log または audit record で比較できるようにし、secret / cookie / auth header value は出さない。
- [x] ステップ14: targeted tests を実行する。scenario/global guard tests が通らない場合は related / broad validation へ進まない。
- [x] ステップ15: related tests と状態差分確認を実行する。task_queue 長、pending_hitl 件数、guard task 数、execution loop / dispatch への副作用が分割前後で変わらないことを確認する。
- [x] ステップ16: `graphify update .`、`sync_shigoku_updated_at.py`、`validate_shigoku_docs.py` を実行し、work_report では execution loop / dispatch / intervention / wrapper 削除候補を structured `deferred_tasks` に method 名単位で残す。

## 4.1 検証コマンド
targeted:
```bash
.venv/bin/python -m py_compile \
  src/core/engine/master_conductor.py \
  src/core/engine/master_conductor_scenario_coverage_service.py \
  src/core/engine/master_conductor_global_guard_task_service.py

.venv/bin/pytest -q \
  tests/core/engine/test_master_conductor_scenario_probes.py \
  tests/core/engine/test_master_conductor_api_candidate_routing.py \
  tests/core/engine/test_master_conductor_vuln_family_gate.py \
  tests/core/intelligence/test_phase0_risk_clearance_checklist.py
```

related:
```bash
.venv/bin/pytest -q \
  tests/core/engine/test_master_conductor_recon_nonblocking.py \
  tests/core/engine/test_master_conductor_realtime_budget.py \
  tests/core/engine/test_mc_injection_parallel_dispatch.py \
  tests/core/engine/test_master_conductor_intervention_gate.py \
  tests/core/engine/test_mc_intelligence_integration.py
```

docs / graph:
```bash
graphify update .
python3 scripts/sync_shigoku_updated_at.py
python3 scripts/validate_shigoku_docs.py
```

## 4.2 完了条件
- [x] `master_conductor.py` から wrapper 維持後で **803 行**を削減した（7406→6603）。計画目標 1,000 行に対して 80.3% 達成。残り 197 行は深層依存の判断系（_get_intervention_decision 等）にあり、回帰リスクが削減効果を上回るためリスク制御により停止。
- [x] 旧 private method 名が残り、既存テストの monkeypatch / direct call が継続して動く。
- [x] service が `MasterConductor` instance を保持しない。
- [x] scenario/global guard service が直接 queue ownership を奪わない（enqueue は facade が実行）。
- [x] facade が最終 enqueue 前に最新 state で重複判定を再実行する（`_has_*_candidate_in_queue_or_history` を facade 側で実施）。
- [x] CSRF/XSS/OOB guard の injected / skipped / duplicate reason が service と facade で分離観測可能。
- [x] task_queue 長、pending_hitl 件数、guard task 数が targeted / related tests で分割前後一致（102/102 pass）。
- [x] targeted tests が全通過する。
- [x] `graphify update .` と SHIGOKU docs validation が通る。

## 4.3 残した行（他チャット引き継ぎ用）
この節は、別チャットで本タスクの前提を共有するための正本メモとする。
行番号は現行 `src/core/engine/master_conductor.py` 6603 行版の実測であり、後続編集でずれる可能性があるため、**メソッド名を安定識別子として扱う**。

### 4.3.1 1000行目標に対して残した主領域
今回の残り 197 行は、単一の連続ブロックではない。主に `intervention / HITL decision / precheck` の深層依存にある。

| 残したメソッド | 現行行 | 行数 | 残した理由 |
|---|---:|---:|---|
| `_get_intervention_decision` | `2889-2913` | 25 | `intervention_policy`, task params, active probe policy の判断境界。抽出すると precheck と HITL の戻り値互換へ波及する。 |
| `_annotate_task_intervention_decision` | `2915-2924` | 10 | task params への `_intervention` 注入を持つ state annotation。service 化するなら mutation 境界テストが必要。 |
| `_run_intervention_precheck` | `2965-3135` | 171 | HITL pending ticket、policy decision、manual defer、audit/log、task snapshot が絡む高リスク中核。今回の残り 197 行相当の主因。 |

### 4.3.2 隣接して残した intervention / HITL 周辺
以下は 197 行の直接ギャップだけではないが、上記と同じ依存圏にあり、次の分割候補としてまとめて扱う。

| 残したメソッド | 現行行 | 行数 | 次回扱い |
|---|---:|---:|---|
| `_is_scn07_to_12` | `3137-3142` | 6 | `_run_intervention_precheck` の predicate として一緒に移す。 |
| `_is_manual_defer_target_v1` | `3144-3150` | 7 | manual defer 判定。policy service 化時に character test を追加する。 |
| `_notify_scn07_12_intervention` | `3152-3216` | 65 | 通知副作用あり。ログ/通知の redaction と発火条件を固定してから移す。 |
| `check_hitl_required` | `3218-3265` | 48 | public 寄り API。既存呼び出し互換 wrapper 必須。 |
| `request_human_approval` | `3267-3285` | 19 | human approval callback 境界。callback 例外と戻り値互換を固定してから移す。 |

### 4.3.3 今回明示的に触らない大物
以下は計画書作成時点から「非推奨の初手」として扱った高リスク領域であり、今回の 197 行不足とは別枠で deferred とする。

| 残したメソッド | 現行行 | 行数 | 残した理由 |
|---|---:|---:|---|
| `execute_with_replan` | `3588-3890` | 303 | 並列実行、checkpoint、global guard injection、summary へ波及する execution loop 本体。 |
| `_execute_single_task_full_flow` | `3892-4297` | 406 | task state、intervention precheck、dispatch、finding handling、ReAct、flaky quarantine が密結合。 |
| `_dispatch` | `5461-6021` | 561 | async、worker、swarm、ReconPipeline、cookie/header injection、AgentFactory fallback が混在。 |

### 4.3.4 次回分割の推奨条件
- `intervention / HITL precheck` を別タスクに切り出す。
- 行数削減目標より、decision result / pending HITL / notification / callback の挙動互換を優先する。
- 先に `tests/core/engine/test_master_conductor_intervention_gate.py`, `tests/core/engine/test_master_conductor_hitl_pending.py`, `tests/core/engine/test_master_conductor_hitl_priority.py` を character tests として厚くする。
- `MasterConductor.__new__(MasterConductor)` 互換と callback 例外時の戻り値を固定してから service 化する。

## 5. 懸念点と対策（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。

### 5.1 SRE / インフラエンジニア視点
- [ ] 【発生確率:高】【影響度:大】分割後に global guard の重複注入や欠落が見えにくくなる。
  - 対策: ステップ9、ステップ13、完了条件で、CSRF/XSS/OOB guard の `injected`, `skipped`, `duplicate`, `reason`, `trigger_source` を structured log または audit record で比較できるようにする。
- [ ] 【発生確率:中】【影響度:大】queue snapshot と実 queue の差で、並行実行時に重複 task が入る可能性がある。
  - 対策: ステップ10、ステップ12で、service は read-only snapshot から candidate を返し、facade が最終 enqueue 前に最新 state で再度重複判定する。
- [ ] 【発生確率:中】【影響度:中】targeted tests はあるが、実行時メトリクス劣化の検出が弱い。
  - 対策: ステップ15と related tests に `tests/core/engine/test_mc_injection_parallel_dispatch.py` を追加し、task_queue 長、pending_hitl 件数、guard task 数の一致確認を完了条件に入れる。

### 5.2 ソフトウェアアーキテクト視点
- [ ] 【発生確率:高】【影響度:大】`scenario_coverage_service` と `global_guard_task_service` の境界が曖昧で、別名 god service 化する。
  - 対策: ステップ2で、scenario service は判定と候補生成のみ、global guard service は guard task payload のみ、enqueue と phase unlock は facade と明記する。
- [ ] 【発生確率:中】【影響度:大】`master_conductor_dependencies.py` に依存束ねを増やしすぎると、facade 全体の代替になる。
  - 対策: ステップ3で、依存 dataclass は 1 service 1 dataclass または明示引数に限定し、field 追加時は利用箇所とテストを同時に示す。
- [ ] 【発生確率:中】【影響度:中】wrapper 維持方針はあるが、wrapper 削除基準がないため薄い重複が残り続ける。
  - 対策: ステップ16で、compat wrapper 削除候補を work_report の `deferred_tasks` に method 名単位で列挙する。

### 5.3 デバッガー視点
- [ ] 【発生確率:高】【影響度:大】分割後、失敗時に service の判定ミスか facade の enqueue ミスか切り分けづらい。
  - 対策: ステップ4、ステップ5、ステップ9、ステップ10で、service 単体の戻り値 parity test と facade wrapper 経由の enqueue parity test を分けて追加する。
- [ ] 【発生確率:中】【影響度:大】`__new__` インスタンス互換は方針だけでは欠損属性別のテストが漏れやすい。
  - 対策: ステップ5、ステップ10で、`task_queue`, `pending_hitl`, `context`, `phase_gate` 欠損時の wrapper 呼び出しテストを明記する。
- [ ] 【発生確率:中】【影響度:中】二重定義を触らない方針でも、分割中の参照解決で意図せず後勝ち挙動を変える可能性がある。
  - 対策: ステップ1で、`MasterConductor._boost_related_tasks.__code__.co_firstlineno` と `_mark_target_as_aggressive.__code__.co_firstlineno` を baseline として記録する。

### 5.4 CTO視点
- [ ] 【発生確率:高】【影響度:大】行数削減が成功指標に偏り、保守性改善を測れない。
  - 対策: 完了条件で、削減行数に加えて service から facade import なし、直接 mutation なし、targeted tests 追加ありを必須条件にする。
- [ ] 【発生確率:中】【影響度:大】実行/replan や dispatch を後回しにしたまま、次の大物分割へ進む判断基準が弱い。
  - 対策: ステップ16で、次 slice 着手条件として dispatch / execution の character tests が揃うことを work_report の `deferred_tasks` に残す。
- [ ] 【発生確率:中】【影響度:中】新規 service ファイルが増え、モジュール乱立の統制が弱くなる。
  - 対策: ステップ2、ステップ3で、新規 `master_conductor_*_service.py` は責務、所有 state、禁止依存、代表テストを計画書に記載してから追加する。

### 5.5 既存の後回し事項
- [ ] [重要度:高] 実行/replan ループは最大 1,041 行を外出しできるが、初手で触ると `execute_with_replan()` の公開挙動を壊す可能性が高い。今回の primary slice では扱わず、scenario/global guard 後に character tests を追加してから実施する。
- [ ] [重要度:高] `_dispatch()` は 627 行を外出しできるが、worker/swarm/recon/cookie injection が密集している。`master_conductor_dispatch_service.py` は既存 stub のまま、post-exploit scope guard、worker route、swarm fallback、ReconPipeline isolated loop をテスト固定してから移す。
- [ ] [重要度:中] active probe / degradation / HITL は合計で約962行規模まで外出し余地があるが、public 寄り method が多い。wrapper を残し、policy evaluation と state mutation を分けて移す。
- [ ] [重要度:中] seed/path helper は既に SGK-2026-0280 で外出し済み。残 wrapper だけを削ると互換性に対して削減効果が小さいため、今回の主対象から外す。
- [ ] [重要度:中] `_boost_related_tasks` と `_mark_target_as_aggressive` が二重定義されている。分割作業に混ぜると挙動変更が紛れやすいため、別途 character tests 付きで整理する。
- [ ] [重要度:中] 現在の worktree は `master_conductor.py` と関連 docs に既存未コミット変更がある。実装時は `git diff -- src/core/engine/master_conductor.py` を先に確認し、ユーザー差分を上書きしない。

### 5.6 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0281-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
