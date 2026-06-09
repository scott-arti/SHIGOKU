---
task_id: SGK-2026-0280
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0264
related_docs:
- docs/shigoku/plans/2026-06-05_master-conductor-split-plan_plan.md
- docs/shigoku/reports/2026-06-09_master-conductor-split_work_report.md
title: 'MasterConductor 追加分割計画: seed/path helper 優先抽出'
created_at: '2026-06-09'
updated_at: '2026-06-09'
tags:
- shigoku
target: src/core/engine/master_conductor.py
---

# 実装計画書：MasterConductor 追加分割計画: seed/path helper 優先抽出

## 1. 達成したいゴール（ユーザー視点）
- [ ] `src/core/engine/master_conductor.py` の残存 8,317 行から、行数削減効果が高く、挙動変更リスクが比較的低い seed/path/target helper 群を優先して分割できること。
- [ ] 既存の `MasterConductor` public/private 呼び出し互換を維持し、既存テストの monkeypatch / `__new__` 利用を壊さないこと。
- [ ] `_dispatch` や `execute_with_replan` のような高リスク領域へ入る前に、recon seed / scope / URL / target resolution の境界を薄くして、後続分割の足場を作ること。
- [ ] 分割後も `master_conductor.py` は facade として既存 import path を維持し、分割先は `src/core/engine/master_conductor_*.py` の平置き構成に統一すること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: （修正）既存 API 互換を保つ facade。対象 private method は thin wrapper として残し、実装を分割先へ委譲する。
  - `src/core/engine/master_conductor_recon_seed_target_service.py`: （新規）recon file path 解決、target 正規化、scope 判定、CSRF/XSS/scenario seed target の採点・収集・refine を担当する候補。
  - `src/core/engine/master_conductor_recon_attack_task_planner.py`: （既存）recon classified results から attack task を作る planner。今回の seed service を callable 依存として受ける既存接続点。
  - `src/core/engine/master_conductor_dependencies.py`: （既存/必要なら修正）seed service へ渡す dependency bundle を追加する候補。
  - `tests/core/engine/test_master_conductor_api_candidate_routing.py`: （既存/修正）CSRF/XSS seed、global guard、API candidate routing の回帰確認。
  - `tests/core/engine/test_master_conductor_scenario_probes.py`: （既存/修正）scenario probe seed / scope 判定 / target 選択の回帰確認。
  - `tests/core/intelligence/test_phase0_risk_clearance_checklist.py`: （既存）scenario probe policy 経由の互換確認。
- **データの流れ / 依存関係:**
  - `MasterConductor._create_attack_tasks_from_recon()` -> `ReconAttackTaskPlanner` -> seed/path/target callable -> `ReconSeedTargetService` -> `list[Task]` を facade へ返す。
  - queue mutation は引き続き `MasterConductor._add_tasks()` が担当し、seed service は `task_queue.add()` を直接呼ばない。
  - `context`, `workspace`, `project_manager`, `target`, `settings` は facade 所有のまま、service には必要な値または callable のみを渡す。
  - service から `MasterConductor` 全体を逆参照しない。依存方向は `master_conductor.py -> master_conductor_recon_seed_target_service.py` の一方向に固定する。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `recon_results` (`dict[str, dict]`), `budget` (`int`), `Task`, `ExecutionContext`, `workspace`, `project_manager`, `target`, `settings`
- **出力/結果 (Output):** seed target list, evidence map, normalized URL / host / scope decision, recon tagged file path, guard target candidate
- **制約・ルール:**
  - 旧 private method 名は互換 wrapper として残す。例: `mc._collect_csrf_seed_targets(...)` は分割後も呼べること。
  - 既存 tests が `MasterConductor.__new__(MasterConductor)` で `__init__` を通さず method を呼ぶため、wrapper は遅延初期化または stateless call に耐えること。
  - `self` 属性の直接代入を seed service へ移さない。今回対象の seed/path/target helper 群は現状 `assigns=0` のため、副作用なし境界として扱う。
  - 例外処理は現行挙動を維持する。tagged file の壊れた JSONL 行、読み込み失敗、URL parse 失敗は現行と同じく該当候補を skip する。
  - `settings` は既存と同じ値を参照し、budget / min_score / phase2 policy の default を変えない。
  - `hashlib`, `uuid`, queue mutation を伴う global guard task 生成は今回の主スコープから外し、必要なら次 subtask で扱う。

## 3.1 現状分析と優先順位
AST 実測時点の `src/core/engine/master_conductor.py` は 8,317 行、`MasterConductor` 本体は 8,141 行、171 methods。Graphify では `MasterConductor` は degree 392 の高結合ノード。

| 候補 | 概算削減 | 結合度 / 副作用 | リスク | 今回判断 |
|---|---:|---|---|---|
| recon seed/path/target helper 群 | 約923行 | `assigns=0`, external self call 0 | 低-中 | 今回の主対象 |
| coverage/scenario evaluation | 約678行 | scenario policy 依存あり | 中 | seed service 後に続ける候補 |
| active probe/degradation policy | 約683行 | public寄り method 多め | 中 | 後続候補 |
| `_dispatch` service | 約619行 | async / worker / swarm / recon / cookie 注入 | 高 | character tests 後 |
| execution/replan loop | 約995行 | `self` attrs 67, external self call 65 | 高 | 最後に回す |

今回の削減対象候補:
- `src/core/engine/master_conductor.py:1474` `_collect_scenario_probe_seed_targets`
- `src/core/engine/master_conductor.py:1539` `_select_targets_for_scenario_probe`
- `src/core/engine/master_conductor.py:1876` `_resolve_recon_file_path`
- `src/core/engine/master_conductor.py:1919` `_resolve_project_tagged_dir`
- `src/core/engine/master_conductor.py:1948` `_collect_history_replay_targets`
- `src/core/engine/master_conductor.py:2082` `_score_csrf_seed_candidate`
- `src/core/engine/master_conductor.py:2200` `_score_xss_seed_candidate`
- `src/core/engine/master_conductor.py:2305` `_collect_xss_seed_targets`
- `src/core/engine/master_conductor.py:2398` `_is_low_value_backfill_target`
- `src/core/engine/master_conductor.py:2431` `_refine_backfill_seed_targets`
- `src/core/engine/master_conductor.py:2519` `_should_enable_phase2_on_empty_for_backfill`
- `src/core/engine/master_conductor.py:2543` `_apply_phase2_on_empty_policy`
- `src/core/engine/master_conductor.py:2551` `_collect_csrf_seed_targets`
- `src/core/engine/master_conductor.py:7329` `_get_context_auth_headers`
- `src/core/engine/master_conductor.py:7357` `_get_context_cookie_string`
- `src/core/engine/master_conductor.py:7360` `_normalize_url_candidate`
- `src/core/engine/master_conductor.py:7372` `_extract_host_candidate`
- `src/core/engine/master_conductor.py:7389` `_resolve_in_scope_hosts`
- `src/core/engine/master_conductor.py:7413` `_is_target_url_in_scope`
- `src/core/engine/master_conductor.py:7421` `_resolve_task_target`

## 3.2 非対象
- `_dispatch()` 本体の service 移行。
- `execute_with_replan()` / `_execute_single_task_full_flow()` の service 移行。
- `_ensure_global_csrf_guard_task()` / `_ensure_global_xss_guard_task()` / `_ensure_global_oob_guard_task()` の queue mutation 移行。
- `_boost_related_tasks` と `_mark_target_as_aggressive` の二重定義整理。これは挙動確認が必要な別リスクとして扱い、今回の削減目的に混ぜない。

## 3.3 追加契約（観測性・境界・検証）
- **観測性契約:**
  - seed 選定処理では、既存 logger を使って `seed_source`, `category`, `candidate_count`, `selected_count`, `skip_reason_count`, `scope_filtered_count` を追跡できるようにする。
  - tagged JSONL の壊れた行、存在しない file、読み込み失敗は現行挙動どおり候補 skip としつつ、集計値で検知できるようにする。
  - ログには cookie / bearer token / raw auth header value を出さない。出すのは header key 名、count、skip reason のみとする。
- **service 境界契約:**
  - `ReconSeedTargetService` は `MasterConductor` instance を受け取らない。
  - service が受け取れるのは `context snapshot`, `workspace base`, `project_manager project_dir`, `settings`, callable のみとする。
  - 移行期間中の正本は facade wrapper とする。`ReconAttackTaskPlanner` へ service method を直接渡すのは wrapper monkeypatch 互換テスト追加後に限る。
  - service 内は 1 ファイル肥大化を避け、少なくとも `UrlScopeResolver` 相当と `SeedTargetSelector` 相当の内部境界を設ける。
- **検証契約:**
  - 代表 `recon_results` fixture を使い、分割前後で selected URLs と evidence map が一致することを確認する。
  - targeted tests が通らない場合は related tests、`graphify update .`、docs validation へ進まない。
  - 行数削減は成功条件の一部にすぎない。output parity、wrapper 互換、mutation 禁止、import 互換を同時に満たすことを完了条件にする。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: character baseline と出力一致 fixture を固定する。対象 method の現行行数、wrapper 呼び出し、`__new__` 生成インスタンスでの呼び出し、monkeypatch 互換、代表 `recon_results` での selected URLs / evidence map を記録する。
- [ ] ステップ2: failure fixture を追加する。壊れた JSONL 行、存在しない tagged file、読み込み失敗、URL parse 失敗、`context/workspace/project_manager` 欠損時の wrapper 呼び出しを、現行挙動維持の character tests として固定する。
- [ ] ステップ3: 観測性・境界契約を実装前に固定する。`seed_source`, `category`, `candidate_count`, `selected_count`, `skip_reason_count`, `scope_filtered_count` の記録方針、secret redaction、service が `MasterConductor` instance を受け取らないことをテストまたは明示チェックで確認する。
- [ ] ステップ4: `master_conductor_recon_seed_target_service.py` を追加し、`ReconSeedTargetService` の内部に `UrlScopeResolver` 相当と `SeedTargetSelector` 相当の境界を設ける。新規 dependency は追加せず、既存 callable / context snapshot / settings を使う。
- [ ] ステップ5: stateless URL/scope helper を移す。対象は `_normalize_url_candidate`, `_extract_host_candidate`, `_is_target_url_in_scope`, `_resolve_task_target`。facade 側は同名 wrapper を残し、移動直後に py_compile と scope/target 系 character tests を実行する。
- [ ] ステップ6: context/workspace 依存の path helper を移す。対象は `_resolve_recon_file_path`, `_resolve_project_tagged_dir`, `_resolve_in_scope_hosts`, `_get_context_auth_headers`, `_get_context_cookie_string`。`__new__` インスタンスで欠損し得る属性は `getattr` default を維持し、auth 値はログへ出さない。
- [ ] ステップ7: seed scorer を移す。対象は `_score_csrf_seed_candidate`, `_score_xss_seed_candidate`, `_is_low_value_backfill_target`, `_should_enable_phase2_on_empty_for_backfill`, `_apply_phase2_on_empty_policy`。移動後に score / reasons の output parity を確認する。
- [ ] ステップ8: seed collector / refiner を移す。対象は `_collect_csrf_seed_targets`, `_collect_xss_seed_targets`, `_collect_history_replay_targets`, `_refine_backfill_seed_targets`。JSONL skip 件数と selected evidence map の一致を確認する。
- [ ] ステップ9: scenario seed helper を移す。対象は `_collect_scenario_probe_seed_targets`, `_select_targets_for_scenario_probe`。`_create_missing_core_scenario_probe_tasks()` は今回そのままにし、scenario seed helper だけ service 経由にする。
- [ ] ステップ10: `ReconAttackTaskPlanner` の dependency injection を確認する。基本は facade wrapper 経由を維持し、planner へ service method を直接渡す場合は wrapper monkeypatch 互換テストを追加してから切り替える。
- [ ] ステップ11: targeted tests を実行する。targeted tests が失敗した場合は related tests、`graphify update .`、docs validation へ進まず、失敗した移行単位を特定して修正する。
- [ ] ステップ12: related tests を実行する。`test_master_conductor_vuln_family_gate.py`, `test_master_conductor_recon_nonblocking.py`, `test_master_conductor_realtime_budget.py` で routing / scenario / recon 非ブロッキングの副作用がないことを確認する。
- [ ] ステップ13: broad validation と graph 更新を実行する。コード変更後は `graphify update .` を実行し、SHIGOKU docs は `sync_shigoku_updated_at.py` 後に `validate_shigoku_docs.py` を通す。
- [ ] ステップ14: work_report に残課題を構造化する。wrapper 削除候補、dispatch service 本格実装、execution loop 分割、global guard task 生成分離を deferred_tasks に列挙し、別 tracking task へつなげる。

## 4.1 検証コマンド
targeted:
```bash
.venv/bin/python -m py_compile src/core/engine/master_conductor.py src/core/engine/master_conductor_recon_seed_target_service.py src/core/engine/master_conductor_recon_attack_task_planner.py
.venv/bin/pytest -q tests/core/engine/test_master_conductor_api_candidate_routing.py tests/core/engine/test_master_conductor_scenario_probes.py tests/core/intelligence/test_phase0_risk_clearance_checklist.py
```

character / parity:
```bash
.venv/bin/pytest -q tests/core/engine/test_master_conductor_api_candidate_routing.py::test_score_csrf_seed_candidate_skips_http_404_seed
.venv/bin/pytest -q tests/core/engine/test_master_conductor_scenario_probes.py
```

related:
```bash
.venv/bin/pytest -q tests/core/engine/test_master_conductor_vuln_family_gate.py tests/core/engine/test_master_conductor_recon_nonblocking.py tests/core/engine/test_master_conductor_realtime_budget.py
```

docs / graph:
```bash
graphify update .
python3 scripts/sync_shigoku_updated_at.py
python3 scripts/validate_shigoku_docs.py
```

## 4.2 完了条件
- `master_conductor.py` から 800 行以上を削減する。目安は約923行。
- 旧 private method 名は残り、既存 tests の monkeypatch が引き続き動く。
- seed service は `task_queue`, `pending_hitl`, `completed_tasks` を直接 mutation しない。
- `ReconAttackTaskPlanner` の task output が分割前後で一致する。
- `ReconSeedTargetService` は `MasterConductor` instance を保持しない。
- tagged JSONL / file / URL parse 失敗時の現行 skip 挙動が character tests で固定されている。
- selected URLs、evidence map、score reasons の output parity が確認されている。
- targeted tests が失敗した状態で related / broad validation に進んでいない。
- `graphify update .` と SHIGOKU docs validation が通る。

## 5. 懸念点と対策（Backlog / 技術的負債）
※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。責任者と工数はこの計画では扱わない。

### 5.1 SRE / インフラエンジニア視点
- [ ] 【発生確率:高】【影響度:大】分割後に seed 選定の失敗原因が見えにくくなる。
  - 対策: `## 3.3 追加契約` とステップ3で `seed_source`, `category`, `candidate_count`, `selected_count`, `skip_reason_count`, `scope_filtered_count` の観測項目を固定する。
- [ ] 【発生確率:中】【影響度:大】JSONL 読み込み失敗を現行どおり skip すると、分割後の劣化を検知できない。
  - 対策: ステップ2とステップ8で壊れた JSONL、存在しない file、読み込み失敗の character tests と skip 集計確認を追加する。
- [ ] 【発生確率:中】【影響度:中】`graphify update .` や docs validation はあるが、実行順と失敗時停止条件が弱い。
  - 対策: ステップ11-13と `## 4.2 完了条件` で、targeted tests が通らない場合は related tests / graph update / docs validation へ進まないことを明記する。

### 5.2 ソフトウェアアーキテクト視点
- [ ] 【発生確率:高】【影響度:大】新規 `ReconSeedTargetService` が service という名前なのに facade 状態へ寄りすぎる恐れがある。
  - 対策: `## 3.3 追加契約` とステップ4で、service は `MasterConductor` instance を受け取らず、context snapshot / workspace base / project_manager project_dir / settings / callable のみを受け取ると固定する。
- [ ] 【発生確率:中】【影響度:大】wrapper 経由と service 直接注入の方針が混在し、二重経路になる。
  - 対策: `## 3.3 追加契約` とステップ10で、移行期間中の正本は facade wrapper とし、直接 service method 注入は wrapper monkeypatch 互換テスト追加後に限る。
- [ ] 【発生確率:中】【影響度:中】20個の helper を1ファイルに移すと、巨大ファイルが別名で再発する。
  - 対策: ステップ4で service 内に `UrlScopeResolver` 相当と `SeedTargetSelector` 相当の内部境界を設け、stateless / path / scorer / collector / scenario seed の順に段階分割する。

### 5.3 デバッガー視点
- [ ] 【発生確率:高】【影響度:大】分割後に出力一致を確認せず、テストが通っても seed ranking が微妙に変わる。
  - 対策: ステップ1、ステップ7、ステップ8、`## 4.2 完了条件` で、代表 fixture の selected URLs、evidence map、score reasons の output parity を確認する。
- [ ] 【発生確率:中】【影響度:大】`__new__` インスタンス互換が計画にあるが、個別確認が弱い。
  - 対策: ステップ1とステップ2で、`MasterConductor.__new__(MasterConductor)` 生成インスタンスに `context/workspace/project_manager` が欠損している場合の wrapper 呼び出しを character tests に含める。
- [ ] 【発生確率:中】【影響度:中】失敗時の切り戻し単位は書いてあるが、どの patch で何を確認するかが曖昧。
  - 対策: ステップ5-9を stateless -> path -> scorer -> collector -> scenario seed に分割し、それぞれ py_compile / parity / targeted tests の確認点を明記する。

### 5.4 CTO視点
- [ ] 【発生確率:高】【影響度:中】成功指標が「800行削減」に寄り、品質維持の定量条件が弱い。
  - 対策: `## 4.2 完了条件` で、行数削減だけでなく targeted tests、output parity、mutation 禁止、import / wrapper 互換を同時に必須条件にする。
- [ ] 【発生確率:中】【影響度:大】private wrapper を残す方針により、恒久的な compatibility 層が増える。
  - 対策: ステップ14と `## 5.5 work_report の deferred_tasks 記載例` で、wrapper 削除候補を work_report の deferred_tasks に列挙し、削除は別 task で実施する。
- [ ] 【発生確率:中】【影響度:中】dispatch / execution loop が後回しだが、次の意思決定条件が弱い。
  - 対策: `## 5.5 work_report の deferred_tasks 記載例` に、dispatch へ進む条件として seed service 完了、targeted / related tests 通過、service から facade 逆参照なしを追加する。
- [ ] 【発生確率:高】【影響度:高】既存 tests は `MasterConductor.__new__` と private method monkeypatch に依存している。wrapper 削除や直接 service call 化は互換破壊になり得る。
  - 対策: ステップ1、ステップ10、`## 4.2 完了条件` で旧 private method 名と monkeypatch 互換を明示的に維持する。
- [ ] 【発生確率:中】【影響度:中】global guard task 生成は seed target 取得と task queue mutation が混在する。
  - 対策: 今回の scope では対象外とし、work_report の deferred_tasks で `coverage_guard_service` などの別分割候補として扱う。
- [ ] 【発生確率:中】【影響度:中】path / JSONL 読み込み helper は壊れた行を silent skip する現行挙動を持つ。厳格化は品質改善に見えるが、今回混ぜると挙動変更になる。
  - 対策: ステップ2とステップ8で現行 skip 挙動を character tests として固定し、厳格化は別 task に分離する。

### 5.5 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0280-D01
    title: "MasterConductor dispatch service 本格実装"
    reason: "_dispatch は scope guard / worker / swarm / recon / AgentFactory を含むため、seed/path helper 分割とは別に character tests が必要"
    impact: high
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "seed service 完了、targeted / related tests 通過、service から facade 逆参照なしを確認後、dispatch 専用 character tests を追加して master_conductor_dispatch_service.py へ移行する"

  - deferred_id: SGK-2026-0280-D02
    title: "MasterConductor execution loop 分割"
    reason: "execute_with_replan と _execute_single_task_full_flow は状態更新が多く、seed/path helper 抽出後の後続作業にする"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "dispatch / recon execution 境界を固定後、execution loop service の計画を起票する"

  - deferred_id: SGK-2026-0280-D03
    title: "MasterConductor compatibility wrapper 削除候補の整理"
    reason: "今回の分割では旧 private method 名を残すため、恒久的な wrapper 増加を防ぐ追跡が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "wrapper 利用箇所と monkeypatch 依存テストを棚卸しし、削除可能な wrapper を別 task で段階削除する"

  - deferred_id: SGK-2026-0280-D04
    title: "coverage guard task 生成の分離"
    reason: "global guard task 生成は seed target 取得と task queue mutation が混在するため、今回の seed/path helper 分割から外した"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "coverage_guard_service などの境界候補を設計し、queue mutation を facade に残すか service 化するかを別計画で決める"
```
