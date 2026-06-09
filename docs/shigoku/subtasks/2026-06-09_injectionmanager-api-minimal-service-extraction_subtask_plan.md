---
task_id: SGK-2026-0277
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0265
related_docs:
- docs/shigoku/plans/2026-06-05_injection-manager-split-plan_plan.md
- docs/shigoku/subtasks/2026-06-09_api-probe-helper-4_subtask_plan.md
title: InjectionManager API minimal check service 化による大規模分割
created_at: '2026-06-09'
updated_at: '2026-06-09'
tags:
- shigoku
target: src/core/agents/swarm/injection/manager.py::_run_api_minimal_check
---

# 実装計画書：InjectionManager API minimal check service 化による大規模分割

## 1. 達成したいゴール（ユーザー視点）
- [ ] `src/core/agents/swarm/injection/manager.py` が 3397 行残っている状態から、検出挙動を変えずに大きな行数を削減できること。
- [ ] 最大塊である `_run_api_minimal_check`（約1007行）を InjectionManager 専用 service へ箱ごと移し、`manager.py` 側は public/private wrapper と state owner に近づくこと。
- [ ] API minimal check の既存 output shape（`findings_count`, `tested_params`, `probe_sent`, `comparison_checks`, `auth_context_matrix`, `object_ab_comparison`, `schema_candidate_params`, `probe_request_raw`, `probe_response_raw`）を維持すること。
- [ ] 未認証 API access、authA/authB matrix、object A/B、method discovery、mass-assignment auto-reverification、authenticated overposting、read-only fallback の既存 character test が移動後も通ること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/agents/swarm/injection/manager.py`: （修正）`_run_api_minimal_check` の実装本体を薄い wrapper に置換する。`current_context`、`_resolve_request_client()`、`_resolve_detection_mode()`、`_looks_like_login_page()`、`EXCLUDED_TESTED_PARAMS` の提供元は facade 側に残す。
  - `src/core/agents/swarm/injection/manager_internal/api_probe_runner.py`: （新規）API minimal check の時系列オーケストレーションを保持する。まずは既存 `_run_api_minimal_check` のロジックを意味変更なしで移す。
  - `src/core/agents/swarm/injection/manager_internal/api_probe_payload.py`: （既存）mass-assignment payload helper 群の提供元。今回の主対象ではなく、既存利用を維持する。
  - `src/core/agents/swarm/injection/manager_internal/api_probe_*`: （既存）auth matrix、object A/B、evidence rendering、read probe、target discovery などの helper 群。runner から呼び出す。
  - `tests/core/agents/swarm/test_injection_manager.py`: （修正候補）manager wrapper 経由の character test を維持し、public/private互換を確認する。
  - `tests/core/agents/swarm/injection/test_api_probe_runner.py`: （新規候補）runner 単体の request/finding shape を固定する character test を追加する。
  - `tests/core/agents/swarm/injection/test_manager_api_probe_character.py`: （既存）landing page discovery の回帰確認。
  - `tests/core/agents/swarm/injection/test_manager_api_probe_mass_assignment_character.py`: （既存）mass-assignment auto-reverification の回帰確認。
- **データの流れ / 依存関係:**
  - `manager._run_api_minimal_check(url, base_params)` -> facade が request client / findings sink / callbacks を注入 -> `api_probe_runner.run_api_minimal_check(...)` -> API probe helper 群 -> `findings_sink` と result dict -> manager wrapper が既存呼び出し元へ返却。
  - 依存方向は `manager.py -> manager_internal/api_probe_runner.py -> manager_internal/api_probe_*.py` とする。`api_probe_runner.py` から `InjectionManagerAgent` 全体への逆参照は禁止する。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - `url: str`
  - `base_params: Dict[str, Any]`
  - `request_client: Any`
  - `findings_sink: List[Any]`
  - `source_agent_name: str`
  - `excluded_params: set`
  - `looks_like_login_page: Callable[[str], bool]`
  - `resolve_detection_mode: Callable[[Dict[str, Any], str], str]`
- **出力/結果 (Output):**
  - 既存 `_run_api_minimal_check` と同じ result dict を返す。
  - finding は既存どおり `findings_sink` に append する。
  - `probe_request_raw` / `probe_response_raw` は既存どおり最後に capture した probe evidence を返す。
  - skipped 時は既存の `probe_skipped_reason` 語彙を維持する。
- **制約・ルール:**
  - `_run_api_minimal_check` の内部時系列を「最適化」しない。まずは移動のみを成功条件にする。
  - `Finding`, `Evidence`, `VulnType`, `Severity` の生成 shape、title、tags、confidence、additional_info キーを変更しない。
  - `request_client.request(...)` の method、timeout、use_cache、allow_redirects、headers、json payload を変更しない。
  - `manager_internal` から `self` または `InjectionManagerAgent` を受け取らない。必要依存だけを引数で渡す。
  - `api_probe_runner.py` は request client を生成・保持・close しない。client lifecycle は facade または既存 owner に限定する。
  - `request_client`、`findings_sink`、callbacks、定数は `ApiProbeDependencies`（TypedDict または dataclass）として束ねることを第一候補とし、runner の引数肥大化を防ぐ。
  - `api_probe_runner.py` は InjectionManager 専用内部実装とし、他 swarm から import しない。共有化が必要な場合は別タスク/別ADRで扱う。
  - broad `except Exception` の挙動は今回の移動で変えない。改善する場合は別タスクで扱う。
  - 既存 `api_probe_*` helper の責務を崩さず、runner は時系列と finding assembly の集約に限定する。
  - 行数削減の成功目安は `manager.py` から 800 行以上を削ること。ただし挙動互換とテスト通過を行数削減より優先する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: 事前 character test を固定する。最低限、`tests/core/agents/swarm/test_injection_manager.py` の API minimal 系、`tests/core/agents/swarm/injection/test_manager_api_probe_character.py`、`tests/core/agents/swarm/injection/test_manager_api_probe_mass_assignment_character.py` を移動前に実行し、現状の pass/fail とコマンド出力を記録する。API minimal targeted test が失敗し、その失敗を pre-existing と説明できない場合は、service 化へ進まず停止する。
- [x] ステップ2: fake request client の call log で、移動前の `request_client.request(...)` call sequence を保存する。method、url、timeout、use_cache、allow_redirects、headers、json payload、呼び出し順を fixture または test helper で比較可能にする。
- [x] ステップ3: 移動前の evidence / finding 増分 snapshot を固定する。`findings_sink` の増分件数、append 順序、`additional_info` の主要キー、`probe_request_raw` / `probe_response_raw` の最後の capture 対象を character test で確認する。
- [x] ステップ4: patch 境界とスコープ境界を分ける。1パッチ目は `api_probe_runner.py` と依存オブジェクトの追加のみ、2パッチ目は manager wrapper の切替、3パッチ目は import cleanup とテスト追加に限定する。`dispatch`、`_process_single_url`、phase2 lane、外部依存追加はこのタスクの変更対象外として明示する。
- [x] ステップ5: `ApiProbeDependencies`（TypedDict または dataclass）を `manager_internal/models.py` または `api_probe_runner.py` に追加する。`request_client`、`findings_sink`、`source_agent_name`、`excluded_params`、`looks_like_login_page`、`resolve_detection_mode` を明示し、runner が `self` や `InjectionManagerAgent` 全体を受け取らないことを型上も分かる形にする。
- [x] ステップ6: `manager_internal/api_probe_runner.py` を新規作成し、`run_api_minimal_check(...)` を追加する。最初は `_run_api_minimal_check` 本体をほぼそのまま移植し、`self` 参照を `ApiProbeDependencies` 経由の依存に置き換える。内部 helper 化、順序整理、例外処理改善、payload 最適化は行わず、移植にロジック再設計が必要になった場合は停止して計画を見直す。
- [x] ステップ7: runner 内では request client を生成・保持・close しないことを確認する。`AsyncNetworkClient` などの client owner import や新規 runtime dependency が入った場合は差し戻し、facade から注入された client だけを使う。
- [x] ステップ8: runner 境界の静的確認を行う。`api_probe_runner.py` に `self.`、`InjectionManagerAgent` import、`dispatch` 参照、`_process_single_url` 参照、client owner import がないことを `rg` または AST 確認で検証する。
- [x] ステップ9: runner 単体 character test を追加する。fake request client と findings_sink を使い、少なくとも unauthenticated API access、mass-assignment reflected recheck、authenticated overposting、read-only fallback の4分岐を wrapper なしで確認する。
- [x] ステップ10: runner 単体 test に exception path の検知を追加する。既存 broad `except Exception` の挙動は変えず、想定外例外が silent skip に見えないよう、`probe_skipped_reason`、error metadata、または call log のどこで失敗したかを assert する。
- [x] ステップ11: `manager.py::_run_api_minimal_check` を薄い wrapper にする。`request_client = self._resolve_request_client()`、`findings_sink = self.current_context.setdefault("findings", [])`、`ApiProbeDependencies` 構築だけを残し、戻り値は runner の result dict をそのまま返す。
- [x] ステップ12: wrapper 経由の既存テストを実行し、移動前後の result shape、request call sequence、`current_context["findings"]` 追加挙動、evidence capture が一致することを確認する。差分が出た場合はテストが通っていても停止し、wrapper injection -> runner dependency -> fake client call log -> normalizer 対象範囲の順で切り分ける。
- [x] ステップ13: `manager.py` から不要 import を削除する。`Finding` / `VulnType` / `Severity` / `Evidence` / API probe helper import のうち、manager 側で不要になったものだけを外す。specialist runner や dispatch が使う import は削らない。
- [x] ステップ14: scope creep guard を再確認する。`git diff -- src/core/agents/swarm/injection/manager.py` などで、`dispatch`、`_process_single_url`、phase2 lane、API minimal 以外の挙動変更が混ざっていないことを確認し、混入していたらこのタスクの差分から外す。
- [x] ステップ15: 行数と構文を確認する。`wc -l src/core/agents/swarm/injection/manager.py`、AST parse、 targeted pytest を実行し、`manager.py` の削減量とテスト結果を work_report に残す。
- [x] ステップ16: targeted tests が通ったら、関連広域テストを実行する。`tests/core/agents/swarm/test_injection_manager.py`、`tests/core/agents/swarm/injection/` 配下の API probe / process_url / phase2 lane 関連を優先する。既知 failure が出た場合は pre-existing か移動起因かを切り分けて報告する。
- [x] ステップ17: 完了 claim 前の evidence gate を実行する。targeted tests、関連広域テスト、AST parse、`graphify update .`、work_report、work_log の記録が揃うまで「完了」としない。
- [x] ステップ18: work_report の deferred_tasks に runner 内部の二次分割候補を残す。候補は auth matrix、object A/B、mass-assignment auto-reverification、read-only fallback の4領域を最低限含める。

## 4.1 推奨検証コマンド
- [x] `.venv/bin/pytest tests/core/agents/swarm/test_injection_manager.py -k "api_minimal_check"`
- [x] `.venv/bin/pytest tests/core/agents/swarm/injection/test_manager_api_probe_character.py tests/core/agents/swarm/injection/test_manager_api_probe_mass_assignment_character.py`
- [x] `.venv/bin/pytest tests/core/agents/swarm/injection/test_api_probe_object_ab.py tests/core/agents/swarm/injection/test_api_probe_auth_matrix.py tests/core/agents/swarm/injection/test_api_probe_read_probe.py tests/core/agents/swarm/injection/test_api_probe_payload.py`
- [x] `.venv/bin/pytest tests/core/agents/swarm/injection/test_api_probe_runner.py`
- [x] `.venv/bin/pytest tests/core/agents/swarm/test_injection_manager.py tests/core/agents/swarm/injection/`
- [x] `.venv/bin/python - <<'PY'` 形式の AST parse で `manager.py` と `manager_internal/*.py` を確認する。`py_compile` は `__pycache__` 権限で失敗しうるため、構文確認は AST parse を優先する。
- [x] `graphify update .`

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] `_run_api_minimal_check` は約1007行で、未認証 probe、auth matrix、object A/B、method discovery、mass-assignment recheck、authenticated recheck、read-only fallback が直列に絡む。 - 今回は内部アルゴリズム分解を禁止し、service への箱ごと移動に限定する。
- [ ] [重要度:高] `findings_sink` への append 順序や `findings_start_index` の扱いがずれると、normalizer 対象範囲が変わる。 - runner に `findings_sink` を直接渡し、移動前と同じ list mutation を維持する。
- [ ] [重要度:中] `probe_request_raw` / `probe_response_raw` は最後に capture した probe に依存するため、関数分割で capture タイミングが変わるとレポート evidence がずれる。 - `_capture_probe_evidence` 相当の state は runner 内に閉じ、capture 順序を変えない。
- [ ] [重要度:中] `self._looks_like_login_page` と `self._resolve_detection_mode` を callback 化するため、引数漏れや default mode 差分が起きやすい。 - wrapper test と runner 単体 test の両方で確認する。
- [ ] [重要度:中] `manager.py` の import cleanup で他 branch が使う symbol を誤って削る可能性がある。 - AST parse と targeted tests の後に import 削除を行う。
- [ ] [重要度:低] service 化後も API probe runner 自体は大きな関数として残る可能性がある。 - 本タスクの成功指標は `manager.py` の肥大化解消であり、runner 内部の二次分割は別タスクに分ける。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0277-D01
    title: "継続監視: API minimal service 化後の検出精度と evidence shape"
    reason: "service 化で manager.py は縮小できるが、API probe runner 内部の時系列依存は継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "実セッションまたは代表 fixture で unauth API / mass-assignment / auth context / read probe の evidence を比較する"
```

## 5.2 懸念点と対策

### SRE / インフラエンジニア視点
- [ ] 【発生確率: 高】【影響度: 大】`request_client` の所有権と close 責務が曖昧になり、service 側が client lifecycle を持ち始める懸念。 - 対策: `api_probe_runner.py` は client の生成・保持・close を禁止し、facade から注入された `request_client` のみを使う。実装ステップ7で owner import がないことを確認する。
- [ ] 【発生確率: 中】【影響度: 大】移動後に timeout / allow_redirects / use_cache の値が変わり、検出精度や実行時間が変わる懸念。 - 対策: 実装ステップ2と12で fake client の call log を比較し、method、timeout、use_cache、allow_redirects、headers、json payload、呼び出し順の一致を確認する。
- [ ] 【発生確率: 中】【影響度: 中】`probe_request_raw` / `probe_response_raw` の capture 順序が変わり、レポート evidence が別 probe を指す懸念。 - 対策: 実装ステップ3と12で最後に capture される request/response を snapshot 化し、移動前後で一致させる。

### ソフトウェアアーキテクト視点
- [ ] 【発生確率: 高】【影響度: 大】`run_api_minimal_check(...)` の引数が増えすぎ、god function の移設になる懸念。 - 対策: 実装ステップ5で `ApiProbeDependencies` を導入し、依存を明示的なオブジェクトに束ねる。
- [ ] 【発生確率: 中】【影響度: 大】`manager_internal/api_probe_runner.py` が他 swarm から再利用され、InjectionManager 専用境界が崩れる懸念。 - 対策: `## 3` の制約として他 swarm からの import 禁止を明記し、共有化は別タスク/別ADRへ分離する。
- [ ] 【発生確率: 中】【影響度: 中】移動後も runner 内が1000行級のままで、次の変更容易性が上がらない懸念。 - 対策: 実装ステップ18と完了条件で、runner 内部の二次分割候補を work_report の deferred_tasks に残す。

### デバッガー視点
- [ ] 【発生確率: 高】【影響度: 大】失敗時に wrapper 起因か runner 起因か fake client 起因か切り分けづらくなる懸念。 - 対策: 実装ステップ12で `wrapper injection -> runner dependency -> fake client call log -> normalizer 対象範囲` の順に切り分けるデバッグ順序を固定する。
- [ ] 【発生確率: 中】【影響度: 大】`findings_start_index` と `findings_sink` append 順序がずれ、normalizer が対象外 finding まで処理する懸念。 - 対策: 実装ステップ3と12で `findings_sink` の増分件数、追加順序、normalized `additional_info` keys を比較する。
- [ ] 【発生確率: 中】【影響度: 中】broad `except Exception` を維持する方針により、移動時の引数漏れが silent skip として見える懸念。 - 対策: 実装ステップ10で exception path の runner 単体 test を追加し、想定外例外の発生位置を call log または error metadata で検知する。

### CTO視点
- [ ] 【発生確率: 高】【影響度: 大】「800行削減」が目的化し、検出価値や payout readiness を壊す懸念。 - 対策: 完了条件で、行数削減は副次指標とし、API minimal targeted tests と evidence shape 互換を満たさない場合は未完了とする。
- [ ] 【発生確率: 中】【影響度: 大】大規模移動でレビュー単位が大きくなりすぎ、差分確認が困難になる懸念。 - 対策: 実装ステップ4で patch 境界を3段階に分け、runner追加、wrapper切替、import cleanup/test追加を混ぜない。
- [ ] 【発生確率: 中】【影響度: 中】service 化後に新規 runner が長期的な技術的負債として固定される懸念。 - 対策: 実装ステップ18と `deferred_tasks` で、auth matrix、object A/B、mass-assignment auto-reverification、read-only fallback の二次分割候補を後続タスク候補として残す。
- [ ] 【発生確率: 中】【影響度: 大】baseline failure と移動起因の regression が混ざり、GO/NO-GO 判断ができなくなる懸念。 - 対策: 実装ステップ1で移動前の pass/fail とコマンド出力を記録し、API minimal targeted test の失敗を pre-existing と説明できない場合は service 化へ進まず停止する。
- [ ] 【発生確率: 高】【影響度: 大】「ついでに綺麗にする」内部リファクタが混ざり、検出時系列・payload・例外処理が変わる懸念。 - 対策: 実装ステップ6で箱ごと移動を優先し、内部 helper 化、順序整理、例外処理改善、payload 最適化を禁止する。ロジック再設計が必要になった場合は停止して計画を見直す。
- [ ] 【発生確率: 中】【影響度: 大】runner が `self` や `InjectionManagerAgent` 全体を要求し、巨大 manager の結合が別ファイルへ移るだけになる懸念。 - 対策: 実装ステップ5と8で `ApiProbeDependencies` と静的確認を行い、runner に `self.`、`InjectionManagerAgent` import、manager 全体参照を入れない。
- [ ] 【発生確率: 中】【影響度: 大】request call sequence や evidence / finding shape の微差がテスト外で検出精度を落とす懸念。 - 対策: 実装ステップ2、3、12で method、url、timeout、use_cache、allow_redirects、headers、json payload、呼び出し順、finding 増分、raw capture を比較し、差分が出た場合はテストが通っていても停止する。
- [ ] 【発生確率: 中】【影響度: 大】作業中に `dispatch` や `_process_single_url` へ手が伸び、レビュー不能な横展開になる懸念。 - 対策: 実装ステップ4と14で `dispatch`、`_process_single_url`、phase2 lane、API minimal 以外の挙動変更をスコープ外として確認し、混入していたら差分から外す。
- [ ] 【発生確率: 低】【影響度: 大】service 化を理由に新規 runtime dependency や request client lifecycle の変更が入り、運用時の接続管理・失敗率が変わる懸念。 - 対策: 実装ステップ7で client owner import、新規 runtime dependency、client close/生成を禁止し、facade から注入された既存 client のみを使う。
- [ ] 【発生確率: 中】【影響度: 大】検証や記録が揃わないまま「完了」と扱われ、後続タスクが壊れた前提を引き継ぐ懸念。 - 対策: 実装ステップ17で targeted tests、関連広域テスト、AST parse、`graphify update .`、work_report、work_log が揃うまで完了 claim を禁止する。

## 6. 完了条件
- [x] `manager.py` の `_run_api_minimal_check` 本体が thin wrapper 化され、API minimal の実装本体が `manager_internal/api_probe_runner.py` に移っている。
- [x] `manager.py` が少なくとも 800 行以上削減されている、または削減できなかった理由が work_report に明記されている。ただし行数削減は副次指標であり、API minimal targeted tests と evidence shape 互換を満たさない場合は未完了とする。
- [x] 移動前後で `request_client.request` の call sequence、`findings_sink` 増分、`probe_request_raw` / `probe_response_raw` の capture 対象が一致している。
- [x] `ApiProbeDependencies` などの依存オブジェクトにより、runner が `self` や `InjectionManagerAgent` 全体を受け取っていない。
- [x] API minimal targeted tests が通過している。
- [x] `tests/core/agents/swarm/test_injection_manager.py` と API probe 関連テストの実行結果が work_report に記録されている。
- [x] runner 内部の二次分割候補が work_report の deferred_tasks に記録されている。
- [x] `graphify update .` が実行され、コードグラフ更新結果が work_log に記録されている。
