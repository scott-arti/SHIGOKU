---
task_id: SGK-2026-0279
doc_type: subtask_plan
doc_usage: execution_plan
status: done
parent_task_id: SGK-2026-0265
related_docs:
- docs/shigoku/plans/2026-06-05_injection-manager-split-plan_plan.md
- docs/shigoku/specs/ARCHITECTURE.md
- docs/shigoku/reports/2026-06-09_sgk-2026-0279_injectionmanager-additional-split_work_report.md
- docs/shigoku/worklogs/2026-06-09_sgk-2026-0279_injectionmanager-additional-split_work_log.md
title: 'InjectionManager 追加分割計画: 残存大規模責務の外出し'
created_at: '2026-06-09'
updated_at: '2026-06-11'
tags:
- shigoku
target: src/core/agents/swarm/injection/manager.py
---

# 実装計画書：InjectionManager 追加分割計画: 残存大規模責務の外出し

## 1. 達成したいゴール（ユーザー視点）
- [x] `src/core/agents/swarm/injection/manager.py` が 2382 行残っている状態から、公開挙動を維持したまま追加分割できること。
- [x] 行数が大きい責務から外出し候補を扱い、各候補の削減見込み・配置先・リスク・検証観点が明確であること。
- [x] `InjectionManagerAgent` の public import path、`AgentRegistry` 登録名、LLM tool action 名、`run_*_hunter` / `_process_single_url` の既存テスト互換を維持すること。
- [x] `dispatch` 全体の丸ごと移動は最終手段とし、まず public wrapper を残せる大きな責務から安全に削減すること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/agents/swarm/injection/manager.py`: （修正）公開 facade / state owner / lifecycle owner として残す。大きな実装本体を `manager_internal/` へ移し、既存メソッド名は wrapper として維持する。
  - `src/core/agents/swarm/injection/manager_internal/tool_runners.py`: （修正）`run_*_hunter` 群の実行・結果整形を集約する。既存 `build_hunter_task` / `format_*` helper を拡張し、manager 側の public method は薄い wrapper にする。
  - `src/core/agents/swarm/injection/manager_internal/process_url_dispatcher.py`: （修正）`_process_single_url` の vuln type branch 実行を集約する。`manager.py` 側は cache owner と wrapper を残す。
  - `src/core/agents/swarm/injection/manager_internal/specialist_factory.py`: （新規候補）specialist lazy import と初期化を保持する。import failure 時の warning 語彙は維持する。
  - `src/core/agents/swarm/injection/manager_internal/tool_registration.py`: （新規候補）LLM tool 登録定義を保持する。登録実行は facade の `register_tool` を使う。
  - `src/core/agents/swarm/injection/manager_internal/cache_policy.py`: （新規候補）cache key、cache bypass、security level 抽出、tested params fallback を保持する。
  - `src/core/agents/swarm/injection/manager_internal/phase1_results.py`: （修正）Phase1 signal summary と execution log assembly の純粋処理を追加する。
  - `src/core/agents/swarm/injection/manager_internal/unknown_scan_runner.py`: （新規候補）`_run_unknown_hypothesis_scans` の specialist loop を保持する。既存 `unknown_hypotheses.py` とは「仮説構築」と「実行」を分ける。
  - `src/core/agents/swarm/injection/manager_internal/phase2_gate.py`: （新規候補・条件付き）`dispatch` 後半の Phase2 gate / early return / execution_log builder だけを保持する。Phase1 loop 本体は原則 facade に残す。
  - `tests/core/agents/swarm/test_injection_manager.py`: （修正候補）facade wrapper 互換、tool runner 互換、`_process_single_url` routing 互換の character test を維持・追加する。
  - `tests/core/agents/swarm/injection/`: （修正候補）GraphQL、CRLF、SSRF、Phase2 lane、API probe、unknown branch、P1 metadata の回帰を局所確認する。
- **データの流れ / 依存関係:**
  - `dispatch(task)` -> target selection / Phase1 loop -> `_process_single_url(...)` wrapper -> `process_url_dispatcher` -> `tool_runners` / builtin probes / unknown scan runner -> `result_normalizer` -> manager-owned `_request_cache` and `current_context["url_results"]` -> Phase2 gate -> `SwarmResult`。
  - 依存方向は `manager.py -> manager_internal/* -> smart_*.py or pure helpers` の一方向を維持する。`manager_internal` から `InjectionManagerAgent` 全体を import しない。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - `Task`: `dispatch` に渡される既存 swarm task。
  - `url: str`, `vuln_type: str`, `base_params: Dict[str, Any]`, `quick_mode: bool`: `_process_single_url` 系の既存入力。
  - `specialists: Dict[str, Specialist]`, `current_context: Dict[str, Any]`, `_phase2_detection_mode: str`, `EXCLUDED_TESTED_PARAMS`: facade から分割先へ明示注入する依存。
- **出力/結果 (Output):**
  - `SwarmResult` の `findings`, `status`, `execution_log`, `swarm_name`, `total_specialists`, `successful_specialists` を既存互換で返す。
  - `_process_single_url` の result dict は既存キーを維持する: `findings_count`, `vuln_type`, `findings`, `tested_params`, `reflection_observed`, `xss_evidence`, `blind_correlation`, `unknown_profile`, `probe_sent`, `probe_skipped_reason`, `probe_request_raw`, `probe_response_raw`, `comparison_checks`, `auth_context_matrix`, `object_ab_comparison`, `schema_candidate_params`, `single_request_validation`, `detection_mode`。
  - `run_*_hunter` 群の result dict、`current_context["findings"]` への append、specialist の `last_tested_params` / `last_blind_correlation` fallback を維持する。
- **制約・ルール:**
  - public method 名は削除しない。`run_sqli_hunter`, `run_xss_hunter`, `run_lfi_check`, `run_open_redirect_check`, `run_ssti_hunter`, `run_cors_hunter`, `run_crlf_hunter`, `run_graphql_hunter`, `run_cmd_ssrf_hunter`, `run_ssrf_hunter`, `_process_single_url`, `_run_unknown_hypothesis_scans` は wrapper として残す。
  - 既存テストが `patch.object(agent, "_process_single_url", ...)` や `patch.object(manager, "run_graphql_hunter", ...)` を使うため、patch 可能な instance method 境界を維持する。
  - `dispatch` 全体の丸ごと移動は禁止する。移動する場合も Phase2 gate / execution_log builder など純粋寄りの後半処理に限定する。
  - `_request_cache`, `current_context`, `_ephemeral_network_clients`, `_finding_validator`, `specialists` の所有権は facade 側に残す。
  - 分割先へ `self` 全体を渡さない。必要依存は `TypedDict` または明示引数で渡す。
  - result shape、skip reason 語彙、timeout / retry / circuit breaker の意味を変更しない。
  - 大きなファイル削減を優先しても、検出精度・payout readiness・既存 character test 通過を行数削減より優先する。

## 3.1 現状サイズと行数順候補

| 順位 | 対象 | 現在位置 | 現在サイズ | 想定削減 | 推奨外出し先 | リスク |
|---|---|---:|---:|---:|---|---|
| 1 | `dispatch` | `manager.py:812-1475` | 約664行 | 150-250行（部分抽出） | `phase2_gate.py`, `phase1_results.py` | 高。Phase1 loop、timeout、circuit breaker、early return、Phase2 budget、`SwarmResult.execution_log` が絡む。丸ごと移動は禁止。 |
| 2 | `run_*_hunter` 群 | `manager.py:1773-2289` | 約517行 | 350-430行 | `tool_runners.py` | 中。public tool 名、戻り dict、`current_context["findings"]` append、specialist fallback の互換が必要。 |
| 3 | `_process_single_url` | `manager.py:1477-1727` | 約251行 | 190-220行 | `process_url_dispatcher.py` | 中-高。cache 書き込み、unknown / IDOR fallback、probe metadata、例外時 cache shape が絡む。wrapper 必須。 |
| 4 | tool 登録 / specialist 初期化 | `manager.py:160-336` | 約175行 | 110-140行 | `specialist_factory.py`, `tool_registration.py` | 低-中。lazy import warning、登録順、LLM tool action 名の互換が必要。 |
| 5 | helper / policy wrapper 群 | `manager.py:438-765` | 約250行中の一部 | 120-200行 | `cache_policy.py`, `phase1_results.py`, `tool_param_normalizer.py` | 低-中。直接テストされている helper は manager wrapper を残す。 |
| 6 | `_run_unknown_hypothesis_scans` | `manager.py:350-426` | 約77行 | 50-65行 | `unknown_scan_runner.py` | 中。`manager` 名前空間 patch と selected specialist 実行順の互換が必要。 |

## 3.2 推奨実装順

1. `run_*_hunter` 群を `tool_runners.py` へ外出しする。
2. `_process_single_url` の branch 実行を `process_url_dispatcher.py` へ外出しする。
3. specialist 初期化と tool 登録を factory / registration module へ外出しする。
4. cache / tool param / Phase1 signal helper を純粋 helper として外出しする。
5. `_run_unknown_hypothesis_scans` を `unknown_scan_runner.py` へ外出しする。
6. 必要な場合だけ、`dispatch` 後半の Phase2 gate / execution_log builder を抽出する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: baseline を固定する。`wc -l src/core/agents/swarm/injection/manager.py` と AST による method size 一覧を work_log に残し、`dispatch`, `_process_single_url`, `run_*_hunter` 群の現状行数を記録する。
- [x] ステップ2: baseline pytest を実行し、pass/fail と既知 failure 名を work_log に記録する。未説明 failure がある場合は実装を停止し、pre-existing と説明できるまで分割へ進まない。
- [x] ステップ3: public wrapper 互換の character test を先に確認する。最低限、`tests/core/agents/swarm/test_injection_manager.py`, `tests/core/agents/swarm/injection/test_graphql_pipeline.py`, `tests/core/agents/swarm/injection/test_crlf_pipeline.py`, `tests/core/agents/swarm/injection/test_manager_phase2_lane2_integration.py`, `tests/core/agents/swarm/injection/test_manager_p1_metadata.py` を対象にする。
- [x] ステップ4: timeout / retry / circuit breaker / Phase2 lane の停止条件を固定する。`test_manager_phase2_lane2_integration.py -k "timeout or circuit or lane2"` を実行し、ここで新規 failure が出た場合は `dispatch` 周辺の抽出へ進まない。
- [x] ステップ5: 分割先の依存境界を先に定義する。`HunterRunnerDependencies` と `ProcessUrlDependencies` は原則8フィールド以内とし、超える場合は `runner`, `context`, `normalizer` など責務別に依存オブジェクトを分ける。`self` 全体や `InjectionManagerAgent` import は禁止する。
- [ ] ステップ6: 分割前の observability baseline を固定する。代表 dispatch fixture または既存テストで `target_url`, `vuln_type`, `scan_profile`, `phase`, `retry_count`, `timeout_seconds`, `skip_reason` のログ/結果キーが観測できることを確認し、work_log に記録する。
- [x] ステップ7: `run_lfi_check`, `run_open_redirect_check`, `run_cors_hunter` から `tool_runners.py` へ移動する。blind correlation を持たない runner で template を固定し、戻り dict、`current_context["findings"]` append 増分、`findings_count` の一致を character test で確認する。
- [x] ステップ8: `run_sqli_hunter`, `run_xss_hunter`, `run_cmd_ssrf_hunter`, `run_ssrf_hunter` を `tool_runners.py` へ移動する。`last_tested_params`, `last_blind_correlation`, `reflection_observed`, `evidence`, `poc_request`, `poc_response` の fallback 差分を character test で確認する。
- [x] ステップ9: `run_ssti_hunter`, `run_crlf_hunter`, `run_graphql_hunter` を `tool_runners.py` へ移動する。`execute` と `execute_with_retry` の使い分け、GraphQL / CRLF / SSTI 固有 result key を snapshot assert で固定する。
- [x] ステップ10: runner 移動後に `tool_runners.py` の行数を確認する。単一ファイルが500行を超える場合は、その時点で追加分割候補を work_report の deferred_tasks に残し、無理に同ファイルへ集約しない。
- [x] ステップ11: `_process_single_url` の result 初期値と branch 実行を `process_url_dispatcher.py` へ移す。manager 側は `detection_mode` 解決、cache key 生成、cache 書き込み、例外時 cache shape の所有を残すか、移動する場合は `ProcessUrlDependencies` で明示注入する。
- [x] ステップ12: `_process_single_url` 移動では、branch ごとに `findings_count` と `current_context["findings"][-findings_count:]` の対応を character test で確認する。`findings` append 前後の list length、戻り `findings_count`、戻り `findings` slice が一致しない場合は停止する。
- [x] ステップ13: `_process_single_url` の unknown branch は二段階で扱う。まず classification-only branch を現状 helper のまま維持し、次に `_run_unknown_hypothesis_scans` branch を wrapper 経由で呼ぶ。IDOR candidate 追加と `unknown_profile` key の互換を確認する。
- [x] ステップ14: broad `except Exception` を含む移動対象では、例外時 cache entry、error field、または log message を character test で固定する。移動中に例外が silent skip として見える場合は停止し、例外の発生位置を切り分ける。
- [x] ステップ15: `specialist_factory.py` を追加し、`_initialize_specialists` の lazy import 表を移す。ImportError 時の warning 文言、specialist key 欠落挙動、初期化順を変えない。
- [x] ステップ16: `tool_registration.py` を追加し、`_register_manager_tools` と `_register_initial_tools` の登録表を移す。`register_tool` の呼び出し順、tool 名、既存 LLM action `run_sqli_hunter(...)` を維持する。
- [ ] ステップ17: `cache_policy.py` または既存 `execution_policy.py` に `_extract_security_level`, `_generate_cache_key`, `_should_bypass_cache`, `_collect_recent_tested_params` の純粋寄り処理を移す。manager 側には backward-compatible wrapper を残す。
- [ ] ステップ18: `tool_param_normalizer.py` を追加するか `tool_runners.py` に `_normalize_param_name_hints` と `_normalize_tool_supplied_params` を移す。`param`, `parameter`, `payload`, `discovered_params`, `candidate_params`, `params_list` の優先順位を変えない。
- [ ] ステップ19: `_summarize_phase1_signals` を `phase1_results.py` へ移す。manager 側 wrapper を残し、blind correlation が未 confirmed の場合は weak signal にしない既存テストを維持する。
- [x] ステップ20: `_run_unknown_hypothesis_scans` を `unknown_scan_runner.py` へ移す。selected specialist loop の順序、merged `tested_params`, `reflection_observed`, `xss_evidence`, `blind_correlation`, `findings` slice を維持する。
- [ ] ステップ21: `dispatch` は丸ごと動かさず、Phase2 gate の純粋 helper だけ抽出する。候補は early return result builder、safe skip result builder、phase2 timeout partial result builder、phase1 summary log builder とする。Phase1 target loop、timeout retry、circuit breaker は facade に残す。
- [ ] ステップ22: Phase2 gate を抽出した場合は、`SwarmResult.execution_log` の `reason`, `urls_checked`, `skip_reason_counts`, `phase2_forced_by_risk`, `high_risk_requires_phase2`, `max_ssrf_score`, `lane2_score_eligible` の shape を snapshot assert で固定する。
- [x] ステップ23: 各段階で targeted tests を実行し、失敗時はその段階で停止する。特に `tests/core/agents/swarm/injection/test_manager_phase2_lane2_integration.py` と `test_crlf_pipeline.py` は dispatch / timeout / runner の代表回帰として必須にする。
- [x] ステップ24: import cleanup は最後に行う。`manager.py` から不要 import を削る前に AST parse と targeted tests を通し、他 branch が使う symbol を誤削除しない。
- [x] ステップ25: 静的境界チェックを実行する。新規/変更 `manager_internal/*` に `InjectionManagerAgent`, `self.`, `AsyncNetworkClient(`, `.close(`, `dispatch(` の不適切な混入がないことを `rg` で確認し、例外が必要な場合は work_report に理由を記録する。
- [x] ステップ26: 完了時に `wc -l`, targeted pytest, 関連広域 pytest, performance/observability baseline 比較、`graphify update .`, work_report, work_log, docs validation を実行し、削減行数・既知 failure・未着手領域を記録する。

## 4.1 推奨検証コマンド

- [ ] `.venv/bin/pytest tests/core/agents/swarm/test_injection_manager.py`
- [ ] `.venv/bin/pytest tests/core/agents/swarm/injection/test_graphql_pipeline.py tests/core/agents/swarm/injection/test_crlf_pipeline.py`
- [ ] `.venv/bin/pytest tests/core/agents/swarm/injection/test_manager_phase2_lane2_integration.py tests/core/agents/swarm/injection/test_manager_p1_metadata.py`
- [ ] `.venv/bin/pytest tests/core/agents/swarm/injection/test_manager_phase2_lane2_integration.py -k "timeout or circuit or lane2"`
- [ ] `.venv/bin/pytest tests/core/agents/swarm/injection/test_manager_result_normalizer_character.py tests/core/agents/swarm/injection/test_process_url_unknown_classification_character.py`
- [ ] `.venv/bin/pytest tests/core/agents/swarm/injection/`
- [ ] `.venv/bin/python - <<'PY'` 形式の AST parse で `manager.py` と `manager_internal/*.py` の構文を確認する。
- [ ] `wc -l src/core/agents/swarm/injection/manager.py src/core/agents/swarm/injection/manager_internal/*.py`
- [ ] `rg -n "self\\.|InjectionManagerAgent" src/core/agents/swarm/injection/manager_internal/tool_runners.py src/core/agents/swarm/injection/manager_internal/process_url_dispatcher.py src/core/agents/swarm/injection/manager_internal/unknown_scan_runner.py`
- [ ] `rg -n "AsyncNetworkClient\\(|\\.close\\(|dispatch\\(" src/core/agents/swarm/injection/manager_internal/`
- [ ] `graphify update .`
- [ ] `python3 scripts/sync_shigoku_updated_at.py`
- [ ] `python3 scripts/validate_shigoku_docs.py`

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] `dispatch` は最大塊だが、Phase1 loop、timeout retry、circuit breaker、Phase2 gate、execution log が密結合している。 - 丸ごと移動は禁止し、Phase2 gate / result builder のような純粋寄り部分だけを条件付きで抽出する。
- [ ] [重要度:高] `_process_single_url` を外へ動かすと、cache shape と result dict key が静かにずれる可能性がある。 - manager wrapper と character test を残し、cache 書き込みは最後まで facade owner にするか依存オブジェクトで明示する。
- [ ] [重要度:高] `run_*_hunter` 群は LLM tool として公開されており、method 名や戻り dict が変わると Phase2 tool use が壊れる。 - public wrapper を残し、tool 登録名・戻りキー・error dict を変更しない。
- [ ] [重要度:中] specialist 初期化を factory 化すると import failure の扱いが変わり、環境差分で specialist availability が変わる可能性がある。 - ImportError 時の warning と key 欠落挙動を character test または snapshot で固定する。
- [ ] [重要度:中] helper 抽出後に `manager_internal` から facade へ逆参照すると、巨大 object が別ファイルへ移るだけになる。 - `self` 全体の注入は禁止し、`TypedDict` / 明示引数で依存を限定する。
- [ ] [重要度:中] `rg "self\\.|InjectionManagerAgent"` だけでは callback 経由の過剰依存を検出できない。 - 依存オブジェクトのフィールドをレビューし、`current_context` mutation と network client ownership を増やさない。
- [ ] [重要度:中] 既存の `manager_internal/api_probe_runner.py` は既に 1000 行級であり、追加移動先が再び巨大化する可能性がある。 - 新規移動は `tool_runners`, `process_url_dispatcher`, `phase2_gate` など責務別に分散し、`api_probe_runner.py` へ追加集約しない。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0279-D01
    title: "継続監視: InjectionManager 追加分割後の Phase1/Phase2 互換性"
    reason: "run_*_hunter と _process_single_url を外出ししても、Phase1 result shape と Phase2 tool use の観測が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "代表セッションで timeout_count, phase2_forced_count, cache_hit_count, validated_rejected_ratio を分割前後比較する"
```

## 5.2 懸念点と対策（レビュー観点別）

### SRE / インフラエンジニア視点
- [ ] 【発生確率: 中】【影響度: 大】`_process_single_url` や runner 移動で timeout / retry / circuit breaker のログ地点が散り、運用時に原因追跡しづらくなる。 - 対策: common log keys `target_url`, `vuln_type`, `scan_profile`, `phase`, `retry_count`, `timeout_seconds`, `skip_reason` を維持する。
- [ ] 【発生確率: 中】【影響度: 大】network client ownership が helper 側へ漏れ、close 漏れや ephemeral client 増加が起きる。 - 対策: client 生成・保持・close は facade に限定し、分割先では注入された client または callable だけを使う。
- [ ] 【発生確率: 高】【影響度: 中】行数削減後に performance regression があっても unit test だけでは検出できない。 - 対策: `per-target duration`, `manager total duration`, `Phase1 completed URLs`, `timeout_count` を work_report に残す。
- [ ] 【発生確率: 高】【影響度: 大】timeout / retry / circuit breaker の意味が抽出で変わる。 - 対策: `test_manager_phase2_lane2_integration.py -k "timeout or circuit or lane2"` を必須検証にし、新規 failure が出たら `dispatch` 周辺の抽出を停止する。
- [ ] 【発生確率: 中】【影響度: 大】ログキー維持が方針だけで、分割前後の比較可能性が弱い。 - 対策: `target_url`, `vuln_type`, `retry_count`, `timeout_seconds`, `skip_reason` のログ/結果出現を代表 fixture または caplog で確認し、work_log に記録する。
- [ ] 【発生確率: 中】【影響度: 大】network client lifecycle が helper 側へ漏れる。 - 対策: 新規/変更 `manager_internal/*` に `AsyncNetworkClient(`, `.close(`, client owner import がないことを `rg` で確認する。
- [ ] 【発生確率: 高】【影響度: 中】performance regression が unit test だけでは見えない。 - 対策: 代表 dispatch fixture で `per-target duration`, `manager total duration`, `timeout_count` を work_report に記録する。

### ソフトウェアアーキテクト視点
- [ ] 【発生確率: 高】【影響度: 大】`manager_internal` に facade 全体を渡すと、god object がファイル分割されただけになる。 - 対策: `HunterRunnerDependencies`, `ProcessUrlDependencies` などで依存を型として固定し、`self` 注入を禁止する。
- [ ] 【発生確率: 中】【影響度: 中】責務別ではなく vuln type 別に分割すると、specialist routing と result normalization が重複する。 - 対策: `tool_runners`, `process_url_dispatcher`, `cache_policy`, `phase2_gate` の責務別分割を優先する。
- [ ] 【発生確率: 中】【影響度: 中】wrapper を残しすぎると行数削減効果が薄い。 - 対策: public / patch 互換が必要な wrapper だけ残し、内部専用 thin wrapper は呼び出し元を直接 import に寄せる。
- [ ] 【発生確率: 高】【影響度: 大】`HunterRunnerDependencies` などが巨大化し、`self` を分解しただけになる。 - 対策: 依存オブジェクトは原則8フィールド以内とし、超える場合は `runner`, `context`, `normalizer` に分割する。
- [ ] 【発生確率: 中】【影響度: 大】`tool_runners.py` が次の1000行級ファイルになる。 - 対策: 移動後に `manager_internal/*.py` の行数を確認し、単一ファイル500行超なら二次分割候補を work_report に残す。
- [ ] 【発生確率: 中】【影響度: 中】`tool_runners.py` と `process_url_dispatcher.py` の責務境界が曖昧になる。 - 対策: `tool_runners.py` は specialist 実行と戻り dict 整形のみ、`process_url_dispatcher.py` は vuln_type 分岐のみ、cache 書き込みは facade owner または明示依存に限定する。
- [ ] 【発生確率: 中】【影響度: 中】wrapper 残置の判断基準が曖昧になる。 - 対策: public tool / 既存 patch 対象 / 外部 import 対象のみ wrapper 残置とし、内部専用 thin wrapper は呼び出し元を直接 import に変更する。

### デバッガー視点
- [ ] 【発生確率: 高】【影響度: 大】`_process_single_url` の結果が壊れたとき、runner、normalizer、cache、unknown branch のどこで壊れたか切り分けづらい。 - 対策: 切り分け順序を `process_url_dispatcher -> tool_runners / builtin probes / unknown_scan_runner -> result_normalizer -> cache_policy` に固定する。
- [ ] 【発生確率: 中】【影響度: 大】`findings_count` と `current_context["findings"][-findings_count:]` の関係が移動で崩れる。 - 対策: findings append 増分と slice 対象を character test で確認する。
- [ ] 【発生確率: 中】【影響度: 中】GraphQL / CRLF / SSRF の固有 result key が format helper 統合で落ちる。 - 対策: `test_graphql_pipeline.py`, `test_crlf_pipeline.py`, `test_ssrf_pipeline.py`, `test_manager_p1_metadata.py` を局所回帰に含める。
- [ ] 【発生確率: 高】【影響度: 大】`_process_single_url` の failure で原因層が追えない。 - 対策: branch result の `findings_count`, `tested_params`, `unknown_profile`, `blind_correlation`, cache entry を段階ごとに character test で固定し、本番 result shape は変更しない。
- [ ] 【発生確率: 中】【影響度: 大】`findings_count` と `current_context["findings"]` slice がずれる。 - 対策: findings append 前後の list length と戻り `findings_count` を assert する character test を追加する。
- [ ] 【発生確率: 中】【影響度: 中】GraphQL / CRLF / SSRF 固有キー欠落が見逃される。 - 対策: GraphQL `introspection_enabled`, CRLF `injected_header`, SSRF `poc_request` などの固有 result keys を snapshot assert する。
- [ ] 【発生確率: 中】【影響度: 中】broad `except Exception` が移動後の依存漏れを隠す。 - 対策: 移動対象で broad exception がある場合、例外時 cache entry / error field / log message を character test で固定する。

### CTO視点
- [ ] 【発生確率: 高】【影響度: 大】最大行数の `dispatch` を先に動かすと、レビュー不能な大差分になり検出価値を壊す。 - 対策: 行数順の候補は明記するが、実装順は `run_*_hunter` -> `_process_single_url` -> factory / helper -> partial dispatch とする。
- [ ] 【発生確率: 中】【影響度: 大】全体の成功指標が「行数が減った」だけになる。 - 対策: 成功条件を public behavior、targeted tests、Phase1/Phase2 observability、result shape 互換に置く。
- [ ] 【発生確率: 中】【影響度: 大】SGK-2026-0265 完了済みタスクを再オープンして追跡が曖昧になる。 - 対策: 本タスク `SGK-2026-0279` を active follow-up として追跡し、親計画は done のまま維持する。
- [ ] 【発生確率: 高】【影響度: 大】行数削減が目的化して検出価値が落ちる。 - 対策: 削減行数より、Phase1 finding count、tested_params、evidence shape、Phase2 tool use 互換を優先する。
- [ ] 【発生確率: 中】【影響度: 大】スコープが広く、1タスクでレビュー不能になる。 - 対策: 各ステップを独立 patch 単位にし、`run_*_hunter` 完了後と `_process_single_url` 完了後に GO/NO-GO 判断を行う。
- [ ] 【発生確率: 中】【影響度: 大】既存 failure と新規 regression が混ざる。 - 対策: baseline pytest の pass/fail と既知 failure 名を記録し、未説明 failure がある場合は実装停止する。
- [ ] 【発生確率: 低】【影響度: 大】親タスク `SGK-2026-0265` との完了/未完了境界が曖昧になる。 - 対策: `SGK-2026-0265` は done 維持、`SGK-2026-0279` の work_report に親計画との差分と未着手領域を明記する。

## 6. 完了条件
- [x] `manager.py` の行数が削減され、削減前後の `wc -l` が work_report に記録されている。
- [x] `run_*_hunter` 群、`_process_single_url`、helper 群のうち、実施した範囲の public wrapper 互換がテストで確認されている。
- [x] `dispatch` 丸ごと移動を行っていない。もし Phase2 gate を抽出した場合は、Phase1 loop と timeout retry / circuit breaker の意味が変わっていないことをテストで確認している。
- [x] `manager_internal` の新規/変更モジュールが `InjectionManagerAgent` 全体を import していない。
- [x] 新規/変更 `manager_internal/*` が network client owner になっていないことを `rg` で確認している。
- [x] baseline failure と新規 regression を区別できる記録が work_log / work_report に残っている。
- [x] Phase1 finding count、tested_params、evidence shape、Phase2 tool use 互換を行数削減より優先して確認している。
- [x] targeted tests と関連広域 tests の結果、既知 failure の有無、未実施理由が work_report に明記されている。
- [x] `graphify update .`、`python3 scripts/sync_shigoku_updated_at.py`、`python3 scripts/validate_shigoku_docs.py` が実行されている。
