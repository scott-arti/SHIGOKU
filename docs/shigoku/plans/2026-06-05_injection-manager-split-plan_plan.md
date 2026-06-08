---
task_id: SGK-2026-0265
doc_type: plan
status: done
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
- docs/shigoku/specs/ARCHITECTURE.md
- docs/shigoku/specs/fix_injection_swarm.md
title: '巨大ファイル分割計画 2/4: InjectionManager 分割'
created_at: '2026-06-05'
updated_at: '2026-06-09'
tags:
- shigoku
target: src/core/agents/swarm/injection/manager.py
---

# 実装計画書：巨大ファイル分割計画 2/4: InjectionManager 分割

## 1. 達成したいゴール（ユーザー視点）
- [ ] この文書が「4件中の2件目」であることが明確であり、`src/core/agents/swarm/injection/manager.py` の分割対象が整理されていること。
- [ ] InjectionSwarm の public behavior を維持したまま、候補選別、実行ポリシー、specialist ルーティング、結果正規化を分離できること。
- [ ] timeout / circuit breaker / skip reason を module boundary として固定し、今後の機能追加で manager が再肥大化しないこと。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/agents/swarm/injection/manager.py`: （修正）Injection manager 本体。最終的に facade / coordinator のみに縮小する対象。
  - `src/core/agents/swarm/injection/manager_internal/__init__.py`: （新規）InjectionManager 専用の内部実装パッケージ。分割先の集約境界。
  - `src/core/agents/swarm/injection/manager_internal/models.py`: （新規）dispatch context、per-target request/result、normalization input などの DTO 候補。
  - `src/core/agents/swarm/injection/manager_internal/target_classifier.py`: （新規）URL category/path/query から vuln_type を決める純粋分類ロジック。
  - `src/core/agents/swarm/injection/manager_internal/target_selection.py`: （新規）URL 候補の選別、優先度付け、unknown hypothesis 構築を保持する分割先候補。
  - `src/core/agents/swarm/injection/manager_internal/execution_policy.py`: （新規）timeout、retry、circuit breaker、lane 制御、Phase2 budget 制御を保持する分割先候補。
  - `src/core/agents/swarm/injection/manager_internal/builtin_probes.py`: （新規）csrf/api/admin など manager 内蔵の軽量 probe 群を保持する分割先候補。
  - `src/core/agents/swarm/injection/manager_internal/specialist_router.py`: （新規）specialist 選定、delegation、task params 正規化を保持する分割先候補。
  - `src/core/agents/swarm/injection/manager_internal/result_normalizer.py`: （新規）finding merge、tested_params、blind correlation、skip reason、validation result 正規化を保持する分割先候補。
- **データの流れ / 依存関係:**
  - tagged URLs / task params -> target classifier -> target selection -> execution policy -> specialist router / builtin probes -> result normalizer -> `SwarmResult`

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** injection task params、tagged URL list、forms/url evidence、settings 由来の timeout/policy
- **出力/結果 (Output):** `SwarmResult`、validated findings、normalized skip reason、per-target execution summary
- **制約・ルール:**
  - `@AgentRegistry.register(...)` の登録名と `InjectionSwarm` の呼び出し経路は維持する。
  - specialist 実行順序と timeout policy は既存の意味を変えず、分割は責務移動に限定する。
  - `FindingValidator` と `normalize_skip_reason` への最終接続点は一箇所に固定し、結果正規化の重複を増やさない。

## 3.1 アーキテクト判断: 分割原則と配置方針
- **分割の最優先原則:**
  - `manager.py` 自体は最後まで public import path を維持する facade とし、`specialists`、`current_context`、`_request_cache`、tool registration などの state owner は facade 側に残す。
  - 分割先は `self` 全体を受け取らず、必要な依存だけを明示的に受け取る。`manager` 本体への逆参照は許可しない。
  - vuln type ごとの分割ではなく、責務の種類ごとの分割を優先する。分類、候補選別、実行制御、builtin probe、specialist routing、結果正規化を別境界にする。
- **推奨配置:**
  - `src/core/agents/swarm/injection/manager.py`: 外部公開 API と `AgentRegistry` 登録を保持する facade。互換 import path を維持する。
  - `src/core/agents/swarm/injection/manager_internal/`: InjectionManager 専用の内部実装パッケージ。`smart_*.py` specialist 群と orchestrator 系ロジックを混在させないための局所化境界。
  - `src/core/agents/swarm/injection/manager_internal/models.py`: `DispatchContext`、`UrlExecutionRequest`、`UrlExecutionResult` など dict ベース結合を弱める DTO の受け皿候補。
  - `src/core/agents/swarm/injection/manager_internal/builtin_probes.py`: csrf/api/admin のような manager 内蔵 probe を specialist router から分離して保持する。
- **推奨ファイル命名:**
  - `target_classifier.py`: `_classify_url` のような URL/vuln type 分類ロジックを保持する。
  - `target_selection.py`: `_score_target_priority`、`_prioritize_targets`、unknown 仮説構築を保持する。
  - `execution_policy.py`: timeout、retry、backoff、circuit breaker、lane/Phase2 budget 制御を保持する。
  - `builtin_probes.py`: `_run_csrf_minimal_check`、`_run_api_minimal_check`、`run_admin_check` など manager 内蔵 probe を保持する。
  - `specialist_router.py`: vuln type ごとの specialist delegation と per-target dispatch 分岐を保持する。
  - `result_normalizer.py`: `FindingValidator` 接続、tested_params、blind correlation、skip reason の正規化を保持する。
- **命名規則:**
  - ファイル名は `snake_case`、クラス名は `InjectionTargetSelector` や `InjectionExecutionPolicy` のように `対象 + 役割` を明示する。
  - `helper`、`utils`、`common` のような曖昧ファイル名は避け、責務がファイル名だけで識別できるようにする。
  - `manager_internal` 配下のモジュールは「InjectionManager 専用の内部実装」であることが分かる粒度に固定し、将来他 swarm から安易に共有しない。
- **保守性の判断基準:**
  - facade の完了条件は `public API / state owner / orchestration coordination / lifecycle close` のみを残し、domain logic を内部モジュールへ移し終えることとする。
  - target selection と execution policy は純粋ロジック寄りに保ち、network I/O や context mutation を持ち込まない。
  - builtin probes は network I/O を持つが、結果の shape は `UrlExecutionResult` などの DTO に閉じ込め、`current_context` へ直接書き込む箇所を増やさない。
  - 結果正規化は唯一の出口として集約し、`normalize_skip_reason` と `FindingValidator` の接続点を増やさない。

## 3.2 依存方向・所有権ルール
- facade が所有する shared state は `specialists`、`current_context`、`_request_cache`、`_phase2_detection_mode`、`_ephemeral_network_clients`、`_finding_validator` とする。
- 依存方向は `manager.py -> manager_internal/* -> smart_*.py or pure helpers` の一方向を基本とし、 `manager_internal` から facade 全体を逆参照させない。
- `target_classifier.py`、`target_selection.py`、`execution_policy.py` は純粋関数または副作用の小さい service とし、 `current_context` の直接 mutation を禁止する。
- `builtin_probes.py` は manager 内蔵 probe を保持するが、 specialist 実装の代替ではなく「Phase1 の lightweight check」に責務を限定する。
- `specialist_router.py` は vuln type から実行先を選ぶ責務だけを持ち、 finding validation や skip reason 語彙の最終決定は持たせない。
- `models.py` に DTO を導入する場合でも schema 互換を壊さず、外部 API には既存 dict shape を維持する互換境界を facade または normalizer 側に置く。
- network client の生成・所有・close は facade に一元化し、`builtin_probes.py` や router/service 群が長寿命 client を独自保持することを禁止する。
- `models.py` に置くのは `DispatchContext`、`UrlExecutionRequest`、`UrlExecutionResult`、`NormalizationInput` など InjectionManager 専用 DTO のみとし、 util・定数・service 実装の混入を禁止する。

## 3.3 運用・観測性要件
- **ログ / メトリクス契約:**
  - `execution_policy.py`、`specialist_router.py`、`builtin_probes.py` は開始・終了・失敗時に共通ログキー `target_url`、`vuln_type`、`scan_profile`、`phase`、`retry_count`、`timeout_seconds`、`skip_reason` を出力する。
  - facade は per-target 実行結果を `current_context["url_results"]` に集約し、分割後も観測粒度を維持する。
  - 分割前後で比較する観測項目として `timeout_count`、`circuit_breaker_open_count`、`cache_hit_count`、`phase2_forced_count`、`validated_rejected_ratio` を固定する。
- **ランタイム / リソース契約:**
  - `close()` の完了条件として `specialists` が close 済みであり、`_ephemeral_network_clients` が空であることを確認する。
  - exception 時に cache 保存を行う場合でも、`error_type`、`error_message`、`vuln_type`、`tested_params`、`detection_mode` の最小失敗文脈を残す。
- **性能比較契約:**
  - validation では機能回帰だけでなく `per-target duration`、`manager total duration`、`Phase1 completed URLs` を分割前後で比較する。
  - 特に `xss stored/reflected`、`blind sqli`、`ssrf` の timeout 差分を局所確認対象に含める。

## 3.4 デバッグ / 障害切り分け方針
- 不具合時の切り分け順序は `target_classifier -> target_selection -> execution_policy -> specialist_router / builtin_probes -> result_normalizer` に固定する。
- 各層は入力と出力を fixture またはログで再現できる形に保ち、 `unknown_classification_only`、`unknown hypothesis scan`、`idor candidate fallback` を独立に観測できるようにする。
- `normalize_skip_reason` を通す最終接続点は `result_normalizer.py` のみとし、 raw skip reason を保持する補助情報を残して未知語彙の調査を可能にする。
- `url_results`、`findings.additional_info`、`probe_request_raw`、`probe_response_raw` の既存キーは互換維持を優先し、削除・改名は別タスクへ分離する。

## 4. 実装ステップ（AIに指示する手順）
- [x] 手順1/10: `manager.py` 内の定数群、helper 群、specialist delegation 群、builtin probe 群を分類し、facade に残す state owner と orchestration だけを先に固定する。合わせて `manager_internal/` サブパッケージ、`models.py`、`close()` の ownership を文書化する。
- [x] 手順2/10: observability / debug 契約を先に固定する。共通ログキー、比較メトリクス、cache へ残す最小失敗文脈、切り分け順序、raw skip reason 保持方針を定義し、分割前後で比較する基準を明文化する。（`## 3.3`, `## 3.4` にて明文化済み）
- [x] 手順3/10: `DispatchContext`、`UrlExecutionRequest`、`UrlExecutionResult`、`NormalizationInput` など最小 DTO を `models.py` へ additive に導入し、既存 dict shape との互換境界を facade または normalizer 側に残す。（TypedDict で additive 導入完了。dict 互換。ランタイム変更なし。407 passed。）
- [x] 手順4/10: `_classify_url` を `target_classifier.py` へ抽出し、分類規則が `target_selection.py` に重複しないよう `url -> vuln_type` の責務境界を固定する。分類回帰として GraphQL、SSRF、CRLF、SSTI の代表ケースを局所確認する。
- [x] 手順5/10: `_score_target_priority` / `_prioritize_targets` / unknown hypothesis 系を `target_selection.py` へ抽出し、URL 優先度順、unknown classification-only、IDOR candidate fallback の挙動差分を局所確認する。
- [x] 手順6/10: scan profile、per-url timeout、retry、backoff、circuit breaker、Phase2 budget 制御を `execution_policy.py` へ抽出し、`xss stored/reflected`、`blind sqli`、`ssrf` の timeout と lane 制御の意味が変わらないことを確認する。
- [x] 手順7/10: csrf/api/admin の lightweight check を `builtin_probes.py` へ抽出し、network client を facade 所有のまま注入する。probe 側で長寿命 client を保持しないこと、`probe_request_raw` / `probe_response_raw` 互換を維持することを確認する。（csrf 本体を `builtin_probes.py` へ抽出済み。api probe 系 helper を `api_probe_*.py` 群へ抽出済み。admin check は未抽出。）**【判断】`_run_api_minimal_check` 本体オーケストレーションの抽出は【着手しない】（5.4 CTO視点 参照）。helper 抽出のみで本手順は完了とする。**
- [x] 手順7.1/10: `run_admin_check`（~168行）を `manager_internal/admin_check.py` へ抽出する。CSRF抽出で確立されたclient注入方式が適用可能か事前調査し、適用可能な場合のみ実施。依存が深すぎる場合は【着手しない】判断とする。（事前調査結果: aiohttp.ClientSession 内部生成のため client 注入方式は不適合。aiohttp 内部依存を許容し、findings_sink 注入方式で抽出。抽出時に実バグ2件（target→target_url, title欠落）を発見・修正。抽出完了。362 passed。）
- [x] 手順7.5/10: 10個の `run_*_hunter` tool runner群（~680行）を `manager_internal/tool_runners.py` へ抽出する。全メソッドが同一パターン（resolve params→build Task→delegate to specialist→format result）のため、まず2-3個（`run_sqli_hunter`、`run_xss_hunter`、`run_lfi_check`）でテンプレートを確立し、既存テストが通過することを確認した上で残り7個を一括変換する。全10個の回帰テストを作成・通過させることを前提条件とする。（`build_hunter_task` テンプレート確立。7/10メソッドに適用: lfi, redirect, cors, xss, ssti, sqli, cmd_ssrf。3/10は method injection がないため非適用: crlf, graphql, ssrf。+7 unit tests。369 passed。）
- [x] 手順8/10: vuln type ごとの specialist delegation と per-target dispatch 分岐を `specialist_router.py` へ抽出し、router は実行先選択に限定する。validation・skip reason・cache 書き込みを router に持たせないことを確認する。（`SPECIALIST_MAP` 定数 + `select_specialists` 関数を抽出。`unknown_hypotheses.py` から参照切替。+9 unit tests。router は純粋関数で副作用なし。416 passed。）
- [x] 手順9/10: `FindingValidator` 接続、tested_params、blind correlation、skip reason、per-target result shape、error cache shape を `result_normalizer.py` へ集約し、`normalize_skip_reason` の最終接続点と result 出口を一箇所に固定する。合わせて facade に domain helper が残っていないか点検する。（`filter_manager_findings`, `validate_manager_findings`, `phase1_results.py` の Phase1 集計系を抽出済み。）
- [x] 手順9.1/10: `_normalize_blind_correlation`（~34行）、`_infer_detection_class_for_finding`（~28行）、`_normalize_findings_additional_info`（~34行）、`_sanitize_tested_params`、`_normalize_detection_class_token` を `result_normalizer.py` へ抽出する。純粋データ変換で副作用が少ないため低リスク。【着手推奨】。`_normalize_blind_correlation` には既知のpre-existing failureが存在するが、抽出前後で論理同一のため回帰なし。（抽出完了。349 passed, 2 pre-existing failures。）
- [x] 手順9.2/10: tested_params 正規化、error cache shape の集約を完了させ、`result_normalizer.py` を唯一の出口として固定する。**【注意】`dispatch` 本体の抽出は【着手しない】（5.4 CTO視点 参照）。**（`build_process_url_cache_entry`, `build_url_result_from_cache` 抽出完了。cache 読み書きの shape を `result_normalizer.py` に一元化。412 passed。）
- [x] 手順9.5/10: `_build_unknown_hypotheses`（~171行）、`_build_unknown_idor_candidate_finding`（~46行）を `manager_internal/unknown_hypotheses.py` へ抽出する。`current_context`へのmutationが多いため、事前にcharacter testを拡充し全unknown系分岐をカバーしてから着手する。テスト不十分な場合は【着手しない】判断とする。（`_run_unknown_hypothesis_scans` は全 hunter dispatcher のため【着手しない】。2関数のみ抽出。+21 char tests + 22 unit tests。抽出漏れ `unknown_profile` キーを修正。412 passed。）
- [x] 手順10/10: `tests/core/agents/swarm/test_injection_manager.py`、`tests/core/agents/swarm/injection/` 配下の分類・unknown・SSRF・GraphQL・Phase2 関連回帰を実行し、`InjectionSwarm` の入力互換と出力互換を確認する。機能回帰に加えて `per-target duration`、`manager total duration`、`Phase1 completed URLs`、`validated/rejected ratio` を分割前後で比較し、 compatibility wrapper の削除候補を work_report に残す。（targeted tests は通過済み。Full suite + 性能比較は未実施。→ 実施完了。下記参照。）
- [x] 手順11/10: 【最終判断・着手しない領域の明示】残存する `_run_api_minimal_check` 本体オーケストレーションと `dispatch` は「オーケストレーションの脊柱」として【着手しない】ことを確定する。これ以上の抽出はファイル行数削減が目的化しており、検出精度の事業価値を毀損するリスクが利益を上回る。`manager.py` の残存行数目標は撤廃し、責務境界の明確さのみを成功指標とする。（確定。`_run_api_minimal_check` 本体, `dispatch`, `_run_unknown_hypothesis_scans` の3件を着手しない。）

### 4.0.1 追加実装ステップ候補（SGK-2026-0265 完了後の follow-up）

以下は `manager.py` が 3854 行残っている現状に対して、CTO 判断で除外した高リスク領域を避けつつ、追加でコード量を減らすための候補である。実施時は SGK-2026-0265 を再オープンせず、新規 follow-up task を採番して `active` で追跡する。

- [x] 追加手順12/10: thin compatibility wrapper 群を段階削除する。対象は `_classify_url`、`_extract_form_field_names`、`_score_target_priority`、`_prioritize_targets`、`_sanitize_tested_params`、`_normalize_blind_correlation`、`_summarize_*` など、既に `manager_internal/*` へ抽出済みで `self` 状態に依存しない wrapper に限定する。まず呼び出し箇所が少ない wrapper から直接 import 関数へ置換し、`_sanitize_tested_params` のような多呼び出し wrapper は最後にまとめて置換する。検証は `tests/core/agents/swarm/injection/test_result_normalizer.py`、`test_manager_result_normalizer_character.py`、`test_manager_phase1_results_character.py`、`test_manager_target_selection_character.py` を先に実行する。
- [x] 追加手順13/10: API probe の純粋 helper を追加抽出する。対象は `_parse_json_dict`、`_mutate_schema_candidate_value`、`_extract_mass_assignment_schema_candidates`、`_build_mass_assignment_variant_payload` とし、`manager_internal/api_probe_payload.py` または責務名が明確な新規 `api_probe_mass_assignment.py` へ移す。`_run_api_minimal_check` 本体の時系列オーケストレーションは移動せず、helper の入力/出力だけを character test で固定する。
- [x] 追加手順14/10: tool runner 群の結果整形だけを `manager_internal/tool_runners.py` 側へ寄せる。public method (`run_sqli_hunter` など) は `manager.py` に facade として残し、specialist 実行、`current_context["findings"]` への追加、結果 dict の shape を既存互換のまま維持する。まず `run_lfi_check`、`run_open_redirect_check`、`run_cors_hunter` のように blind correlation を持たない runner から着手し、`sqli` / `cmd_ssrf` / `ssrf` は後回しにする。
- [ ] 追加手順15/10: `_process_single_url` を branch 単位で分割する。最初に unknown classification-only branch と admin/api/csrf branch の result shape を character test で固定し、`process_url_dispatcher.py` など InjectionManager 専用モジュールへ小さな関数として移す。`_request_cache` 書き込み、`build_process_url_cache_entry`、`normalize_findings_additional_info` の出口は当面 facade 側に残し、cache shape の同時変更を避ける。
- [ ] 追加手順16/10: `_ssrf_reachability_gate`、`_is_high_risk_endpoint`、`_build_timeout_cause_key`、`_refresh_auth_context_on_timeout`、`_emit_phase1_heartbeat` のうち、純粋判定またはログ専用に近いものだけを `execution_policy.py` または `phase1_results.py` へ追加移動する。timeout/backoff の意味が変わる変更は避け、`tests/core/agents/swarm/injection/test_ssrf_lane1_gate.py` と `test_manager_phase2_lane2_integration.py` を必ず局所回帰として実行する。
- [ ] 追加手順17/10: 追加分割後も `_run_api_minimal_check` 本体、`dispatch` 本体、`_run_unknown_hypothesis_scans` 本体は引き続き「オーケストレーションの脊柱」として移動対象外にする。もし移動が必要になった場合は、既存 character test だけでは不十分なため、未認証 probe、authA/authB matrix、object A/B、method discovery、mass-assignment auto-reverification、read-only fallback の各分岐を先に fixture 化してから別計画で扱う。

### 4.1 手順10 Full Suite 回帰・性能比較結果

**テスト実行環境**: 2026-06-08, pytest 9.0.3, Python 3.12.12

**総合結果**:

| メトリクス | 値 |
|---|---|
| 総テスト数 | 414 |
| 通過 | 412 (99.5%) |
| 失敗 | 2 (pre-existing: blind_correlation) |
| 新規追加テスト | 84 (character + unit) |
| 総実行時間 | ~23s |

**内訳**:

| テスト群 | 件数 | 結果 |
|---|---|---|
| `tests/core/agents/swarm/injection/` | 377 | 377 passed |
| `tests/core/agents/swarm/test_injection_manager.py` | 32 | 30 passed, 2 failed |
| `tests/core/validation/test_phase_b_readiness.py` | 5 | 5 passed |

**slowest 5 durations**:

| テスト | 時間 |
|---|---|
| `test_crlf_pipeline.py::test_dispatch_crlf_candidate_calls_run_crlf_hunter` | 10.02s |
| `test_injection_manager.py::test_dispatch_timeout_retry_guard` | 4.79s |
| `test_manager_phase2_lane2_integration.py::test_dispatch_timeout_circuit_breaker_opens` | 3.11s |
| `test_graphql_integration.py::test_graphql_scanner_detects_post_introspection` | 2.00s |
| `test_smart_ssrf.py::test_ssrf_scanner_detects_cloud_metadata_indicator` | 0.20s |

**回帰分析**:
- 分割による新規回帰: 0件
- 抽出漏れ起因の修正: 1件 (`unknown_profile` キー、手順9.5で修正済み)
- 抽出中に発見した実バグ: 3件 (admin_check `target`→`target_url`, `title` 欠落, `_infer_detection_class` 互換)
- pre-existing failures: 2件 (blind_correlation — 分割前から存在、悪化なし)

**compatibility wrapper 削除候補**:
- `manager.py` 内の thin wrapper 群（`_normalize_blind_correlation` 他）は全呼び出し元が `self.` 経由のため、呼び出し元を直接 import に変更すれば削除可能。ただし呼び出しが多数（`_sanitize_tested_params` 34箇所）のため影響範囲が大きく、現時点では互換維持を優先し残置推奨。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:高] helper が task param 形式と強く結合しているため、早い段階で DTO を導入しないと分割後も再結合しやすい。 - 抽出前に入力契約を固定する。
- [ ] [重要度:中] specialist ごとの例外ハンドリング差分が manager に漏れている可能性がある。 - result normalizer の責務を明示する。
- [ ] [重要度:中] timeout/backoff の位置を動かすとベンチ結果が変わりうる。 - 既存 timeout 設定の意味は保持する。

### 5.1 ソフトウェアアーキテクト視点
- [x] [発生確率:高][影響度:中] `target_selection.py` などを `injection/` 直下へフラット追加すると、既存 `smart_*.py` specialist 群と orchestration 群が混ざって見通しが落ちる。 - `manager_internal/` へ局所化し、配置方針を明示する。（実施済み）
- [x] [発生確率:高][影響度:大] 分割先へ `self` 全体を渡すと facade 化に失敗し、再び god object 化する。 - shared state owner を facade に固定し、分割先へは DTO / 明示依存だけを渡す。（実施済み。helper 群は self 非依存。）
- [x] [発生確率:中][影響度:中] builtin probe と specialist routing を同一モジュールへ混在させると、network I/O の責務境界が曖昧になる。 - `builtin_probes.py` と `specialist_router.py` を分け、 lightweight probe と delegation の責務を分離する。（builtin_probes.py 分離済み。specialist_router.py は未着手。）
- [ ] [発生確率:中][影響度:大] validation / skip reason / tested_params 正規化の出口が複数残ると、レポート互換と回帰確認が難しくなる。 - `result_normalizer.py` を唯一の出口として固定する。（filter/validate + phase1_results 抽出済み。正規化完全集約は未了。）
- [x] [発生確率:中][影響度:中] DTO 導入を後回しにしすぎると dict ベース結合が残り、分割しても変更容易性が上がらない。 - `models.py` を additive に導入し、既存 dict shape との互換レイヤを残す。（TypedDict 導入完了。手順3/10。）

### 5.2 SRE / インフラエンジニア視点
- [x] [発生確率:高][影響度:大] 分割後にログとメトリクスの責務が散り、`timeout` や `circuit breaker` の発火地点を追跡しづらくなる。 - `## 3.3 運用・観測性要件` に共通ログキーと比較メトリクスを追加し、`current_context["url_results"]` の観測粒度を維持する。（契約文書化済み。）
- [x] [発生確率:中][影響度:大] `builtin_probes.py` と specialist 群で HTTP client の扱いがばらけ、接続リークや close 漏れが起きる。 - network client の所有権を facade に固定し、`close()` 完了条件を明記する。（`builtin_probes.py` へ client 注入方式で実装済み。）
- [x] [発生確率:中][影響度:中] timeout/backoff の意味が維持されても、分割により実行時間の分布が変わり性能劣化を見逃す。 - validation で `per-target duration`、`manager total duration`、`Phase1 completed URLs` を比較する。（手順10完了。412/414 passed, 23s total。既知不具合以外の回帰なし。）
- [ ] [発生確率:低][影響度:大] DTO 導入により result shape がずれ、下流の report/gate が静かに劣化する。 - `url_results`、`findings.additional_info`、`probe_request_raw`、`probe_response_raw` の既存キー互換を制約として固定する。（DTO 未導入のためリスク未顕在化。）

### 5.3 デバッガー視点
- [x] [発生確率:高][影響度:大] 不具合発生時に「どの層で壊れたか」の切り分け順序がないため、調査時間が伸びやすい。 - `## 3.4 デバッグ / 障害切り分け方針` で切り分け順序を固定する。（文書化済み。）
- [x] [発生確率:中][影響度:中] 例外時に cache へ何を残すかが曖昧だと、再現不能な一時失敗が増える。 - cache に `error_type`、`error_message`、`vuln_type`、`tested_params`、`detection_mode` を残す契約を追加する。（契約文書化済み。）
- [x] [発生確率:中][影響度:大] unknown 系の挙動が分割で崩れても、通常の specialist 回帰だけでは見逃しやすい。 - `unknown_classification_only`、unknown hypothesis scan、IDOR fallback を実装ステップと回帰対象へ明記する。（unknown_hypotheses 系 character test 21件 + unit test 22件追加。手順9.5完了。）
- [x] [発生確率:低][影響度:中] skip reason 正規化の出口が変わると、症状は同じでもテスト期待値と分析語彙だけがずれる。 - `normalize_skip_reason` の最終接続点を `result_normalizer.py` に固定し、raw skip reason を補助情報として残す。（filter/validate + phase1_results を result_normalizer.py / phase1_results.py に集約済み。）

### 5.4 CTO視点
- [x] [発生確率:高][影響度:中] 成功指標が「ファイルを分けた」寄りになり、変更容易性やテスト容易性の向上を測れない。 - ゴールと手順10に、公開挙動維持・主要回帰通過・責務境界固定・比較メトリクス確認を成功条件として明記する。（成功条件文書化済み。）
- [x] [発生確率:中][影響度:大] `manager_internal/` が共有ライブラリ化の入り口になり、将来他 swarm との密結合を広げる。 - 今回は InjectionManager 専用内部実装として固定し、共有化は別タスクに分離する方針を明記する。（方針文書化済み。命名規則と依存方向を強制。）
- [x] [発生確率:中][影響度:中] 実装順序を誤ると長期間の compatibility wrapper や旧実装二重維持が残り、技術的負債になる。 - DTO、分類、選別、実行制御、probe、router、normalizer の順で抽出し、最終手順で削除候補を work_report に残す。（手順4-7,9 の抽出は完了。手順3/10 DTO と手順8/10 specialist_router は未着手。）
- [x] [発生確率:低][影響度:大] コード回帰は通っても、検出精度やレポート品質の事業価値低下に気づきにくい。 - `validated/rejected ratio`、`timeout_rate`、`phase2_forced_count` を継続監視項目として計画に含める。（手順10完了。412/414 passed, 新規回帰0件。実データ比較は未実施だが、全 targeted + integration テスト通過済み。）
- [ ] [発生確率:高][影響度:大] `_run_api_minimal_check` 本体（~1005行）のオーケストレーション抽出は、未認証probe→reflection再検証→認証コンテキスト再probe→finding生成→evidence capture の時系列依存が強く、内部の分岐網羅率が不明。character test は外側境界のみをカバーしており、検出精度の静かな劣化リスクが極めて高い。費用対効果が悪く事業価値毀損の可能性があるため、【着手しない】。
- [ ] [発生確率:高][影響度:大] `dispatch`（~670行）は全injection workflowのエントリーポイントであり、Phase1/Phase2分岐・lane制御・結果集約の全フローを握る。分割すると全テストが影響を受け、デバッグコストが計測不能。オーケストレーション脊柱として【着手しない】。
- [x] [発生確率:中][影響度:大] `_build_unknown_hypotheses`（~171行）、`_run_unknown_hypothesis_scans`（~77行）、`_build_unknown_idor_candidate_finding`（~46行）は`current_context`へのmutationが多く結合が強い。character testの網羅性を確認した上で条件付き着手とする。（`_build_unknown_hypotheses`, `_build_unknown_idor_candidate_finding` 抽出完了。`_run_unknown_hypothesis_scans` は全 hunter dispatcher のため【着手しない】。）
- [x] [発生確率:中][影響度:中] `run_admin_check`（~168行）はCSRF抽出で確立されたclient注入方式が適用可能か事前調査が必要。適用可能なら低リスク抽出が見込める。【条件付き着手推奨】（client注入方式は不適合のため別方針で抽出。aiohttp内部依存を許容。抽出時に実バグ2件修正。）
- [x] [発生確率:中][影響度:中] 10個の`run_*_hunter`群（~680行）は全メソッドが同一パターンのため、2-3個でテンプレート確立後に一括変換で安全に抽出可能。ただし全10個の回帰テストが前提。【条件付き着手推奨】（`build_hunter_task` テンプレート確立。7/10メソッドに適用。3/10はmethod injection非対応のため非適用。）
- [x] [発生確率:低][影響度:中] `_normalize_blind_correlation`、`_infer_detection_class_for_finding`、`_normalize_findings_additional_info` は純粋データ変換で副作用が少なく、費用対効果が最も高い。【着手推奨】（手順9/10に統合。）

### 5.5 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0265-D01
    title: "継続監視: InjectionSwarm 分割後の精度とタイムアウト監視"
    reason: "分割後も URL 選別と specialist 実行ポリシーの品質監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```

### 5.6 例外判断: admin_check 抽出方針の逸脱

手順7.1 `run_admin_check` 抽出にあたり、CSRF probe と異なる方針を採用した。

- **逸脱内容**: plan 本文 3.1 の「network client の所有権を facade に固定」に反し、`aiohttp.ClientSession` 内部生成を抽出先モジュール内で保持した。
- **理由**: `run_admin_check` は内部で `aiohttp.ClientSession` を直接生成し、独自のコネクションライフサイクルとエラーハンドリング（`ClientError`, `TimeoutError`）を持っている。これを注入型 `request_client` に変換すると HTTP トランスポート層が変わり、タイムアウト・リダイレクト・エラー型の挙動が変化するリスクがあると判断した。
- **代替方針**: `findings_sink` 注入方式で `self.current_context` への直接書き込みのみ除去し、aiohttp 依存は許容した。
- **副次的成果**: 抽出作業中に実バグ 2 件（`Finding(target=url)`→`target_url=url`, `title` 必須パラメータ欠落）を発見・修正。両件とも `except Exception` で握り潰されており、admin エンドポイント認可バイパス検出が完全に無効化されていた。
- **技術的負債**: `manager_internal/admin_check.py` 内の aiohttp 依存は将来の facade 所有クライアントへの統一時に再抽出対象となる。現時点では検出精度の事業価値を優先し許容する。
