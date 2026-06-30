---
task_id: SGK-2026-0221-S02
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0221
related_docs:
- docs/shigoku/plans/2026-05-19_sgk-2026-0221_mock-optimizedreciperunner-discovery-graphql_plan.md
- docs/shigoku/specs/bug_bounty_enhancements.md
- docs/shigoku/specs/2026-02-11_PHASE2_MANAGER_ARCH.md
- docs/shigoku/reports/2026-05-21_sgk-2026-0221-s02_groupb_work_report.md
- docs/shigoku/worklogs/2026-05-21_log_sgk-2026-0221-s02_groupb.md
title: 'GroupB: Discovery GraphQL 本実装接続（graphql.py / manager.py）'
created_at: '2026-05-20'
updated_at: '2026-06-30'
tags:
- shigoku
- group-b
- graphql
---

# GroupB Subtask Plan

## Goal
- Discovery の GraphQL 経路を Skeleton 判定から実HTTP検査へ置換し、`DiscoveryManager` から本実装結果を返す。

## Delivery Management (PM)
- owner: AppSec Discovery Team (GroupB)
- estimate: 2.0 engineer-days
- target_date: 2026-05-23
- milestone:
  - M1 (2026-05-22): 契約テストと異常系ユニットテスト追加
  - M2 (2026-05-23): 本実装接続と統合テスト緑化

## Scope
- `src/core/agents/swarm/discovery/graphql.py`
- `src/core/agents/swarm/discovery/manager.py`
- 必要に応じて `src/core/attack/graphql_analyzer.py` の利用接続

## Implementation Tasks
1. 契約先行フェーズ（結合度低減）:
   - `run_graphql_navigator` のI/O契約を typed adapter で固定し、`graphql.py` と `manager.py` の直接依存を adapter 経由へ集約する。
   - `error_code` / `evidence` は列挙定義を単一モジュール化し、文字列直書きを禁止する。
   - 契約互換を維持したまま将来拡張できるよう、契約バージョン（`contract_version`）を導入し、非破壊追加ルールを明文化する。
   - owner/DoD: Software Architect（Discovery） / `manager.py` と `graphql.py` の直結参照が adapter 経由へ移行し、契約型と列挙定義の単一参照化を契約テストで確認。
2. Recon拡張フェーズ（発見網羅性強化）:
   - endpoint候補抽出を multi-source 化（既知パス、HTML、JSバンドル、受動情報源）し、候補ごとに発見根拠を `evidence` へ正規化保存する。
   - APQ専用構成、WAF/CDN応答、Gatewayパスマッピングを誤判定しない判定分岐を追加する。
   - 候補爆発による下流負荷を抑えるため、候補スコアリングと早期打ち切り条件（上限件数・閾値）を導入する。
   - owner/DoD: Bug Hunter Lead（Recon） / multi-source入力でのendpoint候補抽出が有効化され、APQ/WAF/Gatewayの代表ケースで偽陰性回帰がないことをテストで確認。
3. Probe実装フェーズ（機能判定精度）:
   - introspection / GraphiQL / field suggestion 判定を単一シグナル禁止で実装し、HTTP status + body + GraphQLエラーパターンの複合判定へ統一する。
   - 壊れたJSON、HTML混在、4xx/5xx、connection/timeout を `invalid_response` 含む規定 `error_code` へ必ず正規化する。
   - 外部公開 `error_code` は維持しつつ、内部解析用の詳細サブコード（`internal_error_detail`）を追加し、運用改善に必要な粒度を確保する。
   - owner/DoD: Senior Backend Engineer（GraphQL Detection） / 3判定フラグと `error_code` 正規化が異常系テスト（TC-GQL-ERR-001〜005）で100%通過し、例外リーク0件を確認。
4. スケーラビリティ制御フェーズ（SREクリティカル対策）:
   - 全体QPS制御、ホスト単位並列上限、バックプレッシャー（キュー上限）を実装し、キュー無限成長を禁止する。
   - retry storm 回避のため、障害時リトライは jitter付きバックオフ + host quarantine + circuit breaker で制御する。
   - 接続プール上限、FD監視、DNSキャッシュ戦略を設定し、多数ホスト時の基盤枯渇を防止する。
   - タイムアウト/並列度/QPS/キュー上限は設定ファイル管理とし、環境別上書き可能にする（コード直書き禁止）。
   - owner/DoD: SRE/Infra Engineer / 負荷試験でキュー上限・QPS制御・circuit breakerが動作し、OOM/FD枯渇/retry storm再現シナリオで全体停止が発生しないことを確認。
5. 観測性統合フェーズ（ツールチェーン接続）:
   - `graphql_probe_*` をログ文字列ではなく構造化イベントとして出力し、既存 gate/check/report が直接読める形へ統一する。
   - 高負荷時のログドロップ/サンプリング方針を明文化し、観測不能時でも最小メトリクスを維持する。
   - owner/DoD: Platform Engineer（Observability） / gate/check/report が構造化イベントを解釈可能で、サンプリング時でも必須メトリクス欠落なしを検証。
6. 認証コンテキスト対応フェーズ（実運用面）:
   - 未認証/認証後の両方でReconを実行し、認証後にのみ露出するGraphQL surfaceを同一契約で収集する。
   - 再認証失敗時のレート制御を実装し、IdP集中アクセスによる全体停止を防止する。
   - 認証情報の保管/利用/監査要件（secret取り扱い、アクセス監査ログ、ローテーション）を運用仕様として定義する。
   - owner/DoD: Security Engineer（Auth Flows） / 未認証・認証後の両経路で結果契約が一致し、再認証失敗時にIdP向けリクエストレートが上限制御されることを確認。
7. 検証固定フェーズ（回帰と追跡性）:
   - `TC-GQL-ERR-*` を実装先テストへ先に追加し、契約互換・異常系・誤判定抑止をテストで固定してから本実装を有効化する。
   - テストIDとテスト関数の対応をメタデータファイルで管理し、CIで整合検証してリネーム時の参照切れを検出する。
   - owner/DoD: QA Lead（Automation） / TC-GQL-ERR全件の自動実行とID対応表チェックがCI必須ジョブ化され、参照切れ時にパイプラインが確実にFailする。
8. リリース判定フェーズ（PM統合ゲート）:
   - 機能受け入れ（判定精度/契約互換）と運用受け入れ（SLO/安定性）を分離ゲートで評価し、環境ゆらぎによる完了判定反転を防ぐ。
   - ゲート未達時は原因分類（機能/性能/観測性/環境）を必須出力し、再実装スコープを局所化する。
   - owner/DoD: PM（Security Platform） / 分離ゲート結果と未達原因分類がリリース判定テンプレートへ記録され、承認者レビューで再現可能な形で残ることを確認。

## Contract (run_graphql_navigator)
- 必須キー: `introspection_enabled` (bool), `graphiql_enabled` (bool), `field_suggestions_enabled` (bool), `error_code` (str|null), `evidence` (list[str]), `latency_ms` (int|null)
- `error_code` 許可値: `null`, `timeout`, `connection_error`, `http_error`, `invalid_response`
- 互換条件: 既存利用側が参照する GraphQL 可否フラグ3種のキー名・bool型を維持する。
- 例外時契約: 例外を送出せず、上記必須キーをすべて埋めた規定フォーマットを返却する。
- `evidence` 語彙（正規化）: `introspection_success`, `introspection_error_signature`, `graphiql_ui_marker`, `field_suggestion_hint`, `http_status_4xx`, `http_status_5xx`, `timeout_triggered`, `connection_failed`, `invalid_json_payload`, `waf_html_response`
- `evidence` 運用ルール: 重複禁止、発生順で記録、最大10件で打ち切り。

## Architecture Decision
- `src/core/attack/graphql_analyzer.py` は「HTTPレスポンスの解釈ロジックを重複実装せず再利用できる場合」に限り採用する。
- 採用しない条件: analyzer 側契約が Discovery 契約（上記必須キー/型）と不整合、または変換コストが新規実装より高い場合。
- 依存方向: Discovery (`swarm/discovery`) は analyzer を呼び出してよいが、analyzer から Discovery への逆依存は禁止する。

## SRE / Runtime Requirements
- タイムアウト: 1リクエストあたり 3.0 秒、対象URLあたり総検査時間 8.0 秒以内。
- リトライ: `timeout` / `connection_error` のみ最大1回、指数バックオフ（200ms）。
- 並列度: Discovery内GraphQL検査の同時実行上限を 5 に制限。
- 失敗時挙動: 失敗理由は必ず `error_code` へ正規化し、例外を上位へ漏らさない。
- 観測性: `graphql_probe_success_total`, `graphql_probe_failure_total`, `graphql_probe_latency_ms`, `graphql_probe_error_code_total` をログ由来で集計可能なキーとして出力。
- SLO/Alert閾値:
  - `graphql_probe_latency_ms` p95 < 2500ms（5分窓）
  - `graphql_probe_error_code_total / all_probes` < 5%（15分窓）
  - `error_code=timeout` 比率 < 2%（15分窓）
  - `internal_error_category=other` 比率 > 1% かつ `other_count >= 20`（15分窓）で warning
  - `internal_error_category=other` 比率 > 3% かつ `other_count >= 20`（15分窓）で critical
  - 上記を超過した場合は warning を発火し、連続2窓超過で incident 扱いとする。

## Dependencies
- `SGK-2026-0221-S01` 完了後に着手（実行基盤が確定していること）。

## Risks
1. ネットワーク条件で false positive/false negative が増える。
2. タイムアウト増加による全体スループット低下。
3. 異常応答（壊れたJSON/HTML混在/WAFレスポンス）で判定揺れが発生する。

## Risk Mitigation
1. 判定は単一シグナル依存を避け、HTTP status / body / GraphQLエラーパターンの複合根拠で確定する。
2. early-stop 条件（陽性確定時に残検査を省略）で平均レイテンシを抑制する。
3. `invalid_response` を明示分類し、誤って陰性確定しない保守的フォールバックを適用する。

## BugBounty Recon Quality Risks (GraphQL Attack Surface Discovery Only)
1. 既知パス（`/graphql`, `/api/graphql`）偏重で、実運用のカスタムパスやバージョン付きパスを取りこぼす。
2. 単一ホスト前提の探索で、サブドメイン/別オリジン配下のGraphQLエンドポイント発見率が低下する。
3. 静的HTML由来リンク中心の探索では、JSバンドル内のGraphQL endpoint 定義を見逃しやすい。
4. WebSocket（`graphql-ws`/subscription）経路のRecon不足により、HTTP以外の面を未発見化する。
5. Persisted Query専用構成で通常POSTが拒否されるケースを「非GraphQL」と誤判定する。
6. WAF/CDNのブロック応答を終端扱いし、User-Agent/ヘッダ差分で発見できる経路を見逃す。
7. レート制限検出を十分に織り込まず、短時間スキャンで一時遮断され偽陰性化する。
8. GraphQL特有エラーシグネチャ（`Cannot query field`, `Unknown argument`）の表記揺れ対応不足。
9. API Gateway/リバースプロキシ経由時のパスマッピング差分（`/gql` -> upstream `/graphql`）未考慮。
10. 認証前Reconのみで終了し、認証後にのみ露出するGraphQL surfaceを未発見化する。
11. キャッシュレスポンスやエッジキャッシュの影響で、実際には存在するエンドポイントの挙動を誤学習する。
12. `robots.txt`/`sitemap.xml`/frontend config など受動情報源の統合不足で発見網羅性が落ちる。

## SRE Critical Risks (Network/Scalability Only)
1. 固定並列度（5）と固定タイムアウト（3s/8s）がターゲット特性非依存であり、大規模ターゲット群で同時滞留が発生した場合にワーカープールを枯渇させ、Discovery全体を停止に近い状態へ追い込む。
2. `timeout`/`connection_error` に対する即時リトライ（1回）が障害局面で再送バーストを生み、上流WAF/CDN/Originへの自己増幅トラフィックを誘発して、全ターゲットで連鎖的に失敗率を悪化させる（retry storm）。
3. 総検査時間上限（8s）がある一方で、グローバルなバックプレッシャー制御（全体QPS制御、ホスト単位制限、キュー優先度）が未定義のため、スキャン対象数が急増した際にメモリ内キューが無制限成長し、プロセスOOMまたは極端な遅延蓄積を招く。
4. `graphql_probe_*` をログ由来集計に依存しているが、高負荷時にログI/Oがボトルネック化した場合のサンプリング/ドロップ方針が無く、観測不能と処理遅延が同時発生して障害時に制御不能化する。
5. 接続再利用・コネクションプール上限・DNS解決キャッシュ戦略が計画に無く、多数ホスト同時探索時にFD枯渇やDNSリゾルバ飽和を引き起こし、GraphQL以外の検査系まで巻き込んだ全体停止を誘発する。
6. ステージングSLO達成（p95<2500ms等）を受け入れ条件にしているが、分布裾（p99/p999）や長時間ランの劣化監視が未定義で、実運用でのテールレイテンシ暴騰を見逃し、本番ではスループット崩壊後にしか検知できない。
7. 障害モード分離（target-level circuit breaker / host quarantine）が無く、単一不安定ホストがリトライとタイムアウトを占有して共有実行基盤を汚染し、健全ターゲットまで巻き添えで処理不能にする。
8. 認証後Surface探索を組み込む計画に対して、セッション/トークン更新失敗時の再認証レート制御が未定義であり、認証基盤へ集中アクセスを発生させるとアカウントロックやIdPレート制限で全探索パイプラインが停止する。

## Architecture Critical Risks (Coupling/Extensibility/Toolchain Integration Only)
1. `graphql.py` 判定ロジックと `manager.py` の返却契約が暗黙同期のまま進むと、仕様追加時に両者同時改修が必須化し、変更波及が全呼び出し元へ連鎖する高結合ポイントになる。
2. `error_code` と `evidence` を文字列列挙で直接運用しているため、列挙拡張時に下流の集計・ゲート・レポート変換が同時破壊され、後方互換を失ってパイプライン全体が停止しうる。
3. Discovery契約を `run_graphql_navigator` 単一点に集中させる設計は、将来の複数プローブ（HTTP/WS/APQ/Auth-context）統合で肥大化したGod-Interface化を招き、モジュール分離不能の臨界点に達する。
4. `graphql_analyzer.py` 再利用判断を実装時裁量に委ねると、同等責務の判定ロジックが複数モジュールへ重複し、バグ修正の二重実装が恒常化して検出結果の一貫性を失う。
5. 観測キーを「ログ由来集計」に固定すると、既存ツールチェーン（gate/check/report）が期待する構造化イベント契約と乖離した際に、検出は成功しても品質ゲートで失敗する“統合破断”が発生する。
6. テストIDをテスト関数名へ直結する運用は、リネーム/再編時にドキュメント・CI・レポート参照が同時破綻し、検証トレーサビリティ消失でリリース判定不能になる。
7. Discovery層でプロトコル詳細（HTTPステータス、WAF応答、JSON破損）を直接解釈し続けると、将来のプローブ追加時に共通抽象化が効かず、ツールチェーン横断の正規化仕様が崩壊する。
8. 受け入れ条件がステージング依存SLOと機能判定を同一タスクへ結合しているため、設計変更なしでも環境ゆらぎだけで完了可否が反転し、継続的デリバリ基盤の意思決定を不安定化させる。

## Acceptance Criteria
1. URL文字列条件分岐ベースの擬似検出を使わない。
2. `introspection_enabled/graphiql_enabled/field_suggestions_enabled` が実レスポンスで判定される。
3. `DiscoveryManager.run_graphql_navigator` が例外時も規定フォーマットで返却する。
4. 例外系（timeout/connection/http/invalid_response）で `error_code` が100%正規化される。
5. 既存利用側互換キー（上記3フラグ）の欠落が回帰テストで0件。
6. 判定根拠 `evidence` に陽性/失敗理由が記録され、ログ追跡で再現できる。
7. SLO基準（p95 latency / error率 / timeout率）をステージング検証で満たす。

## Validation
- `.venv/bin/pytest tests/core/agents/swarm/discovery/test_graphql.py -q`
- `.venv/bin/pytest tests/core/agents/swarm/discovery/test_manager_graphql_contract.py -q`
- `.venv/bin/pytest tests/core/agents/swarm/injection/test_smart_graphql.py -q`
- `.venv/bin/pytest tests/core/agents/swarm/injection/test_graphql_integration.py -q`
- 異常系モックサーバ検証: 壊れたJSON / 4xx / 5xx / timeout / connection error で契約フォーマット維持を確認
- 異常系テストID:
  - `TC-GQL-ERR-001`: invalid_json（200 + 壊れたJSON）
  - `TC-GQL-ERR-002`: waf_html_200（200 + HTML/WAF本文）
  - `TC-GQL-ERR-003`: http_500（500応答）
  - `TC-GQL-ERR-004`: slow_response（timeout境界）
  - `TC-GQL-ERR-005`: tcp_connection_error（接続拒否/名前解決失敗）
- テストID実装先:
  - `TC-GQL-ERR-001` -> `tests/core/agents/swarm/discovery/test_graphql.py::test_tc_gql_err_001_invalid_json`
  - `TC-GQL-ERR-002` -> `tests/core/agents/swarm/discovery/test_graphql.py::test_tc_gql_err_002_waf_html_200`
  - `TC-GQL-ERR-003` -> `tests/core/agents/swarm/discovery/test_graphql.py::test_tc_gql_err_003_http_500`
  - `TC-GQL-ERR-004` -> `tests/core/agents/swarm/discovery/test_graphql.py::test_tc_gql_err_004_slow_response_timeout`
  - `TC-GQL-ERR-005` -> `tests/core/agents/swarm/discovery/test_graphql.py::test_tc_gql_err_005_connection_error`

## Future Implementation Backlog (Deferred)
1. 観測経路の二重化: 構造化イベントに加え、メトリクス直送/イベントバス連携を追加してログ経路単一点障害を解消する。
2. 設定ホットリロード: 並列度/QPS/タイムアウト等の主要パラメータをノンデプロイで反映可能にする。
3. リリース連動ロールバック: 分離ゲート未達時に feature flag で自動的に段階ロールバックできる運用を追加する。

## CTO Remediation Plan (Phase 1/4/5 Completion)
1. Phase 4未完了対策: host quarantine / circuit breaker を `GraphQLNavigator` に実装し、障害ホスト局所化を保証する。
2. error_code運用境界: `error_policy_version` を契約へ追加し、`error_code`（公開）と `internal_error_detail`（内部）の利用規約を明確化する。
3. 観測統合E2E: manager返却を契約正規化し、構造化イベントキーを固定テストで検証する。
4. 負荷制御副作用検証: backpressure拒否・host quarantine動作をユニットテストで固定し、誤動作回帰を防止する。
5. 既存テスト赤解消: `BaseManagerAgent` のLLM初期化条件を `agenerate` 属性有無まで拡張し、前提差分でのテスト失敗を回避する。
6. 契約バージョン運用: `contract_version` と `error_policy_version` を返却必須化し、将来互換の監査可能性を確保する。

## CTO Checkpoint
- 実装着手条件: 上記1〜6の設計方針がコード/テストで追跡可能であること。
- 完了判定条件: 追加契約テスト（contract/backpressure/quarantine/manager normalize）が全緑であること。

## CTO Concern Closure Plan v2 (1-6)
1. `connection_error` 過集約対策:
   - `error_code` は互換維持し、`internal_error_detail` を標準カテゴリ化（`backpressure_rejected`, `host_quarantined`, `probe_timeout`, `connect_failure` など）する。
   - 構造化イベントにカテゴリを必須出力する。
2. クラス変数干渉対策:
   - `_inflight` / `_qps_timestamps` / host failure state をインスタンス状態へ移行し、設定差分のある並行実行が干渉しないようにする。
3. quarantine復帰戦略:
   - quarantine満了後は half-open（試験通過1本）で復帰し、失敗時は再隔離する。
4. 観測スキーマ固定:
   - `graphql_probe_event` の必須キーと型をテストで固定し、契約破壊をCIで検知する。
5. 負荷シナリオ実証:
   - 遅延/失敗ホスト混在のユニット負荷シナリオを追加し、QPS・backpressure・隔離挙動の回帰を防止する。
6. 契約運用監査:
   - `contract_version` / `error_policy_version` の両方を必須返却に固定し、manager正規化後も欠落しないことをテストで担保する。

## CTO Review Round 1 (NO-GO)
- 判定: NO-GO
- 理由: 負荷シナリオの具体テスト（5）と half-open 復帰条件（3）の成功基準が定量化不足。

## CTO Plan Revision (for GO)
- 5の成功基準を追加:
  - backpressure拒否時に `internal_error_detail=backpressure_rejected` を返す。
  - quarantine中は `host_quarantined` を返す。
  - quarantine解除後の試験通過で隔離解除、試験失敗で再隔離を確認する。
- 3の成功基準を追加:
  - half-open試験は同時1本のみ許可し、それ以外は拒否。

## CTO Review Round 2 (GO)
- 判定: GO
- 理由: 1〜6すべてに実装対象・検証条件・失敗時シグナルが定義され、コード化可能。

## Final Hardening Plan (Operational Finish)
1. half-open飢餓対策:
   - quarantine解除待ちホストを時刻順で管理し、最古の待機ホストを優先して試験復帰させる。
2. `internal_error_category` ガバナンス:
   - 許可カテゴリ集合を定数化し、未知値は `other` に正規化する。
3. 観測イベント互換ポリシー:
   - `graphql_probe_event.v1` の互換ルール（必須キー不削除、追加は任意キーのみ）を明記し、スキーマテストに反映する。
4. 長時間連続実行の健全性:
   - 連続呼び出しテストを追加し、状態リーク（host state / qps buffer / inflight）が無制限増加しないことを確認する。

## CTO Final Review Round 1 (NO-GO)
- 判定: NO-GO
- 理由: 1と4の検証が定量化不足（「どの程度でリークなしと判断するか」が未定義）。

## Final Plan Revision (for GO)
- 1の成功基準:
  - 待機ホスト3件で最古ホストが優先してhalf-open試験されること。
- 4の成功基準:
  - 同一プロセス内で連続100回実行後、`_host_failures`/`_host_quarantine_until` が成功経路でクリアされ、`_inflight` が0へ復帰していること。

## CTO Final Review Round 2 (GO)
- 判定: GO
- 理由: 仕上げ4項目すべてに実装対象と定量DoDが定義され、回帰テスト化可能。

## Item 2 Execution Plan (other_rate threshold)
1. 実装:
   - `other_count` と `total_count` から `warning/critical/none` を返す判定関数を実装する。
2. 判定条件:
   - warning: `other_rate > 1%` かつ `other_count >= 20`
   - critical: `other_rate > 3%` かつ `other_count >= 20`
3. テスト:
   - 境界値（1%, 3%, count=19/20）を固定テスト化する。

## Item 2 CTO Review Round 1 (NO-GO)
- 判定: NO-GO
- 理由: total_count=0 のゼロ除算ケースと、critical優先順位が未定義。

## Item 2 Plan Revision (for GO)
- `total_count <= 0` は `none` を返す。
- `critical` 条件を先評価し、warningより優先する。

## Item 2 CTO Review Round 2 (GO)
- 判定: GO
- 理由: 境界・優先順位・ゼロ件ケースが定義され、実装に移行可能。

## Item 2+3 Integration Plan (Pipeline Wiring + CI Ops)
1. 運用接続（Item 2）:
   - `internal_error_category` の時系列バッファを持ち、15分窓で `other_count/total_count` を算出する。
   - `evaluate_other_category_alert` を利用し、`warning/critical` 発火時に構造化イベント `graphql_probe_alert` を出力する。
2. CI運用化（Item 3）:
   - PR向け軽量ジョブ（contract + alerting）
   - Nightly向け中負荷ジョブ（contract + longrun）
   - Weekly向け重負荷ジョブ（longrun全量）
3. 失敗時通知:
   - PR失敗時はPRへ自動コメント
   - Nightly/Weekly失敗時はIssueを自動起票

## Item 2+3 CTO Review Round 1 (NO-GO)
- 判定: NO-GO
- 理由: 15分窓の掃除戦略（古いイベント削除）と、通知の重複抑止条件が未定義。

## Item 2+3 Plan Revision (for GO)
- 窓管理:
  - 毎回評価時に `now - 900s` より古いイベントを削除する。
- 通知重複抑止:
  - PRコメントはworkflow runごと1回、Issueは日次/週次ジョブ名を含むタイトルで既存Open Issueがある場合は新規作成しない。

## Item 2+3 CTO Review Round 2 (GO)
- 判定: GO
- 理由: 集計窓・発火・通知重複抑止の仕様が定まり、運用接続として実装可能。
