---
task_id: SGK-2026-0221-S03
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0221
related_docs:
- docs/shigoku/plans/2026-05-19_sgk-2026-0221_mock-optimizedreciperunner-discovery-graphql_plan.md
- docs/shigoku/specs/bug_bounty_enhancements.md
title: 'GroupC: 回帰防止テストと可観測性・ドキュメント整備'
created_at: '2026-05-20'
updated_at: '2026-06-30'
tags:
- shigoku
- group-c
- testing
---

# GroupC Subtask Plan (PM Integrated, CTO-Risk Closed)

## Goal
- GroupA/B のモック除去後に回帰を未然検知し、障害発生時に原因を一意に追跡できる運用基盤を実装する。

## SHIGOKU Concept Fit
- 回帰防止: 旧モック前提テストを排除し、実経路ベースで壊れ方を検知する。
- 追跡可能性: 相関ID、観測スキーマ、再現入力、Runbook を統一し、障害調査を再実行可能にする。
- 継続改善: 指標監視、分類精度監査、ポストモーテム反映で再発率を継続低減する。

## Success Metrics
1. `unknown_rate < 5%`
2. `trace_id_presence >= 99.9%`
3. `required fields completeness >= 99.5%`
4. `timeout_rate > 5% (5m)` または `schema_mismatch_count >= 3 (10m)` の検知継続
5. `MTTI` のベースライン比短縮
6. `reopen_regression_rate` の継続低減
7. PR必須ゲート実行時間 SLO: `p95 <= 15分` かつ `p99 <= 20分`

## Scope
- `tests/core/engine/*`
- `tests/core/agents/swarm/discovery/*`
- 回帰防止/追跡性に関わる仕様・運用ドキュメント

## Out Of Scope
- UI/UX変更
- 回帰防止・追跡性に直接関係しないリファクタ

## Specialist Issues To Clear
### PM
- 課題: 完了判定が曖昧で進捗が見えづらい。
- 対応: 全タスクに成果物・検証コマンド・証跡リンクを必須化。

### SRE/インフラ
- 課題: 相関情報不足で初動が遅い。
- 対応: `trace_id/request_id/test_case_id/build_id` と段階別レイテンシを必須化。

### ソフトウェアアーキテクト
- 課題: 判定・観測・通知の密結合で変更耐性が低い。
- 対応: モジュール責務分離、単一DSL、契約テストで接続面を固定。

### バグハンター
- 課題: 異常系網羅と再現性不足。
- 対応: 失敗分類拡張、再現入力スキーマ、Mutation/Fault Injection を導入。

### データアナリスト
- 課題: 品質変動の定量監視不足。
- 対応: 時系列指標、逸脱検知、週次フィードバックループ、分類是正SLAを導入。

## Architecture & Integration Rules (Non-Negotiable)
1. 判定ロジック、観測スキーマ、通知ルールを分離し、循環依存を禁止する。
2. 相関ID発行責務は単一モジュールへ集約し、他層は読み取り専用にする。
3. Contract 判定は単一DSLを唯一の判定仕様として使う。
4. 観測イベントは内部共通モデルを正とし、APM連携は exporter 層で吸収する。
5. スキーマ変更は `warn -> soft-fail -> hard-fail` と `dual-write/dual-read` で段階移行する。
6. ログ項目は PII 禁止ルールと redaction 方針を先に固定する。
7. Runbook CLI は実行基盤 adapter 経由で提供し、環境依存を最小化する。
8. 初回失敗ログは不変保存し、再実行結果で上書きしない。
9. `schema mismatch` は JSONPath 差分を `added/removed/type_changed/nullability_changed` に分離し、重大度（破壊的/非破壊的）を付与する。

## CI Capacity Guardrail (Max-Risk Countermeasure)
1. PR必須ゲートを `Core Blocking` と `Advisory` に分離する。
2. `Core Blocking` は「変更関連短縮スイート + クリティカル固定スモーク + 観測性回帰テスト」に限定する。
3. `Advisory` は非ブロッキングで実行し、結果はPRコメントへ自動添付する。
4. PR実行時間が `p95 > 15分` を3営業日連続で超えた場合、CI Budget Protection Mode を発動する。
5. CI Budget Protection Mode では、新規ブロッキングゲート追加を一時停止し、非必須ゲートをNightlyへ自動退避する。
6. PR実行時間が `p95 <= 15分` に復帰して5営業日維持したら通常モードへ戻す。

## Phased Implementation Plan
### Phase 1: 今すぐ実装（追跡不能リスクの解消）
1. 共通相関キー導入（`trace_id/request_id/test_case_id/build_id`）。
2. 必須観測項目導入（`endpoint`, `error_type`, `timeout_ms`, `retry_count`, `dns/connect/tls/ttfb/read`）。
3. 観測スキーマ完全性チェックを `warn` で導入。
4. Runbook の CLI 実行手順固定化（確認→抽出→照合→再現→記録）。
5. 低サンプル誤報抑止（`minimum_sample_size`）導入と保留通知チャネル追加。
6. 旧モック前提テスト置換対象一覧を凍結。
7. PRクリティカル固定スモークセットを定義。
8. PII redaction 適用と監査ログ導入。

### Phase 2: 次スプリント（判定品質の強化）
1. Unit/Integration/Contract の責務分離でテスト更新。
2. 失敗分類拡張（`timeout/error/schema mismatch/network/auth/data-contract/unknown`）。
3. `schema mismatch` の JSONPath 差分 + 重大度分類を実装。
4. 失敗時の自動再実行 + ログ比較を実装。
5. flaky 隔離キュー導入（隔離期限・復帰条件・棚卸し周期を固定）。
6. CI 環境フィンガープリント保存と失敗時差分自動表示を導入。
7. PR 変更関連テスト優先 + クリティカル固定スモークのハイブリッド運用を開始。
8. 観測完全性ゲートを `soft-fail` に引き上げる。
9. `unknown_rate` 超過時の是正SLA（48時間以内）を運用開始。

### Phase 3: 運用定着（再発抑止ループ）
1. Nightlyで過去30日障害再現ケースを継続再実行し、重要度と再発率でケース重みを更新。
2. インシデントクローズ必須証跡（原因分類/再現可否/再発防止テストID）を強制。
3. 先行指標ダッシュボードを経営向け3指標と運用詳細指標に分離して運用。
4. 失敗分類精度監査を自動サンプル抽出で定期運用。
5. ポストモーテム見逃しシグナルを次回アラートへ反映するループを定着。
6. 観測完全性ゲートを `hard-fail` へ移行。

## Workstream Deliverables
### WS1: Test & Contract
1. 旧モック前提テスト置換/削除。
2. Contract DSL 実装と比較項目固定（`operationName`, `endpoint.path`, `variables keys`, `response.data keys`, `errors[].extensions.code`）。
3. Mutation/Fault Injection サンプルセット導入。
4. 契約境界の責務マップ（Unit/Integration/Contract）を文書化。

### WS2: Observability & Correlation
1. 必須ログキー + 相関ID + 段階別レイテンシ実装。
2. 観測スキーマ versioning と完全性ゲート導入。
3. PII redaction ルール導入。
4. APM exporter 実装（内部モデル非侵食）。
5. ログ集約遅延 SLO（P95 30秒以内）監視導入。

### WS3: Incident Operations
1. CLI Runbook と自動再実行フロー実装。
2. flaky 隔離キュー運用（期限・復帰・棚卸し）。
3. インシデント証跡テンプレート自動入力。
4. 初回失敗ログの不変保存ポリシー導入。
5. インシデントクローズ前の証跡チェック自動化。

### WS4: Analytics Loop
1. `pass_rate/flake_rate/new_failure_count/unknown_rate/MTTI/reopen_regression_rate` を時系列収集。
2. 直近14実行移動中央値逸脱検知。
3. 未テスト失敗パターンの週次抽出と次スプリント連携。
4. `unknown_rate` 超過時の是正SLA（48時間以内）運用。
5. 分類精度監査の月次レポート化。

## Toolchain Integration Plan
1. PR (`Core Blocking`):
   - 変更関連短縮スイート
   - クリティカル固定スモーク
   - 観測性回帰テスト
2. PR (`Advisory`):
   - 関連メトリクスURL
   - 失敗分類詳細
   - 追加非ブロッキング検証
3. Nightly:
   - フルスイート
   - 障害再現ケース再実行
   - 指標集計と分類精度チェック
4. CI Artifact:
   - テスト結果
   - 失敗分類
   - 環境フィンガープリント
   - 初回失敗ログ
   - 再現入力参照
5. Incident Ticket:
   - 発生テスト
   - 該当ログ
   - 再現入力
   - 修正PR
   - 再検証結果

## Acceptance Criteria
1. GroupA/B 主要分岐の回帰防止テストが Unit/Integration/Contract いずれかで整備されている。
2. 旧モック前提テストが残存しない。
3. `unknown_rate < 5%` を満たす。
4. `trace_id_presence >= 99.9%` と `required fields completeness >= 99.5%` を満たす。
5. `schema mismatch` 3種（欠落フィールド/型不一致/null混入）以上を検証できる。
6. 最小再現入力（`payload + seed + clock + retry_policy + endpoint snapshot`）参照先が各失敗パターンに紐づく。
7. Runbook の5手順（確認→抽出→照合→再現→記録）がCLIで実行可能である。
8. PR/Nightly で単一DSL判定が使われる。
9. インシデント必須証跡が未入力ならクローズ不可である。
10. PR実行時間SLO（`p95 <= 15分`, `p99 <= 20分`）を満たし、違反時は CI Budget Protection Mode が機能する。
11. 実装状況/既知制約/正規化仕様ドキュメントが現状コードと整合している。

## Dependencies
- `SGK-2026-0221-S01`
- `SGK-2026-0221-S02`
- 依存未完了中はテスト設計・fixture・期待値定義まで先行し、本番ロジック改修は行わない。

## Risks & Mitigations
1. リスク: 観測/判定/通知の密結合で単一点故障化。
   対応: モジュール分離 + 契約テスト + 単一DSL。
2. リスク: スキーマ更新で互換崩壊しCI停止。
   対応: 段階移行（warn/soft/hard） + dual-write/dual-read。
3. リスク: PR判定とNightly判定の乖離。
   対応: 変更関連 + 固定スモークのハイブリッド。
4. リスク: flaky増加で判定汚染。
   対応: 自動再実行 + 隔離期限 + 復帰基準。
5. リスク: `unknown` 蓄積で追跡不能化。
   対応: 48時間是正SLA + 分類精度監査。
6. リスク: ゲート増加でCI飽和。
   対応: Core Blocking/Advisory 分離 + PR実行時間SLO + CI Budget Protection Mode。
7. リスク: Nightly再現ケース肥大で運用破綻。
   対応: 重要度/再発率重み付けでケース数を制御。
8. リスク: 証跡運用負荷増大で形骸化。
   対応: チケット自動入力とクローズ前自動チェック。

## 未実装項目（現時点の懸念）
1. 1週間実測判定は自動化済み（Nightlyで `observability_weekly_review_*.json/.md` 生成）。ただし現週は `eligible_days=0` のため `provisional` で、データ蓄積待ち。
2. `schema_severity` 下流強制は段階適用に移行済み。Nightlyレビューで `schema_severity_required=true` + `warn_only=true` を運用し、未付与件数を週次で可視化。
3. `failure_category` は `reason_code` 優先判定へ改修済み。`reason_code` が存在する場合は文言フォールバックを使わず分類ぶれを抑制。
4. flaky解除ポリシーは環境別設定化を実装済み（`flaky_quarantine_environment` + `flaky_quarantine_env_profiles_json`）。運用値チューニングと hard-fail 移行タイミングは継続管理。

## Phase3 完了条件の達成状況（固定順）
1. 1週間実測判定クローズ:
   状態: 実装完了 / 判定待ち。
   根拠: Nightlyで固定しきい値レビューを日次生成し、`min_eligible_days=3` 判定を自動適用。
2. `schema_severity` 下流強制クローズ:
   状態: 実装完了（warn段階）。
   根拠: 週次レビューに schema missing の日次検出と警告/違反切替を実装。
3. `failure_category` reason_code優先強化クローズ:
   状態: 完了。
   根拠: 既知 reason_code の厳密マップ + reason_code存在時の文言依存排除。
4. flaky解除ポリシー環境別設定クローズ:
   状態: 完了。
   根拠: 環境別プロファイルJSONから `window_size/min_failures/release_success_streak` を解決可能。

## Validation
- `.venv/bin/pytest tests/core/engine tests/core/agents/swarm -q`
- `.venv/bin/pytest tests/core/engine -k "timeout or schema or graphql" -q`
- `.venv/bin/pytest tests/core/agents/swarm/discovery -q`
- `python3 scripts/sync_shigoku_updated_at.py`
- `python3 scripts/validate_shigoku_docs.py`
