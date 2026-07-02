---
task_id: SGK-2026-0222
doc_type: plan
status: done
parent_task_id: null
related_docs:
- docs/shigoku/subtasks/2026-05-20_sgk-2026-0221-s02_groupb_discovery-graphql_subtask_plan.md
- docs/shigoku/specs/2026-02-11_PHASE2_MANAGER_ARCH.md
- docs/shigoku/specs/bug_bounty_enhancements.md
title: 'SHIGOKU全体: 分散ランタイム制御共通基盤化（QPS/隔離/回復）'
created_at: '2026-05-21'
updated_at: '2026-07-02'
tags:
- shigoku
- platform
- runtime-control
---

# 1. 背景と目的
SHIGOKU 全体で、プロセス間一貫性を持つランタイム制御（QPS、backpressure、quarantine、half-open recovery）を共通基盤化する。実装完了ではなく、品質・運用・統治を含むリリース可能状態を達成目標とする。

# 2. スコープ
## 2.1 対象
- `src/core/agents/swarm/**` の個別制御ロジック共通化
- 分散状態ストア（Redis）による制御状態共有
- 既存 toolchain（gate/check/report）との整合
- 観測性（ログ/メトリクス/識別子）の標準化

## 2.2 非対象
- 検出器そのものの検知ロジック刷新
- 新規脆弱性カテゴリ追加

# 3. 成果物
- `RuntimeControlBackend` 抽象と実装（InMemory/Redis）
- Discovery GraphQL への段階導入（feature flag + shadow mode）
- 構造化イベント契約（policy/shadow/probe）
- リリース判定・証跡・waiver統治の運用実装（`shigoku-ops`）

# 4. アーキテクチャ方針
## 4.1 制御フロー
- 標準フロー: `admit -> execute -> record_outcome -> recover`
- 状態遷移: `closed / open / half-open` を仕様固定
- fail-safe時は `not_tested_runtime_control_fail_safe` として未検査扱い

## 4.2 Backend方針
- Redis固有処理は backend 層に閉じ込める
- 期待挙動は以下の劣化モードで固定:
  - connect_unavailable, timeout, failover, atomic_operation_failed, ttl/clock skew, stale key

## 4.3 Shadow方針
- 差分分類: `same / new_reject / missed_reject / reason_mismatch / latency_regression / other`
- 旧判定は `legacy_decision_provider` 経由で取得し、`old_decision` 欠損は gate fail

# 5. 監視・契約仕様
## 5.1 イベント契約
- `graphql_runtime_control_policy.v1`
- `graphql_runtime_control_shadow_diff.v1`
- 互換ルール:
  - 必須キー削除・型変更は禁止
  - 追加は任意キーのみ
  - 破壊変更は `v2` 新設 + `v1` 1リリース併存

## 5.2 SLO初期値
- `backend_error_rate < 0.5%`（15分窓）
- `reject_rate > 8.0%` で warning（15分窓）
- `admit_p95 > 120ms` で warning（5分窓）
- `backend_rtt_p95 > 40ms` or `p99 > 80ms` で warning（5分窓）
- `MTTRecovery > 900s` で warning

# 6. リリース統治
## 6.1 Release Gate（必須6項目）
1. 互換
2. 分散制御
3. 障害注入
4. shadow mode
5. KPI
6. rollback drill

`fail` が1つでもあれば `decision=hold`。

## 6.2 Gate Evidence テンプレート
`gate_name`, `status`, `date`, `evidence_source`, `evidence_summary`, `risk_if_failed`, `decision`, `approver`, `waiver_reason`

## 6.3 Waiver統治
- 対象: `High` のみ
- 制約: 最大7日、1回のみ、期限超過で自動 hold
- 正本: `docs/shigoku/registry/runtime_control_waiver_registry.yaml`
- 競合制御:
  - `registry_version` 楽観ロック
  - conflict時 backoff 2秒→4秒、最大2回
  - 枯渇時 `waiver_registry_conflict` + hold

# 7. 承認・因果分離運用
## 7.1 承認フロー統合
- 承認正本: GitHub PR Review API + branch protection
- `review_id` 形式: `owner/repo#pull_number:review_id`
- `infra_changes.yaml` は `review_id` 参照のみ保持
- 照合不能時: `approval_source_unavailable`（fail-closed）
- 不一致時: `approval_source_mismatch`（fail）

## 7.2 因果分離メタデータ
- 収集責務: CI
- 検証責務: `shigoku-ops`
- 出力: `artifacts/runtime_control_change_manifest.json`
- 必須キー:
  - `window_start`, `window_end`, `code_changes`, `config_changes`, `flag_changes`, `infra_changes`, `generated_at`
- 品質基準:
  - `window_start < window_end`
  - `generated_at` は `window_end` + 15分以内
  - 4カテゴリ全空は禁止
  - 各カテゴリ時刻は単調増加
- 違反時:
  - 欠落: `causality_evidence_missing`
  - 不正: `causality_evidence_invalid`

# 8. Provider可用性・fallback
## 8.1 `legacy_decision_provider` SLO
- availability `>= 99.5%`（15分窓）
- p95 `<= 150ms`
- timeout率 `< 1%`

## 8.2 Timeout/Fallback
- timeout budget: 200ms + 1回再試行
- fallback cache: TTL 300秒
- `cache_age_seconds > 300` は stale とし `legacy_decision_missing` + gate fail

## 8.3 Cache比率ガード
- warning: `cache_source_ratio > 5%`
- hold候補: `> 10%`
- ヒステリシス（15分窓固定）:
  - hold昇格: 2窓連続（30分）
  - hold解除: 2窓連続（30分）

# 9. 再評価と適用判定
## 9.1 14日再評価
- データ品質基準:
  - `total_requests >= 1000`
  - 日次サンプル `>= 50` を10日以上
  - 欠損率 `< 1%`
- 未達時: `threshold_revalidation` fail + hold

## 9.2 30日再評価トリガー
- 初回有効化から30日、または月3回以上 hold
- 未提出時: `recalibration_missing` fail

## 9.3 非日次環境向け適用基準
- 日数ではなく連続3検証サイクルで判定
- 各サイクル必須:
  - Critical gate 全pass
  - `cache_source_ratio <= 10%`
  - `legacy_decision_missing` 非悪化
  - `causality_evidence_invalid = 0`
- 未達で連続カウントを0に戻す、3連続達成まで hold

# 10. 実装順序（Critical Path）
1. `shigoku-ops runtime-control` 実装（未実装時 hard hold）
2. gate evidence validation のCI必須化
3. shadow実差分化 + provider統合
4. 14日/30日再評価運用をCLI出力正本で開始

# 11. 受け入れ条件
- Release Gate 6項目を満たし、`fail` 残存なし
- Event契約互換がCIで保証される
- waiver/approval/manifest/cache の統治ルールが自動検証される
- fail-safe未検査が陰性集計へ混入しない
- `shigoku-ops runtime-control` 未実装時に hard hold が機能する

# 12. 検証計画
## 12.1 テストカテゴリ
- 単体: backend制御、provider契約、event契約
- 統合: 2プロセス整合、half-open競合、障害注入
- 運用: gate evidence、waiver registry、approval照合、manifest検証
- E2E: run/session/report/gate の未検査整合

## 12.2 検証チェックリスト
- `not_tested_runtime_control_fail_safe` の未検査分離
- `waiver_registry_conflict` / `approval_source_*` / `causality_evidence_*` の期待fail
- cacheヒステリシス（15分窓、2窓連続）確認
- 連続3検証サイクル判定のカウントリセット/達成動作確認

# 13. リスクと緩和
- API依存停止（GitHub）: fail-closed + IC/CTOエスカレーション
- provider不安定: SLO監視 + cache fallback + hold制御
- 運用過負荷: High時限waiver + critical path固定で停止過多を抑制

# 14. 完了条件
- 本計画の受け入れ条件を満たし、`decision=proceed` を Release Gate で確認できること。
