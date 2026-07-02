---
task_id: SGK-2026-0222
doc_type: manual
status: active
parent_task_id: null
related_docs:
  - docs/shigoku/plans/2026-05-21_sgk-2026-0222_distributed-runtime-control_plan.md
  - src/core/agents/swarm/discovery/graphql.py
  - src/core/agents/swarm/runtime_control_backend.py
created_at: '2026-05-26'
updated_at: '2026-07-02'
---

# Runtime Control fail_open 運用ガード Runbook

## 目的
- `graphql_probe_backend_unavailable_policy=fail_open` の誤運用を防ぎ、緊急時の意思決定を固定化する。

## 既定値
- 本番既定値: `fail_safe`
- `fail_open` は例外運用（緊急時・障害訓練時のみ）

## 誰が有効化できるか
- 有効化承認者（いずれか必須）
  - CTO
  - Platform On-call Incident Commander（IC）
- 実行担当者
  - Platform SRE 当番

## 有効化条件（全て必須）
1. runtime control backend 障害が継続し、`fail_safe` 維持でサービス劣化が重大
2. 直近15分で `Runtime backend error rate >= 0.5%` を観測
3. 代替復旧手段（Redis復旧/切替）の一次対応を実施済み
4. 監査チケット作成済み（有効化理由・時刻・承認者・担当者を記録）

## 何分まで有効化できるか
- 最大有効時間: 30分（TTL）
- 30分超過時:
  - システム実装により自動で `fail_safe` へ戻す（`graphql_probe_fail_open_ttl_seconds`）
  - 解除できない場合はICが即時エスカレーション

## 技術担保（実装）
- `GraphQLNavigator` は `fail_open` 開始時刻を保持し、TTL超過後は backend unavailable 時に強制 `fail_safe` 判定へ切替。
- 推奨設定:
  - `graphql_probe_backend_unavailable_policy=fail_open`（例外運用時のみ）
  - `graphql_probe_fail_open_ttl_seconds=1800`

## fail_open 発動の可視化
- 構造化イベント `graphql_runtime_control_policy` を監視対象にする。
- 最低限ダッシュボードで追う項目:
  - `configured_policy`
  - `effective_policy`
  - `ttl_remaining_seconds`
  - `fail_open_count`
  - `fail_safe_count`
  - `stage`（admit / admission_or_qps）
- アラート推奨:
  - `effective_policy=fail_open` が 10分継続
  - `fail_open_count` が急増（例: 5分で10回超）

## 実行手順
1. 承認取得
- CTO または IC の承認を取得し、監査チケットに記録

2. 一時有効化
- `graphql_probe_backend_unavailable_policy=fail_open` を適用
- 変更時刻を記録し、30分後の解除時刻を明示

3. 監視強化（5分間隔）
- backend error rate
- GraphQL probe failure rate
- 誤検知率/誤隔離率の急増有無

4. 解除
- 復旧完了または30分到達で `fail_safe` に戻す
- 解除時刻、結果、未解決課題を監査チケットに記録

## Go/No-Go 判定
- Go（継続）:
  - backend復旧未了だが、ユーザー影響を抑制できている
- No-Go（即時停止）:
  - 誤検知/誤隔離が許容値を超過
  - 監視不能状態が発生

## 監査ログ必須項目
- 承認者
- 実行担当者
- 有効化理由
- 開始時刻・終了時刻
- 主要メトリクス推移
- 事後レビュー結論

## CI失敗時の一次対応（GitHub API一時障害）
- 対象:
  - `runtime-control-governance` ジョブ失敗
  - `approval_source_unavailable` または GitHub API通信エラー
- 再実行基準:
  1. まず同一コミットで1回目の `Re-run failed jobs` を実施
  2. 1回目失敗時は 2〜5 分待機後に2回目を実施
  3. 2回連続で同一エラーなら「一時障害扱い」を終了し、恒常障害としてIC/CTOへエスカレーション
- 判定ルール:
  - 3回目以降の手動連続再実行は禁止（ノイズ増加を防止）
  - 2回目までに回復した場合のみ一時障害クローズ可
  - 回復後も監査チケットに再実行回数と失敗理由を必ず記録
