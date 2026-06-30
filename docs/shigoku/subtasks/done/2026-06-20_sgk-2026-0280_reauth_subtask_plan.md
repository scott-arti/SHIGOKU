---
task_id: SGK-2026-0280
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0278
related_docs:
- docs/shigoku/plans/2026-06-20_sgk-2026-0278_ver-2-planning-bundle-dev-mode-recon_plan.md
- docs/shigoku/roadmaps/future_functions.md
title: 自律再認証運用明確化計画
created_at: '2026-06-20'
updated_at: '2026-06-30'
tags:
- shigoku
target: src/core/agents/swarm/auth/, src/core/infra/network_client.py, src/core/engine/master_conductor.py
---

# 実装計画書：自律再認証運用明確化計画

## 1. 達成したいゴール（ユーザー視点）
- セッション切れが起きたとき、SHIGOKU が「検知 -> 再認証 -> コンテキスト更新 -> 再開」を一貫して実行できる。
- 再認証における `NetworkClient` / `MasterConductor` / `AutoReauthSpecialist` の責務境界を実装レベルで明確化する。
- 現在のプロトタイプ的な refresh/login replay を、実運用に耐える最小構成へ引き上げる。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/infra/network_client.py`: `SESSION_EXPIRED` 等のイベント発火点
  - `src/core/agents/swarm/auth/reauth_specialist.py`: refresh / login replay / token 復旧担当
  - `src/core/engine/master_conductor.py`: 再認証イベント購読と task 再開のオーケストレータ
- **データの流れ / 依存関係:**
  - HTTP 401 / session expiry signal -> `NetworkClient` がセッション失効を検知
  - `MasterConductor` -> 再認証 task 発行 -> `AutoReauthSpecialist`
  - `AutoReauthSpecialist` -> `REAUTH_SUCCESS/REAUTH_FAILED` -> `MasterConductor` が auth context / queue を更新

## 2.1 現行依存と今回の非目標
- 現行実装では `NetworkClient` / `MasterConductor` / `AutoReauthSpecialist` が EventBus を transit dependency として共有しており、Ver.2 の reauth 改修でもこの依存は維持する。
- 本サブタスクの主眼は「401 検知後の再認証復旧を安定化すること」であり、EventBus そのものの置換・除去・直結化は行わない。
- Swarm 間協調、UI/通知向けイベント再編、汎用イベント基盤の整理は別タスクへ切り出す。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - 401 応答、login replay 用 request、refresh token、cookie / auth header context
- **出力/結果 (Output):**
  - 再認証成功時: 更新済み auth 情報が `MasterConductor` に戻り、対象 task 群が再実行可能になる
  - 再認証失敗時: 理由コードつきで fail-soft に止まり、無限再試行しない
- **制約・ルール:**
  - 再認証の起点判定と復旧オーケストレーションは `MasterConductor` 中心で扱う
  - Swarm 間協調の導入は本計画の対象外とする
  - 再認証処理は scope / ethics を破らない
  - 成功体 placeholder は Ver.2 で置換対象とする

## 3.1 イベント契約とコンテキスト契約
- `SESSION_EXPIRED` payload は少なくとも `url`, `method`, `request_headers`, `origin_task_id`, `reauth_attempt_id`, `auth_context_version` を持つ。
- `REAUTH_SUCCESS` payload は `target`, `reauth_attempt_id`, `method`, `new_tokens`, `updated_cookies`, `auth_context_version`, `success_evidence` を持つ。
- `REAUTH_FAILED` payload は `target`, `reauth_attempt_id`, `reason_code`, `reason_detail`, `attempted_strategies`, `cooldown_until` を持つ。
- `MasterConductor` が保持する auth context には `login_request`, `refresh_url`, `cookie_jar_snapshot`, `last_auth_error`, `last_auth_status`, `reauth_triggered_at`, `reauth_completed_at` を明示的に格納する。
- 必須フィールドが欠ける場合は specialist 側で推測せず、`reason_code` を付けて fail-soft に終了する。

## 3.2 再認証ストーム制御と失敗時縮退
- 同一 `target + principal + auth_context_version` に対する reauth は single-flight とし、同時に 1 件だけ in-flight を許可する。
- `SESSION_EXPIRED` が短時間に連発した場合は cooldown window 内で collapse し、重複 dispatch を避ける。
- `REAUTH_FAILED` を `MasterConductor` 側でも購読し、`degraded` 状態への遷移、再試行停止、待機中タスクの隔離、運用ログ記録を行う。
- EventBus 起動失敗、emit/consume backlog 過多、dispatch 失敗時はハングせず、recovery unavailable の監査イベントを残す。
- ストーム抑止の閾値を超えた場合は再認証自体を一時停止し、通常スキャンの追加再実行を発生させない。

## 3.3 Resume Policy Matrix
- `read-only` タスクは idempotent な再送を許可し、再認証完了後に自動再開対象とする。
- `stateful` タスクは副作用重複の危険があるため、再実行前に直前状態の確認または再生成条件の評価を必須とする。
- `auth-sensitive` タスクは auth context version が更新された場合のみ再開候補とし、古い credential を持つ task instance は破棄または再生成する。
- resume 判定は対話入力依存にせず、task 種別・失敗理由・auth context version に基づく自動 policy で決定する。
- resume policy 適用結果は `reauth_attempt_id` と紐付けて監査可能にする。

## 3.4 認証情報の取り扱い
- `refresh_token`, `access_token`, session cookie, login credential, CSRF token はログへ平文出力しない。
- session 永続化へ保存する場合は redaction ルールを適用し、必要最小限の復旧情報のみ保持する。
- `login_request` を保持する際は header/body 全文保存を前提にせず、replay に必要な要素のみ構造化して持つ。
- 再認証処理中に得た新しい credential は旧 credential と置換し、旧値の再利用を防ぐ。

## 3.5 認証パターン対応と成功判定
- 本サブタスクで first-class に扱う対象は `cookie session`, `JWT refresh`, `CSRF form login` とする。
- `OIDC/SAML redirect`, `MFA required`, 人手承認付き再認証は本計画の対象外とし、検出した場合は `reason_code` を付けて fail-safe に終了する。
- login replay の前に必要であれば login page preflight を行い、hidden field / CSRF token / cookie jar を更新してから replay する。
- 再認証成功判定は HTTP 200 のみではなく、`Set-Cookie` 更新、認証済み endpoint probe 成功、refresh response schema 検証のいずれかを必須条件とする。
- synthetic token や placeholder value のみで成功扱いにしない。

## 3.6 Reason Code taxonomy
- 最低限 `missing_refresh_url`, `missing_login_request`, `network_client_unavailable`, `csrf_token_missing`, `token_extraction_failed`, `login_replay_non_200`, `reauth_storm_suppressed`, `unsupported_auth_scheme` を定義する。
- `reason_code` は work_report と run ledger の双方から辿れるようにし、成功/失敗の集計キーとして使う。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: 現行の `SESSION_EXPIRED`, `REAUTH_SUCCESS`, `REAUTH_FAILED` の発火/購読点を棚卸しし、EventBus を含む運用フロー図と payload schema を固定する
- [ ] ステップ2: `SESSION_EXPIRED` / `REAUTH_SUCCESS` / `REAUTH_FAILED` の必須フィールド、`reauth_attempt_id`, `auth_context_version`, `reason_code` をコードと文書で統一する
- [ ] ステップ3: `MasterConductor` 側に single-flight, cooldown, `REAUTH_FAILED` 縮退処理, resume policy matrix を実装する
- [ ] ステップ4: `AutoReauthSpecialist` の refresh/login replay を、`refresh_url` 利用・preflight・token/cookie抽出・失敗 reason code・unsupported auth scheme 判定つきに強化する
- [ ] ステップ5: happy path に加えて、`network_client` 未設定、refresh失敗後replay成功、200だがtoken抽出失敗、重複401 collapse、unsupported auth scheme、`REAUTH_FAILED` 縮退処理の integration test を追加する

## 4.1 対象外の扱い
- Swarm 間協調の実装はこのサブタスクでは扱わない
- UI / 通知向けのイベント整理が必要になった場合は、別タスクとして切り出す
- OIDC/SAML redirect, MFA, 人手承認付き再認証はこのサブタスクでは自動化しない
- EventBus 依存の完全撤去や direct call への差し替えは別タスクとする

## 4.2 完了条件
- 401 から再認証成功までの happy path がコードとテストで追え、`reauth_attempt_id` 単位でログ相関できる
- `AutoReauthSpecialist` の placeholder token 復旧を実レスポンス抽出へ置換し、synthetic success を成功判定に使わない
- `REAUTH_FAILED` が `MasterConductor` に処理され、degraded 遷移・再試行停止・待機タスク隔離が確認できる
- duplicate 401 に対する single-flight / cooldown が有効で、再認証ストームを起こさない
- resume policy が task 種別ごとに自動判定され、対話入力なしで再開可否を決められる
- 成功判定が `Set-Cookie` 更新、認証済み endpoint probe、refresh response schema 検証のいずれかで裏付けられる
- 認証情報のログ/永続化 redaction ルールが文書とテストで確認できる

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] 一部サイトでは refresh endpoint 推測が危険または不安定 - `refresh_url` 明示利用を優先し、推測は後段階に分離する
- [ ] [重要度:中] 再認証復旧と周辺イベント整理を同時に広げると責務が曖昧になる - Ver.2 ではまず再認証復旧に限定する
- [ ] [重要度:高] OIDC/SAML/MFA 系は Ver.2 の自動 reauth 対象外 - `unsupported_auth_scheme` として fail-safe に止め、必要なら別 subtask を起票する
- [ ] [重要度:中] session persistence や run ledger への認証情報混入リスクが残る - redaction 監査を別タスクで継続する
- [ ] [重要度:中] EventBus backlog や shared loop 異常時の再認証可用性評価は限定的 - 観測強化と縮退方針の検証を継続する

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0280-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
