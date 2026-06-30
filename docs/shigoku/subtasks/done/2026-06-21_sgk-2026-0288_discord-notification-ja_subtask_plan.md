---
task_id: SGK-2026-0288
doc_type: subtask_plan
status: backlog
parent_task_id: SGK-2026-0278
related_docs:
- docs/shigoku/plans/2026-06-20_sgk-2026-0278_ver-2-planning-bundle-dev-mode-recon_plan.md
- docs/shigoku/subtasks/2026-06-23_sgk-2026-0297_discord-all-finding-detail-notification_subtask_plan.md
- docs/shigoku/plans/2026-06-24_sgk-2026-0304_active_plan.md
title: Discord通知日本語化 設計計画
created_at: '2026-06-21'
updated_at: '2026-06-30'
tags:
- shigoku
target: src/core/notifications/notifier.py, src/core/notifications/notification_service.py,
  src/core/engine/master_conductor.py
---

# 実装計画書：Discord通知日本語化 設計計画

> 2026-06-24 統合メモ: `SGK-2026-0304` で本計画は `SGK-2026-0297` に吸収した。以後は「通知日本語化」だけを単独実行せず、全 Finding 詳細通知・router・運用保護まで含む `SGK-2026-0297` を primary 実行単位とする。

## 1. 達成したいゴール（ユーザー視点）
- [ ] Discord/projectdiscovery notify 経由で届く SHIGOKU 通知を、日本語で読みやすく表示できること。
- [ ] Finding、scan event、action required、handoff、interrupt などユーザーが見る通知を日本語化すること。
- [ ] machine-readable な severity/type/target/finding_id は壊さず、後続自動処理や検索で使える状態を保つこと。
- [ ] CLIログ翻訳とは分離し、LLM翻訳に依存しない固定テンプレート方式を優先すること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/notifications/notifier.py`: Finding/Event/ActionRequired の通知文面を日本語テンプレートに変更。
  - `src/core/notifications/notification_service.py`: バッチ通知・即時通知の文面整合を確認。
  - `src/core/engine/master_conductor.py`: 直接 `get_notifier().notify(...)` している箇所をテンプレート経由へ寄せる。
  - `src/config.py` / `src/core/config/settings.py`: 通知言語設定 `notify_language` または `user_language` の追加候補。
  - `tests/core/notifications/`（新規候補）: 生成メッセージのスナップショット/部分一致テスト。
- **データの流れ / 依存関係:**
  - Finding/Event/HITL -> NotificationFormatter -> Notifier.notify(message, bulk=True) -> projectdiscovery/notify -> Discord。
  - Notifier は送信責務、Formatter は文面責務に分離する。既存の notify CLI 呼び出しは維持する。
  - `provider="all"` のままでも読めるよう、Discord固有Markdownに寄せすぎない。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** Finding、event_type、target、details、action_type、message、settings.notify_*。
- **出力/結果 (Output):** 日本語メッセージ本文、notify CLI の送信成功/失敗、非致命ログ。
- **制約・ルール:**
  - target URL、severity、vuln_type、source_agent、finding_id は英数字キーまたは固定ラベルで残す。
  - CRITICAL メンション、bulk送信、notify_levelフィルタリングの既存挙動は変えない。
  - LLMによる後翻訳は使わない。日本語テンプレートを正とし、必要なら英語モードを設定で選べるようにする。
  - ユーザー向け通知だけを対象にし、内部 logger の英語メッセージはこのタスクでは触らない。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: 既存の通知発火箇所を棚卸しし、`Notifier.notify_finding()`、`notify_event()`、`notify_action_required()`、MasterConductor直呼びの4系統に分類する。
- [ ] ステップ2: `NotificationFormatter` を追加し、日本語テンプレートをここに集約する。
- [ ] ステップ3: Notifier の各メソッドを formatter 経由に置き換え、direct notify の主要箇所を専用メソッド化する。
- [ ] ステップ4: `notify_language=ja|en` を設計する。初期は `ja` 既定または既存互換の `en` 既定を議論で確定する。
- [ ] ステップ5: Finding/Event/ActionRequired のメッセージ生成テストを追加し、改行・bulk・メンションが壊れないことを確認する。
- [ ] ステップ6: notify CLI が未インストールでもテスト可能なように、送信処理と文面生成のテストを分離する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] Discord以外のSlack等ではMarkdown表示差分がある - provider非依存のプレーン寄りMarkdownにする。
- [ ] [重要度:中] 詳細情報 keys を日本語化すると自動処理しづらい - 表示ラベルだけ日本語化し、raw key は必要に応じて併記する。
- [ ] [重要度:低] 全文日本語だと外部ツール連携で検索しづらい - severity/type/target は英語値を保持する。
- [ ] [重要度:低] CLI日本語化と責務が混ざる - CLI i18n、notification i18n、log translation を別タスクで管理する。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0288-D01
    title: "継続監視: 通知テンプレートの日英切替"
    reason: "初期実装では日本語表示を優先し、全通知種別の日英完全切替は後続で調整する可能性がある"
    impact: low
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "実際のDiscord表示を確認し、テンプレートの長さ・改行・メンションを微調整する"
```
