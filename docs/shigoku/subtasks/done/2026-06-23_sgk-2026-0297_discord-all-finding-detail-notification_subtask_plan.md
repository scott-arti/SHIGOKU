---
task_id: SGK-2026-0297
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0278
related_docs:
- docs/shigoku/plans/2026-06-20_sgk-2026-0278_ver-2-planning-bundle-dev-mode-recon_plan.md
- docs/shigoku/subtasks/2026-06-21_sgk-2026-0288_discord-notification-ja_subtask_plan.md
title: Discord全Finding詳細通知 統一設計計画
created_at: '2026-06-23'
updated_at: '2026-06-30'
tags:
- shigoku
target: src/core/notifications/notifier.py, src/core/notifications/notification_service.py,
  src/core/engine/master_conductor.py, src/commands/hunt.py, src/commands/watch.py
---

# 実装計画書：Discord全Finding詳細通知 統一設計計画

## 1. 達成したいゴール（ユーザー視点）
- [ ] SHIGOKU が脆弱性を `Finding` として認識した時点で、Discord/projectdiscovery notify 経由の詳細通知が必ず送信されること。
- [ ] 通知対象は `MasterConductor` 配下の Swarm / Worker / Agent / Tool 経路に限定せず、`hunt.py` や `watch.py` のような MC 外コマンドも含めること。
- [ ] 通知本文は簡易イベント通知ではなく、`Finding` の主要情報を保持した詳細通知にすること。
- [ ] severity による通知除外を行わず、`critical/high/medium/low/info` のすべてを通知対象にすること。
- [ ] SCN07-12 の手動確認通知は現行方針を維持し、本タスクでは Finding 詳細通知の網羅性に集中すること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/notifications/finding_notification_router.py`: （新規）`Finding` / dict / result payload を正規化し、重複排除つきで詳細通知する統一入口。
  - `src/core/notifications/notifier.py`: （修正）`notify_finding()` の本文を詳細化し、通知送信責務を維持する。
  - `src/core/notifications/notification_service.py`: （修正または縮小）EventBus 経由通知を使う場合の payload 契約を統一し、バッチ前提の挙動を本要件と分離する。
  - `src/core/engine/master_conductor.py`: （修正）`handle_finding()` / `_process_findings()` / `VULN_FOUND` emit を統一 router 経由へ寄せる。
  - `src/commands/hunt.py`: （修正）個別ハンター直呼び後の `notify_finding()` 直呼びを router 経由にする。
  - `src/commands/watch.py`: （修正）`CommitWatcher` が検出した Finding を router 経由で通知する。
  - `tests/core/notifications/`: （新規/修正）正規化、重複排除、詳細本文、MC/EventBus 接続の単体テスト。
  - `tests/core/engine/` / `tests/unit/commands/`: （修正候補）MC 経路、hunt/watch 経路の回帰テスト。
- **データの流れ / 依存関係:**
  - Swarm / Worker / Agent / Tool -> `result.findings` / `result.data.findings` / `finding` -> `FindingNotificationRouter` -> `Notifier.notify_finding()` -> projectdiscovery `notify` -> Discord。
  - MC 外コマンド (`hunt.py`, `watch.py`) -> `FindingNotificationRouter` -> `Notifier.notify_finding()` -> Discord。
  - `FindingNotificationRouter` は通知専用の境界とし、保存 (`ProjectManager.save_finding`, `SharedWorkspace.save_finding`, `AutoReporter.save_report`) とは疎結合にする。
  - EventBus を併用する場合は `VULN_FOUND` payload に full `finding` を含める。ただし本タスクの主経路は同期的に呼べる router とする。

### 2.1 現状分析メモ
- `MasterConductor` は full の `Finding` を受け取っているが、現状の `handle_finding()` は `notify_event("vuln_found")` に `title/severity/type/target` だけ渡しており、詳細通知ではない。
- `MasterConductor._process_findings()` は `critical/high` だけ旧 `NotifyTool` で薄い通知を行い、`medium/low/info` は通知されない。
- `hunt.py` は MC 経由ではなく一部組み込みハンターを直接呼ぶ経路であり、現状は `notify_finding()` による詳細通知に近いが、SHIGOKU全体を代表する経路ではない。
- `watch.py` は `CommitWatcher` の Finding を表示・レポート保存するが、Discord通知していない。
- `NotificationService.start()` の実呼び出しは確認できず、さらに現状の `VULN_FOUND` payload は `event.payload["finding"]` を含まないため、そのままでは詳細通知の補完にならない。
- 保存境界へのフックだけでは、保存されない一時 Finding や report-only 経路を拾えず、重複通知もしやすい。

### 2.2 責務境界と主経路
- `FindingNotificationRouter`: Finding 抽出、DTO 正規化、fingerprint / dedupe、`source_component` / `ingress_path` 付与、通知サマリ生成を担当する。
- `Notifier`: 日本語の通知本文生成、redaction 済み本文の組み立て、projectdiscovery `notify` 呼び出し、provider 境界のエラー処理を担当する。
- `NotificationService`: 本タスクでは通知の正本経路にしない。使う場合は EventBus observer として full `finding` payload を router へ橋渡しする責務に限定する。
- `EventBus`: 監査/二次購読用途とし、通知の一次経路は `FindingNotificationRouter` の直呼びに固定する。
- 保存処理 (`ProjectManager.save_finding`, `SharedWorkspace.save_finding`, `AutoReporter.save_report`) は通知網羅性の主境界にせず、保存されない Finding も router に乗せる。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `Finding` object、`dict` finding、`result` dict、`result.data` dict、`HandoffResult.findings`、`TaskResult.findings`。
- **正規化後データ (Canonical DTO):** router は入力を通知用DTOへ正規化し、以降の通知処理はDTOを正本として扱う。DTO は既存 `Finding.to_dict()` を第一入力として再利用し、dict / nested result も同じ DTO へ寄せる。DTO は少なくとも `id` または fingerprint、`fingerprint_version`, `severity`, `title`, `type/vuln_type`, `target_url`, `source_component`, `ingress_path`, `run_id`, `task_id/source` を保持し、任意で `confidence`, `source_agent`, `description`, `impact`, `evidence_summary`, `reproduction_steps`, `artifact_path`, `raw_severity`, `normalization_warning` を保持する。
- **出力/結果 (Output):** 各 Finding に対する日本語の Discord 詳細通知、構造化された非致命ログ、重複スキップの統計またはログ、run 単位の通知サマリ。
- **制約・ルール:**
  - 通知本文は少なくとも `id`, `severity`, `title`, `type/vuln_type`, `target_url`, `confidence`, `source_agent`, `description`, `impact`, `evidence summary`, `reproduction_steps`, `task_id/source` を含める。
  - 通知本文の表示ラベルと説明文は日本語を標準とする。`id`, `severity`, `target_url`, `provider`, `vuln_type` などの機械可読キーや固有名詞は原文を維持してよいが、ユーザー向け本文は英語の簡易通知へ戻さない。
  - secret/cookie/token/body 全文などの機密値は通知本文へそのまま出さない。少なくとも `Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, `api_key`, `token`, `secret`, `password`, JWT/Bearer token、request/response body 全文を redaction 対象にする。長い evidence は要約し、必要なら artifact path / finding id 参照に留める。
  - 本文生成では safe summary、最大長制限、secret/PII redaction を必須とし、日本語の redaction 済み golden message fixture で回帰確認できるようにする。
  - severity による通知抑止をしない。ユーザー要件は「すべて通知」であり、batch summary ではなく詳細即時通知を基本とする。
  - unknown severity は通知抑止せず `info` 相当に丸め、元値がある場合は `raw_severity` と `normalization_warning` として構造化ログへ残す。
  - 同一 run 内では `finding.id` を第一キー、なければ `vuln_type:title:target_url` を fingerprint として重複通知を抑止する。fingerprint は `fingerprint_version` を持つ安定契約とし、空値正規化、計算対象フィールド、既存 `Finding.id` との優先順位をテストで固定する。必要に応じて `session_id + finding fingerprint` の TTL 付き session-scope dedupe に拡張できる設計にする。
  - 通知ログには `run_id`, `finding_id`, `source_component`, `ingress_path`, `delivery_status`, `dedupe_reason`, `provider`, `latency_ms` を含める。ログは JSONL 形式を基本とし、`workspace/projects/<target>/sessions/notification_events_<run_id>.jsonl` など run/session と紐付く場所へ出力できるようにする。
  - projectdiscovery `notify` 呼び出しは明示タイムアウト、再試行上限、失敗時 fail-open を持つ。初期値は `notify_timeout_seconds=10`, `notify_retry_count=1`, `notify_retry_backoff_seconds=1.0` とし、設定値で上書きできるようにする。通知の緊急停止用 kill switch と dry-run を用意し、通知停止中も検出処理は継続する。
  - Discord など外部 provider へ送る Finding は provider allowlist と program/target ごとの通知可否設定を通す。secret finding や PII を含む可能性がある Finding は redaction 後のみ外部転送可能とし、redaction 不可なら本文ではなく artifact path / finding id 参照に留める。
  - `watch.py` 経路では無限監視を前提に、1巡回あたりの最大通知数、送信キュー上限、連続失敗時の集約ログ化を定義し、監視ループを通知遅延で詰まらせない。
  - 既存の SCN07-12 manual validation 通知は別系統として維持し、Finding 詳細通知へ混ぜない。
  - projectdiscovery `notify` 未導入または config 欠落時も検出処理は失敗させず、通知失敗を非致命ログとして残す。
  - 主経路は `FindingNotificationRouter` の直呼びとする。`NotificationService` を使う場合も EventBus observer として扱い、payload 契約は `finding` full payload を必須とし、薄い event details だけの通知を新規追加しない。
  - `id` 欠損、`target_url` 欠損、文字列 payload、空 findings、unknown severity、malformed dict は検出処理を失敗させず、可能な範囲でDTO化し、通知不可の場合は reason 付きで構造化ログへ記録する。

### 3.1 受け入れ条件
- MC配下の `Worker` が `TaskResult.findings` を返した場合、全 severity の Finding が詳細通知される。
- MC配下の `SwarmDispatcher` が `SwarmResult.findings` を返した場合、全 severity の Finding が詳細通知される。
- MC配下の通常 `Agent` が `result.findings` / `result.data.findings` / `result.finding` を返した場合、全 severity の Finding が詳細通知される。
- `hunt.py` で見つかった Finding が統一 router 経由で詳細通知される。
- `watch.py` で見つかった Finding が統一 router 経由で詳細通知される。
- 同一 Finding が保存経路・MC処理・EventBus 経路を通っても、Discord通知は重複しない。
- `notify` CLI がないテスト環境でも本文生成と router 動作をテストできる。
- `id` 欠損、`target_url` 欠損、文字列 payload、空 findings、unknown severity、malformed dict の各ケースで、期待どおりにDTO化・スキップ・非致命ログ化される。
- 通知失敗、`notify` CLI 不在、config 欠落、timeout、再試行上限到達の各ケースで、検出処理は継続し、`delivery_status` と reason が構造化ログへ残る。
- run 単位で通知成功件数、通知失敗件数、重複スキップ件数、DTO化スキップ件数を確認できる。
- 日本語通知本文の golden message fixture があり、英語の簡易イベント通知へ戻っていないことを確認できる。
- 品質KPIとして、重複率 5% 以下、配信失敗率 10% 以下、redaction 漏れ 0 件、本文生成失敗 0 件を確認できる。dry-run / kill switch 有効時は実送信 0 件であることを合格条件にする。
- dry-run と kill switch が有効な場合、Discord へ実送信せず、送信予定本文と抑止理由をテストできる。
- `watch.py` 経路では 1巡回あたりの最大通知数、送信キュー上限、連続通知失敗時の集約ログ化がテストされる。
- provider allowlist / program ごとの通知可否 / secret finding の外部転送抑止がテストされる。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: 通知現状をテストで固定する。`Notifier.notify_finding()`、MC `handle_finding()`、MC `_process_findings()`、`hunt.py`、`watch.py` の現行挙動を確認し、薄い通知・severity漏れ・未通知経路を明示する。
- [ ] ステップ2: 段階導入ゲートを定義する。Phase A は router + MC 経路、Phase B は `hunt.py` / `watch.py` 拡張、Phase C は `NotificationService` / EventBus 整合とし、各 Phase の合格条件、切り戻し条件、KPI 閾値を文書化する。
- [ ] ステップ3: 通知アーキテクチャの責務境界を確定する。`FindingNotificationRouter` は抽出/正規化/重複判定、`Notifier` は日本語本文生成と provider 呼び出し、`NotificationService` は EventBus observer のみに責務を限定し、主経路を router 直呼びに固定する。
- [ ] ステップ4: Canonical DTO、fingerprint、ログスキーマを定義する。既存 `Finding.to_dict()` を第一入力として再利用する方針、DTO を dataclass / TypedDict / dict のどれで表すか、`fingerprint_version`、空値正規化、JSONL 保存先、unknown severity の `normalization_warning` を先に決める。
- [ ] ステップ5: 通知設定と外部転送ポリシーを定義する。`notify_timeout_seconds`, `notify_retry_count`, `notify_retry_backoff_seconds`, dry-run, kill switch, provider allowlist, program/target ごとの通知可否、secret finding の外部転送可否を設定として扱えるようにする。
- [ ] ステップ6: `FindingNotificationRouter` を追加する。DTO 正規化、run-local dedupe、session-scope dedupe 拡張点、`source_component` / `ingress_path` 付与、JSONL 構造化ログ、通知サマリ生成を実装する。
- [ ] ステップ7: `Notifier.notify_finding()` の本文生成を詳細化する。送信処理と本文生成を分離し、日本語ラベルの詳細本文、safe summary、最大長制限、secret/PII redaction、日本語 golden message fixture を使った本文検証を可能にする。
- [ ] ステップ8: 通知実行の運用保護を入れる。`notify` 呼び出しに明示タイムアウト、再試行上限、backoff、失敗時 fail-open、kill switch、dry-run、構造化ログ項目（`run_id`, `finding_id`, `delivery_status`, `dedupe_reason`, `latency_ms`）を追加する。
- [ ] ステップ9: MC `handle_finding()` を router へ接続する。薄い `notify_event("vuln_found")` ではなく full Finding の日本語詳細通知を行い、`VULN_FOUND` event は監査/二次購読用途として `finding` full payload を含める。既存の `VULN_FOUND` 重複 subscribe も確認し、二重通知につながる購読を整理する。
- [ ] ステップ10: MC `_process_findings()` を router へ接続し、`critical/high` 限定を撤廃する。旧 `NotifyTool` 直呼びは削除または後方互換のみに閉じる。
- [ ] ステップ11: `NotificationService` の扱いを確定する。使う場合は full `finding` payload 契約と即時詳細通知へ整合させ、使わない場合は通知の正本経路ではないことをコメントまたはテストで明確化する。
- [ ] ステップ12: `hunt.py` を router 経由へ移行する。既存の `deduplicate_findings()` と通知順序を見直し、通知前に dedupe が効くようにしたうえで、個別 `notify_finding()` 直呼びを置換する。
- [ ] ステップ13: `watch.py` を router 経由へ移行する。1巡回あたりの最大通知数、送信キュー上限、連続失敗時の集約ログ化を入れ、監視ループが通知遅延で詰まらないことを確認する。
- [ ] ステップ14: テストを追加する。router 正規化、fingerprint version、dedupe、全 severity 通知、日本語本文、redaction must-cover list、MC Worker/Swarm/Agent 経路、hunt/watch 経路、provider allowlist、notify CLI 不在、timeout、再試行上限、dry-run、kill switch、malformed payload を検証する。
- [ ] ステップ15: 段階導入の実行確認を行う。Phase A で MC 経路をダミー notifier で確認し、Phase B で hunt/watch を確認し、Phase C で EventBus / `NotificationService` 整合、KPI（重複率 5% 以下、配信失敗率 10% 以下、redaction 漏れ 0 件、本文生成失敗 0 件）を確認する。

## 5. 懸念点と対策

### 5.1 SRE / インフラエンジニア観点
- [ ] [発生確率:高][影響度:大] `notify` 障害時の振る舞いが「非致命ログ」に留まっており、タイムアウト・再試行・背圧が未定義。
  対策: 3章の制約に「1 Finding あたりの通知タイムアウト、再試行上限、失敗時 fail-open、kill switch、dry-run」を追加し、4章のステップ5/8/14/15で実装・検証する。
- [ ] [発生確率:中][影響度:大] 観測性不足により、配信成功率や重複抑止の有効性を run 単位で追えない。
  対策: 3章の出力/結果に `run_id`, `finding_id`, `source_component`, `ingress_path`, `delivery_status`, `dedupe_reason`, `provider`, `latency_ms` を含む構造化ログ要件を追記し、受け入れ条件に run 単位の件数確認を追加する。
- [ ] [発生確率:中][影響度:中] run-local dedupe だけでは再実行や複数入口併用時の Discord スパムを抑えきれない。
  対策: 3章の重複排除ルールを「run-local を必須、必要に応じて `session_id + finding fingerprint` の TTL 付き dedupe に拡張可能」と修正し、4章のステップ4/6/14で検証する。
- [ ] [発生確率:高][影響度:大] timeout/retry の存在は定義されたが、具体値と設定経路が曖昧なままだと実装ごとに挙動がばらつく。
  対策: 3章に `notify_timeout_seconds=10`, `notify_retry_count=1`, `notify_retry_backoff_seconds=1.0` の初期値と設定上書き方針を明記し、4章のステップ5/8/14で設定優先順位と失敗時挙動を検証する。
- [ ] [発生確率:中][影響度:大] `watch.py` は無限監視であり、通知遅延や連続失敗が監視ループを詰まらせる可能性がある。
  対策: 3章に 1巡回あたりの最大通知数、送信キュー上限、連続失敗時の集約ログ化を追加し、4章のステップ13/14で watch 経路の上限と回復性を検証する。
- [ ] [発生確率:中][影響度:中] 構造化ログの保存形式と保存先が曖昧だと、run 後に通知結果を追跡できない。
  対策: 3章に JSONL 形式と `workspace/projects/<target>/sessions/notification_events_<run_id>.jsonl` 形式の保存先候補を明記し、4章のステップ4/6/15で run 単位サマリと照合する。

### 5.2 ソフトウェアアーキテクト観点
- [ ] [発生確率:高][影響度:中] `FindingNotificationRouter`、`Notifier`、`NotificationService` の責務境界が曖昧で、実装時に責務重複しやすい。
  対策: 2章に責務分担を明記し、4章のステップ3で主経路を router 直呼びへ固定する。
- [ ] [発生確率:中][影響度:大] 入力の型が広い一方で、正規化後の正本スキーマが未定義。
  対策: 3章に Canonical な通知用DTOの必須/任意フィールド、欠損補完規則、未知フィールドの扱いを追記し、4章のステップ4/6で実装する。
- [ ] [発生確率:中][影響度:中] EventBus 経路を「使う場合」として残すことで一次経路がぶれ、保守境界が曖昧になる。
  対策: 2章と4章に「主経路は router、EventBus は監査/二次購読用途」と明記し、ステップ9/11/15で整合させる。
- [ ] [発生確率:高][影響度:中] Canonical DTO が既存 `Finding` と重複し、二重スキーマ化する可能性がある。
  対策: 3章に既存 `Finding.to_dict()` を第一入力として再利用する方針を明記し、4章のステップ4で DTO の表現形式と既存モデルとの責務境界を確定する。
- [ ] [発生確率:中][影響度:大] fingerprint の安定性が未定義だと、将来の dedupe 互換性が崩れる。
  対策: 3章に `fingerprint_version`、計算対象フィールド、空値正規化、既存 `Finding.id` との優先順位を明記し、4章のステップ4/14で互換テストを追加する。
- [ ] [発生確率:中][影響度:中] 既存の `VULN_FOUND` 購読重複や EventBus 整理漏れが、router 導入後の二重通知につながる。
  対策: 4章のステップ9/11に既存 `VULN_FOUND` subscribe の棚卸しと整理を組み込み、EventBus を監査/二次購読用途に限定する。

### 5.3 デバッガー観点
- [ ] [発生確率:高][影響度:大] 受け入れ条件が正常系中心で、壊れた payload や欠損フィールドの再現条件が不足している。
  対策: 3.1 に `id` 欠損、`target_url` 欠損、文字列 payload、空 findings、unknown severity、malformed dict の期待動作を追記し、ステップ14で回帰テスト化する。
- [ ] [発生確率:中][影響度:中] MC / hunt / watch / EventBus のどこで落ちたかを切り分ける情報が計画に不足している。
  対策: 3章の出力/結果へ `source_component` と `ingress_path` を必須追加し、ステップ4/6/14で経路識別可能にする。
- [ ] [発生確率:中][影響度:中] 本文生成の回帰差分を確認するデバッグ素材がなく、将来の通知崩れを発見しにくい。
  対策: 4章のステップ7/14で redaction 済み golden message fixture と snapshot ないし差分比較テストを追加する。
- [ ] [発生確率:高][影響度:中] unknown severity を `info` 相当に丸める方針は、schema バグを見えにくくする可能性がある。
  対策: 3章に `raw_severity` と `normalization_warning` を必ず残す方針を追記し、4章のステップ4/14で unknown severity の警告ログを検証する。
- [ ] [発生確率:中][影響度:大] redaction 対象語彙が抽象的だと、Cookie/JWT/API key/Authorization の漏れをテストで固定しにくい。
  対策: 3章に redaction must-cover list を明記し、4章のステップ7/14で機密値別 fixture を追加する。
- [ ] [発生確率:中][影響度:中] `hunt.py` は現状、通知後に deduplication しているため、移行時に重複通知が残る可能性がある。
  対策: 4章のステップ12に通知前 dedupe の順序見直しを組み込み、`deduplicate_findings()` と router dedupe の役割をテストで固定する。
- [ ] [発生確率:中][影響度:中] 通知本文の日本語要件が fixture 化されないと、将来の修正で英語の簡易イベント通知へ戻る可能性がある。
  対策: 3章と3.1に日本語通知本文の要件を明記し、4章のステップ7/14で日本語 golden message fixture を追加する。

### 5.4 CTO観点
- [ ] [発生確率:高][影響度:大] 全 severity 即時通知は正しいが、導入直後のノイズ急増で利用者離脱を招く可能性がある。
  対策: 3章の制約へ「通知抑止はしないが、緊急停止用 kill switch と dry-run を持つ」を追加し、4章のステップ5/8/14で運用保護として実装する。
- [ ] [発生確率:中][影響度:大] 成功基準が「通知されること」に偏っており、品質 KPI が不足している。
  対策: 3.1 に「重複率、配信失敗率、redaction 漏れ 0 件、本文生成失敗 0 件」を計測基準として追加し、ステップ2/15で確認する。
- [ ] [発生確率:中][影響度:中] `watch.py` まで一気に広げる計画は切り戻し判断が難しく、段階導入条件が弱い。
  対策: 4章を「MC 経路先行導入 -> hunt/watch 拡張 -> EventBus 整合確認」の順に並べ替え、ステップ2/9-15で段階ごとの完了条件を持たせる。
- [ ] [発生確率:高][影響度:大] 運用保護や監査要件が増えたことで、1タスク内の実装スコープが広がりすぎる可能性がある。
  対策: 4章を Phase A/B/C の段階ゲート付きに再編し、MC 経路、hunt/watch 経路、EventBus/NotificationService 整合を分けて合格条件を確認する。
- [ ] [発生確率:中][影響度:大] Discord へ全 Finding 詳細を送る方針は、外部 SaaS への機密転送ポリシーとして明文化が弱い。
  対策: 3章に provider allowlist、program/target ごとの通知可否、secret finding の外部転送可否を追加し、4章のステップ5/14で policy テストを追加する。
- [ ] [発生確率:中][影響度:中] KPI はあるが、配信失敗率や重複率の合格閾値がないとリリース可否判断に使いにくい。
  対策: 3.1 に重複率 5% 以下、配信失敗率 10% 以下、redaction 漏れ 0 件、本文生成失敗 0 件を明記し、4章のステップ15で段階確認する。
- [ ] [発生確率:中][影響度:中] 日本語通知の明文化が弱いと、ユーザー体験として前回の日本語通知方針と一貫しない。
  対策: 3章に「ユーザー向け本文は日本語標準」と明記し、4章のステップ3/7/14で本文生成責務と fixture を日本語前提にする。

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] 外部ツールが raw JSON / 文字列ログだけを返す場合、`Finding` に正規化されず通知対象に乗らない - 各 adapter / tool runner で `Finding` 生成契約を段階的に追加する。
- [ ] [重要度:高] 詳細通知に evidence を入れすぎると secret / cookie / token / PII が漏れる - 通知本文用の safe summary 生成と長さ制限を必須にする。
- [ ] [重要度:中] 保存フック・EventBus・MC後処理を同時に使うと重複通知が発生する - router 側の run-local dedupe と、必要なら session-level dedupe store を追加する。
- [ ] [重要度:中] すべて即時詳細通知にすると件数が多い run で Discord がノイズ化する - 初期要件では全通知を優先し、後続で rate limit / compact mode / user-configurable verbosity を検討する。
- [ ] [重要度:中] `NotificationService` の既存 batch 設計と本要件が衝突する - 本タスクでは router を主経路にし、`NotificationService` は互換整理または廃止候補として扱う。
- [ ] [重要度:低] Discord以外の provider では Markdown 表示差が出る - provider非依存のプレーンMarkdown寄りにする。

### 6.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0297-D01
    title: "継続監視: Finding未正規化ツールの通知網羅率"
    reason: "統一router導入後も、raw JSONや文字列ログだけを返す外部ツールはFinding化されるまで通知対象外になる可能性がある"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "外部ツール別にFinding正規化状況を棚卸しし、未正規化ツールのadapter改修タスクを起票する"
```
