---
task_id: SGK-2026-0224
doc_type: plan
status: done
parent_task_id: SGK-2026-0221
related_docs:
- docs/shigoku/subtasks/2026-05-20_sgk-2026-0221-s02_groupb_discovery-graphql_subtask_plan.md
- docs/shigoku/plans/2026-05-21_sgk-2026-0222_distributed-runtime-control_plan.md
- docs/shigoku/plans/2026-05-21_sgk-2026-0223_graphql-longrun-regression-test_plan.md
- docs/shigoku/reports/2026-05-22_sgk-2026-0224_operational-hardening-backlog_work_report.md
- docs/shigoku/worklogs/2026-05-22_sgk-2026-0224_operational-hardening-backlog_worklog.md
title: 'Operational Hardening Backlog: Alert/Contract/Auth/Learning/Tenant Isolation'
created_at: '2026-05-21'
updated_at: '2026-07-02'
assignee: TBD
tags:
- shigoku
- backlog
- hardening
- operations
---

# Objective

GroupB完了後に残った運用ハードニング課題5項目を、実装状況・優先度・改善ステップ・完了判定条件つきで管理可能なバックログに整理する。
実装者がこの計画書を読むだけで迷いなく着手できることを品質基準とする。

## 今回の重点方針（運用ハードニング5本）

- 対象: Alert Governance / Contract Compatibility / Secret Operations / Other-Category Learning / Multi-tenant Isolation
- 根拠: 本タスクは運用バックログとして開始し、検知精度そのものより「誤報抑止・互換性破壊防止・テナント汚染防止」の事故予防効果を優先して完了した。
- 優先観点: 発見力の拡大より、運用信頼性に直結する再発防止・影響局所化・監査容易性を先に達成する。

---

# 実行環境前提

- **実行環境**: Kali Linux (Docker / `kalilinux/kali-rolling` ベース)。Windows非対応。
- **`fcntl.flock` 使用可能**: Task 4 のファイル並列書き込み競合対策で `fcntl.flock` を採用する（ポータビリティ考慮不要）。

---

# 現状ギャップ評価（2026-05-22時点）

| # | 項目 | 実装状況 | 主要ファイル | ギャップ概要 |
|---|------|---------|------------|------------|
| 1 | Alert Governance | 部分実装 | `graphql.py:264-280, 416-429` | level変化検知のみ。クールダウン・段階エスカレーション未実装 |
| 2 | Contract Compatibility | 部分実装 | `manager.py:19-67`, `graphql.py:22,59-74` | `CONTRACT_VERSION` が2箇所に重複定義。consumer側検証テスト未存在 |
| 3 | Secret Operations | 未実装 | なし | 実装ゼロ。スケジューラー基盤も未定義 |
| 4 | Other-Category Learning | 部分実装 | `graphql.py:237-259` | alert判定ロジックのみ。永続化・定期バッチ・昇格候補出力が未実装 |
| 5 | Multi-tenant Isolation | 未実装 | `manager.py:86` | `project_id`/`session_id` をコンストラクタ・context双方が受け取らない |

---

# 優先度と実装順

優先度は「セキュリティインパクト × 工数コスト」で設定する。

| 優先度 | タスク | 理由 |
|--------|--------|------|
| P0 | 3. Secret Operations（最小実装） | 漏洩インパクト直接的。実装ゼロが最大リスク。他タスクと独立して即着手可 |
| P0 | 2. Contract Compatibility（version統合） | 1行修正で drift確定バグを解消できる |
| P0 | 5. Multi-tenant Isolation（ContextSchema定義のみ） | `project_id` 未確定のままでは Task 3 P1・Task 4 P1 の保存パスが定まらない |
| P1 | 1. Alert Governance（クールダウン） | 既存ロジックの誤動作修正。バグ①の根治 |
| P1 | 3. Secret Operations（P1以降） | Task 5 ContextSchema完了後に保存パスを確定して続行 |
| P1 | 5. Multi-tenant Isolation（コンストラクタ改修） | ContextSchema定義完了後に実装 |
| P2 | 4. Other-Category Learning（永続化） | Task 5 完了後に `project_id` 依存の保存パスを実装 |

**着手トリガー**: P0タスクがすべて Acceptance Criteria 達成した時点で P1 に遷移。
Task 3 P0 のみ他タスクを待たず並行着手可能。

---

# Implementation Tasks

## Task 2: Contract Compatibility Program（P0）

### 問題点
- `CONTRACT_VERSION = "1.0.0"` が `graphql.py:22` と `manager.py:21` の2箇所に重複定義。変更時の drift が確定的。
- `GRAPHQL_PROBE_EVENT_REQUIRED_KEYS`（`graphql.py:59-74`）が定義済みだが `_emit_structured_event` 呼び出し時にキー検証されていない。
- Consumer-driven contract tests が存在しない。

### 改善ステップ
1. **P0（1行修正）**: `graphql.py:22` の `CONTRACT_VERSION` を正本とし、`manager.py:21` を下記に置換。
   ```python
   from src.core.agents.swarm.discovery.graphql import CONTRACT_VERSION
   ```
2. **P1**: `_emit_structured_event`（`graphql.py`）内で `GRAPHQL_PROBE_EVENT_REQUIRED_KEYS` に対するキーバリデーションを追加。欠落キーは `logger.warning` で記録。
3. **P2**: `tests/core/agents/swarm/discovery/` に consumer contract test を追加。`GraphQLNavigatorContractAdapter.normalize` の出力が `GRAPHQL_PROBE_EVENT_REQUIRED_KEYS` 全キーを持つことをテストで担保。

### 完了判定
- `CONTRACT_VERSION` の定義箇所が1箇所のみであることを `grep -r "CONTRACT_VERSION" src/` で確認。
- `GRAPHQL_PROBE_EVENT_REQUIRED_KEYS` に対するバリデーションテストがパスする。
- CI で consumer contract test が実行される。

---

## Task 3: Secret Operations Hardening（P0 → P1）

### 問題点
- 実装ゼロ。スキャン対象からの認証情報漏洩リスクが最大。
- スケジューラー基盤（cron / MasterConductor / shigoku-ops）が未定義。

### 改善ステップ
1. **P0（最小実装・即着手可）**: `scripts/audit_secrets.py` を新規作成。`config/` および `.env` 系ファイルを走査し、有効期限フィールドが `ROTATION_MAX_AGE_DAYS`（デフォルト 90 日）を超えた資格情報を検出して標準出力に JSON で出力。
   - **走査対象フィールド名**: `expires_at`, `last_rotated_at`, `created_at`（この順で優先して参照。複数存在する場合は最も新しい値を採用）。フィールドが存在しない資格情報エントリは `"expiry_unknown": true` として出力する。
2. **P1（Task 5 ContextSchema 定義完了後）**: 監査結果の保存先を `workspace/projects/<project_id>/secret_audit.json` に確定。`<project_id>` は Task 5 `ContextSchema` の `project_id` フィールドを使用。
3. **P1**: `shigoku-ops secret-audit` サブコマンドとして登録し、手動実行・CI実行を可能にする。
4. **P2**: MasterConductor の初期化フェーズに secret audit 呼び出しを追加し、期限超過資格情報を検出した場合に `logger.warning` で警告する。
5. **P3（将来）**: ローテーション自動化・最小権限ロール定義は P2 完了後に別タスクで設計。

### 完了判定
- `scripts/audit_secrets.py` が期限超過エントリを含む設定で正しくアラートを JSON 出力できる（unit test）。
- `shigoku-ops secret-audit` が 0exit で完了する。

---

## Task 5: Multi-tenant Isolation（P0 設計 → P1 実装）

### 問題点
- `DiscoveryManagerAgent.__init__`（`manager.py:86`）が `project_id`/`session_id` を受け取らない。
- `current_context` に `project_id`/`session_id` を載せる規約が未定義。
- `GraphQLNavigator` など Worker への `project_id` 伝達経路が未設計（`graphql.py:105` の `__init__` は `config: Optional[Dict]` のみ受け取る）。

### 改善ステップ

**設計決定（実装前に確定）**
- `ContextSchema` 配置先: **`src/core/agents/swarm/base.py`**（全 Agent/Specialist の共通基底として既に import 済みのため、インポート経路が最短）。
- Worker への `project_id` 伝達経路: **`config` dict に `project_id` を含める規約**とする（Worker のコンストラクタシグネチャ変更を最小に抑えるため）。`GraphQLNavigator` では `self.config.get("project_id", "")` で取得する。

1. **P0（設計先行）**: `src/core/agents/swarm/base.py` に `ContextSchema`（TypedDict）を追加。
   ```python
   class ContextSchema(TypedDict, total=True):
       project_id: str
       session_id: str
       auth_headers: dict
   ```
   **`total=True`（デフォルト）を使用し全キーを必須とする**。Task 3/4 で `project_id` が必須前提の設計であるため、optional にしない。省略可能キーが必要になった場合は `NotRequired[...]` で個別制御すること。
   この完了が **Task 3 P1 / Task 4 P1 のブロッカー**。
2. **P1**: `DiscoveryManagerAgent` および `BaseManagerAgent` のコンストラクタに `project_id: Optional[str] = None` を追加し、`current_context` への格納を統一。
3. **P1**: Worker 委譲メソッド（`run_graphql_navigator` / `run_visual_recon` 等）で `config` dict に `project_id` をマージして渡す。
4. **P2**: cross-tenant 汚染検証テストを追加。異なる `project_id` を持つ 2 インスタンスが同一 Worker オブジェクトを共有しないことをテストで確認。

### 完了判定
- `ContextSchema` が `base.py` に型定義済みで、`current_context` アクセスがすべて同スキーマを参照している。
- cross-tenant isolation test がパスする。

---

## Task 1: Alert Governance Layer（P1）

### 問題点
- `_last_alert_level` によるlevel変化検知のみ実装。クールダウン後の同level再通知が機能しない（`graphql.py:275`）。
- `_last_alert_level` はインスタンス変数のためプロセス再起動でリセット。分散実行時に `other` レートが共有されない（将来課題）。

### 改善ステップ
1. `GraphQLNavigator.__init__` に `_last_alert_at: float = 0.0` を追加（`_last_alert_level` と並列で保持）。
2. `_record_category_and_maybe_alert` のアラート発火条件を「**level上昇 OR 前回発火から `ALERT_COOLDOWN_SECONDS` 経過**」に変更。
3. `ALERT_COOLDOWN_SECONDS` を `GraphQLRuntimeConfig` の設定値として外部化。**デフォルト値は `300.0` 秒**（既存の `quarantine_seconds=30.0` より1桁大きく、アラートスパム防止として妥当なオーダー）。
4. **将来 TODO 注記のみ**: 分散環境では `_error_category_window` / `_last_alert_at` を Redis 等の外部ストアに移管する。本タスクスコープ外。

### 完了判定
- `ALERT_COOLDOWN_SECONDS` 経過後に同level再発でアラートが発火することを unit test で確認。
- warning → critical への段階エスカレーションが unit test で確認できる。
- バグ①の回帰テストがパスする。

---

## Task 4: Other-Category Learning Pipeline（P2）

### 問題点
- `evaluate_other_category_alert`（`graphql.py:243-259`）のアラート判定ロジックは存在するが、`_error_category_window` はメモリ内のみで永続化されない。
- 昇格候補生成・定期バッチ出力が未実装。

### 改善ステップ
1. **P1（Task 5 ContextSchema 定義完了後）**: `_record_category_and_maybe_alert` 内で `other` カテゴリ記録時に `workspace/projects/<project_id>/other_category_log.jsonl` へ 1 行 JSON で追記する。
   - フォーマット: `{"ts": <unix_timestamp>, "url": "<url>", "detail": "<internal_error_detail>"}`
   - **並列書き込み競合対策**: `fcntl.flock(fd, fcntl.LOCK_EX)` によるファイルロックを使用（実行環境 Kali Linux (Docker) であり、`fcntl` 使用確定）。
2. **P2**: `scripts/extract_other_category_candidates.py` を新規作成。`other_category_log.jsonl` を読み込み `internal_error_detail` の上位 N 件を集計し、カテゴリ昇格候補を Markdown/JSON で出力。
3. **P2**: `shigoku-ops learn-categories` コマンドとして登録。
4. **P3**: 昇格反映フローは人手レビュー後に `ALLOWED_ERROR_CATEGORIES`（`graphql.py:46-55`）を更新する PR プロセスとして文書化。

### 完了判定
- 実行後に `other_category_log.jsonl` にエントリが記録される（unit test）。
- `shigoku-ops learn-categories` が上位パターンを出力できる。

---

# Known Bugs（修正必須）

各バグは対応タスク実装時に同時修正し、回帰テストを追加すること。

## バグ①: Alert level 再通知欠落（Task 1 で修正）
- **場所**: `src/core/agents/swarm/discovery/graphql.py:275-280`
- **症状**: `warning`→`warning` の再発時（クールダウン後含む）にアラートが通知されない。
- **修正方針**: `_last_alert_at` を追加し、`ALERT_COOLDOWN_SECONDS` 経過後は同 level でも再通知する。

## バグ②: 複数ホスト競合時に half-open アドミッション判定が誤る（Task 1 で修正）
- **場所**: `src/core/agents/swarm/discovery/graphql.py:180-191`（`_host_admission` の `is_oldest_expired` 判定）
- **症状**: quarantine 期限切れホストが複数存在する場合、`is_oldest_expired` 判定により oldest でないホストが永続的に half-open 試行を拒否される。`quarantine_until` 再設定自体は `failures >= threshold` 分岐で正常動作している。
- **修正方針**: `_host_admission` の half-open 判定を「期限切れかつ `_host_half_open_inflight[host]` が False」のシンプル条件に変更し、`is_oldest_expired` による複数ホスト順位付けロジックを削除する。各ホストを独立して判定することで競合を排除する。

---

# Dependencies

```
Task 2 P0 (contract_version統合)
  └─→ Task 1 / Task 4 / Task 5 着手前に完了（drift バグの伝播防止）

Task 3 P0 (audit_secrets.py 最小実装)
  └─→ 他タスクと独立。即着手可

Task 5 P0 (ContextSchema 定義)
  ├─→ Task 3 P1 のブロッカー（secret_audit.json 保存パスが project_id 依存）
  └─→ Task 4 P1 のブロッカー（other_category_log.jsonl 保存パスが project_id 依存）

Task 5 P1 (コンストラクタ改修)
  └─→ Task 5 P0 完了後

Task 1 P1 (Alert クールダウン)
  └─→ Task 2 P0 完了後

Task 4 P2 (学習バッチ)
  └─→ Task 4 P1 (永続化) 完了後
```

---

# Acceptance Criteria

1. 同一事象の通知スパムが抑制され、`ALERT_COOLDOWN_SECONDS` 経過後の段階エスカレーションが定義どおり動作する。
2. `CONTRACT_VERSION` の定義が `graphql.py` の 1 箇所に統合され、Consumer-driven contract tests で互換破壊を検知できる。
3. `scripts/audit_secrets.py` が期限超過資格情報を検出し、`shigoku-ops secret-audit` として実行できる。
4. `other` カテゴリ昇格候補が `shigoku-ops learn-categories` で定期出力される。
5. 異なる `project_id` 間で制御状態が混在しない（cross-tenant isolation test がパス）。

---

# Validation

| 種別 | 対象 |
|------|------|
| Unit | alert cooldown / escalation / contract version single-source / namespace isolation |
| Unit | half-open re-admission (バグ②回帰) / alert re-notify (バグ①回帰) |
| Integration | notification flow / contract consumer checks / secret audit flow |
| Operational | `shigoku-ops secret-audit` 出力確認 / `shigoku-ops learn-categories` 出力確認 |

---

# Stakeholder コメント

## SRE / インフラエンジニア観点

- Alert cooldown と段階エスカレーションは、オンコール疲弊を防ぎ MTTA/MTTR の安定化に効く。
- Secret audit の `shigoku-ops` 化は、日次運用とCIへの組み込みがしやすく、監査証跡も残しやすい。
- Tenant isolation は障害の blast radius を縮小できるため、運用事故時の影響面積を制御しやすい。

## ソフトウェアアーキテクト観点

- Contract version の単一正本化は、変更容易性と互換維持の両立に必須。
- `ContextSchema` の先行定義で、後続の Secret/Learning 実装に一貫したデータ境界を与えられる。
- 5本を依存順で分割しているため、設計負債を増やさず段階導入できる。

## バグハンター観点

- この5本は「検知漏れ拡大」より先に「誤検知・壊れた契約・クロステナント汚染」を潰す守りの施策。
- 特に contract test と isolation test は、再現性ある回帰検知ポイントとして価値が高い。
- `other` 学習はノイズ源の可視化に寄与し、誤分類由来のアラート品質低下を抑制できる。

## CTO観点

- 短期では大きな新機能追加より、事故予防に集中することで事業継続リスクを下げる判断が妥当。
- 既存アーキテクチャを壊さない最小導入（P0/P1分割）で投資対効果を確保している。
- 完了判定をテスト/CLI運用確認まで定義しており、実装完了と運用品質完了を分離して評価できる。
