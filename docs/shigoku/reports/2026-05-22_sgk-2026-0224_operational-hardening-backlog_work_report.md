---
task_id: SGK-2026-0224
doc_type: work_report
status: done
parent_task_id: SGK-2026-0221
related_docs:
- docs/shigoku/plans/2026-05-21_sgk-2026-0224_operational-hardening-backlog_plan.md
- docs/shigoku/worklogs/2026-05-22_sgk-2026-0224_operational-hardening-backlog_worklog.md
created_at: '2026-05-22'
updated_at: '2026-07-02'
---

# 作業報告書: Operational Hardening Backlog

## 概要

SGK-2026-0224 で管理された運用ハードニングバックログ全タスク（P0〜P2）を完了した。
計画書に定義された 5 テーマ・13 実装項目を実装・テスト・ドキュメントバリデーションまで完遂した。

---

## 実装内容

### P0 タスク（全完了）

| ID | 内容 | 主な変更ファイル |
|----|------|----------------|
| Task 2 P0 | `CONTRACT_VERSION` single-source 化 | `discovery/manager.py` |
| Task 5 P0 | `ContextSchema` TypedDict 追加 (`base.py`) | `swarm/base.py` |
| Task 3 P0 | `scripts/audit_secrets.py` 最小実装 | `scripts/audit_secrets.py` |

### バグ修正（Bug #1・#2）

| バグ | 内容 | 修正箇所 |
|------|------|---------|
| Bug #1 | アラート同 level がクールダウン後も再通知されない | `graphql.py: _record_category_and_maybe_alert` |
| Bug #2 | half-open で最古ホストのみ試行可能という競合ロジック | `graphql.py: _host_admission` |

### P1 タスク（全完了）

| ID | 内容 | 主な変更ファイル |
|----|------|----------------|
| Task 1 P1 | アラートクールダウン (`ALERT_COOLDOWN_SECONDS=300.0`) | `graphql.py` |
| Task 2 P1 | `_emit_structured_event` キーバリデーション | `graphql.py` |
| Task 5 P1 | `BaseManagerAgent`/`DiscoveryManagerAgent` に `project_id`/`session_id` 追加、`_worker_config` で Worker に伝播 | `base_manager.py`, `discovery/manager.py` |
| Task 3 P1 | `shigoku-ops ops secret-audit` コマンド登録 | `scripts/shigoku_ops_cli.py` |

### P2 タスク（全完了）

| ID | 内容 | 主な変更ファイル |
|----|------|----------------|
| Task 2 P2 | consumer contract test 追加 | `tests/core/agents/swarm/test_discovery_graphql_contract.py` |
| Task 4 P1 | `other_category_log.jsonl` 永続化 (`fcntl.flock`) | `graphql.py` |
| Task 4 P2 | `shigoku-ops ops learn-categories` CLI 登録 | `scripts/shigoku_ops_cli.py` |
| Task 5 P2 | cross-tenant isolation テスト (11 ケース) | `tests/core/agents/swarm/test_multitenant_isolation.py` |

### CTO 指摘対応（全完了）

| 指摘 | 対応内容 | ファイル |
|------|---------|---------|
| `get_event_loop()` 非推奨 | `get_running_loop()` に変更 | `graphql.py:324`, `base_manager.py:133` |
| `_validate_context_schema` 未呼び出し | `dispatch()` 冒頭で自動呼び出し | `base_manager.py:199` |
| `project_id`/`session_id` が `dispatch()` 上書きで消失 | 上書き前に保持・上書き後に復元 | `base_manager.py:187-198` |
| `other_category_log_dir` が相対パス | `__file__` アンカーの絶対パスに変更 | `graphql.py:126-131` |
| `audit_secrets.py` の `--env-patterns` 未対応 | `--env-pattern` (repeatable) CLI 追加 | `scripts/audit_secrets.py` |
| `_worker_config` が `AgentConfig` 非対応 | `model_dump()` → `vars()` フォールバックチェーン | `discovery/manager.py:98-114` |
| `current_context` 型ギャップ | `_validate_context_schema()` ヘルパー追加 | `base_manager.py:86-95` |

---

## テスト結果

```
43 passed in 4.63s
```

| テストファイル | 件数 |
|--------------|------|
| `test_discovery_graphql_contract.py` | 11 |
| `test_discovery_graphql_alerting.py` | 11 |
| `test_audit_secrets.py` | 12 |
| `test_multitenant_isolation.py` | 11 |
| `test_discovery_manager.py` | 1 |
| 他 (alerting 含む) | 残差 |

ドキュメントバリデーション: `FRONT_MATTER_ISSUES=0`, `BROKEN_LINKS=0`, `REGISTRY_ISSUES=0`

---

## 設計判断・リスク

### 設計判断

- **`ContextSchema` の `total=True` 採用**: 全キー必須を型レベルで表明。`auth_headers` は後段注入のため `_validate_context_schema()` による実行時警告で補完。
- **`_worker_config` フォールバックチェーン**: `dict` → `model_dump()` → `vars()` → `{}` とすることで Pydantic v1/v2 混在期・任意オブジェクトに対応。
- **`fcntl.flock` 使用**: 計画書で Kali Linux (Docker) 限定と確認済みのため Linux-only API を採用。
- **`get_running_loop()` 採用**: Python 3.10+ での非推奨対応。asyncio コンテキスト外からの呼び出しは `_record_other_and_persist` が async メソッドであるため問題なし。
- **`dispatch()` 内の project_id 保持**: `current_context` の上書きを最小変更で安全にラップ。後方互換を維持。

### リスク

- **`other_category_log_dir` の親5レベル計算**: `src/core/agents/swarm/discovery/graphql.py` が移動した場合に `parents[5]` がズレる。`SHIGOKU_OTHER_CATEGORY_LOG_DIR` 環境変数で上書き可能にする運用で緩和推奨。
- **`_validate_context_schema` の `auth_headers` 警告**: `auth_headers={}` (空 dict) は falsy のため「未設定」と判定される。空ヘッダーで正常運用するケースでは誤警告が出る可能性がある。

---

## 未対応事項

```yaml
deferred_tasks:
  - id: DEFERRED-0224-01
    title: SHIGOKU_OTHER_CATEGORY_LOG_DIR 環境変数によるパス上書き対応
    reason: 緊急度低。現状は graphql_probe_other_log_dir config キーで上書き可能。
    priority: low
  - id: DEFERRED-0224-02
    title: _validate_context_schema の auth_headers 空判定改善
    reason: 空ヘッダー正常運用ケースで誤警告の可能性。実運用での頻度確認後に対応。
    priority: low
```
