---
task_id: SGK-2026-0072
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-01-26'
updated_at: '2026-07-02'
---

# Proxy Integration & Error Replanning Spec

**作成日**: 2026-01-26
**対象フェーズ**: Phase 1.3 & 1.5

## 概要

本仕様書は、Shigokuフレームワークの堅牢性とステルス性を向上させる2つの重要機能の実装定義である。

1.  **Phase 1.3: プロキシ完全統合 (Proxy Integration)**
    - すべての外部HTTPリクエストを `AsyncNetworkClient` 経由に統一し、IPローテーションと匿名性を確保する。
    - `AuthNinja` および `Specialized Agents` に残る `requests`/`httpx` の直接使用を排除する。

2.  **Phase 1.5: エラーハンドリング＆リプラン (Error Replanning)**
    - エラー発生時、単純なリトライだけでなく「戦略的な迂回」を提案する脳 (`ErrorReplanner`) を実装する。
    - WAFブロック (403/406) や検知 (429) に対して、適切な対抗策（Wait, Rotate Proxy, Obfuscate Payload）を自動実行する。

---

## 変更範囲

### 1. Phase 1.3: プロキシ統合

以下のファイルで `import requests`, `import httpx`, `import aiohttp` を削除し、`AsyncNetworkClient` または `self.http_client` を使用するようにリファクタリングする。

| 対象ファイル                                            | 変更内容                                                             |
| ------------------------------------------------------- | -------------------------------------------------------------------- |
| `src/core/agents/swarm/auth_ninja.py`                   | `JWTInspector`, `OAuthDancer` 内の `requests` 呼び出しをすべて置換。 |
| `src/core/agents/swarm/biz_logic_hunter.py`             | `httpx` を置換。                                                     |
| `src/core/agents/specialized/race_condition_agent.py`   | `aiohttp` を `AsyncNetworkClient` (またはその背後のsession) に統合。 |
| `src/core/agents/specialized/api_spec_reconstructor.py` | `httpx` を置換。                                                     |
| `src/core/agents/specialized/scope_parser.py`           | `httpx` を置換。                                                     |
| `src/core/agents/specialized/graphql_navigator.py`      | `httpx` を置換。                                                     |
| `src/core/agents/specialized/visual_recon.py`           | スクリーンショット取得以外のHTTPリクエストを統合。                   |

**検証基準:**

- `grep` で `requests.get`, `httpx.get` 等が検出されないこと。
- E2Eテストでプロキシ設定 (`ProxyManager`) が動作していること（ログで確認）。

### 2. Phase 1.5: エラーリプラン

#### 新規作成: `src/core/engine/error_replanner.py`

```python
class ErrorReplanner:
    def analyze_error(self, task: Task, error: Exception, context: ExecutionContext) -> PlanUpdate:
        """
        エラーを解析し、次のアクションを決定する。

        Returns:
            PlanUpdate: リトライ、スキップ、パラメータ変更、Agent変更などの指示
        """
```

**対応するエラータイプ:**

- **403 Forbidden / 406 Not Acceptable**: WAF検知。
  - Action: `ROTATE_PROXY`, `OBFUSCATE_PAYLOAD`, `INCREASE_DELAY`
- **429 Too Many Requests**: レート制限。
  - Action: `WAIT`, `ROTATE_PROXY`
- **500/502/503/504**: サーバーエラー。
  - Action: `RETRY_WITH_BACKOFF`
- **ConnectionError**: ネットワーク断。
  - Action: `CHECK_NETWORK`, `RETRY`

#### 変更: `src/core/engine/master_conductor.py`

- `execute_task` メソッドの `except` ブロックで `ErrorReplanner` を呼び出す。
- リプラン指示に基づいて、タスクを修正（ミューテーション）して `task_queue` に再投入するか、完全に失敗させるかを分岐。

**検証基準:**

- モックサーバーで 403 エラーを返した際、ログに「Replanning task due to WAF block」等のメッセージが出力され、再試行が行われること。

---

## タスクリスト

### Phase 1.3: Proxy Integration

- [ ] `AuthNinja` リファクタリング
- [ ] `BizLogicHunter` リファクタリング
- [ ] Specialized Agents リファクタリング (`race_condition`, `api_spec`, `scope_parser`, `graphql`)
- [ ] Verification: Grep & Test Start

### Phase 1.5: Error Replanning

- [ ] `ErrorReplanner` 実装
- [ ] `MasterConductor` 統合
- [ ] Verification: Error Simulation Unit Test
