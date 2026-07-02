---
task_id: SGK-2026-0073
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-01-26'
updated_at: '2026-07-02'
---

# 仕様書: Phase 1.3 Proxy Integration Completion

**目標**: システム全体でのプロキシローテーションと統一HTTPクライアント (`AsyncNetworkClient`) の適用を完了させ、匿名性と耐障害性を確保する。

## 1. 概要

現在、`auth_ninja.py` などの一部のエージェントのみが `AsyncNetworkClient` に移行しています。`BizLogicHunter` や Specialized Agents は依然として生の `httpx` を使用しており、プロキシローテーション、レート制限、リトライ機構が一貫して適用されていません。これらをすべて `AsyncNetworkClient` に移行します。

## 2. 変更対象

### 2.1 Core Agents

- **`src/core/agents/swarm/biz_logic_hunter.py`**
  - `httpx` インポートを削除。
  - `_make_request` メソッドを `AsyncNetworkClient.request` を使用するように書き換え。
  - `use_proxy_rotation=True` をデフォルトで適用。

### 2.2 Specialized Agents

以下のエージェントについても `httpx` を `AsyncNetworkClient` に置換します。

- **`src/core/agents/specialized/taint_analysis_agent.py`**
  - `analyze` メソッド内の `httpx.get`/`post` を置換。
- **`src/core/agents/specialized/api_spec_reconstructor.py`**
  - `_fetch_content` メソッド内の `httpx.get` を置換。
- **`src/core/agents/specialized/graphql_navigator.py`**
  - `explore`, `_try_introspection` 等のメソッド内の `httpx.post` を置換。

## 3. 実装詳細ルール

- **依存注入**: 各エージェントの `__init__` で `network_client` を受け取れるようにする（または都度取得）。
- **エラーハンドリング**: `httpx.RequestError` のキャッチ部分は `NetworkClientError` またはそのラッパーに対応させる（互換性のため `httpx.RequestError` は `AsyncNetworkClient` が再送出する場合も考慮）。
- **Verify無効化**: 自己署名証明書対策の `verify=False` は `AsyncNetworkClient` の設定に従う（デフォルト `verify=False`）。

## 4. 検証計画 (Verification)

### 4.1 統合テスト (`tests/unit/core/agents/test_proxy_integration_complete.py`)

新たなテストファイルを作成し、以下のシナリオを検証します。

1. **Client Usage Verification**: 各エージェントを実行した際、モック化された `AsyncNetworkClient.request` が呼び出されることを確認。
2. **Proxy Parameter**: 呼び出し時に `use_proxy_rotation=True` が渡されていることを確認。

```python
# テストイメージ
@patch("src.core.infra.network_client.AsyncNetworkClient.request")
async def test_bizlogic_uses_client(mock_request):
    agent = BizLogicHunter()
    await agent.execute(...)
    mock_request.assert_called_with(..., use_proxy_rotation=True)
```
