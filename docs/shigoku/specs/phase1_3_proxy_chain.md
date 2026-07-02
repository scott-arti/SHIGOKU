---
task_id: SGK-2026-0144
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# Phase 1.3: Proxy Chain & Async Network Client 仕様書

## 概要

**機能名**: `AsyncNetworkClient` with `ProxyChainManager`

**目的**:
Swarm Agent の大量の並列リクエストを支えるため、高速で匿名性の高い非同期ネットワーククライアントを実装する。
特に WAF 回避とレートリミット分散のために、プロキシローテーションとプロキシチェーン（多段プロキシ）をサポートする。

**背景**:

- 既存の `src/core/infra/proxy_rotation.py` は `requests` ベース（同期）でパフォーマンス不足
- 多段プロキシ（Tor -> Proxy など）のサポートがない
- `SwarmRetryEngine` から利用できる統一的な非同期クライアントが必要

---

## 変更範囲

| ファイル                                  | 変更内容                                                      |
| ----------------------------------------- | ------------------------------------------------------------- |
| `src/core/infra/network_client.py`        | 🆕 新規作成 - 非同期ネットワーククライアント                  |
| `src/core/infra/proxy_manager.py`         | 🆕 新規作成 - プロキシ管理（既存 `proxy_rotation.py` の後継） |
| `src/core/agents/swarm/retry_engine.py`   | 📝 修正 - `AsyncNetworkClient` を利用するように変更           |
| `tests/unit/infra/test_network_client.py` | 🆕 新規作成 - テスト                                          |
| `tests/unit/infra/test_proxy_manager.py`  | 🆕 新規作成 - テスト                                          |

---

## 機能詳細

### 1. ProxyChainManager

プロキシリストを管理し、健全なプロキシを提供する。

```python
@dataclass
class ProxyNode:
    url: str  # http://user:pass@host:port
    latency: float = 0.0
    fail_count: int = 0
    is_active: bool = True
    last_used: float = 0.0

class ProxyChainManager:
    """プロキシ管理・ローテーション・チェイン構築"""

    def __init__(self, proxy_urls: List[str] = None):
        self.proxies: List[ProxyNode] = []

    def get_proxy(self) -> Optional[str]:
        """使用可能なプロキシを1つ取得（ラウンドロビン/ランダム）"""
        pass

    def build_chain(self, depth: int = 2) -> List[str]:
        """多段プロキシチェーンを構築（対応している場合）"""
        # ※ 今回はシングルプロキシのローテーションを主眼とし、
        #    aiohttp での多段はライブラリ制約があるため将来拡張とする
        pass

    def report_failure(self, proxy_url: str):
        """プロキシ失敗を報告（スコアダウン/除外）"""
        pass
```

### 2. AsyncNetworkClient

`aiohttp` をラップし、以下の機能を提供する:

- **自動プロキシローテーション**: リクエスト毎に異なるプロキシを使用
- **透過的リトライ**: タイムアウト、接続エラー時の自動リトライ
- **詳細なロギング**: リクエスト/レスポンスの詳細ログ (Debug用)
- **統一されたレスポンス型**: ステータス、ヘッダー、ボディ、時間をまとめたオブジェクト

```python
@dataclass
class NetworkResponse:
    status: int
    headers: Dict[str, str]
    body: str  # テキスト
    elapsed: float
    url: str
    proxy_used: Optional[str] = None

class AsyncNetworkClient:
    def __init__(self, proxy_manager: Optional[ProxyChainManager] = None):
        self.proxy_manager = proxy_manager

    async def request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str] = None,
        data: Any = None,
        json: Any = None,
        timeout: int = 30,
        use_proxy: bool = True,
        retries: int = 3
    ) -> NetworkResponse:
        """
        リクエストを実行

        1. プロキシ取得
        2. aiohttp でリクエスト
        3. 失敗時: 別プロキシでリトライ
        4. WAF検出などは上位レイヤー(RetryEngine)に任せる
        """
        pass
```

### 3. SwarmRetryEngine 統合

現在は `RetryEngine` 内で HTTP クライアントを直書きしていないが（Specialist に依存）、
Specialist が `AsyncNetworkClient` を使うようにパラメータとして渡す、あるいはシングルトンとして利用する形にする。

今回は **Dependency Injection** パターンを採用し、`Specialist` の初期化時に `AsyncNetworkClient` を渡せるようにする。

---

## 実装ステップ

1. **ProxyManager**: プロキシリスト管理ロジック実装
2. **AsyncNetworkClient**: `aiohttp` ラッパー実装
3. **テスト**: ユニットテスト作成
4. **統合**: 既存コードには影響を与えず、新しいAgentから利用可能にする（今回は基盤のみ作成）

## 制約事項

- `aiohttp` のネイティブなプロキシサポートを使用
- プロキシチェーン（多段）は `aiohttp` が標準で対応していないため、今回は **Proxy Rotation (IP分散)** に注力する
- AWS FireProx 等の対応は `ProxyManager` の拡張として実装可能にする

## 完了条件

- `AsyncNetworkClient` を使ってリクエストが送信できる
- 指定したリストからプロキシがローテーションされる
- プロキシダウン時に自動で別プロキシにフォールバックする
