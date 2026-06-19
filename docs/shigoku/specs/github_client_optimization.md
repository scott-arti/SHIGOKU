---
task_id: SGK-2026-0127
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Feature Specification: GitHub Client Optimization

## 概要

`GitHubClient` (`src/tools/osint/github_recon.py`) のパフォーマンスと安定性を向上させるため、セッション確立のオーバーヘッドを排除し、システム標準の `AsyncNetworkClient` を利用するようにリファクタリングする。

## 現状の課題

1. **TCP/SSLオーバーヘッド**: メソッド呼び出しごとに `aiohttp.ClientSession` を作成しており、遅延が大きい。
2. **プロキシ未対応**: システムのプロキシチェーンを経由していないため、GitHub API のレート制限やブロックのリスクが高い。
3. **リソース枯渇**: 大量のインスタンス化によりファイルディスクリプタを消費する。

## 変更内容

### 1. `src/tools/osint/github_recon.py`

- `GitHubClient.__init__` に `network_client: Optional[AsyncNetworkClient]` 引数を追加。
- 既存の `aiohttp.ClientSession` を直接使用するロジックを、`network_client.request()` を使用するように変更。
- 後方互換性のため、`network_client` が提供されない場合は、一時的なセッションを作成する（ただし非推奨とする）。

### 2. `src/core/agents/swarm/intelligence/manager.py`

- `GitHubReconSpecialist` が `set_network_client` メソッドで受け取った共有クライアントを `GitHubClient` に渡すように修正。

## 期待される効果

- APIリクエストのレイテンシ削減 (TCP/SSLハンドシェイク排除)。
- プロキシ利用による匿名性と耐障害性の向上。
- エラーハンドリングの統一。

## 検証計画

- `tests/tools/osint/test_github_recon.py` (新規作成または既存修正) にて、`AsyncNetworkClient` のモックを使用したテストを実施。
- E2Eでの動作確認。
