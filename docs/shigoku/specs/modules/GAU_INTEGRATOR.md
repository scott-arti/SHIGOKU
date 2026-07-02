---
task_id: SGK-2026-0038
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# GAUIntegrator - GAU 統合モジュール

## 概要

**GAUIntegrator** は、GAU (GetAllUrls) ツールを統合し、
ターゲットドメインの URL 収集とパターン分析を行うモジュールです。
API コスト最適化のため、統計サマリーのみを AI に渡します。

---

## 主要機能

### 1. GAU 実行ラッパー

- `gau` コマンドの実行
- タイムアウト管理
- プロバイダー選択

### 2. パターン分析

- パスセグメント頻度分析
- 拡張子分布
- パラメータ分析
- API/管理画面検出

### 3. ワードリスト推奨

- 検出パターンに基づく推奨
- フレームワーク推測

---

## アーキテクチャ

```
┌─────────────────────────────────────────────────┐
│              GAUIntegrator                       │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌─────────────────────────────────────────┐    │
│  │ GAU Command Executor                    │    │
│  │ gau --subs target.com                   │    │
│  └─────────────────────────────────────────┘    │
│                    │                            │
│                    ▼                            │
│  ┌─────────────────────────────────────────┐    │
│  │ Pattern Analyzer                        │    │
│  │ - Path segments (Counter)               │    │
│  │ - Extensions                            │    │
│  │ - Parameters                            │    │
│  │ - API/Admin detection                   │    │
│  └─────────────────────────────────────────┘    │
│                    │                            │
│                    ▼                            │
│  ┌─────────────────────────────────────────┐    │
│  │ Summary for AI                          │    │
│  │ (統計情報のみ、ファイル全体ではない)    │    │
│  └─────────────────────────────────────────┘    │
│                                                 │
└─────────────────────────────────────────────────┘
```

---

## 使用方法

### URL 取得

```python
from src.core.wordlist import get_gau_integrator

gau = get_gau_integrator()

# URL取得
urls = gau.fetch_urls("example.com", timeout=60)
print(f"Found {len(urls)} URLs")
```

### パターン分析

```python
analysis = gau.analyze_patterns(urls)

print(analysis)
# {
#   'total_urls': 5000,
#   'top_paths': {'api': 500, 'admin': 100, 'v1': 300},
#   'top_extensions': {'php': 200, 'js': 800},
#   'patterns': {
#     'has_api': True,
#     'has_admin': True,
#   },
#   'recommendations': ['api', 'php', 'admin']
# }
```

### AI 向けサマリー取得

```python
# APIコスト最適化版
summary = gau.get_summary_for_ai("example.com")
print(summary)
# GAU Analysis for example.com:
# - Total URLs: 5000
# - Top paths: api, admin, v1, login, dashboard
# - Has API endpoints: True
# - Recommended wordlists: api, admin
```

---

## プロバイダー

GAU は以下のプロバイダーから URL を収集：

| プロバイダー | データソース    |
| ------------ | --------------- |
| wayback      | Wayback Machine |
| otx          | AlienVault OTX  |
| commoncrawl  | Common Crawl    |
| urlscan      | URLScan.io      |

### プロバイダー指定

```python
urls = gau.fetch_urls(
    "example.com",
    providers=["wayback", "otx"]
)
```

---

## パターン検出

### API 検出

```python
# 以下のパターンを検出
/api/
/v1/
/v2/
/graphql
/rest/
```

### 管理画面検出

```python
# 以下のパターンを検出
/admin
/backend
/manage
/dashboard
```

---

## API コスト最適化

### 従来の方法（高コスト）

```
❌ URL全件（10万件）をAIに送信
→ トークン消費: 大量
→ 処理時間: 長い
```

### GAUIntegrator 方式（最適化）

```
✅ 統計サマリーのみ送信
→ トークン消費: 最小限
→ 処理速度: 高速

サマリー例:
"Found 50000 URLs, top paths: api(5000), admin(1000)
Detected: API endpoints, admin paths
Recommend: api, admin wordlists"
```

---

## 依存関係

### GAU インストール

```bash
go install github.com/lc/gau/v2/cmd/gau@latest
```

### 確認

```python
gau = get_gau_integrator()
print(f"GAU available: {gau.gau_available}")
```

---

## 関連モジュール

| モジュール                                   | 連携                 |
| -------------------------------------------- | -------------------- |
| [WordlistLearner](WORDLIST_LEARNER.md)       | URL 学習             |
| [WordlistManager](WORDLIST_MANAGER.md)       | 推奨ワードリスト選択 |
| [ProgressiveScanner](PROGRESSIVE_SCANNER.md) | 段階的スキャン       |
