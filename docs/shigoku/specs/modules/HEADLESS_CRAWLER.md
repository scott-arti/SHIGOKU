---
task_id: SGK-2026-0039
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# HeadlessCrawler - Headless ブラウザ統合モジュール

## 概要

**HeadlessCrawler** は、Playwright を使用して JavaScript レンダリングが必要な
SPA サイトをクロールし、動的コンテンツから URL・エンドポイント・API 呼び出しを
抽出するモジュールです。

---

## 主要機能

### 1. JavaScript レンダリング

- Chromium ベースのヘッドレスブラウザ
- ネットワークアイドル待機
- タイムアウト管理

### 2. 動的 URL 抽出

- `<a href>` リンク抽出
- `form action` 抽出
- `data-*` 属性抽出

### 3. API 呼び出し検出

- `/api/` パスの監視
- `/graphql` リクエスト検出
- `.json` リクエスト検出

### 4. JS ファイル収集

- `<script src>` 抽出
- 静的解析用

---

## アーキテクチャ

```
┌─────────────────────────────────────────────────┐
│              HeadlessCrawler                     │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌─────────────────────────────────────────┐    │
│  │ Playwright Browser (Chromium)           │    │
│  └─────────────────────────────────────────┘    │
│         │                                       │
│         │ Request監視                           │
│         ▼                                       │
│  ┌─────────────────────────────────────────┐    │
│  │ Page Navigation                         │    │
│  │ → wait_until="networkidle"              │    │
│  └─────────────────────────────────────────┘    │
│         │                                       │
│    ┌────┴────┬────────────┬───────────┐        │
│    ▼         ▼            ▼           ▼        │
│ ┌──────┐ ┌──────┐ ┌───────────┐ ┌─────────┐    │
│ │ URLs │ │ End │ │ JS Files  │ │API Calls│    │
│ └──────┘ │points│ └───────────┘ └─────────┘    │
│          └──────┘                              │
│                                                 │
└─────────────────────────────────────────────────┘
```

---

## 使用方法

### インストール

```bash
pip install playwright
playwright install chromium
```

### 基本的な使用（非同期）

```python
import asyncio
from src.core.intel.headless_crawler import HeadlessCrawler

async def main():
    crawler = HeadlessCrawler(headless=True)

    result = await crawler.crawl(
        url="https://example.com",
        depth=2,
        same_origin=True
    )

    print(f"URLs: {len(result.discovered_urls)}")
    print(f"Endpoints: {result.discovered_endpoints}")
    print(f"API calls: {result.api_calls}")
    print(f"JS files: {len(result.js_files)}")

    await crawler.close()

asyncio.run(main())
```

### 同期版

```python
from src.core.intel.headless_crawler import create_headless_crawler

crawler = create_headless_crawler(headless=True)
result = crawler.crawl_sync("https://example.com")

print(f"Discovered: {len(result.discovered_urls)} URLs")
```

---

## CrawlResult

```python
@dataclass
class CrawlResult:
    url: str                        # クロール対象URL
    discovered_urls: List[str]      # 発見されたURL
    discovered_endpoints: List[str] # form action, data-* 属性
    js_files: List[str]             # JSファイルパス
    api_calls: List[str]            # 検出されたAPI呼び出し
    errors: List[str]               # エラー一覧
```

---

## 抽出対象

### URL 抽出

```html
<a href="/dashboard">Dashboard</a> → https://example.com/dashboard
```

### エンドポイント抽出

```html
<form action="/api/submit">
  <div data-url="/api/users">
    <button data-api="/graphql">
      <span data-endpoint="/v1/search"></span>
    </button>
  </div>
</form>
```

### API 呼び出し検出

```
[Request監視]
GET /api/users
POST /graphql
GET /data.json
```

---

## オプション

### same_origin

同一オリジン制限の有効/無効

```python
# 同一オリジンのみ
result = await crawler.crawl(url, same_origin=True)

# 外部リンクも収集
result = await crawler.crawl(url, same_origin=False)
```

### headless

ブラウザ表示の有無

```python
# ヘッドレス（デフォルト）
crawler = HeadlessCrawler(headless=True)

# ブラウザ表示（デバッグ用）
crawler = HeadlessCrawler(headless=False)
```

---

## 使用例

### SPA クローリング

```python
# React/Vue/Angularサイト
result = await crawler.crawl("https://spa-app.example.com")

# 動的に生成されたリンクも取得
print(result.discovered_urls)
# ['/app/users', '/app/settings', '/api/profile', ...]
```

### API 発見

```python
result = await crawler.crawl("https://api.example.com/docs")

# SwaggerUI等から検出されたAPI
print(result.api_calls)
# ['/api/v1/users', '/api/v1/orders', ...]
```

---

## WordlistLearner との連携

```python
from src.core.intel.headless_crawler import create_headless_crawler
from src.core.wordlist import get_wordlist_learner

crawler = create_headless_crawler()
result = crawler.crawl_sync("https://example.com")

learner = get_wordlist_learner()
learner.add_urls(result.discovered_urls)
learner.add_urls(result.api_calls)
learner.save_all()
```

---

## 制限事項

1. **Playwright が必要**

   - 未インストール時はエラー
   - `is_playwright_available()` で確認可能

2. **リソース消費**

   - ブラウザ起動のためメモリ使用
   - 並列実行に注意

3. **認証サイト**
   - ログイン必要なサイトは対応外
   - Cookie 設定は手動必要

---

## 関連モジュール

| モジュール                             | 連携             |
| -------------------------------------- | ---------------- |
| [WordlistLearner](WORDLIST_LEARNER.md) | 発見 URL の学習  |
| [GAUIntegrator](GAU_INTEGRATOR.md)     | 静的 URL 収集    |
| [Cartographer](CARTOGRAPHER.md)        | サイトマッピング |
