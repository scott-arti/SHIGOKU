---
task_id: SGK-2026-0034
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Cartographer - サイトマッピングエンジン

**モジュールパス**: `src/core/intel/cartographer.py`

---

## 概要 (Overview)

**Cartographer** は、SHIGOKU の「眼」として機能する偵察モジュールです。指定された URL を起点に再帰的なクロールを実行し、ターゲット Web サイトの完全なサイトマップを構築します。

**主な役割**:

1. Web ページを再帰的にクロールし、リンク構造を解析
2. フォーム（入力フィールド）を検出・抽出
3. 発見した資産（ページ、リンク、フォーム）をナレッジグラフ（Neo4j）に保存
4. `EthicsGuard` と連携し、スコープ外へのクロールを防止

---

## アーキテクチャ (Architecture)

```
              ┌──────────────────┐
              │   Entry Point    │
              │   (Seed URL)     │
              └────────┬─────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│                      Cartographer Engine                      │
│  ┌────────────┐   ┌────────────┐   ┌────────────────────┐    │
│  │URL Queue   │ → │HTML Parser │ → │Link/Form Extractor │    │
│  │(BFS/DFS)   │   │(BeautifulS)│   │                    │    │
│  └────────────┘   └────────────┘   └────────────────────┘    │
│        │                                    │                 │
│        │         ┌──────────────┐           │                 │
│        └────────→│ EthicsGuard │←──────────┘                 │
│                  │ (Scope Check)│                             │
│                  └──────────────┘                             │
└──────────────────────────────────────────────────────────────┘
                       │
                       ▼
              ┌──────────────────┐
              │  Neo4j Graph DB  │
              │  (Store Results) │
              └──────────────────┘
```

---

## 主要機能 (Key Features)

### 1. 再帰的クロール (Recursive Crawling)

指定された深度（`max_depth`）までリンクを辿り、ページを発見します。

**クロール戦略**:

- **BFS (幅優先探索)**: デフォルト。浅いページを先に探索し、サイト全体の概要を素早く把握。
- **DFS (深さ優先探索)**: オプション。特定のディレクトリを深く掘り下げたい場合に有効。

```python
# 深度設定の影響
# max_depth=1: シードURL直下のリンクのみ
# max_depth=2: シードURL + リンク先のページのリンク
# max_depth=3+: さらに深く（時間とリソース消費増大）
```

### 2. リンク抽出 (Link Extraction)

HTML から以下の形式のリンクを抽出します：

| 要素       | 属性     | 例                             |
| :--------- | :------- | :----------------------------- |
| `<a>`      | `href`   | `<a href="/about">About</a>`   |
| `<form>`   | `action` | `<form action="/login">`       |
| `<script>` | `src`    | `<script src="/js/app.js">`    |
| `<link>`   | `href`   | `<link href="/css/style.css">` |
| `<img>`    | `src`    | `<img src="/img/logo.png">`    |
| `<iframe>` | `src`    | `<iframe src="/embed">`        |

**URL 正規化**:

- 相対パス（`/about`）は絶対 URL に変換
- フラグメント（`#section`）は除去
- クエリパラメータはソートして正規化（重複検知のため）

### 3. フォーム検出 (Form Detection)

ページ内の`<form>`要素を解析し、以下の情報を抽出します：

```python
@dataclass
class FormData:
    action: str           # フォームの送信先
    method: str           # GET / POST
    inputs: List[dict]    # 入力フィールドのリスト
    # 例: [{"name": "username", "type": "text"}, {"name": "password", "type": "password"}]
```

**検出されるフォームの例**:

- ログインフォーム
- 検索フォーム
- ユーザー登録フォーム
- コメント投稿フォーム

### 4. スコープ強制 (Scope Enforcement)

`EthicsGuard` と統合し、以下を保証します：

- スコープ外ドメインへのリクエストは送信されない
- 外部リンク（CDN、広告など）は追跡対象から除外
- 禁止パス（`/logout`など）は自動的にスキップ

---

## 設定オプション (Configuration)

### コンストラクタパラメータ

| パラメータ     | 型            | デフォルト | 説明                              |
| :------------- | :------------ | :--------- | :-------------------------------- |
| `ethics_guard` | `EthicsGuard` | **必須**   | スコープチェック用                |
| `max_depth`    | `int`         | `2`        | 最大クロール深度                  |
| `max_pages`    | `int`         | `500`      | 最大ページ数（無限ループ防止）    |
| `timeout`      | `int`         | `10`       | HTTP リクエストタイムアウト（秒） |
| `user_agent`   | `str`         | SHIGOKU UA | カスタム User-Agent               |
| `delay`        | `float`       | `0.5`      | リクエスト間の遅延（秒）          |

### 環境変数

| 変数                     | 説明                   |
| :----------------------- | :--------------------- |
| `CARTOGRAPHER_MAX_DEPTH` | デフォルト深度を上書き |
| `CARTOGRAPHER_TIMEOUT`   | タイムアウトを上書き   |

---

## API リファレンス

### クラス: `Cartographer`

#### `__init__(self, ethics_guard: EthicsGuard, **kwargs)`

Cartographer インスタンスを初期化します。

#### `map_site(self, seed_url: str) -> SiteMap`

指定されたシード URL からサイトマップを生成します。

**戻り値**: `SiteMap` オブジェクト

```python
@dataclass
class SiteMap:
    domain: str                    # ルートドメイン
    pages: List[Page]              # 発見されたページ
    links: List[Tuple[str, str]]   # (from_url, to_url) のリスト
    forms: List[FormData]          # 検出されたフォーム
    stats: dict                    # クロール統計
```

#### `get_page_content(self, url: str) -> Optional[str]`

単一ページの HTML コンテンツを取得します。

#### `extract_links(self, html: str, base_url: str) -> List[str]`

HTML からリンクを抽出し、絶対 URL のリストを返します。

---

## 使用例 (Usage Examples)

### 基本的なサイトマッピング

```python
from src.core.security import EthicsGuard
from src.core.intel import Cartographer

# 初期化
guard = EthicsGuard(scope_file="scopes/target.yaml")
mapper = Cartographer(ethics_guard=guard, max_depth=3)

# サイトマップ生成
sitemap = mapper.map_site("https://api.target.com")

# 結果を表示
print(f"Discovered {len(sitemap.pages)} pages")
for page in sitemap.pages:
    print(f"  - {page.url} [{page.status_code}]")

print(f"Detected {len(sitemap.forms)} forms")
for form in sitemap.forms:
    print(f"  - {form.action} ({form.method})")
```

### ナレッジグラフへの保存

```python
from src.core.infra import KnowledgeGraph

# サイトマップをグラフに保存
kg = KnowledgeGraph()
kg.store_sitemap(sitemap)

# グラフクエリで確認
result = kg.query("MATCH (p:Page) RETURN count(p) as total")
print(f"Total pages in graph: {result[0]['total']}")
```

---

## 出力フォーマット

### サイトマップ統計 (`stats`)

```json
{
  "total_pages": 127,
  "total_links": 543,
  "total_forms": 12,
  "crawl_time_seconds": 45.2,
  "blocked_by_scope": 23,
  "errors": 3,
  "depth_distribution": {
    "1": 15,
    "2": 67,
    "3": 45
  }
}
```

---

## パフォーマンス最適化

### 大規模サイトの扱い

1. **深度を制限**: `max_depth=2` で広く浅く、その後特定ディレクトリを深掘り
2. **ページ数上限**: `max_pages=1000` で無限クロールを防止
3. **除外パターン**: 静的ファイル（`.css`, `.js`, `.png`）はフォローしない

### 並行処理（将来実装予定）

現在はシングルスレッドですが、将来のバージョンでは以下を計画：

- AsyncIO による非同期リクエスト
- ワーカープールによる並列クロール

---

## トラブルシューティング

### 症状: クロールが途中で止まる

**原因**: タイムアウト、または無限リダイレクトループ
**解決策**:

- `timeout` を増やす
- ログを確認し、問題の URL を `out_of_scope` に追加

### 症状: 同じページが何度もクロールされる

**原因**: URL の正規化が不十分（クエリパラメータの順序が異なるなど）
**解決策**: `normalize_url` メソッドを確認し、必要に応じてカスタマイズ

### 症状: フォームが検出されない

**原因**: JavaScript 動的生成のフォーム
**解決策**: 現在のバージョンでは静的 HTML のみ対応。動的サイトはヘッドレスブラウザ統合（将来実装）を待つ

---

## 依存関係

- `httpx`: 非同期 HTTP リクエスト
- `beautifulsoup4`: HTML 解析
- `EthicsGuard`: スコープ強制
- `KnowledgeGraph` (オプション): 結果保存
