---
task_id: SGK-2026-0040
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# KnowledgeGraph - Neo4j ナレッジグラフ連携モジュール

**モジュールパス**: `src/core/infra/knowledge_graph.py`

---

## 概要 (Overview)

**KnowledgeGraph** は、Neo4j グラフデータベースとの連携を担当するモジュールです。偵察で発見された資産（ドメイン、ページ、技術）や脆弱性情報をグラフ構造で保存・クエリし、攻撃の優先順位付けや関連性分析に活用します。

**主な機能**:

1. グラフスキーマの定義と管理
2. ノード・リレーションの作成・更新・削除
3. Cypher クエリの実行
4. 攻撃候補の推論（ルールベース）

---

## アーキテクチャ (Architecture)

```
┌─────────────────────────────────────────────────────────────────────┐
│                       KnowledgeGraph Module                          │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Python Driver (neo4j)                      │   │
│  │  - Connection Management                                     │   │
│  │  - Transaction Handling                                      │   │
│  │  - Retry Logic                                               │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Neo4j Database                             │   │
│  │  ┌────────────────────────────────────────────────────────┐  │   │
│  │  │  Nodes: Domain, Page, Technology, Finding, Form        │  │   │
│  │  │                                                        │  │   │
│  │  │  Relationships:                                        │  │   │
│  │  │    (Domain)-[:CONTAINS]->(Page)                        │  │   │
│  │  │    (Page)-[:LINKS_TO]->(Page)                          │  │   │
│  │  │    (Page)-[:RUNS_ON]->(Technology)                     │  │   │
│  │  │    (Page)-[:HAS_VULNERABILITY]->(Finding)              │  │   │
│  │  │    (Page)-[:HAS_FORM]->(Form)                          │  │   │
│  │  └────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## グラフスキーマ (Graph Schema)

### ノード定義

#### Domain（ドメイン）

ターゲットのトップレベルドメインまたはサブドメインを表します。

| プロパティ      | 型       | 説明                               |
| :-------------- | :------- | :--------------------------------- |
| `name`          | string   | ドメイン名 (例: "api.example.com") |
| `ip_address`    | string   | IP アドレス (オプション)           |
| `is_in_scope`   | boolean  | スコープ内かどうか                 |
| `discovered_at` | datetime | 発見日時                           |

#### Page（ページ）

個別の URL エンドポイントを表します。

| プロパティ    | 型      | 説明                           |
| :------------ | :------ | :----------------------------- |
| `url`         | string  | 完全な URL                     |
| `path`        | string  | URL パス部分                   |
| `method`      | string  | HTTP メソッド (GET, POST 等)   |
| `status_code` | integer | レスポンスステータス           |
| `page_type`   | string  | ページタイプ (LOGIN, ADMIN 等) |
| `depth`       | integer | クロール深度                   |

#### Technology（技術）

検出された技術スタックを表します。

| プロパティ | 型     | 説明                              |
| :--------- | :----- | :-------------------------------- |
| `name`     | string | 技術名 (例: "nginx", "WordPress") |
| `version`  | string | バージョン (オプション)           |
| `category` | string | カテゴリ (SERVER, CMS 等)         |

#### Finding（発見）

確認された脆弱性を表します。

| プロパティ      | 型       | 説明                     |
| :-------------- | :------- | :----------------------- |
| `title`         | string   | 脆弱性タイトル           |
| `severity`      | string   | 重大度                   |
| `vuln_type`     | string   | 脆弱性タイプ             |
| `discovered_at` | datetime | 発見日時                 |
| `report_path`   | string   | 生成されたレポートのパス |

#### Form（フォーム）

ページ内の HTML フォームを表します。

| プロパティ | 型     | 説明                     |
| :--------- | :----- | :----------------------- |
| `action`   | string | フォームの action 属性   |
| `method`   | string | フォームの method 属性   |
| `inputs`   | list   | 入力フィールド名のリスト |

### リレーション定義

| リレーション        | From   | To         | 説明                       |
| :------------------ | :----- | :--------- | :------------------------- |
| `CONTAINS`          | Domain | Page       | ドメインがページを含む     |
| `LINKS_TO`          | Page   | Page       | ページ間のリンク           |
| `RUNS_ON`           | Page   | Technology | ページで使用されている技術 |
| `HAS_VULNERABILITY` | Page   | Finding    | ページで発見された脆弱性   |
| `HAS_FORM`          | Page   | Form       | ページ内のフォーム         |

---

## API リファレンス

### クラス: `KnowledgeGraph`

#### `__init__(self, uri: str = None, user: str = None, password: str = None)`

KnowledgeGraph を初期化します。環境変数からの読み込みも可能。

#### `connect(self) -> bool`

Neo4j データベースに接続します。

#### `close(self) -> None`

接続を閉じます。

#### `store_domain(self, name: str, **properties) -> None`

Domain ノードを作成または更新します。

#### `store_page(self, url: str, domain_name: str, **properties) -> None`

Page ノードを作成し、Domain との関係を設定します。

#### `store_technology(self, page_url: str, technology: Technology) -> None`

Technology ノードと Page との関係を作成します。

#### `store_finding(self, page_url: str, finding: Finding) -> None`

Finding ノードと Page との関係を作成します。

#### `store_sitemap(self, sitemap: SiteMap) -> None`

Cartographer の出力を一括保存します。

#### `query(self, cypher: str, **params) -> List[dict]`

任意の Cypher クエリを実行します。

#### `get_attack_candidates(self) -> List[dict]`

攻撃候補となるページを推論して返します。

---

## 使用例 (Usage Examples)

### 基本的な使用法

```python
from src.core.infra import KnowledgeGraph

# 接続
kg = KnowledgeGraph(
    uri="bolt://localhost:7687",
    user="neo4j",
    password="deephunter2024"
)
kg.connect()

# ドメインを保存
kg.store_domain("api.target.com", is_in_scope=True)

# ページを保存
kg.store_page(
    url="https://api.target.com/login",
    domain_name="api.target.com",
    method="GET",
    status_code=200,
    page_type="LOGIN"
)

# 接続を閉じる
kg.close()
```

### Cypher クエリの実行

```python
# ログインページを持つすべてのドメインを取得
results = kg.query("""
    MATCH (d:Domain)-[:CONTAINS]->(p:Page)
    WHERE p.page_type = 'LOGIN'
    RETURN d.name as domain, p.url as login_page
""")

for row in results:
    print(f"{row['domain']}: {row['login_page']}")
```

### 攻撃候補の推論

```python
# WordPressが動いている管理画面を検索
candidates = kg.query("""
    MATCH (p:Page)-[:RUNS_ON]->(t:Technology)
    WHERE t.name = 'WordPress'
      AND p.url CONTAINS 'wp-admin'
    RETURN p.url as target, t.version as wp_version
""")

for candidate in candidates:
    print(f"Target: {candidate['target']} (WP {candidate['wp_version']})")
```

---

## 推論ルール (Inference Rules)

KnowledgeGraph は、グラフ構造に基づいて攻撃の優先順位を推論します。

### ルール 1: 古いソフトウェア

```cypher
MATCH (p:Page)-[:RUNS_ON]->(t:Technology)
WHERE t.version IS NOT NULL
  AND t.name IN ['WordPress', 'Drupal', 'jQuery']
  AND toFloat(split(t.version, '.')[0]) < 5
RETURN p.url as vulnerable_page, t.name, t.version
```

### ルール 2: 認証なしで到達可能な管理画面

```cypher
MATCH (public:Page)-[:LINKS_TO*1..3]->(admin:Page)
WHERE admin.page_type = 'ADMIN'
  AND NOT exists((public)<-[:LINKS_TO]-(:Page {page_type: 'LOGIN'}))
RETURN admin.url as exposed_admin
```

### ルール 3: 技術の組み合わせリスク

```cypher
// PHP + 古いWordPress + Apache = 高リスク
MATCH (p:Page)-[:RUNS_ON]->(php:Technology {name: 'PHP'})
MATCH (p)-[:RUNS_ON]->(wp:Technology {name: 'WordPress'})
MATCH (p)-[:RUNS_ON]->(apache:Technology {name: 'Apache'})
RETURN p.url as high_risk_target
```

---

## 環境変数

| 変数             | デフォルト              | 説明           |
| :--------------- | :---------------------- | :------------- |
| `NEO4J_URI`      | `bolt://localhost:7687` | Neo4j 接続 URI |
| `NEO4J_USER`     | `neo4j`                 | ユーザー名     |
| `NEO4J_PASSWORD` | (なし)                  | パスワード     |

---

## トラブルシューティング

### 症状: 接続に失敗する

**原因**: Neo4j コンテナが起動していない
**解決策**:

```bash
docker compose up -d neo4j
docker compose ps  # 状態確認
```

### 症状: 認証エラー

**原因**: パスワードが間違っている
**解決策**: `docker-compose.yml` の `NEO4J_AUTH` を確認

### 症状: クエリのタイムアウト

**原因**: 大量のノードに対する非効率なクエリ
**解決策**:

- インデックスを作成
- クエリに LIMIT を追加
