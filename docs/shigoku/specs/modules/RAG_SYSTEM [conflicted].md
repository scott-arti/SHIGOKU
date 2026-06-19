---
task_id: SGK-2026-0043
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# RAGSystem - Obsidian RAG 統合モジュール

**モジュールパス**: `src/core/rag.py`

---

## 概要 (Overview)

**RAGSystem (Retrieval-Augmented Generation)** は、Obsidian Vault に蓄積されたセキュリティナレッジをエージェントの攻撃判断に活用するためのモジュールです。

**主な機能**:

1. Obsidian Markdown ファイルのインジェスト（取り込み）
2. **PDF ファイルのインジェスト（PyMuPDF 連携）** ✨ New
3. テキストのベクトル化と ChromaDB への保存
4. セマンティック検索（類似度ベースの検索）
5. 差分更新（新規・更新ファイルのみ再インデックス）
6. RAGSwitch（オン/オフ切り替え）
7. **RAG Feedback（FP 自動判定）** ✨ New
8. **類似レポート検索** ✨ New

---

## アーキテクチャ (Architecture)

```
┌─────────────────────────────────────────────────────────────────────┐
│                         RAG System                                   │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Obsidian Vault                             │   │
│  │  ~/Obsidian/Security/                                        │   │
│  │    ├── JWT_Attacks.md                                        │   │
│  │    ├── IDOR_Patterns.md                                      │   │
│  │    └── OAuth_Bypass.md                                       │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    ObsidianIngester                           │   │
│  │  - Parse Markdown                                            │   │
│  │  - Extract Metadata (frontmatter, tags)                      │   │
│  │  - Split into Chunks                                         │   │
│  │  - Generate Embeddings                                       │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    ChromaDB (Vector Store)                    │   │
│  │  - Document Vectors                                          │   │
│  │  - Metadata Index                                            │   │
│  │  - Similarity Search                                         │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    RAGSwitch                                  │   │
│  │  - Enable/Disable RAG                                        │   │
│  │  - Query Interface for Agents                                │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## コンポーネント詳細

### 1. ObsidianIngester

Markdown ファイルを解析し、ベクトルデータベースに保存します。

#### 対応フォーマット

- 標準 Markdown
- Obsidian 拡張記法（`[[内部リンク]]`、`#タグ`）
- YAML Frontmatter

#### チャンク分割

長いドキュメントは検索効率のためにチャンク（断片）に分割されます。

```python
# チャンク設定
CHUNK_SIZE = 500       # 1チャンクあたりの最大文字数
CHUNK_OVERLAP = 50     # チャンク間のオーバーラップ
```

#### メタデータ抽出

```yaml
---
title: JWT Attack Techniques
tags: [jwt, authentication, bypass]
date: 2024-01-15
---
```

→ メタデータとして保存され、フィルタリング検索に使用

### 2. RAGSwitch

RAG 機能のオン/オフを制御し、エージェントへのクエリインターフェースを提供します。

```python
class RAGSwitch:
    def __init__(self):
        self._enabled = True
        self._ingester: ObsidianIngester = None

    def toggle(self, enabled: bool) -> None:
        """RAGを有効/無効にする"""
        self._enabled = enabled

    def is_enabled(self) -> bool:
        return self._enabled

    def get_bypass_techniques(self, vulnerability_type: str) -> List[dict]:
        """脆弱性タイプに関連するバイパス技術を検索"""
        if not self._enabled:
            return []
        return self._ingester.query(vulnerability_type)
```

---

## API リファレンス

### 関数: `init_rag()`

RAG システムを初期化します。

```python
def init_rag(
    vault_path: str,
    chroma_host: str = "localhost",
    chroma_port: int = 8001,
    enabled: bool = True
) -> bool:
    """
    RAGシステムを初期化します。

    Args:
        vault_path: Obsidian Vaultのパス
        chroma_host: ChromaDBホスト
        chroma_port: ChromaDBポート
        enabled: 初期状態でRAGを有効にするか

    Returns:
        初期化成功: True
    """
```

### 関数: `get_rag_switch()`

グローバルな RAGSwitch インスタンスを取得します。

```python
rag = get_rag_switch()
if rag.is_enabled():
    techniques = rag.get_bypass_techniques("jwt_alg_none")
```

### クラス: `ObsidianIngester`

#### `ingest_vault(self, vault_path: str) -> int`

Vault 全体をインジェストします。処理したファイル数を返します。

#### `ingest_vault_differential(self, vault_path: str) -> dict`

差分更新（新規・更新ファイルのみ処理）を行います。

#### `query(self, query_text: str, n_results: int = 5) -> List[dict]`

類似ドキュメントを検索します。

#### `get_stats(self) -> dict`

インジェスト統計を返します。

### クラス: `PDFIngester` ✨ New

#### `parse_pdf(self, pdf_path: str) -> list[RAGDocument]`

PDF ファイルを解析し、RAGDocument のリストを返します。

### クラス: `KnowledgeIngester` ✨ New

#### `ingest_pdf(self, pdf_path: str, chunk_size: int = 1000, chunk_overlap: int = 100) -> int`

単一の PDF ファイルを取り込みます。

#### `ingest_directory(self, directory_path: str, include_pdf: bool = True, include_markdown: bool = True, reset_db: bool = False) -> dict`

ディレクトリ内の PDF と Markdown を一括取り込みます。

---

## CLI 使用方法 ✨ New

### RAG ナレッジベース操作

```bash
# ディレクトリ取り込み（PDF + Markdown）
python src/main.py --rag-ingest ./knowledge

# 単一PDF取り込み
python src/main.py --rag-ingest ./security_book.pdf

# PDFのみ取り込み
python src/main.py --rag-ingest ./knowledge --pdf-only

# DB初期化して取り込み
python src/main.py --rag-ingest ./knowledge --reset-db

# 検索
python src/main.py --rag-query "JWT alg none bypass"

# 検索結果数を指定
python src/main.py --rag-query "SSRF technique" -n 10

# JSON形式で出力
python src/main.py --rag-query "OAuth bypass" --json

# 統計情報
python src/main.py --rag-stats
python src/main.py --rag-stats --json
```

## 使用例 (Usage Examples)

### 初期化とインジェスト

```python
from src.core.rag import init_rag, get_rag_switch

# 初期化
success = init_rag(
    vault_path="/home/user/Obsidian/Security",
    chroma_host="localhost",
    chroma_port=8001
)

if success:
    print("RAG initialized successfully!")
    rag = get_rag_switch()
    stats = rag._ingester.get_stats()
    print(f"Documents indexed: {stats['document_count']}")
```

### エージェントからの利用

```python
from src.agents.swarm import JWTInspector
from src.core.rag import get_rag_switch

rag = get_rag_switch()
inspector = JWTInspector(rag_switch=rag)

# JWTInspector内部での利用例
techniques = rag.get_bypass_techniques("jwt alg none")
for tech in techniques:
    print(f"Source: {tech['source']}")
    print(f"Content: {tech['content'][:200]}...")
```

### 差分更新

```python
# 起動時に差分更新（高速）
result = rag._ingester.ingest_vault_differential("/home/user/Obsidian/Security")
print(f"Added: {result['added']}")
print(f"Updated: {result['updated']}")
print(f"Deleted: {result['deleted']}")
```

---

## Obsidian ノートの書き方

RAG は任意の Markdown を処理できますが、以下の形式が推奨されます：

### 推奨フォーマット

````markdown
---
title: JWT Algorithm None Bypass
tags: [jwt, authentication, bypass, critical]
category: auth_attack
---

# JWT Algorithm None Bypass

## 概要

JWT の `alg` ヘッダーを `none` に変更し、署名検証をスキップする攻撃。

## 条件

- サーバーがアルゴリズムを明示的に検証していない
- JWT ライブラリが `none` を許可している

## 攻撃手順

1. 元のトークンを Base64 デコード
2. ヘッダーの `alg` を `none` に変更
3. 署名部分を削除
4. 再エンコードしてリクエストに使用

## ペイロード例

```json
{ "alg": "none", "typ": "JWT" }
```
````

## 参考

- [[JWT Security Best Practices]]
- https://portswigger.net/web-security/jwt

````

### タグの活用

```markdown
tags: [jwt, oauth, mfa, idor, ssrf, sqli, xss]
````

タグは検索のフィルタリングに使用できます：

```python
# タグでフィルタリング
results = rag.query("bypass", filter={"tags": {"$contains": "jwt"}})
```

---

## 環境変数

| 変数                  | デフォルト        | 説明            |
| :-------------------- | :---------------- | :-------------- |
| `OBSIDIAN_VAULT_PATH` | `~/MEGA/obsidian` | Vault のパス    |
| `CHROMA_HOST`         | `localhost`       | ChromaDB ホスト |
| `CHROMA_PORT`         | `8001`            | ChromaDB ポート |

---

## パフォーマンス

### インジェスト時間

- 100 ファイル: 約 10 秒
- 1000 ファイル: 約 2 分
- 差分更新: 変更ファイル数に比例（通常は数秒）

### 検索レイテンシ

- 単一クエリ: 50-200ms
- バッチクエリ: クエリ数に比例

---

## トラブルシューティング

### 症状: ChromaDB に接続できない

**原因**: Docker コンテナが起動していない
**解決策**:

```bash
docker compose up -d chromadb
```

### 症状: 検索結果が期待と異なる

**原因**: インデックスが古い、またはチャンク分割の問題
**解決策**:

- 差分更新を実行: `ingest_vault_differential()`
- チャンクサイズを調整

### 症状: メモリ不足エラー

**原因**: 大量のドキュメントを一括処理
**解決策**:

- バッチサイズを小さくする
- ChromaDB のメモリ設定を増やす
