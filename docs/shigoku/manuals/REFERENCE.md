---
task_id: SGK-2026-0006
doc_type: manual
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# ⚙️ SHIGOKU リファレンスガイド

システム設定、環境変数、コマンドオプション、および制限事項に関する網羅的なリファレンスです。

---

## 目次 (Table of Contents)

1. [環境変数一覧](#1-環境変数一覧)
2. [設定ファイル](#2-設定ファイル)
3. [CLI オプション](#3-cli-オプション)
4. [データモデル](#4-データモデル)
5. [エラーコード](#5-エラーコード)
6. [システム制限](#6-システム制限)
7. [依存関係](#7-依存関係)

---

## 1. 環境変数一覧

### データベース接続

| 変数名           | 必須 | デフォルト              | 説明                |
| :--------------- | :--- | :---------------------- | :------------------ |
| `NEO4J_URI`      | Yes  | `bolt://localhost:7687` | Neo4j Bolt 接続 URI |
| `NEO4J_USER`     | Yes  | `neo4j`                 | Neo4j ユーザー名    |
| `NEO4J_PASSWORD` | Yes  | -                       | Neo4j パスワード    |
| `CHROMA_HOST`    | No   | `localhost`             | ChromaDB ホスト名   |
| `CHROMA_PORT`    | No   | `8001`                  | ChromaDB ポート     |

### RAG 設定

| 変数名                | 必須 | デフォルト        | 説明                     |
| :-------------------- | :--- | :---------------- | :----------------------- |
| `OBSIDIAN_VAULT_PATH` | No   | `~/MEGA/obsidian` | Obsidian Vault パス      |
| `RAG_ENABLED`         | No   | `true`            | RAG 機能の有効/無効      |
| `RAG_CHUNK_SIZE`      | No   | `500`             | チャンク分割サイズ       |
| `RAG_CHUNK_OVERLAP`   | No   | `50`              | チャンク間オーバーラップ |

### エージェント設定

| 変数名              | 必須 | デフォルト | 説明                                   |
| :------------------ | :--- | :--------- | :------------------------------------- |
| `GITHUB_TOKEN`      | No\* | -          | GitHub API トークン (CommitWatcher 用) |
| `OPENAI_API_KEY`    | No\* | -          | OpenAI API キー (LLM 統合用)           |
| `ANTHROPIC_API_KEY` | No\* | -          | Anthropic API キー                     |

\*機能によっては必須

### モジュール固有設定

| 変数名                     | 対象モジュール | デフォルト | 説明                  |
| :------------------------- | :------------- | :--------- | :-------------------- |
| `CARTOGRAPHER_MAX_DEPTH`   | Cartographer   | `2`        | クロール最大深度      |
| `CARTOGRAPHER_TIMEOUT`     | Cartographer   | `10`       | HTTP タイムアウト(秒) |
| `CARTOGRAPHER_DELAY`       | Cartographer   | `0.5`      | リクエスト間隔(秒)    |
| `ETHICS_GUARD_DEFAULT_RPM` | EthicsGuard    | `60`       | デフォルトレート制限  |

### ログ設定

| 変数名       | デフォルト                                             | 説明                                  |
| :----------- | :----------------------------------------------------- | :------------------------------------ |
| `LOG_LEVEL`  | `INFO`                                                 | ログレベル (DEBUG/INFO/WARNING/ERROR) |
| `LOG_FORMAT` | `%(asctime)s - %(name)s - %(levelname)s - %(message)s` | ログフォーマット                      |
| `LOG_FILE`   | (なし)                                                 | ファイル出力パス                      |

---

## 2. 設定ファイル

### 2-1. スコープ定義 (scope.yaml)

**フルスキーマ**:

```yaml
# === プログラム情報 ===
program:
  name: "Target Bug Bounty Program"
  platform: hackerone # hackerone / bugcrowd / intigriti / other
  url: "https://hackerone.com/target"

# === 許可リスト (IN SCOPE) ===
in_scope:
  # ドメイン (ワイルドカード可)
  domains:
    - "api.target.com"
    - "*.staging.target.com"
    - "app.target.com:8080" # ポート指定

  # IPアドレス
  ips:
    - "192.168.1.100"
    - "10.0.0.0/24" # CIDR可

  # CIDRブロック
  cidrs:
    - "172.16.0.0/16"

# === 禁止リスト (OUT OF SCOPE) ===
out_of_scope:
  domains:
    - "auth.target.com" # 認証サーバー
    - "*.internal.target.com" # 内部ネットワーク
    - "static.target.com" # CDN

  ips:
    - "127.0.0.1"
    - "0.0.0.0"

  cidrs:
    - "192.168.0.0/16"

# === 禁止パス ===
disallowed_paths:
  - "/logout"
  - "/signout"
  - "/api/*/delete"
  - "/api/*/destroy"
  - "/unsubscribe/*"
  - "/admin/shutdown"

# === レート制限 ===
rate_limit:
  requests_per_minute: 60
  burst_limit: 120
  cooldown_seconds: 10

# === 追加設定 ===
settings:
  follow_redirects: true
  max_redirects: 5
  verify_ssl: true
  user_agent: "SHIGOKU/1.0 (Security Research)"
```

### 2-2. Docker Compose (docker-compose.yml)

```yaml
version: "3.8"

services:
  neo4j:
    image: neo4j:5.15
    container_name: shigoku-neo4j
    ports:
      - "7474:7474" # HTTP
      - "7687:7687" # Bolt
    environment:
      - NEO4J_AUTH=neo4j/deephunter2024
      - NEO4J_PLUGINS=["apoc"]
    volumes:
      - neo4j_data:/data

  chromadb:
    image: chromadb/chroma:latest
    container_name: shigoku-chromadb
    ports:
      - "8001:8000"
    volumes:
      - chroma_data:/chroma/chroma

volumes:
  neo4j_data:
  chroma_data:
```

---

## 3. CLI オプション

### コマンド構文

```
python -m src.main [MODE] [OPTIONS]
```

### モードオプション

| オプション | 引数           | 説明                     |
| :--------- | :------------- | :----------------------- |
| `--recon`  | `<URL>`        | 偵察モード               |
| `--log`    | `<FILE>`       | ハイブリッドハントモード |
| `--watch`  | `<OWNER/REPO>` | センチネルモード         |
| `--demo`   | (なし)         | デモモード               |

### RAG オプション ✨ New

| オプション             | 引数         | 説明                          |
| :--------------------- | :----------- | :---------------------------- |
| `--rag-ingest`         | `<PATH>`     | ファイル/ディレクトリ取り込み |
| `--rag-query`          | `<QUESTION>` | ナレッジベース検索            |
| `--rag-stats`          | (なし)       | 統計情報表示                  |
| `--pdf-only`           | (なし)       | PDF のみ取り込み              |
| `--reset-db`           | (なし)       | DB 初期化して取り込み         |
| `-n` / `--num-results` | `<N>`        | 検索結果数（デフォルト: 5）   |

### DNS / 出力オプション ✨ New

| オプション | 引数       | 説明                                 |
| :--------- | :--------- | :----------------------------------- |
| `--dns`    | `<DOMAIN>` | DNS 履歴取得                         |
| `--json`   | (なし)     | JSON 形式出力                        |
| `--mode`   | `<MODE>`   | 動作モード（bugbounty/vulntest/ctf） |

### 共通オプション

| オプション       | 引数     | デフォルト   | 説明                   |
| :--------------- | :------- | :----------- | :--------------------- |
| `--scope`        | `<FILE>` | (なし)       | スコープ定義ファイル   |
| `--vault`        | `<PATH>` | 環境変数参照 | Obsidian Vault パス    |
| `--full-refresh` | (なし)   | `false`      | RAG 完全再インデックス |
| `--verbose`      | (なし)   | `false`      | 詳細ログ出力           |
| `--output`       | `<DIR>`  | `reports/`   | レポート出力先         |
| `--help`         | (なし)   | -            | ヘルプ表示             |

### 使用例

```bash
# 基本的な偵察
python -m src.main --recon https://api.target.com

# スコープ付き偵察
python -m src.main --recon https://api.target.com --scope scopes/target.yaml

# ハイブリッドハント
python -m src.main --log traffic.har --scope scopes/target.yaml --mode vulntest

# GitHub監視
python -m src.main --watch facebook/react

# RAGナレッジベース操作
python -m src.main --rag-ingest ./knowledge
python -m src.main --rag-query "JWT bypass" --json -n 10
python -m src.main --rag-stats

# DNS履歴
python -m src.main --dns example.com --json
```

---

## 4. データモデル

### 4-1. Finding

脆弱性を表現するコアデータモデル:

```python
@dataclass
class Finding:
    title: str              # 脆弱性タイトル
    severity: Severity      # CRITICAL/HIGH/MEDIUM/LOW/INFO
    vuln_type: VulnType     # 脆弱性タイプ
    description: str        # 詳細説明
    evidence: List[Evidence]  # 証跡リスト
    affected_url: str       # 影響を受けるURL
    discovered_at: datetime # 発見日時
```

### 4-2. Severity (重大度)

| 値              | CVSS     | 説明                                   |
| :-------------- | :------- | :------------------------------------- |
| `CRITICAL`      | 9.0-10.0 | 認証なし RCE、完全なデータ漏洩         |
| `HIGH`          | 7.0-8.9  | 認証バイパス、重要データアクセス       |
| `MEDIUM`        | 4.0-6.9  | IDOR、CSRF、部分的情報漏洩             |
| `LOW`           | 0.1-3.9  | 軽微な情報漏洩、ベストプラクティス違反 |
| `INFORMATIONAL` | 0.0      | 参考情報、推奨事項                     |

### 4-3. VulnType (脆弱性タイプ)

| 値                      | CWE     | 説明                       |
| :---------------------- | :------ | :------------------------- |
| `JWT_ALG_NONE`          | CWE-327 | JWT 署名アルゴリズム無効化 |
| `JWT_WEAK_SECRET`       | CWE-521 | JWT 弱い秘密鍵             |
| `OAUTH_REDIRECT_BYPASS` | CWE-601 | OAuth リダイレクトバイパス |
| `OAUTH_PKCE_BYPASS`     | CWE-287 | PKCE ダウングレード        |
| `MFA_BYPASS`            | CWE-308 | 多要素認証バイパス         |
| `IDOR`                  | CWE-639 | 安全でないオブジェクト参照 |
| `PRIVILEGE_ESCALATION`  | CWE-269 | 権限昇格                   |
| `SECRET_LEAK`           | CWE-540 | シークレット漏洩           |
| `ADMIN_ACCESS`          | CWE-284 | 不正な管理画面アクセス     |

### 4-4. Evidence (証跡)

```python
@dataclass
class Evidence:
    request: str            # リクエスト内容
    response: str           # レスポンス内容
    screenshot: str = None  # スクリーンショットパス
    metadata: dict = None   # 追加メタデータ
```

---

## 5. エラーコード

### EthicsGuard エラー

| エラー                | コード | 説明                            |
| :-------------------- | :----- | :------------------------------ |
| `ScopeViolationError` | `E001` | スコープ外 URL へのアクセス試行 |
| `RateLimitExceeded`   | `E002` | レート制限超過                  |
| `DisallowedPathError` | `E003` | 禁止パスへのアクセス試行        |

### 接続エラー

| エラー                    | コード | 説明              |
| :------------------------ | :----- | :---------------- |
| `Neo4jConnectionError`    | `E101` | Neo4j 接続失敗    |
| `ChromaDBConnectionError` | `E102` | ChromaDB 接続失敗 |
| `GitHubAPIError`          | `E103` | GitHub API エラー |

### 解析エラー

| エラー               | コード | 説明                      |
| :------------------- | :----- | :------------------------ |
| `ScopeParseError`    | `E201` | スコープ YAML 解析失敗    |
| `HARParseError`      | `E202` | HAR ファイル解析失敗      |
| `MarkdownParseError` | `E203` | Markdown ファイル解析失敗 |

---

## 6. システム制限

### パフォーマンス上限

| 項目                   | 上限値 | 備考             |
| :--------------------- | :----- | :--------------- |
| 最大クロール深度       | 10     | 設定で制限可能   |
| 最大ページ数/サイト    | 10,000 | メモリ使用に依存 |
| 最大ログファイルサイズ | 100MB  | 分割推奨         |
| 最大同時接続           | 10     | シングルスレッド |

### 対応フォーマット

| カテゴリ         | 対応                     | 非対応          |
| :--------------- | :----------------------- | :-------------- |
| **プロキシログ** | HAR 1.2, Caido JSON      | Burp XML (予定) |
| **画像**         | PNG, JPEG, WebP          | GIF, SVG        |
| **ドキュメント** | Markdown, **PDF** ✨ New | Word            |

### プロトコル制限

| プロトコル    | サポート状況       |
| :------------ | :----------------- |
| HTTP/1.1      | ✅ フルサポート    |
| HTTP/2        | ✅ フルサポート    |
| WebSocket     | ✅ サポート ✨ New |
| HTTP/3 (QUIC) | ❌ 未対応          |
| gRPC          | ❌ 未対応          |

---

## 7. 依存関係

### Python パッケージ

| パッケージ       | バージョン | 用途                     |
| :--------------- | :--------- | :----------------------- |
| `requests`       | 2.31+      | HTTP クライアント        |
| `beautifulsoup4` | 4.12+      | HTML 解析                |
| `neo4j`          | 5.15+      | グラフ DB ドライバ       |
| `chromadb`       | 0.4+       | ベクトル DB クライアント |
| `pyyaml`         | 6.0+       | YAML 解析                |
| `Pillow`         | 10.0+      | 画像処理                 |
| `pytesseract`    | 0.3+       | OCR                      |

### システム依存

| ソフトウェア   | バージョン | 用途                          |
| :------------- | :--------- | :---------------------------- |
| Docker         | 24.0+      | コンテナ実行                  |
| Docker Compose | v2.0+      | マルチコンテナ管理            |
| Tesseract OCR  | 5.0+       | 画像テキスト抽出 (オプション) |

### 外部サービス

| サービス   | 用途                 | 認証                  |
| :--------- | :------------------- | :-------------------- |
| Neo4j      | グラフデータベース   | ユーザー/パスワード   |
| ChromaDB   | ベクトルデータベース | なし (ローカル)       |
| GitHub API | リポジトリ監視       | Personal Access Token |
