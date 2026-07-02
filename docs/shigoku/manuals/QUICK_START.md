---
task_id: SGK-2026-0005
doc_type: manual
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# 🚀 SHIGOKU クイックスタートガイド

**SHIGOKU** エンジンを安全かつ確実に始動させるための詳細手順書です。
このガイドに従えば、約 10 分で SHIGOKU を起動し、最初の偵察ミッションを実行できます。

---

## 目次 (Table of Contents)

1. [前提条件 (Prerequisites)](#1-前提条件-prerequisites)
2. [インフラ構築 (Infrastructure Setup)](#2-インフラ構築-infrastructure-setup)
3. [Python 環境 (Python Environment)](#3-python環境-python-environment)
4. [初回起動 (First Launch)](#4-初回起動-first-launch)
5. [動作確認 (Verification)](#5-動作確認-verification)
6. [トラブルシューティング (Troubleshooting)](#6-トラブルシューティング-troubleshooting)
7. [次のステップ (Next Steps)](#7-次のステップ-next-steps)

---

## 1. 前提条件 (Prerequisites)

### 1-1. オペレーティングシステム

| OS                    | サポート状況 | 備考                         |
| :-------------------- | :----------- | :--------------------------- |
| **Ubuntu 22.04+**     | ✅ 推奨      | フルサポート                 |
| **Debian 12+**        | ✅ 対応      | フルサポート                 |
| **macOS Ventura+**    | ✅ 対応      | Homebrew 経由でセットアップ  |
| **Windows 11 + WSL2** | ⚠️ 条件付き  | WSL2 Ubuntu 上で動作確認済み |
| **Windows (Native)**  | ❌ 非対応    | WSL2 を使用してください      |

### 1-2. 必須ソフトウェア

```bash
# バージョン確認コマンド
docker --version    # 24.0.0 以上
docker compose version  # v2.0.0 以上
python3 --version   # 3.10 以上
```

**インストールされていない場合**:

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install docker.io docker-compose-v2 python3 python3-venv python3-pip

# macOS (Homebrew)
brew install docker python@3.11
```

### 1-3. オプションソフトウェア

| ソフトウェア        | 用途                         | インストール                         |
| :------------------ | :--------------------------- | :----------------------------------- |
| `tesseract-ocr`     | VisualFilter OCR 機能        | `sudo apt install tesseract-ocr`     |
| `tesseract-ocr-jpn` | 日本語 OCR                   | `sudo apt install tesseract-ocr-jpn` |
| GitHub Token        | CommitWatcher レート制限回避 | GitHub Settings > Developer settings |

### 1-4. ハードウェア要件

| リソース         | 最小               | 推奨         |
| :--------------- | :----------------- | :----------- |
| **CPU**          | 2 コア             | 4 コア以上   |
| **RAM**          | 4GB                | 8GB 以上     |
| **ディスク**     | 5GB                | 20GB 以上    |
| **ネットワーク** | インターネット接続 | 安定した接続 |

---

## 2. インフラ構築 (Infrastructure Setup)

SHIGOKU は以下のコンテナを使用します：

- **Neo4j**: ナレッジグラフ（資産管理）
- **ChromaDB**: ベクトルデータベース（RAG 検索）

### 2-1. Docker コンテナの起動

```bash
cd /path/to/shigoku
docker compose up -d
```

### 2-2. コンテナ状態の確認

```bash
docker compose ps
```

**期待される出力**:

```
NAME                SERVICE    STATUS    PORTS
shigoku-neo4j-1     neo4j      running   7474->7474, 7687->7687
shigoku-chromadb-1  chromadb   running   8001->8000
```

### 2-3. サービス接続確認

#### Neo4j (グラフデータベース)

1. ブラウザで [http://localhost:7474](http://localhost:7474) にアクセス
2. 接続情報を入力:
   - **Connect URL**: `bolt://localhost:7687`
   - **Username**: `neo4j`
   - **Password**: `deephunter2024` (docker-compose.yml 参照)
3. 「Connect」をクリック

**成功時**: Cypher 入力画面が表示される

#### ChromaDB (ベクトル DB)

```bash
curl http://localhost:8001/api/v1/heartbeat
```

**成功時**: `{"nanosecond heartbeat": 1234567890123456789}` のような JSON が返る

---

## 3. Python 環境 (Python Environment)

### 3-1. 仮想環境の作成

```bash
# プロジェクトディレクトリに移動
cd /path/to/shigoku

# 仮想環境を作成
python3 -m venv .venv

# 仮想環境を有効化
source .venv/bin/activate

# プロンプトが変わることを確認
# (venv) user@host:~/shigoku$
```

### 3-2. 依存パッケージのインストール

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**インストールされる主要パッケージ**:

- `requests`: HTTP クライアント
- `beautifulsoup4`: HTML 解析
- `neo4j`: グラフ DB ドライバ
- `chromadb`: ベクトル DB クライアント
- `Pillow`: 画像処理
- `pytesseract`: OCR バインディング

### 3-3. 環境変数の設定 (オプション)

`.env` ファイルを作成して環境変数を設定できます：

```bash
# .env ファイル例
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=deephunter2024
CHROMA_HOST=localhost
CHROMA_PORT=8001
GITHUB_TOKEN=ghp_your_token_here  # オプション
OBSIDIAN_VAULT_PATH=~/Obsidian/Security  # オプション
```

---

## 4. 初回起動 (First Launch)

### 4-1. ヘルプの表示

```bash
python -m src.main --help
```

**出力**:

```
SHIGOKU (至極) - 自律型バグバウンティハンター

Caidoログ解析、GitHub監視、RAGナレッジベース検索、DNS履歴取得など、
バグハンティングに必要な機能を統合したCLIツール。

options:
  --log FILE       Hybrid Hunt: Analyze proxy log and execute attacks
  --scope FILE     Scope definition file (YAML)
  --watch REPO     Sentinel Watch: Monitor GitHub repo (owner/repo)
  --demo           Grand Demo: Demonstrate all features
  --recon URL      Recon Phase: Map site, identify tech, and store in Neo4j
  --mode MODE      Hunting mode: bugbounty (default), vulntest, ctf
  --rag-ingest PATH       RAG: Ingest files from path (directory or PDF)
  --rag-query QUESTION    RAG: Query the knowledge base
  --rag-stats             RAG: Show knowledge base statistics
  --dns DOMAIN            DNS History: Get historical DNS records
  --json                  Output in JSON format

使用例:
  shigoku --log caido.json              # ハイブリッドハント
  shigoku --rag-ingest ./knowledge      # ナレッジ取り込み
  shigoku --rag-query "JWT bypass"      # RAG検索
  shigoku --dns example.com             # DNS履歴

モード設定:
  --mode bugbounty  : バグバウンティモード（デフォルト）
  --mode vulntest   : 脆弱性診断モード
  --mode ctf        : CTFモード
```

### 4-2. デモモードの実行

まずはデモモードでシステム全体の動作を確認します：

```bash
python -m src.main --demo
```

**期待される出力**:

```
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║         至   極    -    S  H  I  G  O  K  U                   ║
║                                                               ║
║            Autonomous Bug Bounty Hunter v1.0                  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

🔧 Initializing RAG system...
✅ RAG initialized successfully!
   Documents: 42

🎯 Running Demo Mode...
```

### 4-3. 最初の偵察 (Recon)

**重要**: 偵察対象は必ず**あなたが所有している**か**許可を得ている**システムにしてください。

```bash
# ローカルテストサーバーを偵察
python -m src.main --recon http://localhost:8888

# スコープファイルを指定して偵察
python -m src.main --recon https://api.your-target.com --scope scopes/target.yaml
```

---

## 5. 動作確認 (Verification)

### 5-1. Neo4j でグラフを確認

偵察完了後、Neo4j ブラウザで以下の Cypher クエリを実行：

```cypher
-- 全ノードを確認
MATCH (n) RETURN n LIMIT 50

-- ドメインとページの関係を確認
MATCH (d:Domain)-[:CONTAINS]->(p:Page)
RETURN d.name, p.url LIMIT 20

-- 検出された技術を確認
MATCH (p:Page)-[:RUNS_ON]->(t:Technology)
RETURN p.url, t.name, t.version LIMIT 20
```

### 5-2. 生成されたレポートを確認

脆弱性が発見された場合、`reports/` ディレクトリに Markdown ファイルが生成されます：

```bash
ls -la reports/
# 2024-01-15_jwt_algorithm_none_bypass.md
# 2024-01-15_idor_user_profile.md
```

---

## 6. トラブルシューティング (Troubleshooting)

### 問題: Docker コンテナが起動しない

**症状**: `docker compose up -d` でエラー

**原因と解決策**:

| 原因                            | 解決策                                                  |
| :------------------------------ | :------------------------------------------------------ |
| Docker デーモンが起動していない | `sudo systemctl start docker`                           |
| ポートが使用中                  | `lsof -i :7474` で確認し、競合アプリを停止              |
| 権限不足                        | `sudo usermod -aG docker $USER` 後にログアウト/ログイン |

### 問題: Neo4j に接続できない

**症状**: `AuthError` または `ConnectionRefused`

**解決策**:

```bash
# コンテナログを確認
docker compose logs neo4j

# ボリュームをリセット (データ消失注意)
docker compose down -v
docker compose up -d
```

### 問題: ChromaDB に接続できない

**症状**: `ConnectionError: Cannot connect to ChromaDB`

**解決策**:

```bash
# ヘルスチェック
curl http://localhost:8001/api/v1/heartbeat

# コンテナ再起動
docker compose restart chromadb
```

### 問題: Python パッケージのインストール失敗

**症状**: `pip install` でエラー

**解決策**:

```bash
# ビルドツールをインストール
sudo apt install build-essential python3-dev

# 特定パッケージの問題 (例: neo4j)
pip install --no-cache-dir neo4j
```

### 問題: OCR が機能しない

**症状**: `tesseract is not installed` エラー

**解決策**:

```bash
# Ubuntu
sudo apt install tesseract-ocr tesseract-ocr-jpn

# macOS
brew install tesseract tesseract-lang

# 確認
tesseract --version
pytho3 -c "import pytesseract; print(pytesseract.get_tesseract_version())"
```

---

## 7. 次のステップ (Next Steps)

セットアップが完了したら、以下のドキュメントに進んでください：

| ドキュメント                               | 内容                                          |
| :----------------------------------------- | :-------------------------------------------- |
| [2026-07-02_sgk-2026-0338_operator-user-manual.md](2026-07-02_sgk-2026-0338_operator-user-manual.md) | 初期設定、Docker、モード、出力ファイル、ユースケース別コマンド |
| [../specs/2026-07-02_sgk-2026-0338_internal-architecture-and-dataflow-spec.md](../specs/2026-07-02_sgk-2026-0338_internal-architecture-and-dataflow-spec.md) | 現行の実行経路、データフロー、内部モジュール仕様 |
| [USER_MANUAL.md](USER_MANUAL.md)           | 3 つのモード（Recon/Hybrid/Sentinel）の使い方 |
| [2026-07-02_sgk-2026-0337_detailed-command-reference.md](2026-07-02_sgk-2026-0337_detailed-command-reference.md) | `shigoku-ops` と `src.main` の詳細CLIリファレンス |
| [../specs/TECHNICAL_DESIGN2026-01-26.md](../specs/TECHNICAL_DESIGN2026-01-26.md) | 内部アーキテクチャの理解                      |
| [REFERENCE.md](REFERENCE.md)               | 全設定オプションと環境変数                    |

### 推奨ワークフロー

1. **スコープファイルを作成**: `scopes/target.yaml`
2. **偵察を実行**: `--recon` でサイトマップを構築
3. **プロキシログを収集**: Burp/Caido でブラウジング
4. **ハイブリッドハント**: `--log` でログを分析・攻撃
5. **レポート確認**: `reports/` を確認し、必要に応じて編集
6. **提出**: HackerOne/Bugcrowd にレポートをアップロード
