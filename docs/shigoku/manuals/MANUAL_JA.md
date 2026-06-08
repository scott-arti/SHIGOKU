---
task_id: SGK-2026-0003
doc_type: manual
status: active
parent_task_id: SGK-2026-0101
related_docs:
- docs/shigoku/specs/TECHNICAL_SPEC_JA.md
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# 📖 SHIGOKU ユーザーマニュアル（日本語版）

**SHIGOKU（至極）** - 自律型バグバウンティハンター

---

## 1. 概要

SHIGOKU は、バグバウンティハンティングを自動化・効率化するための統合 CLI ツールです。

### 主要機能

| 機能                   | 説明                          |
| ---------------------- | ----------------------------- |
| **Hybrid Hunt**        | Caido ログ解析 → 自動攻撃     |
| **Sentinel Watch**     | GitHub 監視・シークレット検出 |
| **Recon Phase**        | サイトマップ・技術識別        |
| **Knowledge Graph**    | Neo4j 資産・脆弱性グラフ      |
| **RAG ナレッジベース** | PDF/Markdown 取り込み・検索   |
| **DNS History**        | DNS 履歴取得                  |

---

## 2. クイックスタート

### インストール

```bash
git clone https://github.com/your-org/shigoku.git
cd shigoku
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Docker 環境（推奨）

```bash
docker compose up -d  # Neo4j + ChromaDB
```

---

## 3. 基本的な使い方

### ヘルプ表示

```bash
python src/main.py --help
```

### ハイブリッドハント

```bash
# Caidoログ解析
python src/main.py --log caido.json

# スコープ付き
python src/main.py --log caido.json --scope scope.yaml

# モード指定
python src/main.py --log caido.json --mode vulntest
```

### RAG ナレッジベース

```bash
# ディレクトリ取り込み
python src/main.py --rag-ingest ./knowledge

# PDF取り込み
python src/main.py --rag-ingest ./security_book.pdf

# 検索
python src/main.py --rag-query "JWT bypass"

# 統計
python src/main.py --rag-stats
```

### DNS 履歴

```bash
python src/main.py --dns example.com
python src/main.py --dns example.com --json
```

python src/main.py --dns example.com --json

````

### プロジェクト管理

```bash
# 全プロジェクトの一覧表示
python src/main.py --projects

# JSON形式で出力
python src/main.py --projects --json
````

### Knowledge Graph (Neo4j)

```bash
# 接続確認と統計情報
python tests/verify_knowledge_graph.py

# データ Ingstion は自動で行われますが、手動実行も可能です（開発者向け）
# Katana:
python -c "from src.core.knowledge.ingestors.katana import KatanaIngestor; KatanaIngestor().ingest('workspace/projects/project_name/scans/raw/katana.json', 'project_name')"
```

---

## 4. モード設定

3 つの動作モードをサポート：

| モード        | 用途               | 特徴                     |
| ------------- | ------------------ | ------------------------ |
| **bugbounty** | 本番バグバウンティ | 高精度重視、控えめな攻撃 |
| **vulntest**  | 脆弱性診断         | バランス型、網羅的テスト |
| **ctf**       | CTF 競技           | 積極的攻撃、速度重視     |

---

## 5. スコープ設定

`scope.yaml` でスコープを定義：

```yaml
program:
  name: "Example Bug Bounty"
  platform: "hackerone"

in_scope:
  domains:
    - "api.example.com"
    - "*.staging.example.com"

out_of_scope:
  domains:
    - "auth.example.com"
  paths:
    - "/admin/*"
```

---

## 6. RAG Feedback（FP 自動判定）

ハイブリッドハント実行時に自動的に False Positive 判定を実行：

```
🧠 RAG FEEDBACK ANALYSIS
⚠️ False Positive candidates detected: 2
   └─ JWT alg none bypass (confidence: 85%, reason: Similar to known FP)
✅ Findings after FP filtering: 3
```

---

## 7. 攻撃モジュール

### Phase 7 で追加された 12 モジュール

1. CORS Tester
2. CRLF Injection Tester
3. GraphQL Analyzer
4. LFI Tester
5. Open Redirect Tester
6. OpenAPI/Swagger Tester
7. Parameter Fuzzer
8. Race Condition Tester
9. SSRF Tester
10. WebSocket Tester
11. XSS Tester
12. SSTI Scanner

### Feature Expansion (Phase 1-3)

以下の高度な攻撃モジュールが追加されました：

1. **NoSQL Injection Tester**: MongoDB/Redis/CouchDB に対するインジェクション
2. **LDAP Injection Tester**: ディレクトリサービスに対するクエリ改ざん
3. **Deserialization Tester**: 安全でないデシリアライズ（Java/PHP/Python 等）
4. **Prototype Pollution Tester**: Node.js アプリケーションのプロトタイプ汚染
5. **Time-Based Blind Tester**: SQL/NoSQL/Command の時間差攻撃
6. **WAF Payload Mutator**: WAF 回避のためのペイロード変異（エンコード/難読化）
7. **Adaptive Payload Adjuster**: 入力コンテキストに応じたペイロード自動調整
8. **Error Message Analyzer**: エラー詳細からのスタック特定と脆弱性推論
9. **JWT Attacker (Advanced)**: None Alg, KID Manipulation, Confusion 攻撃
10. **Mass Assignment Tester**: API パラメータの不正な上書き
11. **GraphQL Crafter**: Introspection, DoS, Batching 攻撃
12. **High Risk Tester**: HTTP Smuggling, Cache Poisoning

### Hybrid Swarm Intelligence (Phase 2-3)

各Swarmに統合されたLLM専門家が、ルールベースでは検知できない高度なコンテキスト依存型の脆弱性を発見します。

| Swarm         | Specialist                  | 役割                                          |
| ------------- | --------------------------- | --------------------------------------------- |
| **Injection** | `LLMSQLiHunter`             | Blind SQLiの微細な変化検知、WAF回避           |
| **Injection** | `LLMSSRFHunter`             | 🆕 OOB (外部サーバ通信) によるSSRF検知        |
| **Injection** | `LLMCommandInjectionHunter` | 🆕 OOBペロードを用いたBlind RCE検知           |
| **Injection** | `XSSVerifier`               | 🆕 Playwrightを用いた実際のブラウザ発火検証   |
| **Auth**      | `LLMAuthEscalator`          | 権限昇格シナリオの仮説生成と検証              |
| **Discovery** | `LLMSecretScanner`          | 変数名や文脈からのシークレット監査（Auditor） |

---

## 8. 作業報告書の deferred_tasks 記載例（手動作成時）

`doc_type: work_report` で未完了事項を残す場合は、次の形式を推奨します。

```yaml
deferred_tasks:
  - deferred_id: SGK-YYYY-NNNN-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
| **Logic**     | `LLMBizLogicHunter`         | IDORやビジネスロジック不備の推論              |
| **Scanner**   | `LLMCryptoAnalyzer`         | TLS/SSL設定のコンプライアンス分析             |
| **Secret**    | `LLMCloudMisconfigAnalyzer` | 複雑なS3/GCSバケットポリシーの診断            |

---

## 8. 出力形式

### JSON 出力

```bash
python src/main.py --rag-query "SSRF" --json
python src/main.py --dns example.com --json
```

### レポート形式

発見された脆弱性は自動的に HackerOne 形式の Markdown レポートに変換：

- `reports/YYYYMMDD_HHMMSS_finding_title.md`

---

## 9. 環境変数

| 変数                  | デフォルト              | 説明                |
| --------------------- | ----------------------- | ------------------- |
| `NEO4J_URI`           | `bolt://localhost:7687` | Neo4j 接続 URI      |
| `NEO4J_USER`          | `neo4j`                 | Neo4j ユーザー      |
| `NEO4J_PASSWORD`      | `deephunter2024`        | Neo4j パスワード    |
| `CHROMA_HOST`         | `localhost`             | ChromaDB ホスト     |
| `CHROMA_PORT`         | `8001`                  | ChromaDB ポート     |
| `OBSIDIAN_VAULT_PATH` | `~/MEGA/obsidian`       | Obsidian Vault パス |

### 通知設定

| 変数                              | デフォルト | 説明                                      |
| --------------------------------- | ---------- | ----------------------------------------- |
| `SHIGOKU_NOTIFY_ON_TASK_START`    | `false`    | タスク開始時に通知 (デフォルト OFF)       |
| `SHIGOKU_NOTIFY_ON_TASK_COMPLETE` | `true`     | タスク完了時に通知                        |
| `SHIGOKU_NOTIFY_ON_FINDING`       | `true`     | Critical/High 発見時に通知                |
| `SHIGOKU_NOTIFY_ON_ERROR`         | `true`     | システムエラー時に通知                    |
| `SHIGOKU_NOTIFY_CRITICAL_MENTION` | (空)       | CRITICAL 発見時のメンション (@channel 等) |

### モデルルーティング設定 (コスト最適化)

| 変数                                | デフォルト        | 説明                                  |
| :---------------------------------- | :---------------- | :------------------------------------ |
| `SHIGOKU_MODEL_LIGHTWEIGHT`         | `ollama/qwen3:8b` | 軽量タスク用モデル (ReAct, Critic)    |
| `SHIGOKU_MODEL_OUTPUT`              | `gpt-4o`          | 高精度タスク用モデル (Report, Plan)   |
| `SHIGOKU_USE_LOCAL_FOR_LIGHTWEIGHT` | `true`            | 軽量タスクにローカル LLM を使用するか |

> **推奨**: コストを抑えるために `SHIGOKU_USE_LOCAL_FOR_LIGHTWEIGHT=true` (デフォルト) を使用し、Ollama で `qwen3:8b` などを実行してください。API のみを使用する場合は `false` に設定し、`SHIGOKU_MODEL_LIGHTWEIGHT` に `gpt-4o-mini` などを指定します。

> **注意**: 通知を受け取るには `~/.config/notify/provider-config.yaml` の設定が必要です。

---

## 10. トラブルシューティング

### Q: Neo4j に接続できない

```bash
docker compose ps  # コンテナ状態確認
docker compose logs neo4j  # ログ確認
```

### Q: RAG インジェストが遅い

```bash
# PDF変わりにMarkdownを優先
python src/main.py --rag-ingest ./knowledge --reset-db
```

### Q: モジュールが見つからない

```bash
pip install -r requirements.txt  # 依存パッケージ再インストール
```

---

## 11. フェーズ完了状況

| Phase     | 内容                 | 状態    |
| --------- | -------------------- | ------- |
| Phase 1-5 | 基盤・偵察・攻撃     | ✅ 100% |
| Phase 6   | PDF RAG・DNS 履歴    | ✅ 100% |
| Phase 7   | 12 攻撃モジュール    | ✅ 100% |
| Phase 8   | CLI 統合強化         | ✅ 100% |
| Phase 9   | 高度機能             | ✅ 100% |
| Phase 10  | アーキテクチャ刷新   | ✅ 100% |
| Phase 11  | GPU/並列/新 Agent    | ✅ 100% |
| Phase 12  | ワークフロー改善     | ✅ 100% |
| Phase 13  | Agent 最適化 (20→17) | ✅ 100% |

**総モジュール数**: 42+ (17 アクティブエージェント)

---

## 12. Phase 10 新機能（アーキテクチャ刷新）

### 🎮 インタラクティブ制御 (Interactive Handoff)

実行中に `Ctrl+C` を入力すると、即座にプロセスを終了するのではなく、インタラクティブメニューが表示されます。

```text
🛑 Agent interrupted!
Current Task: Scanning example.com

[1] New Instruction (新しい指示を入力)
[2] Continue (続行)
[3] Exit (終了)
```

これにより、スキャン結果を見て「あ、ここもっと深く掘って」とリアルタイムに指示を割り込ませることが可能です。

### 🍳 黄金レシピ (Golden Recipes)

**13 種類の「鉄板」レシピ** が標準搭載されました。これらは汎用的なスキャンだけでなく、特定の技術（WordPress, GraphQL など）が検出された瞬間に**自動的に割り込み注入**されます。

| レシピ名                  | 対象                | Severity | 自動トリガー条件 |
| :------------------------ | :------------------ | :------- | :--------------- |
| **Generic Exposure**      | .env, .git, backups | High     | 常時             |
| **Subdomain Takeover**    | CNAME 乗っ取り      | Critical | 常時             |
| **WordPress Gold**        | User Enum, XMLRPC   | High     | WordPress 検出時 |
| **GraphQL Introspection** | Schema Dump         | High     | GraphQL 検出時   |
| **API Key Leak**          | JS 内の Secret      | Critical | 常時             |
| **SSRF Probe**            | OOB 検出            | Critical | 常時             |
| **HTTP Smuggling**        | CL.TE / TE.CL       | Critical | 常時             |
| **Host Header Injection** | Poisoning           | High     | 常時             |
| ...他 5 種                |                     |          |                  |

### ⚡️ イベント駆動型アーキテクチャ

`ScopeParserAgent.fingerprint()` メソッドが新しい技術スタック（例: "WordPress"）を検出すると、即座にシステム全体にイベントが通知され、対応するレシピ（`wordpress_gold`）がタスクキューの**最優先順位**に自動的に追加されます。
これにより、偵察で見つかった技術に対して、間髪入れずに深掘り攻撃を行うことが可能になりました。

---

## 13. Phase 11 新機能（スマート並列実行・GPU）

### 🧠 Smart Parallel Conductor

タスク間の依存関係だけでなく、「意思決定依存（Decision Dependency）」を考慮した並列実行が可能になりました。
例：Recon で認証不要ページが見つかった場合、ログイン試行タスクを自動的にスキップします。

### 🎮 インタラクティブ RAG 制御

新しい `/rag` コマンドで、実行中にナレッジベースの利用を ON/OFF できます。

```bash
/rag on      # ナレッジベース有効化
/rag off     # ナレッジベース無効化（LLMの知識のみ使用）
/rag status  # 現在の状態を表示
```

### 👁️ GPU 特化機能 (RTX 3060)

ローカル GPU（Ollama / Embeddings）を活用したコストゼロの高度解析：

1. **VisualReconAgent**: スクリーンショットを LLaVA (7B) で解析し、Admin パネルやエラー画面を自動識別。
2. **SemanticGrep**: 「データベースエラー」のような概念で HTTP レスポンスを検索。
   ```python
   grep.search("database errors") # -> "SQL syntax error" もヒット
   ```
3. **Hybrid ProxyLog**: 正規表現で漏れた怪しいログを LLM (qwen2.5-coder) で再評価。

### 🕵️ 新しい専門エージェント

- **RaceConditionAgent**: 並列リクエストによる競合状態・ダブルスペンディング検出 (※タイミング精度確保のため、デフォルトでプロキシは無効化されます)
- **TaintAnalysisAgent**: カナリア値注入による高精度 XSS 検出（コンテキスト認識）
- **ReportRefinerAgent**: レポートの重複排除とビジネスインパクトの自動生成

---

## 14. Phase 12 新機能（ワークフロー改善）

### 📂 ワークスペース管理 2.0

ターゲットごとに独立したワークスペース (`~/.shigoku/workspace/{target}/`) が作成され、全エージェントの出力がここに集約されます。
また、ファイル名には自動的にタイムスタンプが付与され、ツール実行時の上書き事故を防止します。

### 🕵️ 専門エージェントの追加

- **ScopeParserAgent**: スコープ定義ファイルを構造的に解析し、厳密なターゲットリストを作成します。
- **ScopeParserAgent**: スコープ定義の構造化解析 + 技術スタック特定（旧 FingerprinterAgent 統合）

### 🔗 パス伝播と CoT

すべてのエージェントは、ワークスペースのパスを認識し、Chain of Thought (CoT) プロセスを経てからツールを実行します。これによ
り、「なぜそのツールを使ったか」「どこに出力したか」が明確になり、自律動作の透明性が向上しました。

---

## 16. RAG 機能強化 (Phase 14)

### 🧠 Agentic RAG (Context-Aware Query)

RAG 検索時に、現在の実行コンテキスト（検出された技術スタック、サーバー情報など）を自動的にクエリに付加します。
例えば、「SQL injection」について検索する場合、ターゲットが `PostgreSQL` であることが判明していれば、自動的に `[Tech: PostgreSQL] SQL injection` として検索され、より関連性の高い情報を取得します。

### 🔄 MasterConductor ReAct Loop

タスクが「成功」した場合でも、MasterConductor は即座に次のタスクへ移行せず、「成功要因の分析」と「追加攻撃ベクトルの再思考（Rethink）」を行います。
これにより、1 つの脆弱性発見をきっかけに、芋づる式に関連する脆弱性を見つけ出す自律的な挙動が強化されました。
（この機能は `config.py` または環境変数 `ENABLE_REACT_OBSERVATION` で制御可能です）

### 🕵️ BizLogicHunter Critic Mode

ビジネスロジック脆弱性検知において、LLM の幻覚（Hallucination）による誤検知を減らすため、「自己検証（Critic）」ループを導入しました。
デフォルトでは API コスト削減のため無効化されていますが、精度を最優先する場合は以下のコードで有効化できます：

```python
hunter = BizLogicHunter(...)
hunter.enable_critic(True, max_iterations=3)
```

---

## 15. IDOR クロステスト

### 概要

マルチアカウントセッションを使用して、IDOR（Insecure Direct Object Reference）を確実に検出する機能です。

従来の IDOR 検出は「ID=1 や ID=0 でアクセスして成功したら IDOR」という静的テストでしたが、これでは誤検知が多発します。
クロステストでは、**実際の 2 つのアカウント（Attacker/Victim）**を使用し、「Attacker が Victim のリソースにアクセスできるか」を確実に検証します。

### ユーザーフロー

```
1. 通常のハントでIDOR候補を検出
   ↓
2. 「IDOR候補検出」通知がユーザーに送られる
   ↓
3. ユーザーが2つのテストアカウントを作成
   ↓
4. sessions.json にセッション情報を記載
   ↓
5. --cross-test-approved フラグ付きで再実行
   ↓
6. 確実なIDORが検出される
```

### sessions.json の作成

以下の形式でセッションファイルを作成します：

```json
{
  "sessions": [
    {
      "name": "victim",
      "auth_type": "cookie",
      "credentials": {
        "cookie": "session=victim_session_id; csrf_token=xyz"
      }
    },
    {
      "name": "attacker",
      "auth_type": "cookie",
      "credentials": {
        "cookie": "session=attacker_session_id; csrf_token=abc"
      }
    }
  ]
}
```

#### 対応認証方式

| auth_type | credentials に必要なキー       | 例                          |
| --------- | ------------------------------ | --------------------------- |
| `cookie`  | `cookie`                       | `"session=abc123"`          |
| `bearer`  | `token`                        | `"eyJhbGciOiJIUzI1NiJ9..."` |
| `basic`   | `username`, `password`         | `"admin"`, `"secret"`       |
| `api_key` | `api_key`, `header_name`(任意) | `"sk-xxx"`, `"X-API-Key"`   |

### 使用方法

```bash
# 通常のハント（IDOR候補を検出するのみ）
python src/main.py --log caido.json

# セッションファイル指定（クロステスト未承認）
# → IDOR候補があれば通知が送られる
python src/main.py --log caido.json --sessions-file sessions.json

# クロステスト実行（明示的な承認）
python src/main.py --log caido.json --sessions-file sessions.json --cross-test-approved
```

### 検出フロー

クロステストは以下のフローで動作します：

1. **Victim セッションでアクセス**: 正規ユーザーとしてリソースを取得（ベースライン）
2. **Attacker セッションで同じリソースにアクセス**
3. **レスポンス比較**:
   - 403/401 → 正常にブロック（脆弱性なし）
   - 200 + Victim と同じデータ → **IDOR 確定**
   - 200 + 異なるデータ → 判定不能（部分的 IDOR 可能性）

### 注意事項

> [!WARNING]
>
> - クロステストは**テスト環境でのみ使用**してください
> - セッション情報はログに出力されませんが、`sessions.json` の適切なファイルパーミッション（600）を設定してください
> - クロステストは**非破壊（READ のみ）**ですが、アクセスログが残る可能性があります

---

## 16. ポストエクスプロイトとフラグ検出 (Phase 4)

### 🚩 FlagWatcher (CTF 自動化)

CTFモードなどで、フラグ（例: `FLAG{...}`）を自動的に検出・記録する機能です。
以下の箇所で自動的に監視が行われます：

- HTTPレスポンス（ヘッダー・ボディ）
- コマンド実行結果（標準出力）
- OOB（Out-of-Band）コールバック

設定方法 (`.env`):

```env
SHIGOKU_CTF_FLAG_FORMAT="FLAG\{[a-zA-Z0-9_-]+\}"
```

### 🕵️ Post-Exploitation Swarm

侵入に成功（RCEやSSRFなどでコード実行・内部アクセスを確保）した際、自動的に以下の調査を開始します：

1. **Internal Recon**: ホスト名、OS情報、内部ネットワークインターフェースの調査。
2. **Secret Looting**: 環境変数、履歴ファイル、SSHキー、パスワードの検索。
3. **Pivoting**: 内部ネットワーク上の他のホストのスキャン。

> [!IMPORTANT]
> Bug Bountyモードでは、RoE（実行規定）遵守のため、デフォルトでこの機能は制限されています。有効にするには設定が必要です。
