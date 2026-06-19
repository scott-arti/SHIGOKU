---
task_id: SGK-2026-0101
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs:
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
- docs/shigoku/manuals/MANUAL_JA.md
- docs/shigoku/roadmaps/shigoku_unified_roadmap_20260301.md
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# 🏗️ SHIGOKU 技術仕様書

## 1. システム概要

**SHIGOKU（至極）** は、バグバウンティハンティングを自動化する統合フレームワークです。

### 技術スタック

| 項目            | 技術                 |
| --------------- | -------------------- |
| **言語**        | Python 3.10+         |
| **LLM**         | OpenAI API / LiteLLM |
| **ベクトル DB** | ChromaDB             |
| **グラフ DB**   | Neo4j (Community)    |
| **PDF 解析**    | PyMuPDF (fitz)       |
| **設定管理**    | Pydantic Settings    |
| **CLI**         | argparse             |

---

## 2. ディレクトリ構成

```text
src/
├── main.py                     # CLIエントリーポイント
├── config.py                   # 設定管理
│
├── core/                       # コアモジュール
│   ├── rag.py                  # RAGシステム（PDF/Markdown取り込み）
│   ├── rag_feedback.py         # RAG FP判定
│   ├── deduplication.py        # 重複排除
│   ├── parallel_scanner.py     # 並列スキャン
│   ├── config/                 # 🆕 Phase 3 設定管理
│   │   └── feature_config.py   # Phase 3機能オン/オフ管理
│   ├── models/                 # データモデル
│   │   └── finding.py          # 脆弱性モデル
│   ├── reports/                # レポート生成
│   │   ├── auto_reporter.py    # 自動レポーター（🆕 JSON/PDF export）
│   │   └── poc_generator.py    # PoC生成
│   ├── security/               # セキュリティ
│   │   ├── ethics_guard.py     # スコープ強制
│   │   ├── scope_parser.py     # YAML解析
│   │   ├── input_sanitizer.py  # 🆕 Phase 1: プロンプトインジェクション検出
│   │   ├── pii_masker.py       # 🆕 双方向PII/機密情報マスキング
│   │   └── guardrails.py       # 🆕 Phase 17: Unicodeホモグラフ検知・入出力ガードレール
│   ├── notifications/          # 🆕 通知システム
│   │   ├── notifier.py         # Notify CLI wrapper
│   │   └── notification_service.py  # 🆕 Phase 1: EventBus統合通知
│   ├── intel/                  # 偵察モジュール
│   │   ├── cartographer.py     # サイトマップ
│   │   ├── fingerprinter.py    # 技術識別
│   │   ├── commit_watcher.py   # Git監視
│   │   └── dns_history.py      # DNS履歴
│   ├── infra/                  # インフラ連携
│   │   ├── knowledge_graph.py  # Neo4j
│   │   ├── proxy_rotation.py   # IP回転
│   │   ├── network_client.py   # 🆕 Phase 1.3: 統一非同期ネットワーククライアント
│   │   ├── event_bus.py        # 🆕 非同期イベント通知
│   │   └── rate_limiter.py     # 🆕 適応型レート制限
│   ├── engine/                 # 🆕 Phase 2 実行エンジン
│   │   ├── phase_manager.py    # Recon→Attack→Report フェーズ管理
│   │   └── flag_watcher.py     # 🆕 Phase 4: リアルタイムフラグ検出
│   ├── intelligence/           # 🆕 インテリジェンス
│   │   ├── risk_predictor.py   # リスクスコアリング
│   │   ├── risk_predictor.py   # リスクスコアリング
│   │   ├── self_reflection.py  # 自己省察
│   │   ├── error_replanner.py  # 🆕 Phase 1.5: 自動エラー回復
│   │   ├── error_analyzer.py   # エラー分析
│   │   ├── failure_inference.py # 失敗推論
│   │   ├── retry_tracker.py    # 🆕 Phase 1: ループ停止判断
│   │   ├── priority_booster.py # 優先度調整
│   │   ├── decision_enhancer.py # 意思決定
│   │   └── adaptive_fuzzer.py  # 自己修正Fuzzing
│   ├── llm/                    # 🆕 LLM統合
│   │   ├── local_provider.py   # Ollama統合
│   │   └── micro_agent.py      # 🆕 Phase 3: ツール出力解析
│   ├── learning/               # 🆕 学習
│   │   ├── repository.py       # SQLite永続化
│   │   └── findings_repository.py  # 🆕 Phase 1: Finding専用DB
│   └── attack/                 # 攻撃モジュール
│       ├── cors_tester.py
│       ├── crlf_tester.py
│       ├── graphql_analyzer.py
│       ├── lfi_tester.py
│       ├── open_redirect_tester.py
│       ├── openapi_tester.py
│       ├── parameter_fuzzer.py
│       ├── race_condition_tester.py
│       ├── ssti_scanner.py
│       ├── ssrf_tester.py
│       ├── websocket_tester.py
│       ├── xss_tester.py
│       ├── exploit_verifier.py     # 🆕 Phase 3: PoC検証
│       └── host_header_injection.py # 🆕 Phase 3: Host Header Injection
│
├── tools/                      # 🆕 ツールプロファイル
│   ├── tool_profiles.py        # 🆕 Phase 2: speed/stealth/thorough
│   └── builtin/
│       └── sandbox_linux_cmd.py # 🆕 Phase 3: サンドボックス実行
│
├── agents/                     # AIエージェント
│   ├── specialized/            # 専門エージェント (Phase 12)
│   │   ├── scope_parser.py     # スコープ解析
│   │   └── fingerprinter.py    # 技術特定
│   └── swarm/
│       ├── auth_ninja.py       # JWT/OAuth/MFA
│       ├── biz_logic_hunter.py # IDOR/権限昇格
│       ├── post_exploit/       # 🆕 Phase 4: ポストエクスプロイト
│       │   └── workers/        # internal_recon, secret_looter, pivot_scan
│       ├── manager.py          # Swarm Manager (各Swarm)
│       └── llm_specialists.py  # 🆕 LLM専門家 (各Swarm)
│
├── intelligence/               # 分析
│   └── proxy_log_analyzer.py   # Caidoログ解析
│
├── recipes/                    # 🆕 Phase 2 Recipe
│   └── cloud/
│       └── cloud_metadata_diag.yaml  # クラウド診断Recipe
│
└── dashboard/                  # Web UI
    └── api/
        └── main.py             # FastAPI
```

---

## 3. アーキテクチャ

```
┌────────────────────────────────────────────────────────────┐
│                      SHIGOKU Architecture                  │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                   CLI Layer                          │   │
│  │  main.py (argparse)                                  │   │
│  │  • --log, --recon, --watch                          │   │
│  │  • --rag-ingest, --rag-query, --rag-stats          │   │
│  │  • --dns, --json                                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ▼                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                 Core Brain Layer                     │   │
│  │  • EthicsGuard (スコープ強制)                       │   │
│  │  • RAGSwitch (ナレッジ検索)                         │   │
│  │  • RAGFeedback (FP判定)                            │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│          ┌────────────────┼────────────────┐               │
│          ▼                ▼                ▼               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ Intel Layer │  │Action Layer │  │ Data Layer  │        │
│  │ (偵察)      │  │ (攻撃)      │  │ (永続化)    │        │
│  │             │  │             │  │             │        │
│  │ Cartograph. │  │ AuthNinja   │  │ Neo4j       │        │
│  │ Fingerprint.│  │ BizLogic    │  │ ChromaDB    │        │
│  │ CommitWatch │  │ 12 Testers  │  │ Reports     │        │
│  │ DNSHistory  │  │ AutoReport  │  │             │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
│                                                            │
│  ┌───────────────────────────────────────────────────┐    │
│  │              Notification Layer                    │    │
│  │  Notifier (projectdiscovery/notify wrapper)       │    │
│  │  → Discord/Slack/Telegram通知                     │    │
│  └───────────────────────────────────────────────────┘    │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

---

## 4. 主要コンポーネント

### 4.1 RAG システム (`rag.py`)

```python
class PDFIngester:
    """PyMuPDFによるPDF解析"""
    def parse_pdf(pdf_path: str) -> list[RAGDocument]

class KnowledgeIngester:
    """ナレッジ取り込み・検索"""
    def ingest_pdf(pdf_path: str) -> int
    def ingest_directory(directory_path: str) -> dict
    def query(question: str, n_results: int, context: dict = None) -> list[RAGDocument]
    def _split_markdown_by_headers(content: str) -> list[str]  # 🆕 チャンク分割

class RAGSwitch:
    """RAG有効/無効制御"""
    def query(question: str, context: dict = None) -> list[RAGDocument]
    def query_if_enabled(query: str, context: dict = None) -> list[RAGDocument]
    def get_bypass_techniques(attack_type: str) -> list[dict]

class Settings(BaseSettings):
    """設定管理 (config.py)"""
    model_lightweight: str  # 軽量タスク用モデル
    model_output: str       # 高精度タスク用モデル
    def get_lightweight_model() -> str: ...

```

````

### 4.2 Knowledge Graph Infrastructure (`infra/knowledge_graph.py`)

Knowledge Graphはプロジェクトの「長期記憶」と「状況認識」の中核を担います。

```python
class Neo4jDriver:
    """Neo4j接続管理 (Singleton)"""
    def get_driver() -> neo4j.Driver
    def verify_connectivity()

class GraphSchema:
    """スキーマ定義と制約"""
    def apply_constraints() # Uniqueness制約適用

class BaseIngestor:
    """データ取り込み基底クラス"""
    def ingest(file_path: Path, project_name: str)

class KatanaIngestor(BaseIngestor):
    """Assets/Endpoints/TechStack構築"""

class NucleiIngestor(BaseIngestor):
    """Vuln/Findings/Evidence構築"""
````

### 4.3 攻撃モジュール

| モジュール                      | 機能                                            |
| ------------------------------- | ----------------------------------------------- |
| `cors_tester.py`                | CORS 設定ミス検出                               |
| `crlf_tester.py`                | CRLF インジェクション                           |
| `graphql_analyzer.py`           | GraphQL Introspection                           |
| `lfi_tester.py`                 | ローカルファイルインクルージョン                |
| `open_redirect_tester.py`       | オープンリダイレクト                            |
| `openapi_tester.py`             | OpenAPI/Swagger 解析                            |
| `parameter_fuzzer.py`           | パラメータファジング                            |
| `race_condition_tester.py`      | レースコンディション検証                        |
| `ssrf_tester.py`                | SSRF 検出                                       |
| `ssti_scanner.py`               | SSTI テンプレートインジェクション               |
| `websocket_tester.py`           | WebSocket 脆弱性                                |
| `xss_tester.py`                 | XSS 検出                                        |
| `nosql_tester.py`               | NoSQL インジェクション（MongoDB/CouchDB/Redis） |
| `ldap_tester.py`                | LDAP インジェクション                           |
| `deserial_tester.py`            | デシリアライズ脆弱性検出                        |
| `prototype_pollution_tester.py` | Prototype Pollution (Node.js)                   |
| `time_based_tester.py`          | 時間ベースブラインド検出                        |
| `waf_mutator.py`                | WAF バイパス用ペイロード進化                    |
| `adaptive_adjuster.py`          | コンテキスト適応型ペイロード調整                |
| `error_analyzer.py`             | エラーメッセージ解析                            |
| `param_analyzer.py`             | パラメータ意味論的解析                          |
| `jwt_attacker.py`               | JWT 攻撃（None Alg/KID/Confusion）              |
| `mass_assignment_tester.py`     | マスアサインメント検出                          |
| `graphql_crafter.py`            | GraphQL 攻撃クエリ生成                          |
| `high_risk_tester.py`           | HTTP Smuggling / Cache Poisoning                |
| `session_hijacker.py`           | Session Fixation / Cookie 属性監査              |
| `error_replanner.py`            | 🆕 自動エラー回復（403/429/Timeout対応）        |
| `llm_specialists.py`            | 🆕 Hybrid Swarm Intelligence (LLMベース解析)    |
| `oob_verifier.py`               | 🆕 OOB (Out-of-Band) 検知 (SSRF/RCE)            |
| `playwright_validator.py`       | 🆕 ヘッドレスブラウザ XSS 検証                  |

### 4.4 Hybrid Swarm Intelligence (Phase 2 & 3)

各Swarm（Injection, Auth, Discovery, Logic, Scanner, Secret）に配備されたLLM専門家エージェント群です。

- **InjectionSwarm**: `LLMSQLiHunter`, `LLMXSSHunter`, `LLMSSRFHunter` (New), `LLMCommandInjectionHunter` (New)
- **AuthSwarm**: `LLMAuthEscalator`
- **DiscoverySwarm**: `LLMSecretScanner`
- **LogicSwarm**: `LLMBizLogicHunter`
- **ScannerSwarm**: `LLMCryptoAnalyzer`
- **SecretSwarm**: `LLMCloudMisconfigAnalyzer`

### 4.3 RAG Feedback (`rag_feedback.py`)

```python
class RAGFeedbackManager:
    """偽陽性判定"""
    def filter_likely_fps(findings: list, threshold: float) -> tuple[list, list]
    def learn_from_fp(finding: Finding, confidence: float)
```

---

## 5. データフロー

### ハイブリッドハント

```
Caidoログ
    │
    ▼
ProxyLogAnalyzer (Smell検出)
    │
    ▼
AttackPlanner (候補絞り込み)
    │
    ▼
Agent実行 (JWT/OAuth/MFA/BizLogic)
    │
    ▼
DuplicateFinder (重複排除)
    │
    ▼
RAGFeedback (FP判定)
    │
    ▼
AutoReporter (レポート生成)
```

AutoReporter (レポート生成)

```

### Knowledge Graph Data Pipeline

```

Recon/Attack Tools (Katana, Nuclei)
│
▼ JSON/JSONL
Ingestors (KatanaIngestor, NucleiIngestor)
│
▼ Cypher Query
Neo4j (Knowledge Graph)
│ Nodes: Asset, Endpoint, Parameter, Technology, Finding
│ Edges: BELONGS_TO, ACCEPTS, BUILT_WITH, AFFECTS
▼
MasterConductor (Context-Aware Planning)
│ "High IQ" Context Retrieval
▼
ReportRefinerAgent (Evidence Retrieval)
│ Curl Command, HTTP Req/Res
▼
Report Generation (Haddix Style)

```

### RAG 取り込み

```

PDF/Markdown
│
▼
PDFIngester / ObsidianIngester
│
▼
チャンク分割 (1000文字, 100 overlap)
│
▼
Embedding生成
│
▼
ChromaDB格納

```

---

## 6. Phase 実装完了状況

| Phase | 内容                                           | 状態    |
| ----- | ---------------------------------------------- | ------- |
| 1-5   | 基盤・偵察・攻撃エージェント                   | ✅ 100% |
| 6     | PDF RAG・URL タグ付け・DNS 履歴                | ✅ 100% |
| 7     | 12 攻撃モジュール                              | ✅ 100% |
| 8     | CLI 統合強化                                   | ✅ 100% |
| 9     | 並列スキャン・重複検出・RAG Feedback           | ✅ 100% |
| 10    | アーキテクチャ刷新・黄金レシピ                 | ✅ 100% |
| 11    | スマート並列実行・GPU 特化機能・新エージェント | ✅ 100% |
| 12    | ワークフロー改善・専門エージェント・パス伝播   | ✅ 100% |
| 13    | エージェント最適化                             | ✅ 100% |
| 14    | RAG Engine 2.0・ReAct・Agentic RAG             | ✅ 100% |
| 15    | Intelligence モジュール（学習/適応/意思決定）  | ✅ 100% |
| 19    | セッション永続化・Fingerprint 統合             | ✅ 100% |
| 20    | Knowledge Graph (Neo4j)・Context Planning      | ✅ 100% |

**総モジュール数**: 50+

**Phase 19 新機能**:

- MasterConductor セッション永続化（`save_session` / `load_session`）
- JSON 形式でタスクキュー・コンテキストを保存・復元
- `--resume` フラグでプロセス中断後も作業継続
- 自動チェックポイント保存（5 タスクごと）
- ReconPipeline への詳細 Fingerprinting ロジック統合

```

```

```
