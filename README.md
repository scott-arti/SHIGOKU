# SHIGOKU (至極) - Sovereign VAPT Engine

> **"From Recon to Report, Fully Autonomous."**
> ROI（投資対効果）を最大化し、脆弱性診断の「至極」を目指す自律型 AI エンジン。

![Status](https://img.shields.io/badge/Status-Beta-orange) ![Python](https://img.shields.io/badge/Python-3.10+-blue) ![Docker](https://img.shields.io/badge/Docker-Compose-green) ![License](https://img.shields.io/badge/License-MIT-purple)

---

## 目次 (Table of Contents)

1. [概要 (Overview)](#-概要-overview)
2. [なぜ SHIGOKU か (Why SHIGOKU)](#-なぜshigokuか-why-shigoku)
3. [主要機能 (Key Features)](#-主要機能-key-features)
4. [システム要件 (Requirements)](#-システム要件-requirements)
5. [アーキテクチャ (Architecture)](#-アーキテクチャ-architecture)
6. [プロジェクト構造 (Project Structure)](#-プロジェクト構造-project-structure)
7. [クイックスタート (Quick Start)](#-クイックスタート-quick-start)
8. [ドキュメント (Documentation)](#-ドキュメント-documentation)
9. [ロードマップ (Roadmap)](#-ロードマップ-roadmap)
10. [貢献 (Contributing)](#-貢献-contributing)
11. [免責事項 (Disclaimer)](#-免責事項-disclaimer)

---

## ⛩ 概要 (Overview)

**SHIGOKU (至極)** は、単なる脆弱性スキャナーではありません。ホワイトハッカーの相棒として機能するように設計された、**自律型攻撃エンジン** です。

従来のツールが「網羅性」を重視して大量のノイズを生み出すのに対し、SHIGOKU は「**インパクト（影響度）**」を最優先します。ターゲットシステムのビジネスロジックを理解し、厳格なスコープ定義（EthicsGuard）の中で、ナレッジグラフと RAG（Retrieval-Augmented Generation）を駆使して、最も収益性の高い攻撃パスを特定・実行します。

### 名前の由来

「**至極**」は日本語で「この上なく優れている」「究極」を意味します。バグバウンティにおける究極の相棒を目指し、この名を冠しています。

---

## 🎯 なぜ SHIGOKU か (Why SHIGOKU)

### 従来のツールとの違い

| 観点         | 従来のスキャナー           | SHIGOKU                        |
| :----------- | :------------------------- | :----------------------------- |
| **焦点**     | 網羅性（すべてをスキャン） | インパクト（P1/P2 に集中）     |
| **出力**     | 大量のノイズ               | 厳選された高確率候補           |
| **学習**     | 静的ルール                 | RAG+ナレッジグラフ（動的学習） |
| **倫理**     | オペレーター任せ           | EthicsGuard による強制         |
| **レポート** | 手動作成                   | HackerOne 形式自動生成         |

### SHIGOKU が選ばれる 5 つの理由

1. **Finding-Oriented (成果主義)**:
   - `P1 (Critical)` / `P2 (High)` の脆弱性発見にリソースを集中
   - 些末な設定ミスより、認証バイパスや IDOR を狙う

2. **Program-Aware (コンプライアンス遵守)**:
   - **EthicsGuard** により、バグバウンティプログラムのスコープを物理的・論理的に強制
   - スコープ外への攻撃は送信前にブロック

3. **Knowledge-Driven (進化する知能)**:
   - Neo4j グラフデータベースで資産とリレーションを管理
   - Obsidian RAG で過去の成功パターンやあなた個人のナレッジを活用

4. **Human-in-the-Loop (人間との協調)**:
   - 完全自動ではなく、重要な判断はオペレーターに委ねる
   - プロキシログから「シード」を取得し、質の高い攻撃を生成

5. **Report-Ready (即提出可能)**:
   - 発見された脆弱性は即座に HackerOne/Bugcrowd 形式の Markdown レポートに変換
   - CVSS、CWE、再現手順、修正案を自動付与

初期版リリース判定ポリシー（明示）:
- 初期版ゲートでは `SCN10 (semantic/business logic)` と `SCN12 (advanced SSRF internal topology)` の未達を許容し、後続フェーズ（HITL/手動検証）で扱います。

---

## 🚀 主要機能 (Key Features)

### 偵察フェーズ (Reconnaissance)

| モジュール        | 機能                    | 詳細ドキュメント                                                |
| :---------------- | :---------------------- | :-------------------------------------------------------------- |
| **Cartographer**  | サイトマッピング        | [CARTOGRAPHER.md](docs/modules/CARTOGRAPHER.md)                 |
| **Fingerprinter** | 技術スタック識別        | [FINGERPRINTER.md](docs/modules/FINGERPRINTER.md)               |
| **VisualFilter**  | ページタイプ分類 (OCR)  | [VISUAL_FILTER.md](docs/modules/VISUAL_FILTER.md)               |
| **CommitWatcher** | GitHub シークレット検出 | [COMMIT_WATCHER.md](docs/modules/COMMIT_WATCHER.md)             |
| **URLTagging**    | 🆕 URL 分類とタグ付け   | [URL_TAGGING_PIPELINE.md](docs/modules/URL_TAGGING_PIPELINE.md) |

### 攻撃フェーズ (Exploitation)

| モジュール           | 機能                        | 詳細ドキュメント                                            |
| :------------------- | :-------------------------- | :---------------------------------------------------------- |
| **AuthNinja**        | JWT/OAuth/MFA バイパス      | [AUTH_NINJA.md](docs/modules/AUTH_NINJA.md)                 |
| **BizLogicHunter**   | IDOR/権限昇格検証           | [BIZ_LOGIC_HUNTER.md](docs/modules/BIZ_LOGIC_HUNTER.md)     |
| **ProxyLogAnalyzer** | プロキシログ解析/Smell 検出 | [PROXY_LOG_ANALYZER.md](docs/modules/PROXY_LOG_ANALYZER.md) |

### コアインフラ (Core Infrastructure)

| モジュール         | 機能                         | 詳細ドキュメント                                      |
| :----------------- | :--------------------------- | :---------------------------------------------------- |
| **EthicsGuard**    | スコープ強制/レート制限      | [ETHICS_GUARD.md](docs/modules/ETHICS_GUARD.md)       |
| **KnowledgeGraph** | Neo4j 資産・脆弱性グラフ     | [KNOWLEDGE_GRAPH.md](docs/modules/KNOWLEDGE_GRAPH.md) |
| **ContextAwareMC** | KG活用タスク計画 ("High IQ") | `src/core/engine/master_conductor.py`                 |
| **ErrorReplanner** | 自動エラー回復 (403/Timeout) | `src/core/engine/error_replanner.py`                  |
| **PremiumReport**  | Haddix相応レポート生成       | `src/core/agents/specialized/report_refiner_agent.py` |
| **RAGSystem**      | Obsidian ナレッジ連携        | [RAG_SYSTEM.md](docs/modules/RAG_SYSTEM.md)           |
| **ModelRouter**    | LLM コスト最適化             | `config.py`                                           |
| **AgentRegistry**  | 🆕 エージェントタグシステム  | `src/core/engine/agent_registry.py`                   |
| **PIIMasker**      | 🆕 双方向 PII/機密情報マスク | `src/core/security/pii_masker.py`                     |
| **AutoReporter**   | レポート自動生成             | [AUTO_REPORTER.md](docs/modules/AUTO_REPORTER.md)     |

### ワードリスト最適化 (Wordlist Optimization)

| モジュール              | 機能                     | 詳細ドキュメント                                              |
| :---------------------- | :----------------------- | :------------------------------------------------------------ |
| **WordlistManager**     | メタデータベース選択     | [WORDLIST_MANAGER.md](docs/modules/WORDLIST_MANAGER.md)       |
| **WordlistLearner**     | 自動学習・カスタム生成   | [WORDLIST_LEARNER.md](docs/modules/WORDLIST_LEARNER.md)       |
| **GAUIntegrator**       | GAU 統合・パターン抽出   | [GAU_INTEGRATOR.md](docs/modules/GAU_INTEGRATOR.md)           |
| **ProgressiveScanner**  | 段階的スキャン・早期終了 | [PROGRESSIVE_SCANNER.md](docs/modules/PROGRESSIVE_SCANNER.md) |
| **HeadlessCrawler**     | Playwright/SPA 対応      | [HEADLESS_CRAWLER.md](docs/modules/HEADLESS_CRAWLER.md)       |
| **OOBVerifier**         | 🆕 OOB (SSRF/RCE) 検知   | [OOB_HEADLESS.md](docs/specs/2026-01-26_OOB_Headless.md)      |
| **PlaywrightValidator** | 🆕 XSS ブラウザ検証      | [OOB_HEADLESS.md](docs/specs/2026-01-26_OOB_Headless.md)      |

### 高度な攻撃・回避 (Advanced Attacks & Evasion)

| モジュール                  | 機能                                           | ステータス |
| :-------------------------- | :--------------------------------------------- | :--------- |
| **NoSQL/LDAP Injection**    | MongoDB/Redis/LDAP インジェクション            | ✅ New     |
| **Deserialization**         | Java/PHP/Python シリアライズ攻撃               | ✅ New     |
| **Prototype Pollution**     | Client/Server-side Pollution                   | ✅ New     |
| **WAF Mutation Engine**     | 遺伝的アルゴリズムによる WAF 回避              | ✅ New     |
| **Adaptive Adjuster**       | コンテキスト (JSON/XML/SQL) 適応型ペイロード   | ✅ New     |
| **Error Analyzer**          | エラーメッセージからの技術スタック推論         | ✅ New     |
| **JWT Advanced**            | Kid/Alg Confusion/None Attack                  | ✅ New     |
| **GraphQL/Cache/Smuggling** | 高度な API/プロトコル攻撃                      | ✅ New     |
| **Host Header Injection**   | キャッシュポイズニング・パスワードリセット攻撃 | ✅ Phase 3 |

### 自動化・インテリジェンス (Automation & Intelligence)

| モジュール              | 機能                              | ステータス                  |
| :---------------------- | :-------------------------------- | :-------------------------- |
| **FindingsRepository**  | SQLite による脆弱性永続化         | ✅ Phase 1                  |
| **NotificationService** | Telegram/Discord リアルタイム通知 | ✅ Phase 1                  |
| **RetryTracker**        | 適応型ループ停止判断              | ✅ Phase 1                  |
| **InputSanitizer**      | プロンプトインジェクション検出    | ✅ Phase 1                  |
| **ToolProfiles**        | speed/stealth/thorough モード管理 | ✅ Phase 2                  |
| **PhaseManager**        | Recon→Attack→Report フェーズ遷移  | ✅ Phase 2                  |
| **ExploitVerifier**     | 非破壊的 PoC 検証                 | ✅ Phase 3                  |
| **MicroAgent**          | ローカル LLM ツール出力解析       | ✅ Phase 3                  |
| **MicroAgent**          | ローカル LLM ツール出力解析       | ✅ Phase 3                  |
| **SandboxLinuxCmd**     | Docker 隔離環境コマンド実行       | ✅ Phase 3                  |
| **Hybrid Swarm**        | LLM専門家による高度推論           | [AGENTS.md](docs/AGENTS.md) |
| **SecurityGuardrails**  | Unicode ホモグラフ検知・保護      | ✅ Phase 17                 |

---

## 💻 システム要件 (Requirements)

### ハードウェア

| 項目           | 最小要件 | 推奨要件                       |
| :------------- | :------- | :----------------------------- |
| **CPU**        | 2 コア   | 4 コア以上                     |
| **RAM**        | 4GB      | 8GB 以上                       |
| **ストレージ** | 5GB      | 20GB 以上 (ログ・グラフ DB 用) |

### ソフトウェア

| 項目               | バージョン                              |
| :----------------- | :-------------------------------------- |
| **OS**             | Linux (Ubuntu 22.04+), macOS (Ventura+) |
| **Python**         | 3.10 以上                               |
| **Docker**         | 24.0 以上                               |
| **Docker Compose** | v2.0 以上                               |

### オプション依存関係

| 項目                | 用途                     |
| :------------------ | :----------------------- |
| `tesseract-ocr`     | VisualFilter の OCR 機能 |
| `tesseract-ocr-jpn` | 日本語 OCR サポート      |

---

## 🏯 アーキテクチャ (Architecture)

SHIGOKU は、人間のハッカーの思考プロセスを模倣した 3 つの自律レイヤーで構成されています。

```
┌────────────────────────────────────────────────────────────────────────┐
│                           SHIGOKU Architecture                          │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                      USER INTERFACE LAYER                       │   │
│   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │   │
│   │  │  CLI (main.py)│  │ Scope YAML  │  │  Obsidian Vault     │  │   │
│   │  └──────────────┘  └──────────────┘  └──────────────────────┘  │   │
│   └────────────────────────────────────────────────────────────────┘   │
│                                  │                                      │
│                                  ▼                                      │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                      CORE BRAIN LAYER                           │   │
│   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │   │
│   │  │Master Conduc.│  │ EthicsGuard  │  │   RAGSwitch         │  │   │
│   │  │(Orchestrator)│  │(Safety Layer)│  │(Knowledge Retrieval)│  │   │
│   │  └──────────────┘  └──────────────┘  └──────────────────────┘  │   │
│   └────────────────────────────────────────────────────────────────┘   │
│                                  │                                      │
│          ┌───────────────────────┼───────────────────────┐              │
│          ▼                       ▼                       ▼              │
│   ┌─────────────┐         ┌─────────────┐         ┌─────────────┐      │
│   │ INTEL LAYER │         │ACTION LAYER │         │ DATA LAYER  │      │
│   │ (Eyes)      │         │ (Hands)     │         │ (Memory)    │      │
│   │             │         │             │         │             │      │
│   │ Cartographer│         │ AuthNinja   │         │ Neo4j       │      │
│   │ Fingerprint.│         │ BizLogic    │         │ ChromaDB    │      │
│   │ VisualFilter│         │ CommitWatch │         │ Findings    │      │
│   │ ProxyLogAn. │         │ AutoReporter│         │             │      │
│   └─────────────┘         └─────────────┘         └─────────────┘      │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### レイヤー説明

| レイヤー           | 役割                 | 主要コンポーネント                 |
| :----------------- | :------------------- | :--------------------------------- |
| **User Interface** | オペレーターとの接点 | CLI, Scope YAML, Obsidian          |
| **Core Brain**     | 意思決定と安全制御   | Master Conductor, EthicsGuard, RAG |
| **Intel Layer**    | 情報収集と分析       | Cartographer, Fingerprinter, etc.  |
| **Action Layer**   | 攻撃実行とレポート   | AuthNinja, BizLogicHunter, etc.    |
| **Data Layer**     | 永続化と検索         | Neo4j (Knowledge Graph), ChromaDB  |

---

## 📂 プロジェクト構造 (Project Structure)

````
SHIGOKU/
├── src/
│   ├── agents/                 # 攻撃エージェント群
│   │   └── swarm/
│   │       ├── auth_ninja.py       # JWT/OAuth/MFA攻撃
│   │       └── biz_logic_hunter.py # IDOR/権限昇格
│   ├── core/                   # コアモジュール
│   │   ├── infra/                  # インフラ連携
│   │   │   ├── knowledge_graph.py  # Neo4j
│   │   │   └── proxy_rotation.py   # IP回転
│   │   ├── intel/                  # 偵察モジュール
│   │   │   ├── cartographer.py     # サイトマップ
│   │   │   ├── fingerprinter.py    # 技術識別
│   │   │   ├── commit_watcher.py   # Git監視
│   │   │   └── visual_filter.py    # OCR分類
│   │   ├── models/                 # データモデル
│   │   │   └── finding.py          # 脆弱性モデル
│   │   ├── reports/                # レポート生成
│   │   │   └── auto_reporter.py    # 自動レポーター
│   │   ├── security/               # セキュリティ
│   │   │   ├── ethics_guard.py     # スコープ強制
│   │   │   └── scope_parser.py     # YAML解析
│   │   ├── intelligence/           # 🆕 インテリジェンス
│   │   │   ├── risk_predictor.py   # リスクスコアリング
│   │   │   ├── self_reflection.py  # 自己省察
│   │   │   ├── error_analyzer.py   # エラー分析
│   │   │   ├── failure_inference.py # 失敗推論
│   │   │   ├── priority_booster.py # 優先度調整
│   │   │   ├── decision_enhancer.py # 意思決定
│   │   │   └── adaptive_fuzzer.py  # 自己修正Fuzzing
│   │   ├── llm/                    # 🆕 LLM統合
│   │   │   └── local_provider.py   # Ollama統合
│   │   ├── learning/               # 🆕 学習
│   │   │   └── repository.py       # SQLite永続化
│   │   └── rag.py                  # RAGシステム
│   ├── intelligence/           # 分析モジュール
│   │   └── proxy_log_analyzer.py   # プロキシログ解析
│   └── main.py                 # CLI エントリポイント
├── docs/                       # ドキュメント
│   ├── modules/                    # モジュール別詳細ドキュメント
│   ├── QUICK_START.md
│   ├── USER_MANUAL.md
│   ├── TECHNICAL_DESIGN.md
│   └── REFERENCE.md
├── reports/                    # 生成されたレポート
├── scopes/                     # スコープ定義ファイル
├── tests/                      # テストコード
├── docker-compose.yml          # Docker環境定義
├── pyproject.toml              # Python依存関係
└── README.md                   # このファイル

---

## 至極 (SHIGOKU) - Autonomous Bug Bounty Hunter

**極限まで進化した AI 駆動のバグバウンティハンティングシステム**

SHIGOKUは、完全自律型のAIエージェント群による脆弱性発見・報告システムです。

---

## ✨ 主要機能

### 🎯 モード別ハンティング
3つの動作モードで最適な戦略を実行：
- **BugBounty** - 本番環境向け（安全性・品質優先）
- **VulnTest** - テスト環境向け（学習効果最大化）
- **CTF** - 競技向け（速度最優先）

### 🤖 AI エージェント群
- **JWTInspector** - JWT認証バイパス
- **OAuthDancer** - OAuth/OIDC脆弱性検出
- **MFABypasser** - 多要素認証バイパス
- **BizLogicHunter** - ビジネスロジック脆弱性
- **CommitWatcher** - GitHub監視・シークレット検出

### 📊 Dashboard & Reporting
- Web UI（FastAPI + React）
- 脆弱度スコア（10点満点）
- Finding一覧・フィルタリング
- ワンクリックPoC再現（curl/httpie/Python）
- 自動レポート生成（HackerOne形式）

### 🔔 通知システム (Notification System)
- **projectdiscovery/notify** 統合 (Discord/Slack/Telegram等)
- Critical/High脆弱性発見時にリアルタイム通知
- タスク完了時のリッチサマリー (Findings数, 新規資産数)
- CRITICALメンション機能 (`@channel`, `@here`)
- カスタマイズ可能な設定 (`.env`):
  - `SHIGOKU_NOTIFY_ON_TASK_START=false` (デフォルトOFF)
  - `SHIGOKU_NOTIFY_ON_FINDING=true`
  - Critical mention support (`SHIGOKU_NOTIFY_CRITICAL_MENTION`).

- **RAG Engine 2.0**:
  - Implemented **ReAct Observation Loop** in MasterConductor (`_observe_and_rethink`) to discover additional attack vectors from successful tasks.
  - Added **Agentic RAG** capability: `query()` method now accepts `context` (tech stack, etc.) for enhanced retrieval.
  - Added **Critic Feature** to `BizLogicHunter` for self-verification of findings (configurable via `enable_critic`).

### Changed

- **RAG Embedding Model**:
  - Changed default embedding model to `cl-nagoya/ruri-v3-310m` for better Japanese language support.
  - Made embedding model configurable via `RAG_EMBEDDING_MODEL` env var.

### 📤 エクスポート
- JSON/CSV/PDF/Markdown形式
- 統計情報付き

### 📝 ハンティング履歴
- AI思考プロセス記録
- プロジェクト別管理
- 証拠ファイル自動保存

---

## 🚀 クイックスタート

### インストール
```bash
git clone https://github.com/yourusername/shigoku.git
cd shigoku
uv sync --frozen
````

### 基本的な使用方法

```bash
# インタラクティブモード（推奨）- Master Conductor統合
python -m src.main --interactive --mode bugbounty

# 従来モード - プロキシログ解析
python -m src.main --mode bugbounty --log caido.json --scope scope.yaml

# 中断後のセッション再開（NEW）
python -m src.main --resume

# レガシーモード
python -m src.main --legacy --mode vulntest --log caido.json

# CTF競技
python -m src.main --mode ctf --log caido.json

# プロジェクト一覧
python -m src.main --projects
```

**NEW: セッション再開機能**

- プロセス中断（Ctrl+C）後も `--resume` で作業を継続
- タスクキューと実行コンテキストを自動保存
- チェックポイント: 5 タスクごと、エラー時も保存
- 保存ファイル: `session_state.json`

**NEW: インタラクティブモード**

- Master Conductor が対話式でタスクを管理
- モード別の質問に沿ってコンテキストを構築
- 自動プランニング&タスク実行
- 共有ワークスペースで結果を統一管理

### Dashboard 起動

```bash
# バックエンド
cd src/dashboard
python -m uvicorn api.main:app --reload

# フロントエンド
cd src/dashboard/frontend
npm install && npm run dev
```

アクセス: http://localhost:5173

---

## 📁 プロジェクト構造

※ 以下は `workspace/projects/` 配下（ターゲット単位）の構造です。リポジトリ直下のディレクトリ構造ではありません。

```
workspace/projects/
  └── example_com/
      ├── meta.yaml           # プロジェクト情報
      ├── scans/              # スキャン結果
      ├── findings/           # 発見された脆弱性
      ├── reports/            # 生成されたレポート
      ├── hunting_log/        # AI思考ログ
      └── exports/            # エクスポートデータ
```

---

## ⚡ クイックスタート (Quick Start)

### 1. リポジトリのクローン

```bash
git clone https://github.com/your-org/shigoku.git
cd shigoku
```

### 2. Docker 環境の起動

```bash
docker compose up -d
# Neo4j: http://localhost:7474 (Bolt: 7687)
# ChromaDB: http://localhost:8001
```

### 3. Python 環境のセットアップ

```bash
python -m venv .venv
source .venv/bin/activate
uv sync --frozen
```

### 3.1 依存関係の固定運用（推奨）

`uv.lock` に固定された依存関係を使用し、意図しないバージョン更新を防ぐため、セットアップ時は `uv sync --frozen` を使用してください。

```bash
uv sync --frozen
uv run python -c "import importlib.metadata as m; print(m.version('litellm'))"
```

期待値: `1.81.9`

### 4. 最初の偵察

```bash
python -m src.main --recon http://localhost:8888
```

**詳細な手順**: [QUICK_START.md](docs/QUICK_START.md)

---

## 📜 ドキュメント (Documentation)

### 概要ドキュメント

| ドキュメント                                    | 内容                               |
| :---------------------------------------------- | :--------------------------------- |
| [QUICK_START.md](docs/QUICK_START.md)           | 環境構築から最初のスキャンまで     |
| [USER_MANUAL.md](docs/USER_MANUAL.md)           | ワークフロー、RAG 設定、ROI 最適化 |
| [TECHNICAL_DESIGN.md](docs/TECHNICAL_DESIGN.md) | 内部アーキテクチャ、グラフスキーマ |
| [REFERENCE.md](docs/REFERENCE.md)               | 環境変数、設定オプション、制限事項 |
| [REPORT_OUTPUTS.md](docs/REPORT_OUTPUTS.md)     | `--report` の text/haddix/html 出力項目 |

### モジュール別ドキュメント

`docs/modules/` ディレクトリに各モジュールの詳細ドキュメントがあります。

---

## 🗺 ロードマップ (Roadmap)

### Phase 1-2 (完了 ✅)

- [x] コアモジュール実装 (EthicsGuard, RAG, KnowledgeGraph)
- [x] 偵察エージェント (Cartographer, Fingerprinter)
- [x] 攻撃エージェント (AuthNinja, BizLogicHunter)
- [x] レポート自動生成 (AutoReporter)

### Phase 3 (完了 ✅)

- [x] プロジェクトリネーム (DeepHunter → SHIGOKU)
- [x] 包括的なドキュメント整備
- [x] モード別ハンティング (BugBounty/VulnTest/CTF)
- [x] AI エージェントモード認識
- [x] モード別 RAG 連携

### 🛡️ Post-Exploitation & Flag Capture (Phase 4)

- **FlagWatcher** - リアルタイムフラグ検出 (HTTP/Cmd/OOB)
- **Post-Exploit Swarm** - 侵入後の自動調査 (Secrets/Internal Recon/Pivot)
- **Escalation Logic** - 脆弱性発見からの自動自動ポストエクスプロイト移行

---

## 🗺 ロードマップ (Roadmap)

...

- [x] Phase 4 (完了 ✅): 深層攻撃の実装 (Post-Exploitation & Flag Capture)

### Phase 5 (完了 ✅)

- [x] ワードリストメタデータ管理
- [x] ワードリスト自動学習 (WordlistLearner)
- [x] GAU 統合・パターン抽出 (GAUIntegrator)
- [x] 段階的スキャン + 早期終了 (ProgressiveScanner)
- [x] Headless Browser 統合 (HeadlessCrawler/Playwright)

### Phase 6 (完了 ✅)

- [x] URL Tagging Pipeline (Hybrid Discovery & Rule-based Tagging)
- [x] SubdomainEnricher (GAU 新規サブドメイン検出)
- [x] TaggingFilter (Rule-based URL Classification)

### Phase 7 (完了 ✅)

- [x] CORS Tester
- [x] CRLF Injection Tester
- [x] GraphQL Analyzer
- [x] LFI Tester
- [x] Open Redirect Tester
- [x] OpenAPI/Swagger Tester
- [x] Parameter Fuzzer
- [x] SSTI Scanner
- [x] Race Condition Tester
- [x] SSRF Tester
- [x] WebSocket Vulnerability Tester
- [x] XSS Tester
- [x] SSTI Scanner (Template Injection)

### Phase 8 (完了 ✅)

- [x] main.py CLI 統合強化
- [x] RAG CLI (ingest/query/stats)
- [x] DNS History CLI
- [x] 日本語ヘルプ・使用例充実
- [x] RAG Feedback 統合（FP 自動判定）

### Phase 9 (完了 ✅)

- [x] 並列スキャン (ParallelScanner)
- [x] 重複検出 (DuplicateFinder)
- [x] RAG フィードバックループ (rag_feedback.py)
- [x] レポートエクスポート強化

### Phase 10 (完了 ✅)

- [x] アーキテクチャ最適化 (Legacy Code Removal)
- [x] インタラクティブ制御強化 (Ctrl+C Handoff)
- [x] イベント駆動型 Recipe 注入
- [x] 13 種類の黄金レシピ (Golden Recipes)
- [x] サブエージェント強化 (ScopeParser 統合版)

### Phase 11 (Current) ✅

- [x] **Smart Parallel Conductor**: 意思決定依存性（Decision Dependency）を持つ並列タスク実行
- [x] **RTX3060 Specialized Features**:
  - `VisualReconAgent` (LLaVA): コストゼロのスクリーンショット解析
  - `SemanticGrep` (Embeddings): HTTP レスポンスの意味検索
  - `ProxyLogAnalyzer`: LLM によるハイブリッドログランキング
- [x] **Specialized Agents**:
  - `RaceConditionAgent`: 並列リクエスト競合検出
  - `TaintAnalysisAgent`: コンテキスト認識型 XSS 検出
  - `ReportRefinerAgent`: レポート品質向上（衝撃度・重複排除）
- [x] **Interactive RAG**: `/rag` コマンドによる動的制御
- [x] **Self-Healing**: エラー適応型リトライ（WAF バイパス/プロキシ回転）

### Phase 12 (Current) ✅

- [x] **Workflow Refinement**:
  - **Shared Workspace 2.0**: ターゲット別ディレクトリ分離 (`workspace/{target}/`) と上書き防止
  - **Path Propagation**: `BaseAgent` へのパス注入と CoT プロンプト強化
- [x] **Agent Specialization**:
  - `ScopeParserAgent`: スコープ定義の構造化解析
  - `ScopeParserAgent`: スコープ解析 + 技術スタック特定（Fingerprinter 統合）
- [x] **Compliance Verification**: 自動テストによるポリシールール準拠確認

### Phase 13 (Current) ✅

- [x] **Agent Portfolio Optimization**:
  - エージェント数を 20→17 に最適化 (ルーティング精度向上)
  - `FingerprinterAgent` を `ScopeParserAgent` に統合
  - `PrivEscMatrix`, `LateralMovementAgent` を `BizLogicHunter` に統合案内（非推奨化）
  - `VisualReconAgent`, `TriageSimulator` を Recipe 化

### Phase 14 (Current) ✅

- [x] **RAG Engine 2.0**:
  - **ReAct Observation Loop**: MasterConductor が成功タスクから自律的に追加攻撃ベクトルを導出
  - **Agentic RAG**: コンテキスト（技術スタック等）をクエリに自動反映し検索精度向上
  - **BizLogic Critic**: 脆弱性候補の自己検証ループ（False Positive 削減）
  - **High-Performance Embeddings**: `cl-nagoya/ruri-v3-310m` 採用による日本語精度向上

### Phase 15 (Current) ✅

- [x] **Intelligence Module**:
  - **Event-Driven Architecture**: `EventBus`による非同期 MC↔Agent 通信
  - **Local LLM Integration**: Ollama(Qwen3:8b)統合、自動ルーティング
  - **Learning Repository**: SQLite 学習永続化、TTL 管理
  - **Adaptive Rate Limiter**: レート制限自動検知、3 段階ステルスモード
  - **Risk Predictor**: アクションリスクスコアリング、検知確率推定
  - **Self Reflection**: 成功/失敗パターン分析、改善提案生成
  - **Error Analyzer**: エラー分類、根本原因推定
  - **Failure Inference**: 失敗予測、類似失敗検索
  - **Priority Booster**: 動的優先度調整、高価値資産自動検出
  - **Decision Enhancer**: コンテキスト意思決定、WAF 回避提案
  - **Adaptive Fuzzer**: 自己修正ペイロード、成功パターンキャッシュ

### Phase 18 (Current) ✅

- [x] **Unimplemented Features Implementation**:
  - **Progressive Scanner**: Ffuf 統合、JSON パース、動的レート制限
  - **Interactive Bridge**: 対話的タスク実行制御、厳格なリスク緩和策 (Step Limit/Timeout)
  - **Session Hijacker**: Session Fixation 検知、Cookie 属性監査

### Phase 16 (Current) ✅

- [x] **Agent Context Filtering (Phased Visibility)**:
  - **Agent Registry**: エージェント・ツールのタグシステム（50 種エージェント、41 種ツール）
  - **Contextual Filtering**: CTF モード限定で Web タグフィルタリング（コンテキスト 30%削減）
  - **Hallucination Prevention**: 不適切なエージェント選択の防止（例: Crypto 問題で SQLi 誤選択）

### Phase 16 (Current) ✅

- [x] **Agent Context Filtering (Phased Visibility)**:
  - **Agent Registry**: エージェント・ツールのタグシステム（50 種エージェント、41 種ツール）
  - **Contextual Filtering**: CTF モード限定で Web タグフィルタリング（コンテキスト 30%削減）
  - **Hallucination Prevention**: 不適切なエージェント選択の防止（例: Crypto 問題で SQLi 誤選択）
  - **Mode Preservation**: bugbounty/vulntest モードには影響なし

### Phase 17 (Current) ✅

- [x] **Security Guardrails Enhancement**:
  - **Unicode Homograph Detection**: キリル文字等の視覚的類似文字によるインジェクション検知
  - **BaseAgent Integration**: 全エージェントでの統一的な Input/Output 検査（コマンド実行保護）
  - **Strict Output Validation**: ツール実行前の危険コマンド（rm -rf /, Fork Bomb 等）ブロック機能

### 今後の計画

- [ ] クラウド連携 (AWS/GCP/Azure)
- [ ] カスタムエージェント開発フレームワーク
- [ ] パイプライン自動化ツール

---

## 🤝 貢献 (Contributing)

バグ報告、機能リクエスト、プルリクエストを歓迎します。

1. Issue を作成して議論を開始
2. フォークしてブランチを作成
3. 変更をコミット (Conventional Commits 形式)
4. プルリクエストを提出

---

## ⚖️ 免責事項 (Disclaimer)

**SHIGOKU** は、**許可されたセキュリティテストおよびバグバウンティプログラム** での使用を目的とした専門ツールです。

### 法的責任

- 本ツールを使用して、所有権を持たない、または明示的な許可を得ていないシステムに対してスキャンや攻撃を行うことは、**法律で固く禁じられています**。
- オペレーターは、すべての活動が現地の法律およびターゲットプログラムのルールに準拠していることを確認する**全責任**を負います。

### EthicsGuard について

- **EthicsGuard** は安全装置として機能しますが、最終的な法的・倫理的責任はオペレーターにあります。
- EthicsGuard の設定ミスやバイパスによって生じた問題について、開発チームは責任を負いません。

### 保証の否認

本ソフトウェアは「現状有姿」で提供され、明示的または黙示的な保証はありません。開発チームは、本ツールの使用から生じるいかなる損害についても責任を負いません。

---

_(c) 2025 Deepmind Advanced Coding Team. Code with honor._
# SHIGOKU
