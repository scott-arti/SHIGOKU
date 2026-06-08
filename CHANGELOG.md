# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.6.0] - 2026-02-13

### Added

- **Post-Exploitation & Flag Capture (Phase 4)**:
  - **FlagWatcher System**: リアルタイムフラグ検出エンジン。HTTP、コマンド出力、OOBコールバックを監視。
  - **Post-Exploitation Swarm**: 侵入後の内部調査 (`InternalReconWorker`)、シークレット収集 (`SecretLooterWorker`)、ピボット探索 (`PivotWorker`) を実装。
  - **Automated Escalation**: `MasterConductor` が深刻な脆弱性（RCE, SSRF, LFI）を検出した際、自動的にポストエクスプロイトタスクをトリガーする機能を追加。
  - **OOB Flag Detection**: `LocalOOBListener` にフラグ検出フックを統合。

### Fixed

- **CLI / Entry Point**:
  - `main.py` における `await` の構文エラーを修正。
  - `ScopeManager.load` の `AttributeError` を修正。静的メソッドとして再実装し、ファイルとURLの両方をサポート。
  - `main.py` における `settings` 関連の `NameError` を修正。

## [v0.5.1] - 2026-01-26

### Added

- **OOB Detection Integration (Phase 2.2)**:
  - Integrated `LocalOOBListener` and `OOBVerifier` into `InjectionSwarm`.
  - Added `LLMSSRFHunter` for OOB-based SSRF detection.
  - Added `LLMCommandInjectionHunter` for Blind RCE detection using OOB payloads.

- **Headless Browser Verification (Phase 2.3)**:
  - Integrated `PlaywrightValidator` for accurate XSS verification (alert/dialog detection).
  - Added `XSSVerifier` agent/wrapper for browser-based checks.
  - Integrated logic into `PrototypePollutionSpecialist` to escalate and verify potential XSS via browser.

- **Error Handling & Replanning (Phase 1.5)**:
  - Implemented `ErrorReplanner` for automated recovery from network errors (403, 429, Timeout).
  - Integrated with `MasterConductor` to dynamically generate fallback tasks (Proxy Rotation, Delay, Bypass).
  - Supports RAG-based hints for error context analysis.

- **Unit Tests**:
  - Added comprehensive unit tests for `LocalOOBListener` and `PlaywrightValidator`.

## [Unreleased]

### Changed

- **Network Client Integration (Phase 1.3) - 2026-01-26**:
  - Consolidate all agents to use `AsyncNetworkClient` for unified proxy/rate-limiting/logging.
  - `RaceConditionAgent` defaults to `use_proxy=False` for timing accuracy.
  - `VisualReconAgent` uses async client for Ollama API.
  - `ScopeParserAgent` uses async fingerprinting.
  - Swarm Agents (`Auth`, `Injection`, `Discovery`) migrated to `AsyncNetworkClient`.

### Changed

- **Core Network Client Refactor (2026-01-26)**:
  - Replaced `requests` library with `httpx` across all core modules (`AuthNinja`, `BizLogicHunter`, `MultiAccountSessionManager`, `CommitWatcher`, `MicroAgent`).
  - Standardized on asynchronous-compatible `httpx.Client`.
  - Updated error handling from `requests.RequestException` to `httpx.RequestError`.
  - Removed `requests` from project dependencies.

### Added

- **Hybrid Swarm Intelligence (Phase 2 & 3)**: 全SwarmへのLLM専門家統合完了
  - **InjectionSwarm**: `LLMSQLiHunter` (Blind SQLi), `LLMXSSHunter` (Context-aware XSS)
  - **AuthSwarm**: `LLMAuthEscalator` (Privilege Escalation Hypothesis)
  - **DiscoverySwarm**: `LLMSecretScanner` (False Positive Elimination for Secrets)
  - **LogicSwarm**: `LLMBizLogicHunter` (IDOR/BizLogic), `LLMCORSTester`
  - **ScannerSwarm**: `LLMCryptoAnalyzer` (TLS/SSL Compliance & Weakness Analysis)
  - **SecretSwarm**: `LLMCloudMisconfigAnalyzer` (S3/GCS Policy Analysis)

- **E2E Testing Suite**:
  - Added 9 comprehensive E2E tests covering all new LLM specialists.
  - Verification of LLM-based decision making and vulnerability detection.

### Added

- **Knowledge Graph Integration (v0.5.0 - 2026-01-22)**:
  - **Neo4j Backend**: Neo4j Community Editionを統合し、`Asset`, `Endpoint`, `Parameter`, `Technology`, `Finding` をグラフ構造で管理
  - **Context-Aware MasterConductor**: MCがKGから技術スタックや未テストパラメータを取得し、それに基づいて動的にタスクを生成・優先度調整 ("High IQ Hunter")
  - **Premium Reporting**: `ReportRefinerAgent` がKGから生のエビデンス (Curlコマンド, リクエスト/レスポンス) を取得し、Jason Haddixスタイルの再現性の高いレポートを自動生成
  - **Automated Ingestion Pipeline**:
    - `KatanaIngestor`: クロール結果からエンドポイント・技術スタック・パラメータを構築
    - `NucleiIngestor`: スキャン結果から脆弱性情報と詳細メタデータをグラフにアノテーション

### Added

- **URL タグ付けパイプライン E2E (2026-01-19)**:
  - **SubdomainEnricher**: GAU で発見した新サブドメインに WAF/Port コンテキストを自動付与
  - **subdomain_context**: 各エントリに WAF/Port 情報を追加し MC がコンテキスト付きでディスパッチ可能
  - **GAU スコープフィルタ**: URL ホストがターゲットドメインに属するか `urlparse` でチェック
  - **URL サンプリング**: httpx 処理を 50 件に制限（タイムアウト対策）
  - **E2E テスト**: `testphp.vulnweb.com` 対象の統合テスト成功

### Fixed

- **ツールラッパー修正 (2026-01-19)**:
  - `KatanaTool`: `-json` → `-jsonl` フラグ修正（v1.4.0 対応）
  - `KatanaTool`: `-no-sandbox` を headless モード専用に移動
  - `KatanaTool`: 入力に `http://` プレフィックス追加
  - `HttpxTool`: Python httpx との競合回避（Go バイナリパス明示）
  - `HttpxTool`: `-jsonl` → `-json` フラグ修正
  - `TaggingFilter._classify_entry`: deprecated `self.patterns` → `self.rules` に書き換え

- **セッション永続化 (Session Persistence)** (2026-01-14):
  - MasterConductor に `save_session()` / `load_session()` メソッドを実装
  - タスクキュー、完了タスク、実行コンテキストを JSON 形式で保存・復元
  - プロセス中断後も `--resume` フラグで作業を継続可能
  - 自動チェックポイント保存（5 タスクごと、エラー時も保存）
  - 保存場所: `session_state.json`（プロジェクトルート）

### Changed

- **Technology Fingerprinting の最適化** (2026-01-14):
  - 重複していた Phase 3 タスク（Technology Fingerprinting）を削除
  - ReconPipeline の Step 3 に詳細 Fingerprinting ロジックを統合
  - whatweb + ScopeParserAgent による 2 段階解析で精度向上
  - 無駄な HTTP リクエストを削減

### Added

- **双方向 PII マスキング (PII Masker)**:
  - AI API への送信前に PII/機密情報をトークン化してマスク
  - ツール実行時にトークンを元の値に復元
  - 対応パターン: API キー(OpenAI/AWS/GitHub/Slack/Stripe/Google)、JWT、Bearer Token、メール、電話番号(JP)、クレジットカード、IP アドレス、UUID、秘密鍵(RSA/EC)
  - `LLMClient.generate()` / `Agent._execute_tool_wrapper()` に統合
  - 二重マスク防止ロジック搭載

### Fixed

- **Technical Debt Resolution (2026-01-05)**:
  - **FastAPI Blocking I/O**: Changed all file I/O endpoints from `async def` to `def` in `dashboard/api/main.py` to prevent event loop blocking. FastAPI now automatically runs these in thread pool.
  - **Error Handling**: Added debug logging to RAG query errors in `master_conductor.py` (was silently suppressed).
  - **Code Quality**: Removed unused imports in `main.py`, fixed indentation issues, added explicit file encoding (`utf-8`).
  - **Exception Specificity**: Changed broad `except Exception` to `except (json.JSONDecodeError, OSError)` in dashboard API for better error diagnostics.
  - **Logging Best Practices**: Changed f-string logging to lazy `%s` formatting for performance.

### Added

- **Phase 1: Advanced Injection Testers**:
  - `NoSQLInjectionTester`: MongoDB/CouchDB/Redis 向けインジェクション検出
  - `LDAPInjectionTester`: LDAP フィルターバイパス、認証バイパス検出
  - `DeserializationTester`: Java/PHP/Python/Ruby/C#シリアライズデータ検出
  - `PrototypePollutionTester`: Node.js **proto**汚染検出
  - `TimeBasedBlindTester`: 時間ベースブラインドインジェクション検出

- **Phase 2: Payload Evolution Engine**:
  - `WAFPayloadMutator`: 遺伝的アルゴリズム風ペイロード進化
  - `AdaptivePayloadAdjuster`: コンテキスト適応型ペイロード調整
  - `ErrorMessageAnalyzer`: エラーメッセージから技術スタック推測
  - `ParameterSemanticAnalyzer`: パラメータ役割自動推定、攻撃ベクター選択

- **Phase 3: API/Protocol Attacks**:
  - `JWTAttacker`: None Algorithm、KID Manipulation、Algorithm Confusion 攻撃
  - `MassAssignmentTester`: 危険パラメータ注入検出
  - `GraphQLCrafter`: Introspection、DoS（深層ネスト）、バッチ攻撃
  - `SmugglingTester`: HTTP Request Smuggling (CL.TE/TE.CL)
  - `CachePoisoner`: Unkeyed Header 検出、キャッシュバスター生成
  - `GopherTool`: SSRF 用 Gopher ペイロード生成

- **Intelligence Module (Phase 15)**:
  - **Event-Driven Architecture**: `EventBus` による非同期 MC↔Agent 通信
  - **Local LLM Integration**: Ollama(Qwen3:8b)統合、自動ルーティング
  - **Learning Repository**: SQLite 学習永続化、TTL 管理
  - **Adaptive Rate Limiter**: レート制限自動検知、3 段階ステルスモード
  - **Risk Predictor**: アクションリスクスコアリング、検知確率推定
  - **Self Reflection**: 成功/失敗パターン分析、改善提案生成
  - **Error Analyzer**: エラー分類、根本原因推定、対処法提案
  - **Failure Inference**: 失敗予測、類似失敗検索、予防策
  - **Priority Booster**: 動的優先度調整、高価値資産自動検出
  - **Decision Enhancer**: コンテキスト意思決定、WAF 回避提案
  - **Adaptive Fuzzer**: 自己修正ペイロード、成功パターンキャッシュ

- **Notification System (projectdiscovery/notify)**:
  - Integration with `projectdiscovery/notify` for Discord/Slack/Telegram notifications.
  - Configurable notification triggers:
    - `SHIGOKU_NOTIFY_ON_TASK_START` (default: false)
    - `SHIGOKU_NOTIFY_ON_TASK_COMPLETE` (default: true)
    - `SHIGOKU_NOTIFY_ON_FINDING` (default: true)
    - `SHIGOKU_NOTIFY_ON_ERROR` (default: true)
  - Rich summary on task completion (Findings count, New Assets count).
  - Critical mention support (`SHIGOKU_NOTIFY_CRITICAL_MENTION`).

- **RAG Engine 2.0**:
  - Implemented **ReAct Observation Loop** in MasterConductor (`_observe_and_rethink`) to discover additional attack vectors from successful tasks.
  - Added **Agentic RAG** capability: `query()` method now accepts `context` (tech stack, etc.) for enhanced retrieval.
  - Added **Critic Feature** to `BizLogicHunter` for self-verification of findings (configurable via `enable_critic`).
  - Added **RAG Header-Based Chunking**: Markdown files are now split by headers (#, ##, ###) for more precise retrieval chunks.

- **Model Routing & Optimization**:
  - Implemented **Tiered Model Strategy** to optimize costs:
    - **Lightweight Model**: Local LLM (Ollama) or cheaper API for iterative tasks (ReAct, Critic).
    - **High-Performance Model**: GPT-4o for complex planning and final reporting.
  - Added `config.py` settings for model routing (`model_lightweight`, `model_output`).

- **Project Management**:
  - Added `--projects` command to list all managed projects and their last scan status.

### Changed

- **RAG Embedding Model**:
  - Changed default embedding model to `cl-nagoya/ruri-v3-310m` for better Japanese language support.
  - Made embedding model configurable via `RAG_EMBEDDING_MODEL` env var.

- Refactored `src/core/notifications/notifier.py` to use CLI wrapper instead of `requests` library.
- Updated `Dockerfile` to install `projectdiscovery/notify`.

### Phase 16 (2026-01-03) - Feature Expansion ✅

**Added:**

- **Phase 1: Immediate Implementation**:
  - `FindingsRepository`: SQLite-based vulnerability persistence with CRUD operations, search, and statistics
  - `NotificationService`: Real-time/batch notifications via Telegram/Discord integrated with EventBus
  - `RetryTracker`: Adaptive retry threshold calculation and intelligent loop stop decision
  - `AutoReporter` export features: JSON/PDF export with weasyprint integration
  - `InputSanitizer`: Prompt injection detection with risk scoring

- **Phase 2: Mid-term Implementation**:
  - `ToolProfiles`: Tool argument presets (speed/stealth/thorough modes) with context-aware selection
  - `PhaseManager`: Recon→Attack→Report phase transition management with manifest inheritance
  - Cloud Diagnostic Recipe: SSRF-based cloud metadata scanning workflow

- **Phase 3: Optional Features (Toggleable in `config/features.yaml`)**:
  - `FeatureConfig`: Centralized configuration management for Phase 3 features
  - `SandboxLinuxCmd`: Docker-isolated Linux command execution with resource limits
  - `ExploitVerifier`: Non-destructive PoC verification (XSS/SQLi/SSRF)
  - `MicroAgent`: Local LLM (Ollama) tool output analysis
  - `HostHeaderInjectionTester`: Cache poisoning & password reset poisoning detection

### Phase 18 (2026-01-04) - Unimplemented Features Implementation ✅

**Added:**

- **Progressive Scanner (Ffuf Integration)**:
  - Integrated `FfufTool` into `_execute_scan` for high-speed directory fuzzing.
  - Added JSON output parsing (`_parse_ffuf_output`) for reliable results.
  - Configurable `max_requests_per_stage` for rate limiting and risk mitigation.

- **Interactive Bridge (Risk Mitigated)**:
  - Fully implemented `InteractiveBridge._run_execution_loop` for step-by-step user control.
  - Added `MasterConductor` public APIs: `next_task()` and `execute_single_task()`.
  - Implemented critical safeguards: Hard step limit (30), input timeout (300s), fail streak limit (3), and LLM cost control (disable ReAct).

- **Session Hijacker Agent**:
  - Implemented `SessionHijacker` class for detecting session management vulnerabilities.
  - **Session Fixation Detection**: Triple verification of session ID persistence across login.
  - **Cookie Attribute Audit**: Checks for missing HttpOnly, Secure, and SameSite attributes.
  - Integrated with `AuthNinja` factory.

### Phase 17 (2026-01-04) - Security Guardrails ✅

**Added:**

- **Security Guardrails Enhancement**:
  - **Unicode Homograph Detection**: Added normalization and detection for homograph attacks using Cyrillic characters.
  - **BaseAgent Integration**: Integrated `check_input_guardrail` and `check_output_guardrail` into `BaseAgent` for universal protection.
  - **Output Guardrail**: Added strict blocking patterns for dangerous commands (e.g., recursive delete, fork bombs, reverse shells) before tool execution.

**Changed:**

- `AutoReporter.save_report()`: Now automatically saves findings to `FindingsRepository`
- All Phase 3 features are disabled by default and controlled via `config/features.yaml`

**Tests:**

- Added 34 unit tests for Phase 1-3 features (100% pass rate)
- Total test suite: 385 tests passing

---
