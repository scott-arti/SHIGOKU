---
task_id: SGK-2026-0004
doc_type: manual
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# SHIGOKU アーキテクチャ Q&A (2025.12)

現在のコードベース調査に基づく、SHIGOKU のサブエージェント、ツール構成、およびオーケストレーションに関する現状と仕様のまとめです。

## 1. エージェント構成 (Agents)

### Q. 仕様書と現在の実装にギャップはありますか？

**A. はい、明確なギャップが存在します。**

- **自律性の不足:** 多くのサブエージェント（特に Specialized 系）はクラスが存在するものの、中身は汎用 Agent の継承のみで、固有のロジックが未実装です。
- **柔軟性の不足:** MasterConductor の動的プランニングが失敗した際、固定されたフェーズ（Scope -> Recon -> Fingerprint）へのフォールバックがハードコードされており、状況に応じた柔軟な対応ができていません。

### Q. 現在どのようなサブエージェントが存在しますか？

| カテゴリ         | エージェント名           | 役割・特徴                                                | 状態                                |
| :--------------- | :----------------------- | :-------------------------------------------------------- | :---------------------------------- |
| **Core** (汎用)  | **SecurityBot**          | 汎用セキュリティアドバイザー (BaseAgent)                  | 稼働中                              |
|                  | **ReconBot**             | CLI ツール(ffuf, meg 等)を使用する偵察担当 (CommandAgent) | 稼働中                              |
|                  | **RedTeamBot**           | Python コード実行による攻撃担当 (CodeAgent)               | 稼働中                              |
|                  | **ThoughtAgent**         | 推論・ルーティングを行う Router Agent                     | **非推奨** (MasterConductor に統合) |
| **Swarm** (専門) | **AuthNinja**            | 認証攻撃担当 (JWTInspector, OAuthDancer, MFABypasser)     | 稼働中                              |
|                  | **BizLogicHunter**       | IDOR/権限昇格 + 決済ロジック検出                          | 稼働中                              |
| **Specialized**  | **ScopeParserAgent**     | スコープ解析 + 技術スタック特定 (Fingerprinter 統合)      | 稼働中                              |
|                  | **RaceConditionAgent**   | 並列リクエスト競合検出                                    | 稼働中                              |
|                  | **TaintAnalysisAgent**   | XSS/SQLi コンテキスト検出                                 | 稼働中                              |
|                  | **ReportRefinerAgent**   | レポート品質向上 + Secret 誤検知除去                      | 稼働中                              |
|                  | **APISpecReconstructor** | JS 解析による Shadow API 発見                             | 稼働中                              |
|                  | **JSMineAgent**          | JS 内 Secret/ロジック抽出                                 | 稼働中                              |
|                  | **GraphQLNavigator**     | GraphQL 偵察・脆弱性検査                                  | 稼働中                              |

### Q. ThoughtAgent (Router) の現状は？

**A. 「プレースホルダー」的な状態です。**
プロンプトによる役割定義（「あなたは Router です」）はなされていますが、複雑なルーティング判断ロジックや、エラー時の高度な自己反省（Self-Reflection）ループといった自律的な振る舞いはまだコード化されていません。AgentFactory には存在しますが、MasterConductor からの積極的な活用フローも確立されていません。

## 2. ツール構成 (Tools)

### Q. ツールのカテゴリ構成は？

ご認識の通り、以下の 3 カテゴリで構成されています。

1.  **Command Line Tools (CLI ラッパー)**
    - `nmap`, `ffuf`, `meg` など。
    - AI はこれらを `LinuxCmd` や専用ラッパー ([src/tools/builtin/ffuf.py](file:///home/bbb/Documents/App/Shigoku/src/tools/custom/ffuf.py)) を通じて利用します。
2.  **Integrated Tools (統合ツール)**
    - [Nuclei](file:///home/bbb/Documents/App/Shigoku/src/core/tools/nuclei_integrator.py#28-41): Python コード ([src/core/tools/nuclei_integrator.py](file:///home/bbb/Documents/App/Shigoku/src/core/tools/nuclei_integrator.py)) として深く統合され、実行から結果パースまで自動化されています。
3.  **Developed Tools (独自開発)**
    - [AdaptiveRateLimiter](file:///home/bbb/Documents/App/Shigoku/src/core/engine/adaptive_rate_limiter.py#26-157): 429 エラーを検知して動的にリクエスト速度を調整します。
    - **Cloud Enum / ScoutSuite**: S3 バケット等の設定ミスを検知（外部 OSS ツール統合）。

### Q. ツールは誰が持ち、どう呼び出されますか？

- **所有:** 各エージェント（Sub-Agent）が自身の役割に必要なツールリスト ([tools](file:///home/bbb/Documents/App/Shigoku/src/core/factory.py#L14)) を保持しています。
- **呼び出し:** LLM の **Tool Calling (Function Calling)** 機能を使用します。MasterConductor はタスクを指示するだけで、具体的なツールの選択と実行はサブエージェントが行います。

### Q. 新しいツール (例: amass) を追加するには？

1.  **登録:** [src/core/tool_registry.py](file:///home/bbb/Documents/App/Shigoku/src/core/tool_registry.py) に [ToolInfo](file:///home/bbb/Documents/App/Shigoku/src/core/tool_registry.py#14-23) を追加してカタログ登録します。
2.  **装備:** [AgentFactory](file:///home/bbb/Documents/App/Shigoku/src/core/factory.py#9-112) で、`ReconBot` などの使用させたいエージェントの初期化パラメータ (`tools=[...]`) にそのツールクラスを追加します。
    - 汎用の `LinuxCmd` 経由であればツールクラスなしでも実行可能ですが、安全性と使いやすさのために専用ラッパークラスを作成することが推奨されます。

## 3. オーケストレーション (Orchestration)

### Q. 全体の指揮系統はどうなっていますか？

1.  **Head (MasterConductor):**
    - **役割:** 作戦立案と人員配置。
    - **動作:** ゴールをタスクに分解し、「次は偵察(ReconBot)」「次は攻撃(AuthNinja)」とエージェントを指名（Dispatch）します。Handoff コンテキストを管理します。
2.  **Arms (Core Agents):**
    - **役割:** 現場実行。
    - **動作:** 指示されたタスクに対し、持っているツールを駆使して実行し、結果を返します。
3.  **Specialists (Swarm Agents):**
    - **役割:** 特定領域の深掘り。
    - **動作:** 認証バイパスやロジック攻撃など、高度な専門タスクを実行します。

### Q. 「MasterConductor の Fallback 問題」とは？

LLM による動的プランニングが失敗した際、**常に「Scope 確認 -> 偵察 -> 技術特定」という固定フローに戻ってしまう**仕様のことです。
これにより、途中再開やターゲット特性に合わせた柔軟な（偵察をスキップしていきなり攻撃するなど）対応ができず、柔軟性を損なっています。

## 4. プリセットとレシピ (Presets & Recipes)

### Q. 「ツールの組み合わせプリセット」機能はありますか？

**A. はい、[RecipeLoader](file:///home/bbb/Documents/App/Shigoku/src/core/engine/recipe_loader.py#42-283) として実装されています。**
([src/core/engine/recipe_loader.py](file:///home/bbb/Documents/App/Shigoku/src/core/engine/recipe_loader.py))

- **機能:** YAML ファイル (`recipes/*.yaml`) に定義された「ツール実行手順」を読み込みます。
- **動作:** MasterConductor はコンテキスト（例: "auth=jwt"）にマッチするレシピ（例: `jwt_alg_none.yaml`）を見つけると、それを具体的なタスクリストに展開して実行計画に組み込みます。
- **補足:** [AdaptiveRateLimiter](file:///home/bbb/Documents/App/Shigoku/src/core/engine/adaptive_rate_limiter.py#26-157) にも、スキャン強度に応じた速度設定のプリセット (`intel_passive`, `attack_auth` 等) が存在します。
