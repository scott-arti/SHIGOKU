---
task_id: SGK-2026-0082
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-02-11'
updated_at: '2026-05-19'
---

# Phase 2: Hierarchical Manager Architecture Specification

## 概要

Shigokuのエージェントアーキテクチャを「フラット・手続き型」から「階層型・自律型」へ移行します。
具体的には、LLM駆動のループ（思考→行動→観察）を持つ `BaseManagerAgent` を導入し、
その配下に専門的な `Worker`（従来のSpecialist）を配置する3階層構造を実現します。

## 目的

- **タスク分解の高度化**: 複雑な攻撃シナリオ（例: 「WAFを回避しながらSQLi」）を、単一の手続きでは実現困難な柔軟な思考ループで解決する。
- **コンテキスト管理の効率化**: Managerが大局的な文脈（戦略）を保持し、Workerは局所的なタスク（戦術）に集中することで、LLMのトークン制限とハルシネーションを回避する。
- **並列性とリカバリ**: Managerが複数のWorkerを並列に動かしたり、失敗したWorkerの後に別のWorkerを試すといったリカバリ策を講じることを可能にする。

## アーキテクチャ変更点

### 1. 新しい基底クラス: `BaseManagerAgent`

`SwarmManager` を継承・拡張し、以下の機能を追加します。

- **Thinking Loop**: `dispatch()` メソッドをオーバーライドし、単なるforループではなく、`while not done:` 形式のLLM思考ループに変更します。
- **Tool Use (ReAct)**: `delegate_task(worker_name, params)` や `run_tool(tool_name, args)` といったツールをLLMに提供します。
- **Context Management**: 実行中のタスク状態、発見されたFindings、試行したアクションの履歴を管理します。

### 2. マネージャーとワーカーの構成図

Phase 2では以下の3つの主要Managerを定義し、既存エージェントを配下に置きます。

#### A. `InjectionManager` (SQLi, XSS, SSRF, CMDi)

- **Workers**: `SmartSQLiHunter`, `LLMXSSHunter`, `LLMSSRFHunter`
- **Tools**: `TaintAnalysisAgent` (反射確認用ツールとして利用)

#### B. `AuthManager` (AuthNinja, Session)

- **Workers**: `LLMAuthEscalator` (IDOR/権限昇格)
- **Tools**: `AuthNinja` (JWT/OAuth高速チェック), `SessionHijacker`

#### C. `DiscoveryManager` (Recon, API)

- **Workers**: `VisualRecon`, `GraphQLNavigator`
- **Tools**: `APISpecReconstructor`, `JSMineAgent` (JS解析・機密情報)

#### D. `BizLogicManager` (Logic, Race Condition)

- **Workers**: `BizLogicHunter` (Logic), `RaceConditionAgent`

### 3. プロンプトエンジニアリングトの統合方針 (Phase 2 Roadmap Items)

今回のフェーズではアーキテクチャ基盤を確立し、以下のエージェントも順次統合・強化します。

#### [INTEGRATE] `TriageSimulator`

- **役割**: 発見されたFindingに対し、「バグバウンティでの採択確率」「推定報酬額」を計算するCalculator。
- **配置**: `ReportRefinerAgent` と並列、あるいは `MasterConductor` がFindingを受け取った直後の評価フェーズで呼び出し。

#### [NEW] `ContextDesigner`

- **役割**: ターゲットサイトの「目的」と「守るべき資産 (Crown Jewels)」を定義。
- **実装**: 偵察フェーズ完了後にLLMがサイト概要を分析し、全ManagerのSystem Promptに注入する「戦略テキスト」を生成するモジュール。

#### [ENHANCE] `BizLogicHunter` & `APIFuzzer`

- `BaseManagerAgent` を継承し、各ドメイン（ビジネスロジック、API）の攻撃を統括するManagerに昇格させる。

## 実装計画 (Changes)

### [NEW] `src/core/agents/swarm/base_manager.py`

- LLMクライアントを持ち、CoTループを実行する基底クラス。
- `delegate_to_worker` ツールを実装。

### [NEW] `src/core/agents/swarm/injection/manager.py`

- `BaseManagerAgent` を継承した具象クラス。
- インジェクション攻撃特有の戦略（WAF回避、エンコーディング）を知識として持つ。

### [MODIFY] `src/core/agents/swarm/injection/llm_specialists.py`

- 既存の `LLMSQLiHunter` などを、Managerから呼び出される `Worker` としてリファクタリング。
- 独立して動くエージェントから、入力（パラメータ）を受け取って結果を返す関数的なエージェントへ。

### [NEW] `src/prompts/agents/manager_base.md` & `injection_manager.md`

- Manager用のシステムプロンプトテンプレート。

## 検証計画 (Verification)

### 1. 単体テスト (Unit Test)

- **Tool Call Parsing**: LLMの出力（文字列）から `delegate_task` が正しくパースされるか。
- **Loop Termination**: 解決（Solved）または諦め（Given Up）でループが終了するか。

### 2.統合テスト (Integration Test)

- 擬似的な脆弱性を持つローカルサーバー（またはMock）に対し、`InjectionManager` を実行。
- Managerが「これはSQLiだ」と判断し、`SmartSQLiHunter` を呼び出し、Findingを生成するまでの一連の流れを確認。

## 完了条件

- `InjectionManager` が `SmartSQLiHunter` を適切に呼び出し、SQLi脆弱性を報告できること。
- MasterConductorから `InjectionManager` を呼び出せること。
