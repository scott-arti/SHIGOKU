---
task_id: SGK-2026-0065
doc_type: roadmap
status: active
parent_task_id: SGK-2026-0101
related_docs:
- docs/shigoku/specs/TECHNICAL_SPEC_JA.md
- docs/shigoku/plans/2026-05-14_ssti_docs/shigoku/plans/file_upload_implementation_plan_legacy.md
- docs/shigoku/subtasks/phase1_tasks.md
- docs/shigoku/reports/REPORT_OUTPUTS.md
created_at: '2026-05-19'
updated_at: '2026-06-30'
---

# SHIGOKU 実装ロードマップ

本ドキュメントは、SHIGOKUを「自律型かつ戦略的なセキュリティ診断ツール」へと進化させるための実装フェーズを定義します。
「既存の独立エージェントの整理」と「戦略エンジンの導入」を主軸とし、以下の4フェーズで開発を進めます。

## Phase 1: 足場固めと構造改革 (Swarm化 & 入力正規化) - **Completed**

目的: **「MCが命令しやすく、かつツールが入力（ターゲット）を正しく理解できる状態」** を作る。
独立エージェントを廃止し、Swarm/Worker階層へ完全移行します。

### 1. TargetAssetの実装 (入力の抽象化)

- [ ] **TargetAsset Class**: `src/core/domain/model/target.py`
  - URL/ドメイン/ファイルを統一的に扱うクラス。
  - `TargetType`: WILDCARD_DOMAIN, SINGLE_URL_PUBLIC, INTERNAL, LOCAL_FILE 等の分類ロジック。
- [ ] **ScopeManager Extension**: `src/core/domain/scope/scope_manager.py`
  - `scope.txt` から `TargetAsset` リストを生成するロジックの実装。

### 2. Worker基底クラスの整備

- [ ] **Base Classes**: `src/core/swarm/worker/base.py`
  - 全Workerの共通インターフェース (`BaseWorker`).
- [ ] **ProceduralWorker**: `src/core/swarm/worker/procedural.py`
  - 外部ツール実行 (subprocess) 特化。LLM非依存。
- [ ] **LLMWorker**: `src/core/swarm/worker/llm_worker.py`
  - 推論・コード生成・判断特化。
- [ ] **NetworkClient Wrapper**: `src/core/common/network_client.py`
  - `ProceduralWorker` から呼び出しやすい形への適合。

### 3. 独立エージェントの統廃合 (Migration)

既存の `src/agents/` を解体し、各Swarm配下のWorkerへ移行。

- [ ] **InjectionSwarm**
  - [ ] `TaintAnalysisWorker` (Procedural): `TaintAnalysisAgent` から移行。単純な反射確認。
  - [ ] `GraphQLWorker` (Hybrid): `GraphQLNavigator` から移行。
- [ ] **DiscoverySwarm**
  - [ ] `JSMineWorker` (Procedural): `JSMineAgent` から移行。正規表現マッチング。
  - [ ] `APISpecWorker` (LLM): `APISpecReconstructor` から移行。JS解析と推論。
- [ ] **LogicSwarm**
  - [ ] `RaceConditionWorker` (Procedural): `RaceConditionAgent` から移行。並列リクエスト送信。
- [ ] **IntelligenceSwarm**
  - [ ] `VisualReconWorker` (LLM): `VisualReconAgent` から移行。スクショ解析。
- [ ] **InfrastructureSwarm** (新設)
  - [ ] `PortScanWorker` (Procedural): Nmap/Naabu実行。
  - [ ] `ServiceIdentifyWorker` (LLM): バナー情報からのサービス特定。
  - [ ] `GeneralAgent` 廃止。

### 4. Master Conductor (MC) との連携修正

- [x] **ActionDispatcher Refactor**: `src/core/engine/action_dispatcher.py`
  - [x] 独立エージェント呼び出し分岐 (`if agent_name == ...`) を削除。
  - [x] 全タスクを `SwarmManager.assign_task()` 経由に統一。

---

## Phase 2: 頭脳のアップグレード (MC & Strategy) - **Completed**

目的: 「とりあえずスキャン」ではなく、「状況に応じた最適な戦略」を立案・修正できる指揮官としてのMCを実装する。

### 1. StrategyOptimizer (戦略参謀) の導入

- [x] **StrategyOptimizer Class**: `src/core/engine/strategy_optimizer.py`
  - 資産のROI（重要度）評価ロジック。
  - タスクキューの間引き (Pruning) と優先順位の動的再計算 (Re-prioritization)。
- [x] **TaskQueue の拡張**: `src/core/engine/task_queue.py`
  - 資産ベースのタスク一括削除・優先度ブースト機能の追加。

### 2. モード別思考回路 (Persona)

- [x] **Conductor Prompts**: `src/core/engine/conductor_prompts.py`
  - CTF / Bug Bounty モードに応じたシステムプロンプトの分離定義。
- [x] **MasterConductor Initialization**: モードに応じたプロンプト選択ロジックの実装。

### 3. 戦略的メインループ (Strategic Loop)

- [x] **MC Main Loop Refactor**:
  - 「戦略フェーズ」→「計画フェーズ」→「実行フェーズ」の3段階サイクルへの移行。
  - 定期的な「作戦会議（Strategy Review）」の組み込み。

---

## Phase 3: 調査プロセスのパイプライン化 (Adaptive Recon) - **Completed**

目的: 柔軟かつ効率的な偵察プロセスの確立。MCが始動する前に「良質な燃料（資産情報）」を供給する。

### 1. Adaptive Recon Pipeline (`src/core/recon/`)

- [x] **ReconOrchestrator**: ターゲットの種類とモードに基づき、適切なレシピを選択・実行する。
- [x] **ReconRecipeFactory**: 7つの偵察パターン（レシピ）の生成。
- [x] **BaseReconRecipe & Concrete Recipes**: 7パターンの実装完了。
- [x] **Fast Phase vs Deep Phase**: 並走実行モデルの導入。

### 2. main.py への統合

- [x] **Orchestrator Integration**: MC起動前の初動偵察（Fast Phase）の実装。

---

## Phase 4: 深層攻撃の実装 (Post-Exploitation & Flag Capture) - **Completed**

目的: **「侵入後の価値を最大化し、CTFにおける自動フラグ獲得を実現する」**。

- [x] **FlagWatcher System**:
  - [x] `src/core/engine/flag_watcher.py`: リアルタイム監視エンジン (Singleton)。
  - [x] 統合: `NetworkClient`, `ProceduralWorker`, `LocalOOBListener` へのフック追加。
- [x] **Post-Exploitation Swarm Implementation**:
  - [x] `InternalReconWorker`: システム情報、ネットワーク、プロセスの調査。
  - [x] `SecretLooterWorker`: 環境変数、設定ファイル、SSHキー、.bash_history からの機密情報収集。
  - [x] `PivotWorker`: 内部ネットワークへのさらなる探索。
- [x] **Master Conductor Escalation Logic**:
  - [x] 脆弱性検知時の自動トリガー (`_trigger_post_exploit`).
  - [x] RoE に基づく制御 (`allow_post_exploit` 設定)。

---

## Phase 5: 連携と報告の高度化 (Advanced Integration) - **Next Focus**

目的: **「外部ツールとのシームレスな連携と、決定打となるレポートの生成」**。

- [ ] **External API Integration**:
  - [ ] HackerOne/Bugcrowd API によるプログラム情報同期。
  - [ ] Caido API 経由の直接攻撃指示。
- [ ] **Advanced Visualization**:
  - [ ] 攻撃パスのグラフ化 (Neo4j -> UI)。
  - [ ] リアルタイム・タイムライン・ダッシュボード。

### 次期Ver.メモ

- `HackerOne/Bugcrowd API` は次期Ver.で扱う。
- `Caido API` も次期Ver.で扱う。
- `Replay / HITL 通知` は同じく次期Ver.の運用改善テーマとして扱う。
- `VisualReconWorker` は継続候補だが、今回の判断では次期Ver.送りとする。
- 関連計画:
  - [2026-06-20_sgk-2026-0280_reauth_subtask_plan.md](../subtasks/done/2026-06-20_sgk-2026-0280_reauth_subtask_plan.md)
  - <!-- [REMOVED: target not found] -->

目的: 侵入後の価値最大化と、CTFにおける勝利条件の自動達成。

### 1. CTF Flag 監視システム (FlagWatcher)

- [ ] **FlagWatcher Core**: `src/core/engine/flag_watcher.py`
  - レスポンスや出力からのフラグ自動検知とMC停止フック。
- [ ] **Integration Hooks**:
  - `NetworkClient` (HTTP Response), `ProceduralWorker` (Command Output), `InteractionServer` (OOB).

### 2. Post-Exploitation Swarm (`src/core/swarm/post_exploit/`)

- [ ] **InternalReconWorker**: RCE/LFI後の内部情報収集。
- [ ] **ShellStabilizerWorker**: シェルのアップグレード。
- [ ] **PivotWorker**: SSRFや侵入先経由の内部ネットワークスキャン。
- [ ] **SecretLooterWorker**: 認証情報や機密ファイルの探索。

### 3. Master Conductor (MC) Trigger Mechanism

- [ ] **Finding Event Listener**: 脆弱性発見イベントのハンドリング。
- [ ] **Automatic Escalation**: 致命的脆弱性発見時に自動でPost-Exploitタスクを割り込ませるロジック。
