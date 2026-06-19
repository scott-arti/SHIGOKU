---
task_id: SGK-2026-0145
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Phase 1: 足場固めと構造改革 (Swarm化 & 入力正規化) 詳細仕様書

**Status**: Planning
**Author**: Antigravity
**Based on**: User Request (2026-02-12)

## 1. 目的とスコープ

**目的:**

- **入力ターゲットの抽象化**: URL文字列だけでなく、ドメイン、ローカルファイルパスなどを統一的に扱うための `TargetAsset` クラスを導入する。
- **独立エージェントの廃止**: `src/agents/` 以下の独立エージェント（`TaintAnalysisAgent` など）を解体し、Swarm配下の `Worker` として再定義する。これにより「Manager-Worker」階層型アーキテクチャへの完全移行を行う。
- **LLM依存の低減**: 手続き的な処理（単純なツール実行やパターンマッチング）を行う `ProceduralWorker` と、高度な判断を行う `LLMWorker` を明確に分離し、高速化と安定化を図る。

**影響範囲:**

- `src/core/domain/`
- `src/core/swarm/`
- `src/agents/` (削除・移動)
- `src/core/engine/action_dispatcher.py`

---

## 2. 実装詳細: TargetAsset (ターゲット資産管理)

URLリスト管理を廃止し、属性を持つ資産オブジェクトとして管理します。
BBモードとCTFモードの入力を統一的に扱います。

### 2.1 クラス設計: `TargetAsset`

**配置:** `src/core/domain/model/target.py`

#### 要件

- `TargetType` Enumの実装: `WILDCARD_DOMAIN`, `SINGLE_URL_PUBLIC`, `SINGLE_URL_INTERNAL`, `LOCAL_FILE`, `LOCAL_DIR`
- `TargetAsset` Dataclass:
  - `raw_input`: 元の入力文字列
  - `asset_type`: `TargetType`
  - `priority`: 優先度
  - `metadata`: 任意のメタデータ (Flag形式など)
- ファクトリメソッド `create(input_str, config)`:
  - 文字列からタイプを自動判定する `_classify` ロジックを内包。
  - Internal/Public判定 (`_is_internal`) を含む。

### 2.2 ScopeManager の改修

**配置:** `src/core/domain/scope/scope_manager.py`

#### 要件

- `scope.txt` を読み込み、`TargetAsset` のリストとして保持する。
- 既存の除外リストロジックもここに集約して適用する。

---

## 3. 実装詳細: Worker基底クラスの分離

### 3.1 基底クラス: `BaseWorker`

**配置:** `src/core/swarm/worker/base.py`

#### 要件

- 全Workerが継承する抽象基底クラス。
- `execute(task: Task) -> TaskResult` メソッドを定義。

### 3.2 手続き型Worker: `ProceduralWorker`

**配置:** `src/core/swarm/worker/procedural.py`

#### 要件

- 外部ツール（subprocess）実行ラッパーとしての機能。
- **LLMを使用しない**。
- `run_command(cmd_list, timeout)`: コマンド実行と出力キャプチャ。
- `parse_output(output)`: ツール出力を `Findings` 等に変換。

### 3.3 自律型Worker: `LLMWorker`

**配置:** `src/core/swarm/worker/llm_worker.py`

#### 要件

- `LLMEngine` へのアクセス権を持つ。
- `think(context)`: 次のアクションを推論。
- `verify(result)`: 攻撃成功判定。

---

## 4. 実装詳細: 独立エージェントの統廃合 (Migration Plan)

既存の `src/agents/*.py` を廃止し、対応するSwarmの `workers/` ディレクトリへ移行します。

### 4.1 移行マッピング

1.  **InjectionSwarm**
    - `TaintAnalysisAgent` -> **`TaintAnalysisWorker`** (Procedural): カナリア値の反射確認のみ。LLM判断排除。
    - `GraphQLNavigator` -> **`GraphQLWorker`** (Hybrid): Introspection (Procedural) + Query構築 (LLM)。

2.  **DiscoverySwarm**
    - `JSMineAgent` -> **`JSMineWorker`** (Procedural): JSファイル内の正規表現マッチング (LinkFinder相当)。
    - `APISpecReconstructor` -> **`APISpecWorker`** (LLM): JSコードからのAPI仕様推論。

3.  **LogicSwarm**
    - `RaceConditionAgent` -> **`RaceConditionWorker`** (Procedural): 並列リクエスト送信特化。

4.  **IntelligenceSwarm**
    - `VisualReconAgent` -> **`VisualReconWorker`** (LLM): スクリーンショット解析。

5.  **InfrastructureSwarm (新設)** (`src/core/swarm/infrastructure/`)
    - `GeneralAgent` (廃止) の機能を分割移譲。
    - **`PortScanWorker`** (Procedural): `nmap`/`naabu` 実行。
    - **`ServiceIdentifyWorker`** (LLM): バナー情報からのサービス特定。

---

## 5. Master Conductor (MC) との連携修正

### 5.1 `ActionDispatcher` の修正

**配置:** `src/core/engine/action_dispatcher.py` (または該当箇所)

#### 要件

- `dispatch_task` メソッド内の `if agent_name == "TaintAnalysisAgent":` 等のハードコードされた分岐を削除。
- `target_swarm = self.swarm_router.get_swarm_for_task(task.category)` でSwarmを取得し、`swarm.assign_task(task)` に委譲するフローに統一。

---

## 6. Development Step Plan

1.  **Domain Domain**: `TargetAsset` と `TargetType` の実装と単体テスト。
2.  **Worker Core**: `BaseWorker`, `ProceduralWorker`, `LLMWorker` の実装。
3.  **Migration (Incremental)**:
    - まず `TaintAnalysisWorker` を作成し、`InjectionSwarm` に組み込む。
    - 順次、他のエージェントを移行。
4.  **Cleanup**: `ActionDispatcher` の分岐削除と統合テスト。
