---
task_id: SGK-2026-0083
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-02-12'
updated_at: '2026-07-02'
---

# Phase 1: 足場固めと構造改革 (Swarm化 & 入力正規化) 仕様書

**Target**: `docs/IMPLEMENTATION_ROADMAP.md` Phase 1
**Date**: 2026-02-12
**Author**: Antigravity

## 1. 概要

SHIGOKUのアーキテクチャを「独立エージェント型」から「Swarm/Worker階層型」へ移行し、入力ターゲットの取り扱いを統一するためのリファクタリングを実施します。
これにより、MCがより柔軟に戦略を立案できるようになり、ツールの実行効率が向上します。

## 2. 変更内容

### 2.1 TargetAsset (入力の抽象化)

- **ファイル:** `src/core/domain/model/target.py` (新規作成)
  - `TargetType` Enum: `WILDCARD_DOMAIN`, `SINGLE_URL_PUBLIC`, `SINGLE_URL_INTERNAL`, `LOCAL_FILE`
  - `TargetAsset` Dataclass: `raw_input`, `asset_type`, `priority`, `metadata`
  - `create(input_str)` ファクトリメソッド: URL解析とInternal判定ロジックを実装。
- **ファイル:** `src/core/domain/scope/scope_manager.py` (改修)
  - `scope.txt` を読み込み、`List[TargetAsset]` を生成する機能を追加。
  - 除外リストの適用ロジックを集約。

### 2.2 Worker基盤 (実行エンジンの刷新)

- **ファイル:** `src/core/swarm/worker/base.py` (新規作成)
  - `BaseWorker` 抽象基底クラス。
- **ファイル:** `src/core/swarm/worker/procedural.py` (新規作成)
  - `ProceduralWorker`: 外部ツール (subprocess) 実行ラッパー。
  - `run_command(cmd, timeout)`: コマンド実行と出力キャプチャ。
- **ファイル:** `src/core/swarm/worker/llm_worker.py` (新規作成)
  - `LLMWorker`: `think`, `verify` メソッドを持つ自律型Worker。

### 2.3 エージェント移行 (Migration)

以下の独立エージェントを廃止し、対応するSwarm配下のWorkerへ移行します。

| 旧 (Independent)       | 新 (Worker)                                | 所属Swarm             | タイプ           |
| :--------------------- | :----------------------------------------- | :-------------------- | :--------------- |
| `TaintAnalysisAgent`   | `TaintAnalysisWorker`                      | `InjectionSwarm`      | Procedural       |
| `GraphQLNavigator`     | `GraphQLWorker`                            | `InjectionSwarm`      | Hybrid           |
| `JSMineAgent`          | `JSMineWorker`                             | `DiscoverySwarm`      | Procedural       |
| `APISpecReconstructor` | `APISpecWorker`                            | `DiscoverySwarm`      | LLM              |
| `RaceConditionAgent`   | `RaceConditionWorker`                      | `LogicSwarm`          | Procedural       |
| `VisualReconAgent`     | `VisualReconWorker`                        | `IntelligenceSwarm`   | LLM              |
| `GeneralAgent` (廃止)  | `PortScanWorker` / `ServiceIdentifyWorker` | `InfrastructureSwarm` | Procedural / LLM |

### 2.4 MC連携修正

- **ファイル:** `src/core/engine/action_dispatcher.py` / `master_conductor.py`
  - ハードコードされたエージェント分岐を削除し、`SwarmManager` への委譲に統一。

## 3. Verification (検証計画)

### 3.1 単体テスト (Pytest)

- **TargetAsset**:
  - `test_target_asset_creation`: 様々なURL/ファイルパスを入力し、正しい `TargetType` が判定されること。
  - `test_internal_detection`: `localhost`, `192.168.1.1` 等が `INTERNAL` と判定されること。
- **Worker**:
  - `test_procedural_worker_run`: `echo hello` 等のコマンドを実行し、標準出力を正しく取得できること。

### 3.2 統合テスト (E2E simulation)

- **Migration Verification**:
  - `python -m src.main --target http://example.com --mode bugbounty` を実行し、エラーなく起動すること。
  - ログに `InjectionSwarm` や `TaintAnalysisWorker` がロードされた形跡があること。
