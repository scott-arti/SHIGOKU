---
task_id: SGK-2026-0413
doc_type: plan
status: done
parent_task_id: null
related_docs:
- src/core/engine/master_conductor.py
- src/core/engine/lane_policy.py
- src/core/engine/parallel_orchestrator.py
- src/core/domain/model/task.py
- tests/unit/engine/test_lane_policy.py
- tests/core/engine/test_master_conductor_phase5_parallelism.py
- tests/core/engine/test_master_conductor_execution_admission.py
- workspace/projects/localhost:3000/sessions/session_20260731_145535.json
- docs/shigoku/reports/2026-07-31_sgk-2026-0413_execution-pipeline-dependency-admission-consistency_work_report.md
- docs/shigoku/worklogs/2026-07-31_sgk-2026-0413_execution-pipeline-dependency-admission-consistency_work_log.md
title: 探索・実行判定・カバー率ガードの依存整合性修正
created_at: '2026-07-31'
updated_at: '2026-08-07'
tags:
- shigoku
target: MasterConductor execution workflow
---

# 実装計画書：探索・実行判定・カバー率ガードの依存整合性修正

## 1. 達成したいゴール（ユーザー視点）

- [x] SHIGOKUでWebアプリを診断すると、対象確認、探索、攻撃、報告が正しい順序で実行されること。
- [x] 探索タスクが安全判定の食い違いで実行前に失われず、発見したURL・API・入力面を後続の攻撃タスクへ渡せること。
- [x] 実行できなかったタスクは理由付きで記録され、未完了（`pending`）のまま正常完了にならないこと。
- [x] 特定の製品・URL形式・既知脆弱性に依存せず、DVWA、SPA、一般のWebアプリに共通して適用できること。

## 2. 全体像とアーキテクチャ

### 2.1 現在の問題

`session_20260731_145535.json` では、探索タスク `task_002` は選択済みであるにもかかわらず実行記録を持たず、`pending` のまま保存された。現在は、以下の二重判定が矛盾している。

- `LanePolicy` は `recon_master` を、並列実行できるレート制限付き探索として分類する。
- `ParallelOrchestrator` は実行カテゴリに `agent_type` を渡し、厳格カテゴリゲートが未登録の `recon_master` を実行前に拒否する。
- 拒否されたタスクは結果配列に入らないため、実行ループが終了済みとして扱う。

また、実行ループは探索完了を待たず、優先度の高いカバー率用タスクを投入する。そのため、入力面が未発見のトップページに対する検査が先行する。

### 2.2 目標とするデータの流れ

```text
Scope Verification (成功)
        ↓ 明示的依存
Reconnaissance (成功または理由付き終了)
        ↓ 攻撃フェーズの解放 + 発見結果
Attack task generation / coverage guard
        ↓
Evidence-based reporting
```

探索、攻撃、報告の各段階で、選択済みタスクは必ず終端状態（`success`、`failed`、`skipped`、`replanned`）になる。`parent_id` は従来どおり表示・追跡用の関係として残し、実行順序は `depends_on_task_ids` で明示する。

### 2.3 対象コンポーネント

- `src/core/engine/lane_policy.py`: 実行レーン、レート制限、並列実行カテゴリを一つの実行契約として解決する。
- `src/core/engine/parallel_orchestrator.py`: 解決済みの並列実行カテゴリだけを受け、既存の同時実行数・レート制限を適用する。
- `src/core/engine/master_conductor.py`: 依存待機、攻撃フェーズ確認、拒否タスクの終端化、完了判定を行う。
- `src/core/domain/model/task.py`: 既存スキーマを壊さず、加算的な実行契約メタデータを保持する。
- `tests/unit/engine/test_lane_policy.py`、`tests/unit/engine/test_parallel_orchestrator.py`、`tests/core/engine/test_master_conductor_phase5_parallelism.py`、`tests/core/engine/test_master_conductor_scenario_probes.py`、新規の実行順序テスト: 回帰を防ぐ。

## 3. 具体的な仕様と制約条件

### 3.1 実行契約

- `agent_type` は担当実装の名前、`execution_category` は並列実行の資源分類として分離する。脆弱性分類に使う既存の `params["category"]` は再利用しない。
- 実行カテゴリは `LanePolicy` の結果から解決し、許可済みカテゴリ（例: レート制限付き探索なら `intel_active`）だけを `ParallelOrchestrator` へ渡す。
- 明示した `execution_category` は許可リストで検証する。未知のエージェントを並列実行へ昇格させず、従来どおり逐次実行する。
- `recon_master` には探索フェーズと `scope` 成功への明示的依存を付与する。

### 3.2 依存・フェーズ制御

- バッチ作成時は、依存先が成功していないタスクを取り出さず、キューに残す。
- 依存先が失敗・スキップ・再計画済みで実行不能な場合、子タスクを理由コード付き `skipped` として終端化する。循環依存や存在しない依存先も同様に明示する。
- カバー率用のXSS、CSRF、OOBタスクは、`PhaseGate` が攻撃フェーズを解放した後にのみ投入する。探索結果がないことを、攻撃済み・安全とみなさない。
- インポート済み探索成果物や既存の構造化攻撃対象が攻撃フェーズを正当に解放する経路は維持する。

### 3.3 拒否と完了の記録

- 実行カテゴリ、依存、スコープ、安全ポリシーで拒否されたタスクは、`TaskState.SKIPPED`、理由コード、監査用の実行記録を持つ。
- バッチ実行後に終端状態でない選択済みタスクを検出した場合は、内部制御エラーとして終端化し、通常完了メッセージを出さない。
- 既存のサマリー項目とCLIの互換性は維持しつつ、必須タスクが未完了なら加算的な `completion_status: incomplete` を記録する。

### 3.4 非目標と安全制約

- Juice Shop、DVWA、特定のSPAルート、既知の脆弱性を判定条件に追加しない。
- 対象範囲、認証、人手確認、レート制限、タイムアウト、攻撃性の既存ポリシーを緩和しない。
- 報告・セッションの既存フィールドを削除、改名、転用しない。必要な情報はメタデータと理由コードとして追加する。
- ネットワークを必要とする実ターゲット再実行は、本実装の単体・結合テストが通った後に、利用者の明示指示がある場合のみ行う。

## 4. 実装ステップ（AIに指示する手順）

- [x] ステップ1: 現在の `LanePolicy` と `ParallelOrchestrator` の二重分類を棚卸しし、実行レーン・レート制限・`execution_category` を返す小さな共通解決処理を追加する。既存のレーン判定、レート制限、未知エージェントの逐次実行は維持する。
- [x] ステップ2: `MasterConductor` の初期計画で、探索タスクを `recon` フェーズに設定し、`task_001` への `depends_on_task_ids` を明示する。選択処理に依存待機・依存失敗の終端化を追加する。`parent_id` の既存の表示・追跡の意味は変更しない。
- [x] ステップ3: 並列実行への引き渡しで `agent_type` ではなく解決済み `execution_category` を使用する。入場拒否は結果・理由コード・終端状態として集計し、`pending` のままの選択済みタスクを残さない。
- [x] ステップ4: カバー率用ガードの投入を `PhaseGate` の攻撃フェーズ解放後に限定する。探索済みの攻撃面が存在する通常経路、インポート済み成果物、構造化攻撃対象の既存経路をテストで保護する。
- [x] ステップ5: 実行終了時に必須タスクの未完了を検査し、従来のサマリーを保ったまま `completion_status` と理由コードを追加する。必須探索が未完了なら「正常完了」と表示しない。
- [x] ステップ6: 以下のTDD順序で検証する。
  - `recon_master` が安全ゲートを通過し、既定の探索カテゴリと既存のレート制限で実行される。
  - scope → recon → attack の順序を守り、探索前にカバー率用攻撃タスクを投入しない。
  - 拒否・依存不成立・循環依存の各ケースで、タスクが理由付き終端状態になり、セッションに残る。
  - 既存のDVWA向け信号ルーティングと一般的なSPA/APIの模擬探索結果のどちらも、探索後に攻撃タスクを生成できる。
  - 既存のPhase 5/7、シナリオプローブ、タスク直列化のテストを実行し、対象外の並列化や攻撃性の増加がないことを確認する。
- [x] ステップ7: 対象テスト後に関連テスト群を実行し、実装差分、セッション出力、`graphify update .` を確認する。完了時には作業報告書・作業ログ・台帳を更新し、`sync_shigoku_updated_at.py` と `validate_shigoku_docs.py` を実行する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）

- [ ] [重要度:中] 実行キューはこれまで `parent_id` を実行依存として扱っていない。今回対象にする初期探索の明示的依存以外の親子タスクを一括で依存化すると、既存の並列処理を変えるおそれがある。今回の完了後、実行依存が必要な動的タスクの棚卸しを別タスクとして起票する。
- [ ] [重要度:低] セッション内のRun Ledger本体が空でスプールだけが残る場合がある。これは今回の実行拒否の根本原因ではないため、セッション観測性として別タスクで扱う。

## 6. 完了条件

- 新しい実行契約が、既存の安全レーン・同時実行制限を保ったまま探索タスクに適用される。
- 初期探索が実行前に消失せず、探索前のカバー率ガード投入が起きない。
- 選択済みタスクが未終端でセッション終了するケースが、理由コード付きで検出・記録される。
- 対象の単体・結合テストと関連回帰テストが成功する。文書検証では、今回の文書に書式・リンクエラーがないことを確認する（台帳全体に既存の欠落参照がある場合は別途記録する）。

## 7. 実装結果

- `ExecutionProfile` により、担当エージェント名と実行用カテゴリを分離した。レート制限付きの読み取り専用タスクは `intel_active`、それ以外の読み取り専用並列タスクは `intel_passive` を使う。
- 初期探索は scope 成功への明示的依存を持つ。依存先の欠落、失敗、循環は理由付き `skipped` と監査記録になる。
- 攻撃フェーズが未解放なら、カバー率ガードをキューに追加しない。解放後の既存ガード生成は維持する。
- 選択済みだが未終端のタスクが残れば、サマリーの `completion_status` は `incomplete` となり、通常完了メッセージを表示しない。
- 文書検証は Front Matter とリンクのエラー0件だった。台帳全体には今回と無関係な既存の欠落参照2件が残るため、全体の `REGISTRY_ISSUES` は2件である。
