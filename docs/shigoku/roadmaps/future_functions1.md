---
task_id: SGK-2026-0030
doc_type: roadmap
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# Future Functions & Improvements

本プロジェクトにおいて、開発効率と機能拡張性のために実装が推奨されるが、現時点では未実装・保留となっている機能のリスト。

## ✅ 実装済み機能 (Implemented)

### 1. MasterConductor セッション永続化 (2026-01-14)

- `save_session()` / `load_session()` によるタスクキュー・コンテキストの保存・復元。
- `main.py` への `--resume` フラグ追加。
- 自動チェックポイント保存（5 タスクごと）。

### 2. Technology Fingerprinting 統合 (2026-01-14)

- 重複していた MC の Phase 3 タスクを削除。
- `ReconPipeline` Step 3 に `ScopeParserAgent` の詳細解析ロジックを統合。

---

## 🚧 未実装・検討事項 (To Be Implemented / Considered)

### 1. ReconPipeline 内部のステップ単位 Resume 機能

**現状の課題:**
MasterConductor レベルでの Resume（タスク単位）は実装されたが、`ReconPipeline` 実行中（巨大な処理ブロック）に中断した場合、Pipeline の最初（Step 1）からやり直しになる。

**実装案:**

- `ReconPipeline` の各ステップ完了時に中間状態（state）をディスクに保存する。
- 起動時に中間ファイルが存在すれば、完了したステップをスキップして途中から再開するロジックを追加。
- `pipeline.run(resume=True)` のようなオプションをサポート。

### 2. 過去の Recon 結果の再利用・インポート

**現状の課題:**
過去に調査済みのターゲットであっても、新しいセッションでは Recon 結果（ファイルや DB）を再利用せず、フルスキャンが走る。

**実装案:**

- 指定したプロジェクトの過去の出力ファイル（`live_subs.txt` 等）が存在する場合、それを読み込んで Step をスキップする機能。
- `--import-recon <dir>` のような CLI オプション。

### 3. ScopeParser の完全なロジック統合 (Refactoring)

**現状の課題:**
`src/core/security/scope_parser.py` (Core) と `src/core/agents/specialized/scope_parser.py` (Agent) でロジックが重複・分散している。また、Pipeline から Agent クラスを直接 import して使う形は結合度が高い。

**実装案:**

- エージェント側の `ScopeParser` がセキュリティ側のクラスを内部的に利用するようにリファクタリング。
- Fingerprint ロジックを独立した `ToolRunner` または `IntelModule` として切り出し、Agent と Pipeline 両方から利用できるようにする（疎結合化）。

### 4. 動的エージェント選択 (Tag-based Selection)

**現状の課題:**
`_create_attack_tasks_from_recon` メソッド内で、攻撃タスクのエージェントタイプがハードコードされている（例: `'auth_ninja'`, `'biz_logic_hunter'`）。

**実装案:**

- `AgentRegistry` のタグシステムを活用する。
- Recon で特定された技術（例: "jwt"）に基づき、`get_agents_for_phase_and_tags(phase="attack", tags=["jwt"])` のように動的にエージェントを検索・選定するロジックを実装。
- これにより、新しいエージェントを追加した際に MC のコード修正が不要になる。

### 5. RecipeLoader の Attack フェーズ完全統合

**現状の課題:**
コンセプトとしては存在するが、Recon 完了後に「技術スタックに基づいて Golden Recipes を動的にロード・注入する」フローの E2E 動作確認が不十分。

**実装案:**

- `_create_attack_tasks_from_recon` 内で `RecipeLoader.match_recipes_to_context(tech_stack)` を呼び出し。
- マッチしたレシピをタスク化してキューに優先注入する処理の統合テストを実施。

### 6. PhaseGate の詳細制御

**現状の課題:**
現在は「Recon 完了 → Attack アンロック」という単純なゲートのみ。

**実装案:**

- より粒度の細かいゲート制御の実装。
  - 「Critical な脆弱性が見つかったら即 Report フェーズへ移行し、他の攻撃を一時停止」
  - 「スコープ外アクセス検知時（EthicsGuard アラート）に全タスクをロック」
  - 「予算（時間・リクエスト数）超過時に Attack フェーズをスキップして Report へ」

**追跡計画:**
- [2026-06-21_sgk-2026-0284_phasegate-fine-grained_subtask_plan.md](../subtasks/2026-06-21_sgk-2026-0284_phasegate-fine-grained_subtask_plan.md)

### 7. CLI 機能拡張

**現状の課題:**
`--resume` はデフォルトの `session_state.json` しか読み込めない。

**実装案:**

- `python -m src.main --resume my_session_backup.json` のように、任意のセッションファイルを指定可能にする。

## 8. フェーズ+タグによるサブエージェントへの割当
4.　と同じか?

## 9. サブエージェントの追加。
MCがより専門性の高いサブエージェントにタスクを降って精度を上げる。
SQLi, XSS, Oauthなど。


## 10. 分類別サブエージェントへのタスク振り。



## 11. サブエージェントのループ


## 12. Swarmで検出できるものの強化

## 13. 自律再認証と EventBus 運用の明確化

**現状の課題:**
EventBus は MC に接続され始めているが、長時間実行時の `401 -> 再認証 -> 再開` を製品機能として安定運用するには、trigger / ownership / fallback がまだ粗い。

**実装案:**

- `SESSION_EXPIRED`, `REAUTH_SUCCESS`, `REAUTH_FAILED` の扱いを MC 中心で固定する。
- Auth 系 Swarm は再認証の実行担当、MC は再開可否と再計画の担当に分ける。
- scope / budget / HITL を破らない自律再認証フローを設計する。

**追跡計画:**
- [2026-06-20_sgk-2026-0280_reauth_subtask_plan.md](../subtasks/done/2026-06-20_sgk-2026-0280_reauth_subtask_plan.md)

## 14. Replay / HITL 通知の次期Ver.整理

**現状の課題:**
Replay と HITL 通知は placeholder や部分導線があるが、運用機能としては未完成。

**実装案:**

- Replay を「どの証拠・どの再現フローに使うか」で用途別に整理する。
- HITL 通知は pending ticket / delivery / retry / fallback を含めて運用設計する。
- EventBus / dashboard / CLI handler の責務を揃える。

## 15. MultiSessionManager

**現状の課題:**
複数アカウントを跨いだ検証ロジックの芽はあるが、UserA/UserB/Admin などの実セッション管理基盤がない。

**実装案:**

- `alt_sessions` の実データ供給基盤を導入する。
- セッションごとの role, freshness, auth scope を管理する。
- cross-account 系タスクへ安全に handoff する。

## 16. Agentic RAG の hypothesis advisor 化

**現状の課題:**
今の Agentic RAG は `retrieve -> confidence 評価 -> query 改善` が中心で、MC がどう仮説へ取り込むかの契約が弱い。

**実装案:**

- MC が `chain state` と `hypothesis set` を持つ。
- RAG は `primary lane` を決めず、`alternative hypothesis`, `checklist`, `caution`, `counter-example hint` を返す補助層へ寄せる。
- `RAG にないから却下` を禁止し、runtime facts を正本にする。

**追跡計画:**
- <!-- [REMOVED: target not found] -->
