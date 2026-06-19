---
task_id: SGK-2026-0262
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0221
related_docs:
- docs/shigoku/subtasks/2026-06-03_recon-signal-mc-swarm_subtask_plan.md
- docs/shigoku/subtasks/2026-06-03_recipe-recon-swarm_subtask_plan.md
- docs/shigoku/roadmaps/2026-06-03_continuous-learning-architecture-reference.md
- docs/shigoku/specs/modules/RAG_SYSTEM.md
- docs/shigoku/specs/modules/KNOWLEDGE_GRAPH.md
- docs/shigoku/roadmaps/future_functions.md
title: '継続学習運用改善: Obsidian/RAG・KG・Recipe連携の再設計'
created_at: '2026-06-03'
updated_at: '2026-06-18'
tags:
- shigoku
target: src/core/rag_module/rag.py, src/core/intelligence/agentic_rag.py, src/core/learning/repository.py,
  src/core/infra/knowledge_graph.py, src/core/engine/master_conductor.py, src/core/engine/recipe_loader.py
---

# 実装計画書：継続学習運用改善: Obsidian/RAG・KG・Recipe連携の再設計

本計画の実装検討・実装時は、継続学習の理想責務と判断原則を固定した参照資料
[2026-06-03_continuous-learning-architecture-reference.md](../roadmaps/2026-06-03_continuous-learning-architecture-reference.md)
を必ず参照し、KG/RAG/MC/Recipe/Recon の責務分担、`RAG は gating しない`、`novelty budget`、`counter-example budget`、`provenance` の原則に反しないよう判断すること。

## 1. 達成したいゴール（ユーザー視点）
- [x] Obsidian/Markdown に蓄積した Writeup・調査メモ・失敗例・チェック観点を、SHIGOKU が安全に参照し、Recon / MC / Swarm / Recipe の判断品質を継続的に改善できること。（部分完了: RAGHint/RAGProvenance/LearningPolicy 型と policy モジュールを定義。MC/Swarm/Recipe への runtime 統合は後続タスク）
- [x] 過去の既知パターンに過学習せず、新規性の高い attack surface や未知の workflow bug を見落とさない「学習しながら探索する」運用モデルを確立できること。（部分完了: novelty_budget/counter_example_budget を LearningPolicy と RAGBudgetState に定義。実行時適用は後続タスク）
- [x] RAG が payload コピペ装置や gatekeeper ではなく、KG と Recipe を補助する hypothesis advisor として機能すること。（部分完了: RAGHint 型の hint_type を checklist/similar_case/caution/strategy に制限。is_valid() ガード追加。get_bypass_techniques() の再設計は別タスクで検討）
- [x] KG に残る target-specific memory、Recipe に残る execution memory、RAG に残る external/writeup memory が役割分担され、MC がそれらを説明可能に使い分けられること。（部分完了: LearningRepository の責務再整理、RAGFeedbackManager との連携追加。KG write-back は別途 SGK-2026-0260/0261 が担当）

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/rag_module/rag.py`: （修正）Obsidian/Markdown/PDF の ingest・query・mode switch の正本。RAG を payload source ではなく advisor query に寄せる。
  - `src/core/intelligence/agentic_rag.py`: （修正）confidence-based retrieve loop を、実際の RAG API 契約と一致させる。
  - `src/core/rag_module/rag_feedback.py`: （修正候補）FP/TP フィードバックを RAG 固有の記録から learning policy 側へ接続する。
  - `src/core/learning/repository.py`: （修正）TTL 付き軽量学習ストアを、RAG・KG・Recipe 間の補助メモリとして再定義する。
  - `src/core/infra/knowledge_graph.py`: （修正候補）RAG 由来ではない runtime facts と、RAG が参照した provenance を切り分けて保存する。
  - `src/core/engine/master_conductor.py`: （修正）KG と RAG の参照順序、RAG 利用条件、RAG provenance 記録、novelty budget 運用を担う。
  - `src/core/engine/recipe_loader.py`: （修正候補）Recipe 選抜では RAG を trigger 正本にせず、signal/KG を主としつつ補助ヒントだけ受ける。
  - `src/recon/` と `src/core/intel/`: （修正候補）`AttackSurfaceSignal` に対して、RAG 由来の hints を別フィールドで付与できるようにする。
  - `docs/shigoku/specs/modules/RAG_SYSTEM.md`: （更新候補）モジュール spec を運用実態と一致させる。
  - `tests/core/intelligence/`, `tests/core/engine/`, `tests/core/rag_module/`: （修正候補）RAG API 契約、MC handoff、bias guard、fallback の回帰を固定する。
- **データの流れ / 依存関係:**
  - Obsidian Vault / Markdown / PDF -> `KnowledgeIngester` -> chunked documents / embeddings -> ChromaDB collection
  - runtime target facts -> `AttackSurfaceSignal[]` -> KnowledgeGraph / MC / Swarm / Recipe
  - `AttackSurfaceSignal[]` + KG context -> MC が必要時のみ RAG query -> `RAGHint[]` を取得
  - `RAGHint[]` -> hypothesis expansion / checklist / similar-case reminder / FP caution に限定して利用
  - Recipe / Swarm execution result -> `RecipeRun` / `Finding` / `SuppressionDecision` / learning entry として保存
  - human feedback / TP-FP verdict / success-failure traces -> `LearningRepository` と KG に反映し、次回の ranking hint と suppression hint に再利用

### 2.1 現状整理
- **RAG 基盤は存在する**:
  - `KnowledgeIngester` は Obsidian Markdown を ChromaDB に保存し、差分 ingest も持つ。
  - Markdown は見出し単位で chunk 化される。
  - `RAGSwitch` は `query()` と `get_bypass_techniques()` を持つ。
- **ただし runtime 連携は未整合がある**:
  - `AgenticRAGFeedbackLoop` は `rag.retrieve()` を期待するが、`KnowledgeIngester` / `RAGSwitch` の正規 API は `query()` 寄りで、契約差がある。
  - MC は RAG を使う経路を持つが、どの局面で何のために使うかが policy 化されていない。
  - `rag_feedback.py` は FP/TP 記録を持つが、KG / Recipe rerun suppression / Recon suppression との連携が弱い。
- **学習ストアは別立てで存在する**:
  - `LearningRepository` は SQLite + TTL で軽量メモリを持つが、RAG と intelligence の間で統一運用されていない。
- **設計上の危険が残る**:
  - `get_bypass_techniques()` は content から payload 抽出寄りで、RAG を payload source にしやすい。
  - そのまま強化すると、既知 writeup 依存が強まり、新規バグを落とすバイアス源になりうる。

### 2.2 理想形
- **SHIGOKU の継続学習は「既知パターンへの最適化」ではない**:
  - 過去知識で探索効率を上げる
  - 失敗の再試行を減らす
  - 観点漏れを減らす
  - それでも未知の仮説を一定量探索し続ける
- **理想の役割分担**:
  - KG: target-specific memory / runtime facts / execution lineage / dedupe
  - Recipe: deterministic verification / repeatable deep-dive / execution memory
  - RAG: writeup memory / strategy memory / blind-spot reminder / hypothesis advisor
  - MC: 上記 3 つを使い分ける policy engine
- **守るべき原則**:
  - RAG は gatekeeper にしない
  - RAG に出ないから却下、を禁止する
  - Recipe trigger の正本は signal + KG に置く
  - novelty budget と counter-example budget を明示的に持つ
  - RAG provenance を保存し、「どのノートが判断に影響したか」を追跡可能にする

### 2.3 理想の継続学習ループ概念図
```text
 Obsidian Notes / Writeups / PDFs
                |
                v
        +---------------+
        |      RAG      |
        | strategy mem  |
        | blind spots   |
        +-------+-------+
                |
          RAGHint[] only
                |
                v
 AttackSurfaceSignal[] ---> KnowledgeGraph <--- RecipeRun / Finding / Suppression
         |                       ^
         |                       |
         v                       |
  MasterConductor ---------------+
         |
   +-----+------+
   |            |
   v            v
 Swarm       Recipe
   |            |
   +-----+------+
         |
         v
 LearningRepository
 (TP/FP, success/failure,
  retry cost, caution hints)
```

### 2.4 この計画書の担当範囲と他計画書との境界
- **この計画書で扱うこと**:
  - Obsidian/RAG を SHIGOKU 全体でどう安全に使うかという policy
  - KG / Recipe / MC / RAG の責務分担
  - RAG API 契約と agentic retrieve loop の整合
  - `RAGHint` / provenance / novelty budget / bias guard の設計
  - `LearningRepository` の位置づけ再整理
- **この計画書で扱わないこと**:
  - `AttackSurfaceSignal` schema の正本定義詳細
  - Recipe YAML trigger / score weight の詳細
  - KG ノード・リレーション全体スキーマの正本定義詳細
- **隣接する計画書との境界**:
  - [2026-06-03_recon-signal-mc-swarm_subtask_plan.md](2026-06-03_recon-signal-mc-swarm_subtask_plan.md)
    - `AttackSurfaceSignal` と KG signal/asset graph の正本を supply する
  - [2026-06-03_recipe-recon-swarm_subtask_plan.md](2026-06-03_recipe-recon-swarm_subtask_plan.md)
    - `AttackSurfaceSignal` / KG context を使った Recipe 選抜と execution graph を扱う
  - [RAG_SYSTEM.md](../specs/modules/RAG_SYSTEM.md)
    - RAG 単体モジュール spec。今回の計画はその運用責務と連携 policy を再定義する

### 2.5 責務固定表（最終版）

| 項目 | 正本オーナー | この計画書 (`SGK-2026-0262`) | Recon計画書 (`SGK-2026-0261`) | Recipe計画書 (`SGK-2026-0260`) | 備考 |
|---|---|---|---|---|---|
| `AttackSurfaceSignal` schema | Recon | consume only | own | consume | RAG 側は正本変更しない |
| Recipe trigger 正本 | Recipe | assist only | supply signal | own | RAG は trigger gate にならない |
| KG asset/signal/execution graph 正本 | Recon/Recipe | consume/provenance追記 | own(asset/signal) | own(execution) | この計画は policy を定義 |
| `RAGHint` schema | Learning/RAG | own | consume | consume | advisor 専用 |
| RAG query timing / usage policy | MC/Learning | own | input供給 | input供給 | MC がいつ RAG を引くか |
| RAG provenance 保存 | Learning/KG | own | consume | consume | note/source/chunk を残す |
| novelty budget / counter-example budget | MC/Learning | own | input供給 | consume | 既知例偏重を防ぐ |
| TP/FP / success/failure 学習ポリシー | Learning | own | consume | consume/write | KG と SQLite を橋渡し |
| payload extraction の扱い | Learning/RAG | own | 参照しない | hint としてのみ扱う | exploit source にしない |
| agentic retrieve loop 契約 | RAG | own | 参照しない | 参照しない | `query` 系 API と整合させる |

### 2.6 境界固定ルール
- RAG は `AttackSurfaceSignal` を生成しない。signal 正本は常に Recon 側が持つ。
- RAG は Recipe trigger を直接決めない。Recipe trigger の正本は Recipe 側に残す。
- KG は runtime facts の正本、RAG は external/writeup memory の補助記憶として分離する。
- `LearningRepository` は RAG 固有の補助 DB ではなく、TP/FP・成功/失敗・retry cost・caution hints を扱う横断メモリとして再定義する。
- RAG query 結果は `RAGHint` と provenance に正規化し、MC / Swarm / Recipe へそのまま raw chunk をばらまかない。
- RAG が返す内容は ranking hint / checklist hint / caution hint / similar-case hint に制限し、payload は実行判断の正本にしない。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - `AttackSurfaceSignal[]` (`list[dict]`): Recon 正本 signal
  - KG context (`dict`): endpoint/param/auth/workflow/finding/recipe history
  - Obsidian / Markdown / PDF corpus (`.md`, `.pdf`)
  - user / automation feedback (`TP/FP`, `success/failure`, `suppression`)
- **出力/結果 (Output):**
  - `RAGHint[]`: strategy/checklist/caution/similar-case の advisor hints
  - `RAGProvenance[]`: source note, chunk, score, query lineage
  - `LearningEntry`: TTL 付き補助メモリ
  - MC policy decision: `no_rag`, `rag_assist`, `rag_retry`, `rag_fallback`
  - failure 時は、RAG 不可でも KG + signal 正本で処理継続する
- **制約・ルール:**
  - RAG 未応答や Chroma 障害があっても、MC / Swarm / Recipe の本流は停止しない。
  - RAG を未学習・未ヒットとしても、未知の仮説は一定割合で探索する。
  - writeup 由来の payload は、そのまま実行せず evidence / signal / guardrail を通した文脈付き利用に制限する。
  - raw note 全文の濫用を避け、必要最小限の chunk / summary / provenance を handoff する。
  - RAG 側で扱う query / source / score は追跡可能にし、後から bias source を監査できるようにする。
  - Obsidian 特有の frontmatter / tags / internal links は保持するが、runtime 判定は metadata 依存だけにしない。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `rag.py`, `agentic_rag.py`, `master_conductor.py` を精査し、RAG API 契約 (`query`, `retrieve`, `RAGHint`) と利用局面を一本化する。
- [x] ステップ2: `RAGHint`, `RAGProvenance`, `LearningPolicy` を定義し、RAG を hypothesis advisor に限定する guardrail を設計する。
- [x] ステップ3: `LearningRepository`, `rag_feedback.py`, KG write-back の責務を整理し、TP/FP・成功/失敗・suppression・retry cost を横断メモリとして扱う方針を決める。
- [x] ステップ4: Recon / MC / Swarm / Recipe のどこで RAG を参照可能にするか、novelty budget / counter-example budget を含めた policy を設計する。
- [x] ステップ5: API 契約テスト、RAG 断時フォールバック、RAG 未ヒット時の探索継続、既知例偏重防止の回帰観点を整理する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [x] [重要度:高] `AgenticRAGFeedbackLoop` と `RAGSwitch/KnowledgeIngester` の API 契約差 (`retrieve` vs `query`) が残っている - まず契約を一本化してから MC 側の高度化に進む。→ **対応済: retrieve() メソッドを追加し、agentic_rag.py の async/sync 互換性を確保。テストで検証済（41件）。**
- [ ] [重要度:高] `get_bypass_techniques()` の payload 抽出中心設計は、既知 writeup 依存を強める可能性がある - strategy/checklist/caution 中心へ再設計する。→ **残リスク: RAGHint 型とガードレールは定義済だが、get_bypass_techniques() 自体の再設計は別タスク。現状でも RAG が gating しない設計原則は確立。**
- [x] [重要度:中] `LearningRepository` と `rag_feedback.py` と KG write-back が別系統で、重複保存や意味の不一致が起きうる - key 設計と ownership を固定する。→ **対応済: RAGFeedbackManager に LearningRepository 連携を追加。tp_fp_verdict / caution_hint カテゴリで保存。**
- [ ] [重要度:中] Vault 自動監視や差分同期常駐は未確立 - runtime 改修と切り分け、後続タスクで watcher 導入要否を判断する。→ **本計画のスコープ外。後続タスクで検討。**
- [ ] [重要度:中] モジュール spec (`RAG_SYSTEM.md`) と実装のズレがある - 実装方針が固まった時点で spec 更新を別パッチで反映する。→ **spec 更新は別パッチ（SGK-2026-0262-spec など）で対応推奨。**

### 5.1 deferred_tasks / 残リスク

#### deferred_tasks（実在 tracking_task_id あり）

```yaml
deferred_tasks:
  # SGK-2026-0262 の実装スコープ内では deferred_tasks に該当する項目なし。
  # 未解決項目は以下の「残リスク」として記録する。
```

#### 残リスク（tracking_task_id 未発行。起票要検討）

```yaml
remaining_risks:
  - risk_id: SGK-2026-0262-R01
    title: "get_bypass_techniques() の payload 抽出中心設計の再設計"
    description: >
      RAGHint 型とガードレール（hint_type 制限、is_valid()）は定義済だが、
      get_bypass_techniques() 自体は依然としてペイロード抽出中心の実装。
      strategy/checklist/caution 中心に再設計するには別タスクが必要。
    severity: high
    recommendation: "SGK 新規タスクを起票し、RAGHint ベースのバイパス手法検索に置き換える"

  - risk_id: SGK-2026-0262-R02
    title: "モジュール spec (RAG_SYSTEM.md) と実装のズレ修正"
    description: >
      RAGHint, RAGProvenance, LearningPolicy, rag_policy.py など
      新規追加要素が spec に反映されていない。
    severity: medium
    recommendation: "SGK 新規タスクを起票し、spec 更新パッチを作成する"

  - risk_id: SGK-2026-0262-R03
    title: "Vault 自動監視・差分同期常駐"
    description: >
      Obsidian Vault の変更を自動検知して再インデックスする watcher は未確立。
      本計画のスコープ外だが、継続学習の運用には重要。
    severity: medium
    recommendation: "後続タスクで watcher 導入要否を判断する"
```
