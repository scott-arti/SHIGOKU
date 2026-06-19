---
task_id: SGK-2026-0260
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0221
related_docs:
- docs/shigoku/subtasks/2026-06-03_recon-signal-mc-swarm_subtask_plan.md
- docs/shigoku/subtasks/2026-06-03_recipe-auth-jwt-oauth_subtask_plan.md
- docs/shigoku/roadmaps/2026-06-03_continuous-learning-architecture-reference.md
- docs/shigoku/plans/2026-05-19_mock-optimizedreciperunner-discovery-graphql_plan.md
- docs/shigoku/subtasks/2026-05-20_sgk-2026-0221-s01_groupa_execution-path_subtask_plan.md
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
- docs/shigoku/roadmaps/future_functions1.md
title: 'Recipe運用フロー改善: Recon起点の選抜・実行・Swarm連携'
created_at: '2026-06-03'
updated_at: '2026-06-19'
tags:
- shigoku
target: src/core/engine/master_conductor.py, src/core/engine/recipe_loader.py, src/core/engine/optimized_runner.py,
  src/core/infra/knowledge_graph.py, src/recon, recipes
---

# 実装計画書：Recipe運用フロー改善: Recon起点の選抜・実行・Swarm連携

本計画の実装検討・実装時は、継続学習の理想責務と判断原則を固定した参照資料
[2026-06-03_continuous-learning-architecture-reference.md](../roadmaps/2026-06-03_continuous-learning-architecture-reference.md)
を必ず参照し、Recipe trigger は signal + KG を正本とし、RAG は trigger gate ではなく follow-up / checklist / caution の補助に限定すること。

## 1. 達成したいゴール（ユーザー視点）
- [ ] SHIGOKU が Recon / Discovery で得た signal をそのまま埋もれさせず、適切な Recipe を選抜して高期待値の検証へつなげられること。
- [ ] Swarm/LLM の自由探索、Recipe の定型深掘り、KnowledgeGraph の永続記憶が役割分担された一貫フローとして動作すること。
- [ ] `auth_attack` や `sqli_scan` のような direct swarm dispatch と `run_recipe` 実行の境界が明確化され、どの条件でどちらを使うかが deterministic に説明できること。
- [ ] 同じ signal から無秩序に重複タスクを増やさず、Recon -> selection -> execution -> evidence -> feedback の循環が低ノイズで回ること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/recon/` および関連 Discovery 実装: （修正候補）Recipe 選抜に使う signal を正規化して `context.target_info` / KG に渡す。
  - `src/core/engine/master_conductor.py`: （修正）direct swarm dispatch と recipe dispatch の責務分離、選択オーケストレーション。
  - `src/core/engine/recipe_loader.py`: （修正）Recipe candidate selection の中核。trigger / score / reason を返す。
  - `src/core/engine/optimized_runner.py`: （修正）Recipe 実行後の evidence / verdict / follow-up signal を構造化する。
  - `src/core/infra/knowledge_graph.py`: （修正候補）Recipe 選抜と重複抑制に使う graph-backed context を提供する。
  - `src/core/engine/recipe_contracts.py`: （修正）action / signal / verdict 契約の明文化。
  - `recipes/`: （修正）workflow-ready schema と分類方針へ段階移行。
  - `tests/core/engine/` と `tests/unit/engine/`: （修正）選抜経路・重複抑制・follow-up routing のテスト追加。
- **データの流れ / 依存関係:**
  - Recon / Discovery / auth observation / endpoint classification -> normalized signals -> `context.target_info` と KnowledgeGraph に保存。
  - normalized signals + KG context -> `RecipeLoader` が `RecipeCandidate` 群を score 化。
  - candidate 判定:
    - high-confidence, deterministic path -> `run_recipe`
    - broad / ambiguous / exploratory path -> direct swarm task
    - recipe 実行中に新 signal を得た場合 -> evidence 保存後、必要に応じて Swarm/LLM follow-up task を生成
  - Recipe 結果 -> evidence / verdict / follow-up signals -> task queue / finding / KG に反映。

### 2.1 目指す運用モデル
- **Swarm/LLM の役割**: 広く観測し、曖昧な局面や複数仮説がある局面を捌く。
- **Recipe の役割**: 条件が揃った高期待値仮説を、再現性ある順序で深掘りする。
- **KnowledgeGraph の役割**: signal の永続化、重複抑制、関連 endpoint / tech / finding の近接情報提供。
- **MasterConductor の役割**: direct swarm dispatch と `run_recipe` の切り替え、および結果のフィードバック制御。

### 2.2 現状からのズレ
- `_inject_matching_recipes()` は名前に反して YAML Recipe を inject しておらず、direct swarm task を追加している。
- `RecipeLoader` は loaded recipes をほぼ無条件で返しており、signal-based selection の責務を果たしていない。
- Recon / Discovery 由来の signal が recipe-ready な vocabulary に正規化されていない。
- KnowledgeGraph は tech/page 保存には使われているが、Recipe 選抜の正本としては未接続。

### 2.3 この計画書の担当範囲と他計画書との境界
- **この計画書で扱うこと**:
  - `AttackSurfaceSignal` / KG context を入力として recipe candidate をどう選ぶか
  - `RecipeCandidate(score, reasons, required_signals, supporting_context)` 契約
  - direct swarm / recipe / follow-up swarm の切替条件
  - `RecipeRun`, `Finding`, `FollowUpDecision` を KG にどう反映するか
- **この計画書で扱わないこと**:
  - raw discovery entry の正規化実装詳細
  - `TaggingFilter` / `URLClassifier` の taxonomy 設計詳細
  - Recon handoff の legacy 互換レイヤ実装詳細
- **隣接する計画書との境界**:
  - [2026-06-03_recon-signal-mc-swarm_subtask_plan.md](2026-06-03_recon-signal-mc-swarm_subtask_plan.md)
    - recipe selector に渡す `AttackSurfaceSignal` と KG 正本スキーマを supply する
  - [2026-06-03_recipe-auth-jwt-oauth_subtask_plan.md](2026-06-03_recipe-auth-jwt-oauth_subtask_plan.md)
    - auth/jwt/oauth の個別 recipe trigger と recipe 内容を扱う

### 2.3.1 責務固定表（最終版）

| 項目 | 正本オーナー | Recon計画書 (`SGK-2026-0261`) | この計画書 (`SGK-2026-0260`) | 備考 |
|---|---|---|---|---|
| raw discovery entry の収集 | Recon | own | 参照しない | Recipe 側で再読込しない前提へ移行 |
| `AttackSurfaceSignal` schema 定義 | Recon | define | consume | 変更要求は Recon 側へ返す |
| `AttackSurfaceSignal` 生成 | Recon | produce | consume | Recipe 側では再生成禁止 |
| `RecipeCandidate` schema 定義 | Recipe | inputを供給される | define/own | selector 契約は Recipe 側正本 |
| recipe candidate scoring | Recipe | inputを供給される | own | KG supporting context の使い方を含む |
| `MasterConductor` の Recon 側責務 | Recon | own | 前提として受ける | handoff 受信と summary 生成まで |
| `MasterConductor` の Recipe 側責務 | Recipe | inputを受け渡す | own | recipe/direct swarm/follow-up の最終判定 |
| `SuppressionDecision` schema | Recon | define | consume | 共通 reason code を使う |
| low-value / malformed suppression | Recon | own | 再実装しない | Recipe 側は尊重する |
| recipe 重複実行 suppression | Recipe | context供給 | own | `RecipeRun` / selector 側で実施 |
| KG asset graph | Recon | own | consume | endpoint/param/auth/workflow/tech |
| KG signal graph | Recon | own | consume | signal/evidence/reconrun/session |
| KG execution graph | Recipe | context供給 | own | reciperun/taskexecution/finding |
| `RecipeRun` 書き戻し | Recipe | 参照 | own | selector/runner の結果 |
| `Finding` 書き戻し | Recipe | 参照 | own | confirmed_from signal を含む |
| Swarm suggestion/follow-up decision 書き戻し | Recipe | 参照 | own | `SwarmDecision` 等 |
| recipe trigger vocabulary | Recipe | recipe-ready signal を供給 | own | trigger 判定語彙の最終責任 |

### 2.3.2 境界固定ルール
- Recipe 側は `AttackSurfaceSignal` を入力正本として扱い、raw recon file を recipe 選抜の一次情報にしない。
- Recipe 側が raw recon file を読むのは移行互換期間の補助参照に限定し、正本判定は必ず signal / KG context を通す。
- `MasterConductor` の recipe/direct swarm/follow-up 判定ロジックはこの計画書の責務として固定する。
- `SuppressionDecision` の生成主体は Recon 側と Recipe 側で分かれる。low-value suppression は Recon 側、recipe re-run suppression は Recipe 側。
- KG の asset/signal graph は Recon 側が正本更新、execution/result graph は Recipe 側が正本更新とする。

### 2.4 KnowledgeGraph 理想形の概念図（Recipe 選抜視点）
```text
 ReconRun
    |
    v
 AttackSurfaceSignal -----> Endpoint/Parameter/AuthSurface/WorkflowSurface
    |   \                         ^
    |    \                        |
    |     +-----> Evidence        |
    |                              \
    +-----> SwarmDecision           +-----> Technology
    |
    +-----> RecipeRun -----> TaskExecution -----> Finding
                 |
                 +-----> Follow-up Swarm Task
```

### 2.5 Recipe 計画から見た KG 利用方針
- **Recon 側が正本として供給するもの**:
  - `AttackSurfaceSignal`
  - `Evidence`
  - `ReconRun`
  - `SessionContext`
  - `Endpoint` / `Parameter` / `AuthSurface` / `WorkflowSurface` / `Technology`
- **Recipe 側が主に consume するもの**:
  - signal の `labels`, `primary_label`, `confidence`, `normalized_key`
  - endpoint 近傍の auth/workflow/tech/finding 関係
  - `first_seen_at`, `last_seen_at`, `seen_count` による novelty / stability
  - `SuppressionDecision` による除外理由
- **Recipe 側が KG へ追加で書き戻すもの**:
  - `RecipeRun`
  - `TaskExecution`
  - `Finding`
  - `RecipeRun -[:TRIGGERED_BY]-> AttackSurfaceSignal`
  - `Finding -[:CONFIRMED_FROM]-> AttackSurfaceSignal`
  - 必要に応じて `SwarmDecision` / follow-up decision

### 2.6 Recipe 側で必要な KG ノード/リレーション最小集合

| 要素 | 用途 | この計画書での扱い |
|---|---|---|
| `AttackSurfaceSignal` | recipe 選抜の入力正本 | consume |
| `Endpoint` | endpoint 近傍情報・重複抑制 | consume |
| `Parameter` | parameter 単位の multi-label 選抜 | consume |
| `AuthSurface` | login/callback/refresh/oauth 系 recipe の trigger | consume |
| `WorkflowSurface` | basket/order/payment/realtime/csrf 系 recipe の trigger | consume |
| `Technology` | tech 補助スコア | consume |
| `Evidence` | 理由説明・prompt/context 補強 | consume |
| `ReconRun` | novelty / recency 判定 | consume |
| `SuppressionDecision` | 既に落とした理由の再利用 | consume |
| `RecipeRun` | 重複実行抑制・履歴比較 | produce |
| `TaskExecution` | 実行追跡 | produce |
| `Finding` | 結果保存 | produce |

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - Recon / Discovery 由来の signal
    - `tech_stack`
    - `discovered_urls`
    - `form_params`, `query_params`, `js_files`
    - auth surface metadata
    - session / bearer / cookie presence
  - KnowledgeGraph context
    - known pages / endpoints / technologies
    - nearby findings / previous recipe runs
    - route / relation density
  - Recipe metadata
    - trigger rules
    - attack surface tags / vulnerability tags
    - supported categories
    - supported step actions / specialist binding
    - deterministic vs exploratory suitability
- **出力/結果 (Output):**
  - 成功時:
    - signal ごとに `direct swarm`, `run_recipe`, `defer` のどれを選んだか説明可能
    - Recipe 実行後に follow-up が必要なら、理由付きで後続 task が生成される
    - 重複実行の少ない task graph と evidence graph が形成される
  - 失敗時:
    - signal 不足や schema 不整合は fail-fast
    - broad exploration と deterministic validation の責務が混ざらない
- **制約・ルール:**
  - `Swarm/LLM` は広い探索と曖昧性解消に使い、定型検証は可能な限り Recipe に寄せる。
  - Recipe 選抜は deterministic first とし、LLM 単独の気分で発火しない。
  - 同一 signal から同種 task を無制限に増やさず、 dedupe / suppression key を持つ。
  - Recipe の候補集合は「その時点で必要な YAML のみ」で構成し、過去にロード済みだった全 Recipe を累積再利用しない。
  - Recipe 実行結果は KnowledgeGraph または同等の永続コンテキストへ反映可能であること。
  - direct swarm dispatch を残す場合でも、なぜ Recipe ではなく swarm なのか判定理由を残す。
  - Recipe YAML が選ばれても step action が実行不能では意味がないため、 selector と runner の allowlist / specialist binding を同じ契約で管理する。
  - 実装は `SGK-2026-0259` の個別 Recipe 高度化と整合する vocabulary を使う。

### 3.1 目標フロー
1. Recon / Discovery が raw signal を収集する。
2. signal normalizer が raw signal を recipe-ready vocabulary に変換する。
3. `RecipeLoader` が attack surface tags / vulnerability tags / supported actions を見て candidate selection を行い、`RecipeCandidate(score, reasons, required_signals, supporting_context)` を返す。
4. `MasterConductor` が次を決める。
   - 明確な高期待値 candidate がある -> `run_recipe`
   - 不確実だが価値がありそう -> swarm/LLM で追加探索
   - evidence 十分で follow-up 先が明確 -> specialized swarm task
5. Recipe 実行後、evidence と新 signal を保存する。
6. 新 signal があれば follow-up routing を行う。

### 3.2 direct swarm と Recipe の使い分け
- **Recipe を使う条件**
  - trigger が明確
  - success / stop condition を定義できる
  - 同じ検証列を繰り返し再利用したい
- **direct swarm を使う条件**
  - signal が曖昧
  - 何を試すべきか branching が多い
  - LLM の探索で候補列挙したほうが価値が高い
- **Recipe 後に swarm を使う条件**
  - Recipe が additional evidence や adjacent attack surface を発見した
  - 決定論的な確認は終わったが、次の横展開が必要

### 3.3 KnowledgeGraph 連携方針
- KG を `page/tech` 保存だけでなく、Recipe selection context の供給元にする。
- `RecipeRun`, `Signal`, `Evidence`, `FollowUpDecision` に相当する構造を保持できるようにする。
- 同一 endpoint / cluster / finding lineage に対する Recipe 重複実行を抑制するキーとして使う。
- endpoint 近傍の `login`, `callback`, `refresh`, `admin`, `graphql` 関係を recipe scoring に加点できるようにする。

### 3.4 Recon 計画との接続契約
- Recipe selector が直接 raw URL 群や単純カテゴリ count を読むのではなく、Recon 計画で定義する `AttackSurfaceSignal` を入力正本とする。
- `match_recipes_to_context()` は将来的に `tech_stack` だけでなく、signal list と KG supporting context を受け取る前提で再設計する。
- KG 側の asset graph は recipe scoring の補助情報とし、signal graph が trigger の一次情報になるよう責務分離する。
- Recon 計画側で schema が増えても、Recipe 計画側では `required_signals`, `supporting_context`, `reasons` 契約に吸収できる構成を目指す。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: Recon / Discovery から Recipe 選抜へ渡す signal vocabulary を定義し、raw signal との対応表を設計する。
- [ ] ステップ2: `master_conductor.py` の direct swarm dispatch 経路と `run_recipe` 経路を棚卸しし、責務境界と切替条件を明文化する。
- [ ] ステップ3: `RecipeLoader` が `RecipeCandidate` を返す新しい selection 契約を設計し、Recipe ごとの attack surface tags / vulnerability tags / supported actions を照合可能にする。
- [ ] ステップ4: KnowledgeGraph から selection に必要な supporting context を取得する I/O を設計する。
- [ ] ステップ5: Recipe 候補集合のライフサイクルを見直し、過去ロード済み YAML を無条件で全再利用しない selection / cache / invalidation 方針を設計する。
- [ ] ステップ6: Recipe 実行後の evidence / follow-up routing 契約を `optimized_runner.py` / conductor 側へ導入し、allowlist にない action を事前に検出して graceful に落とす。
- [ ] ステップ7: 重複抑制、suppression key、decision trace を追加し、同一 signal からの task explosion を防ぐ。
- [ ] ステップ8: Recipe selector の主体を `MasterConductor` 中心に残すか、Swarm に寄せるか、または Swarm-assisted selection にするかを設計判断として明文化する。
- [ ] ステップ9: docs とテストで `direct swarm` / `run_recipe` / `recipe -> swarm feedback` の3経路を固定化する。

### 4.2 Recon 計画書との分担
- Recon 計画書 (`SGK-2026-0261`) の完了条件:
  - `AttackSurfaceSignal` schema が固定される
  - KG の signal graph / asset graph の正本境界が固定される
  - MC/Swarm へ渡す handoff が定義される
- この Recipe 計画書 (`SGK-2026-0260`) の完了条件:
  - 上記 schema を入力として recipe selector が説明可能に動く
  - `RecipeRun` / `Finding` / follow-up decision を KG に戻せる
  - direct swarm と recipe の切替条件が deterministic に説明できる

### 4.1 テスト観点
- 同じ auth surface から `auth_attack` と auth Recipe が無秩序に二重起票されないこと。
- signal が弱い場合は direct swarm、強い場合は Recipe が選ばれること。
- attack surface tags / vulnerability tags により、同一 parameter / endpoint から複数 specialist 候補へ multi-label に fan-out できること。
- Recipe 実行後に新 signal が出たときだけ follow-up swarm task が作られること。
- KG context の有無で selection score が説明可能な形で変化すること。
- decision trace に「なぜ Recipe を選んだか / なぜ選ばなかったか」が残ること。
- いったんロード済みの unrelated Recipe が、別 signal の回で無条件に `run_recipe` 候補化されないこと。
- allowlist にない action を含む Recipe は、選抜時または実行前検証で理由付きに抑止されること。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] workflow 設計だけ先行し、実際の signal quality が不足すると selection が机上設計化する - Recon 側の signal normalizer を同時に定義する。
- [ ] [重要度:高] direct swarm と Recipe の二重系統がしばらく共存し、暫定互換期間に複雑さが増す - migration phase を設け、旧経路に deprecation trace を入れる。
- [ ] [重要度:中] KnowledgeGraph の更新粒度が荒いと selection に stale context を使う可能性 - freshness / last_seen を scoring に含める。
- [ ] [重要度:中] follow-up routing を増やしすぎると task explosion が再発する - suppression key と top-N policy を必須化する。
- [ ] [重要度:中] Recipe の selector 主体を MC に固定しすぎると、曖昧局面で Swarm の仮説列挙力を活かせない - MC final gate + Swarm-assisted suggestion など中間案も比較する。
- [ ] [重要度:中] attack surface tags / vulnerability tags が Recipe 側で未整備だと selector が機能せず、YAML 数だけが増える - schema 拡張と migration を先に定義する。
- [ ] [重要度:中] load 済み Recipe のキャッシュ方針を誤ると、関係ない YAML が累積的に再実行候補へ混入する - per-run candidate set と cache invalidation を分離する。
- [ ] [重要度:中] LLM 探索に戻す条件が曖昧だと deterministic flow が崩れる - `recipe_to_swarm_reason` を固定語彙化する。
- [ ] [重要度:低] docs 上の Recipe 用語とコード上の命名がしばらく乖離する - `_inject_matching_recipes` などの命名整理を別ステップで行う。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0260-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```

## 6. 現行フロー図解メモ（追記）

### 6.1 現行フロー A: signal -> direct swarm task

```text
Recon / Discovery / Context updates
  -> context.target_info に raw signal を格納
  -> MasterConductor._inject_matching_recipes()
  -> if auth URL detected:
       Task(agent_type="swarm", action="auth_attack", tags=["auth_bypass", ...])
  -> if params detected:
       Task(agent_type="swarm", action="sqli_scan", tags=["sqli_union", ...])
  -> if JS detected:
       Task(agent_type="swarm", action="xss_scan", tags=["dom_xss", ...])
  -> if tech stack hit(jwt/oauth/graphql/api):
       Task(agent_type="swarm", action="scan", tags=[...])
  -> MasterConductor._dispatch()
  -> SwarmDispatcher.dispatch(tags, target, params)
  -> matching swarm(s) を決定
  -> swarm.dispatch(task)
  -> specialists 実行
  -> findings / execution_log を返却
```

**かんたんな説明**
- 現行の主系統はこちら。
- 名前は `_inject_matching_recipes()` だが、実際には YAML Recipe を選んでいない。
- signal から直接 `auth_attack`, `sqli_scan`, `xss_scan`, `scan` といった swarm task を作っている。
- つまり Recipe 層を経由せず、`signal -> swarm task` の直結になっている。

### 6.2 現行フロー B: signal -> recipe -> run_recipe

```text
CLI / bridge / 何らかのコードが recipe_loader.load_recipe(filepath) を呼ぶ
  -> RecipeLoader.recipes に YAML 由来 Recipe を保持
  -> MasterConductor.plan()
  -> MasterConductor._load_recipe_tasks()
  -> recipe_loader.match_recipes_to_context(context_dict)
  -> matched recipes を run_recipe task に変換
  -> Task(agent_type="swarm", action="run_recipe", params={"recipe_name": ..., "target": ...})
  -> MasterConductor._dispatch()
  -> task.action == "run_recipe" 分岐
  -> MasterConductor._execute_recipe_task()
  -> OptimizedRecipeRunner.run_recipe()
  -> step_executor 経由で各 step を dispatch
  -> result_bundle(summary, steps, success) を返却
```

**かんたんな説明**
- こちらが Recipe 実行の本流。
- ただし `RecipeLoader` は現状ディレクトリ自動走査をせず、明示的に `load_recipe()` されたものだけが対象。
- さらに `match_recipes_to_context()` が賢い選抜をしておらず、loaded recipes をそのまま返す。
- そのため、現在は「signal を見て適切な Recipe を選ぶ」より「ロードされている Recipe を run_recipe にする」色が強い。

### 6.3 理想フロー（比較用）

```text
Recon / Discovery / Browser / API probes
  -> signal normalizer
  -> KnowledgeGraph / context.target_info に正規化 signal を保存
  -> Recipe selector
       - candidate scoring
       - required signals check
       - dedupe / suppression
  -> if deterministic and high-confidence:
       run_recipe
     else if ambiguous / exploratory:
       direct swarm task
  -> Recipe 実行
  -> evidence / verdict / follow-up signal
  -> 必要なら Swarm / LLM follow-up task を生成
```

**かんたんな説明**
- 理想形では、Swarm は広い探索と曖昧性解消、Recipe は高期待値仮説の定型深掘りを担当する。
- つまり `signal -> selector -> recipe or swarm` の分岐が必要。
- 現状は selector が弱く、Recipe 層が飛ばされるケースが多い。

## 7. 現時点で明確になった疑問と回答、および課題詳細メモ（追記）

### 7.1 Swarm は現状 Recipe を使っているのか
- **結論**:
  - 通常の attack dispatch では、Swarm は Recipe を使っていない。
  - Recipe を使うのは `run_recipe` 経路のみ。
  - `recipe_loader` を SwarmDispatcher / Swarm に渡す配線はあるが、通常の `auth_attack`, `sqli_scan`, `xss_scan` などの経路では Recipe を参照していない。
- **現状の意味**:
  - `Swarm が signal を出す -> Recipe selector が Recipe を選ぶ -> run_recipe` という理想形にはまだなっていない。
  - 今は `signal -> direct swarm task` と `loaded recipe -> run_recipe` が別系統で共存している。

### 7.2 `_inject_matching_recipes()` という命名と実態のズレ
- **実態**:
  - 認証 URL があれば `auth_attack`
  - パラメータがあれば `sqli_scan`
  - JS があれば `xss_scan`
  - tech stack に jwt/oauth/graphql/api があれば `scan`
  - という swarm task を直接生成している。
- **ズレの本質**:
  - 関数名は `Recipe` を inject するように見える。
  - 実際は YAML Recipe を選んでいない。
  - そのためコードを読む人に誤解を生みやすい。
- **課題**:
  - 命名整理が必要。
  - direct swarm routing と recipe routing を別責務として明示すべき。

### 7.3 `auth_attack`, `sqli_scan`, `xss_scan` は何か
- **結論**:
  - YAML ではなく、`Task.action` の値。
  - つまり「どういう種類の実行命令か」を表す command / action vocabulary。
- **一緒に渡されるもの**:
  - `target`
  - `tags`
  - `params`
  - `_dispatch()` で注入される `auth_headers`
  - 必要に応じて cookies 由来情報
- **課題**:
  - LLM / Swarm に渡る情報はあるが、signal の正規化が弱い。
  - `auth_urls`, `params`, `js_files` のような raw に近い形で渡っており、`login_surface`, `oauth_callback_detected`, `refresh_endpoint_detected` のような recipe-ready vocabulary になっていない。

### 7.4 LLM が判断できるだけの情報が正しく渡されているか
- **現状評価**:
  - 部分的には渡っている。
  - しかし、「何が怪しいか」をすぐ判断できるほど整理されていないケースが多い。
- **具体的な不足**:
  - auth surface の型分類不足
  - token / session / callback / refresh の区別不足
  - endpoint importance / nearby context の欠如
  - KG の関連関係が selection / swarm prompt に乗っていない
- **課題**:
  - signal normalizer を作る必要がある。
  - LLM に渡すときの structured context schema を固定する必要がある。

### 7.5 `RecipeLoader` はいつ動き、何をしているか
- **現状**:
  - `RecipeLoader` は `MasterConductor` 初期化時に保持される。
  - YAML のロードは主に `load_recipe(filepath)` 呼び出し時で、明示的に 1 件ずつ。
  - `plan()` 内の `_load_recipe_tasks()` が loaded recipes を `run_recipe` task に変換する。
- **重要な実態**:
  - `recipes/` ディレクトリ全体の自動走査はしていない。
  - だが、一度ロードした Recipe は内部辞書に保持され続ける。
  - `match_recipes_to_context()` は今ほぼ loaded recipes 全件返し。
- **ユーザー理解としての要点**:
  - 1個ロードしたら1個候補。
  - 2個ロードしたら2個候補。
  - 3個ロードしたら3個候補。
  - 現状は「コンテキストに応じて賢く絞る」動作ではない。
- **追加で明示すべき問題**:
  - 「今必要な YAML だけをその場で選ぶ」のではなく、「過去にロード済みの YAML 全体」が次回以降の候補母集団に残る。
  - そのため、signal に無関係な Recipe が累積的に `run_recipe` 候補へ混ざる。

### 7.6 `match_recipes_to_context()` が賢くない、の意味
- **意味**:
  - 本来は `tech_stack`, auth surface, endpoint class, session state, KG context から「今この target で意味がある Recipe だけ」を返すべき。
  - 現在は loaded recipes の list をそのまま返しているだけ。
- **影響**:
  - selection ではなく enumeration になっている。
  - Recipe 数が増えると、不要な `run_recipe` 候補が増えやすい。
  - 将来的に direct swarm と Recipe の二重起票が起きやすい。
- **課題**:
  - `RecipeCandidate(score, reasons, required_signals, supporting_context)` 契約が必要。
  - top-N、dedupe、suppression key が必要。

### 7.7 1つのパラメータや signal から複数 attack path を並行評価しているか
- **現状評価**:
  - 限定的には yes。
  - ただし細粒度の multi-label routing ではない。
- **現状の挙動**:
  - auth URL があれば auth
  - params があれば sqli
  - JS があれば xss
  - という面単位の粗い fan-out。
- **不足**:
  - 1つの parameter / endpoint が `sqli`, `xss`, `ssrf`, `idor`, `redirect` の複数候補を持つ場合の、多面的 scoring / routing が弱い。
- **課題**:
  - signal を endpoint / parameter 単位で多ラベル化する必要がある。
  - Recipe selector / swarm router の両方に multi-label support が必要。

### 7.8 Loader が読む schema が狭い、とは何か
- **現状の Loader が読んでいるもの**:
  - `name`
  - `description`
  - `agent`
  - `trigger`
  - `steps[].id`
  - `steps[].name`
  - `steps[].action`
  - `steps[].params`
  - `steps[].dependencies`
- **ほぼ使えていないもの**:
  - `tags`
  - `tool`
  - `args`
  - `conditions`
  - `tasks`
  - `phases`
  - `triggers`
  - `metadata`
  - `severity`
  - `target_condition`
- **意味**:
  - 既存 YAML 群の書式が混在しており、Loader/Runner が理解できる正本 schema に統一されていない。
- **課題**:
  - attack surface tags / vulnerability tags / supported actions を selector が使えるよう schema に昇格する。
  - Recipe schema の一本化。
  - 既存 YAML の migration / archive / rewrite が必要。

### 7.9 Runner が受け付ける `action` とは何か
- **意味**:
  - Recipe step の実行命令の種類。
  - Runner は step を処理する前に、その `action` が allowlist に入っているか確認する。
- **影響**:
  - allowlist にない action は `UNSUPPORTED_ACTION` で失敗。
- **課題**:
  - Recipe の action vocabulary と specialist/tool binding の設計が必要。
  - `action` と `tool` の責務分離または統合方針を明示する必要がある。
  - selector が `action` 実行可能性を見ずに Recipe を返すと、「選ばれるが走れない Recipe」が大量発生するため、選抜時点で allowlist 整合を見る必要がある。

### 7.10 `/recipes/auth/oauth_redirect_bypass.yaml` は空ではないが、現行では実行不能に近い
- **現状の理解**:
  - YAML 自体は定義がある。
  - 例: `redirect_bypass`, `pkce_downgrade`
- **問題**:
  - Loader は action 文字列として保持しても、その意味を specialist / tool に結び付けていない。
  - `redirect_bypass` や `pkce_downgrade` は現行 Runner の allowlist に入っていない。
- **結果**:
  - 「中身が空」ではない。
  - しかし「現行契約ではそのまま動かない」。
- **課題**:
  - `oauth_*` 系 specialist / tool binding の設計
  - AuthSwarm との接続方式設計
  - action vocabulary 拡張 or adapter 導入

### 7.11 Swarm と Recipe の理想的な関係
- **理想**:
  - Swarm/LLM が広く観測して signal を出す
  - selector が適切な Recipe を選ぶ
  - `run_recipe` で決定論的深掘りをする
  - evidence を元に追加の swarm/LLM task を必要時のみ生成する
- **現状との差**:
  - 今は selector 不在に近い
  - direct swarm dispatch が主で Recipe 層が飛ばされる
  - Recipe 実行も loaded recipes 全件返し寄りで precision が低い
- **課題**:
  - selector の設計
  - signal vocabulary の設計
  - direct swarm / recipe / follow-up swarm の切替条件定義
  - Recipe 選抜主体を MC 単独とするか、Swarm に suggestion させて MC が最終判定するかの責務分担定義

### 7.12 KnowledgeGraph 連携に関する現時点の整理
- **現状**:
  - KG は page / domain / tech 保存には使われている
  - ただし Recipe 選抜の正本にはなっていない
- **活用すべき文脈**:
  - `login`, `callback`, `refresh`, `admin`, `graphql` 近接性
  - nearby findings
  - previous recipe runs
  - endpoint cluster / lineage
- **課題**:
  - KG を selection context の供給元として統合する
  - `RecipeRun`, `Signal`, `Evidence`, `FollowUpDecision` 相当を保持する
  - stale context / freshness を scoring に組み込む

### 7.13 実装時に特に注意すべき詳細課題一覧
1. direct swarm dispatch と Recipe dispatch の二重起票抑制
2. loaded recipes 全件返しの解消
3. signal の正規化 vocabulary 設計
4. action vocabulary と tool binding の整合
5. 既存 YAML の migration 方針
6. decision trace の保存
7. KG を用いた dedupe / suppression
8. Recipe 実行後の follow-up routing 契約
9. specialist が必要とする structured context schema の固定
10. `Recipe` 用語と実装命名の整合性回復
