---
task_id: SGK-2026-0261
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0221
related_docs:
- docs/shigoku/subtasks/2026-06-03_sgk-2026-0260_recipe-recon-swarm_subtask_plan.md
- docs/shigoku/subtasks/2026-06-03_sgk-2026-0262_obsidian-rag-kg-recipe_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-03_sgk-2026-0259_recipe-auth-jwt-oauth_subtask_plan.md
- docs/shigoku/roadmaps/2026-06-03_continuous-learning-architecture-reference.md
- docs/shigoku/plans/2026-05-19_sgk-2026-0221_mock-optimizedreciperunner-discovery-graphql_plan.md
- docs/shigoku/subtasks/2026-05-20_sgk-2026-0221-s01_groupa_execution-path_subtask_plan.md
- docs/shigoku/specs/design/recon_scenario.md
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
- docs/shigoku/roadmaps/future_functions1.md
title: 'Recon運用フロー改善: 攻撃面分類・Signal正規化・MC/Swarm受け渡し'
created_at: '2026-06-03'
updated_at: '2026-07-21'
tags:
- shigoku
target: src/recon/pipeline.py, src/core/intel/tagging_filter.py, src/core/validation/url_classifier.py,
  src/core/engine/master_conductor.py, src/core/engine/swarm_dispatcher.py, src/core/models/url_context.py
---

# 実装計画書：Recon運用フロー改善: 攻撃面分類・Signal正規化・MC/Swarm受け渡し

本計画の実装検討・実装時は、継続学習の理想責務と判断原則を固定した参照資料
[2026-06-03_continuous-learning-architecture-reference.md](../roadmaps/2026-06-03_continuous-learning-architecture-reference.md)
を必ず参照し、Recon は runtime facts と `AttackSurfaceSignal` の正本を produce する層であり、RAG による gating や既知例偏重を入れないことを判断基準にする。

## 0. 2026-07-17 時点の現状棚卸し
- `src/recon/pipeline.py` の本流は、現在も `classified_files` と `tagged_urls` を中心に組み立てられており、MC 返却の主形式は `file/count/description/tags` である。
- `src/core/intel/tagging_filter.py` の `process_to_rich_contexts()` と `src/core/engine/swarm_dispatcher.py` の `dispatch_rich_url()` は存在するが、本流 handoff の正本ではなく、部分経路または検証経路に留まっている。
- `src/core/validation/url_classifier.py` の extended taxonomy は sidecar ファイル (`extended_taxonomy_tags.json`) として出力されるが、MC の一次入力としては昇格していない。
- `src/core/infra/knowledge_graph.py` の保存経路は `Endpoint`/`Technology` 中心であり、`AttackSurfaceSignal`/`Evidence` を正本として保存する経路は未整備である。
- したがって、本タスクは「構想済み・部分土台あり・本流未接続」の状態にある。本計画書は、ここからの additive migration を定義するための更新版として扱う。

## 1. 達成したいゴール（ユーザー視点）
- [ ] SHIGOKU が Recon 中に見つけた URL / param / form / auth surface / JS / realtime / file surface を、単なるファイル出力で終わらせず、攻撃面オブジェクトとして正規化して保持できること。
- [ ] 同じ endpoint や parameter が `sqli`, `xss`, `ssrf`, `idor`, `redirect`, `authz` など複数の attack path を持つ場合でも、粗い単一カテゴリではなく multi-label な候補として MC / Swarm に渡せること。
- [ ] MC が広いコンテキストと強いモデルを使う前提で、Recon の結果から「何が怪しいか」「なぜその specialist / recipe に回すのか」を説明可能な構造化 signal を受け取れること。
- [ ] Swarm が必要な raw evidence を失わず、Recipe selector / direct swarm router / KnowledgeGraph が同じ正本 signal を共有できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/recon/pipeline.py`: （修正）Katana / GAU / Httpx / Caido / Playwright の収集結果を統合し、tagging / taxonomy 後の normalized signal bundle を生成する。
  - `src/core/intel/tagging_filter.py`: （修正）rule match 由来の rich tagging を保持し、攻撃面の根拠と multi-label 候補を失わないようにする。
  - `src/core/validation/url_classifier.py`: （修正）URL taxonomy を recipe-ready / specialist-ready な vocabulary と接続する。
  - `src/core/models/url_context.py`: （修正候補）URL ごとの auth / param / response / subdomain 文脈を保持するデータ契約を拡張する。
  - `src/core/engine/master_conductor.py`: （修正）Recon handoff の正本受け取り、MC 用 context summary 構築、Swarm / Recipe への routing 材料の集約を行う。
  - `src/core/engine/swarm_dispatcher.py`: （修正候補）`RichUrlContext` / signal object を直接 dispatch できる経路を本流化または再利用する。
  - `src/core/engine/tag_taxonomy_registry.py`: （修正候補）tag/category と attack surface vocabulary の対応を整理する。
  - `src/core/infra/knowledge_graph.py`: （修正候補）Recon signal を KG に保存し、後続の dedupe / scoring / lineage に利用できるようにする。
  - `tests/recon/`, `tests/core/engine/`, `tests/e2e/`: （修正）signal normalizer, MC handoff, swarm routing, recipe handoff の回帰を固定する。
- **データの流れ / 依存関係:**
  - Katana / GAU / Httpx / Caido / Playwright -> raw discovery entries -> `TaggingFilter` / `URLClassifier` / auth metadata 抽出 -> `AttackSurfaceSignal[]` と summary context を構築。
  - `AttackSurfaceSignal[]` -> `target_info` / phase gate / KnowledgeGraph / task evidence に保存。
  - MC は normalized signal を見て、`direct swarm`, `recipe suggestion`, `defer` を判断する。
  - Swarm は signal 単位の evidence と multi-label 候補を受け、曖昧局面では仮説列挙を返す。
  - Recipe selector は Recon signal を recipe-ready vocabulary として参照し、必要時のみ candidate を返す。

### 2.1 目指す Recon 運用モデル
- **Recon の役割**: たくさん URL を集めるだけでなく、攻撃面の意味づけと正規化まで行う。
- **MC の役割**: Recon の正規化結果を正本として保持し、global dedupe / budget / routing / recipe selection の最終判断を行う。
- **Swarm の役割**: 曖昧な signal に対して仮説を広げ、multi-label 候補のうち優先度が高いものを提案する。
- **Recipe の役割**: Recon / Swarm が十分に条件を揃えた高期待値仮説を決定論的に深掘りする。

### 2.2 この計画書の担当範囲と他計画書との境界
- **この計画書で扱うこと**:
  - Recon raw entry を `AttackSurfaceSignal` に正規化する契約
  - MC / Swarm / KG へ渡す handoff 形式
  - KnowledgeGraph の理想スキーマのうち、signal 永続化と過去実行照合に必要な層
  - `target_info` / `phase_gate` / `tagged_urls` / `targets_file` の正本整理
- **この計画書で扱わないこと**:
  - YAML Recipe の trigger 設計詳細
  - Recipe candidate score の重み付け実装詳細
  - Recipe step action allowlist の拡張詳細
- **隣接する計画書との境界**:
  - [2026-06-03_sgk-2026-0260_recipe-recon-swarm_subtask_plan.md](2026-06-03_sgk-2026-0260_recipe-recon-swarm_subtask_plan.md)
    - この計画書が supply する `AttackSurfaceSignal` / KG context を recipe selector がどう consume するかを扱う
  - [2026-06-03_sgk-2026-0262_obsidian-rag-kg-recipe_subtask_plan.md](2026-06-03_sgk-2026-0262_obsidian-rag-kg-recipe_subtask_plan.md)
    - この計画書が凍結する signal / KG 契約を、RAG/KG/Recipe 側でどう補助参照するかを扱う。schema や vocabulary 変更要求はまず 0261 に返す
  - [2026-06-03_sgk-2026-0259_recipe-auth-jwt-oauth_subtask_plan.md](done/2026-06-03_sgk-2026-0259_recipe-auth-jwt-oauth_subtask_plan.md)
    - auth/jwt/oauth 系 recipe の個別 trigger と実行内容を扱う

### 2.2.1 責務固定表（最終版）

| 項目 | 正本オーナー | この計画書 (`SGK-2026-0261`) | Recipe計画書 (`SGK-2026-0260`) | 備考 |
|---|---|---|---|---|
| raw discovery entry の収集 | Recon | produce | 参照しない | Katana/GAU/Httpx/Caido/Playwright |
| `AttackSurfaceSignal` schema 定義 | Recon | define | consume | 正本 schema は Recon 側で固定 |
| `AttackSurfaceSignal` 生成 | Recon | produce | consume | Recipe 側で再生成しない |
| `Evidence` schema/生成 | Recon | produce | consume/追加参照 | Recipe は新規 evidence を別途追加可 |
| `target_info` への handoff 形式 | Recon | define/produce | consume | `count/tag/file` 互換を含む |
| `phase_gate` に渡す分類結果 | Recon | produce | consume しない | attack phase unlock は Recon 側 |
| `RichUrlContext` / Swarm handoff の正本形式 | Recon | define/produce | consume しない | Swarm suggestion の入力 |
| `MasterConductor` の Recon 側責務 | Recon | own | consume | handoff 受信、summary 構築、初期 routing 材料整理まで |
| `MasterConductor` の Recipe 側責務 | Recipe | 参照 | own | recipe/direct swarm/follow-up の最終判定 |
| `SuppressionDecision` の schema | Recon | define | consume | schema 正本は Recon 側 |
| low-value / static / malformed 抑止 | Recon | own | 再実装しない | Recon 前処理の責務 |
| recipe 重複実行抑止 | Recipe | context供給 | own | `RecipeRun` と selector 側で処理 |
| KG asset graph (`Endpoint`, `Parameter`, `AuthSurface` など) | Recon | own | consume | 収集起点なので Recon 側が更新正本 |
| KG signal graph (`AttackSurfaceSignal`, `Evidence`, `ReconRun`, `SessionContext`) | Recon | own | consume | Recon 正本 |
| KG execution graph (`RecipeRun`, `TaskExecution`, `Finding`) | Recipe | context供給 | own | 実行結果は Recipe 側正本 |
| `SwarmDecision` の write-back | Recipe | input context供給 | own | suggestion/follow-up 記録 |
| recipe trigger vocabulary | Recipe | supply先を意識 | own | Recon は recipe-ready signal を渡すだけ |
| YAML Recipe schema / scoring | Recipe | 扱わない | own | 明確にスコープ外 |

### 2.2.2 境界固定ルール
- Recon 側は `AttackSurfaceSignal` を作るが、Recipe 候補の採点ロジックは持たない。
- Recipe 側は `AttackSurfaceSignal` を読むが、raw discovery entry から signal を再構築しない。
- `MasterConductor` は二重責務を持つが、Recon handoff 受信までを Recon 側、recipe/direct swarm 最終選択を Recipe 側に帰属させる。
- Phase C 以降、Attack / direct swarm / recipe follow-up の task 作成の正本オーナーは `MasterConductor` のみとし、Recon / pipeline / tagging 側は task を直接 enqueue せず signal bundle と互換 artifact の返却に専念する。
- `SuppressionDecision` は Recon 側が schema と low-value suppression を定義し、Recipe 側はその記録を再利用して recipe 重複抑止に使う。
- KG への書き戻しは、asset/signal graph は Recon 側、execution/result graph は Recipe 側を正本オーナーとする。

### 2.2.3 現行実装との差分と v1 移行原則
- v1 は全面置換ではなく、`tagged_urls` / `classified_files` / `targets_file` / `RichUrlContext` を土台にした additive migration とする。
- `AttackSurfaceSignal` は最初から巨大な完成版 schema を要求せず、既存 `RichUrlContext` と `TagMatch` を拡張した最小契約から開始する。
- `step8_return_to_mc()` は一気に旧 payload を廃止せず、`host_surface_summary` / `endpoint_signal_bundle` を主 payload、`file/count/tags` を互換 payload として併存させる。
- MC / Swarm / KG の切替は「新 payload を読めるようにしてから旧 payload を縮退させる」順序で行い、先に reader を直し、最後に writer の依存先を整理する。
- 本タスクの完了判定は、「signal schema の命名」ではなく「本流 Recon 実行で signal が生成され、MC と KG がそれを一次入力として利用できること」とする。

### 2.3 KnowledgeGraph 理想形の概念図
```text
                     +----------------------+
                     |       Program        |
                     +----------+-----------+
                                |
                                v
                     +----------------------+
                     |    Domain / Host     |
                     +----------+-----------+
                                |
                                v
      +-------------+   +----------------------+   +------------------+
      | Technology  |<--|       Endpoint       |-->|   Parameter      |
      +-------------+   +----------+-----------+   +------------------+
                                |        \
                                |         \
                                v          v
                         +-------------+  +---------------+
                         | AuthSurface |  | WorkflowSurface|
                         +------+------+  +-------+-------+
                                ^                 ^
                                |                 |
                                +--------+--------+
                                         |
                                         v
                               +----------------------+
                               | AttackSurfaceSignal  |
                               +----+------+------+---+
                                    |      |      |
                                    v      v      v
                              +---------+  |  +-------------+
                              | Evidence |  |  |SessionContext|
                              +---------+  |  +-------------+
                                           |
                    +----------------------+----------------------+
                    |                                             |
                    v                                             v
            +---------------+                             +---------------+
            | SwarmDecision |                             |   RecipeRun   |
            +-------+-------+                             +-------+-------+
                    |                                             |
                    +--------------------+------------------------+
                                         |
                                         v
                                   +-----------+
                                   |  Finding  |
                                   +-----------+
```

### 2.4 KnowledgeGraph 理想スキーマ案

#### 2.4.1 ノード定義

| Node | 役割 | 主な必須プロパティ | この計画書での扱い |
|---|---|---|---|
| `Program` | bug bounty program / project 単位の親ノード | `program_id`, `name`, `scope_root`, `created_at`, `updated_at` | 参照 |
| `Domain` | ルートドメイン/サブドメイン | `name`, `in_scope`, `first_seen_at`, `last_seen_at` | 参照 |
| `Host` | 実際のホスト/IP/FQDN | `host`, `ip`, `scheme_hint`, `port_hint`, `first_seen_at`, `last_seen_at` | 参照 |
| `Endpoint` | URL + method 単位の攻撃対象 | `endpoint_key`, `url`, `method`, `path`, `normalized_path`, `auth_required`, `first_seen_at`, `last_seen_at`, `seen_count` | 更新 |
| `Parameter` | query/body/header/path/form の入力点 | `param_key`, `name`, `location`, `normalized_name`, `first_seen_at`, `last_seen_at`, `seen_count` | 更新 |
| `Form` | 送信フォーム | `form_key`, `action`, `method`, `field_names`, `has_file`, `first_seen_at`, `last_seen_at` | 更新 |
| `JSAsset` | JS ファイル/SPA route/sink 候補 | `asset_key`, `url`, `route_hint`, `framework_hint`, `first_seen_at`, `last_seen_at` | 更新 |
| `AuthSurface` | login/callback/refresh/reset/token exchange 等 | `surface_key`, `surface_type`, `url`, `auth_scheme_hint`, `first_seen_at`, `last_seen_at` | 更新 |
| `WorkflowSurface` | basket/order/payment/admin/realtime 等の多段遷移面 | `workflow_key`, `workflow_type`, `url`, `stateful`, `first_seen_at`, `last_seen_at` | 更新 |
| `Technology` | tech stack | `name`, `category`, `version`, `first_seen_at`, `last_seen_at` | 参照/更新 |
| `ReconRun` | 1回の偵察実行 | `run_id`, `program_id`, `target`, `started_at`, `ended_at`, `config_hash`, `status` | 新規 |
| `AttackSurfaceSignal` | Recon 正規化シグナルの正本 | `signal_id`, `entity_type`, `primary_label`, `labels`, `confidence`, `normalized_key`, `status`, `first_seen_at`, `last_seen_at`, `seen_count` | 新規・正本 |
| `Evidence` | signal の根拠 | `evidence_id`, `source`, `matched_on`, `matched_value`, `response_status`, `snippet_hash`, `captured_at` | 新規 |
| `SessionContext` | cookie/bearer/auth state の観測 | `session_id`, `auth_required`, `cookie_present`, `bearer_present`, `csrf_present`, `observed_at` | 新規 |
| `SwarmDecision` | Swarm が出した仮説/提案 | `decision_id`, `decision_type`, `suggested_action`, `confidence`, `reason_code`, `created_at` | 連携対象 |
| `RecipeRun` | Recipe 実行履歴 | `recipe_run_id`, `recipe_name`, `status`, `started_at`, `ended_at`, `verdict`, `dedupe_key` | 連携対象 |
| `TaskExecution` | MC/Swarm/Recipe の task 実行 | `task_id`, `action`, `agent_type`, `status`, `started_at`, `ended_at` | 連携対象 |
| `Finding` | 確認済み脆弱性 | `finding_id`, `title`, `vuln_type`, `severity`, `confidence`, `created_at`, `status` | 連携対象 |
| `SuppressionDecision` | dedupe/low-value/scope 外などの抑止判断 | `suppression_id`, `reason_code`, `scope`, `created_at` | 新規 |

#### 2.4.2 リレーション定義

| From | Relation | To | 役割 | この計画書での扱い |
|---|---|---|---|---|
| `Program` | `HAS_DOMAIN` | `Domain` | program 配下のドメイン管理 | 参照 |
| `Domain` | `RESOLVES_TO` | `Host` | DNS/IP 対応 | 参照 |
| `Host` | `EXPOSES` | `Endpoint` | endpoint 所属 | 参照 |
| `Endpoint` | `ACCEPTS_PARAM` | `Parameter` | 入力点の関連付け | 更新 |
| `Endpoint` | `HAS_FORM` | `Form` | フォームとの対応 | 更新 |
| `Endpoint` | `SERVES_JS` | `JSAsset` | JS 配信元 | 更新 |
| `Endpoint` | `IMPLEMENTS_AUTH` | `AuthSurface` | auth surface 対応 | 更新 |
| `Endpoint` | `PART_OF_WORKFLOW` | `WorkflowSurface` | workflow 上の位置づけ | 更新 |
| `Endpoint` | `RUNS_ON` | `Technology` | tech stack 紐付け | 更新 |
| `ReconRun` | `OBSERVED` | `AttackSurfaceSignal` | どの run で観測したか | 新規 |
| `AttackSurfaceSignal` | `TARGETS_ENDPOINT` | `Endpoint` | signal の対象 endpoint | 新規 |
| `AttackSurfaceSignal` | `TARGETS_PARAM` | `Parameter` | signal の対象 parameter | 新規 |
| `AttackSurfaceSignal` | `TARGETS_AUTH_SURFACE` | `AuthSurface` | auth 系 signal の対象 | 新規 |
| `AttackSurfaceSignal` | `TARGETS_WORKFLOW` | `WorkflowSurface` | workflow 系 signal の対象 | 新規 |
| `AttackSurfaceSignal` | `SUPPORTED_BY` | `Evidence` | signal の根拠 | 新規 |
| `AttackSurfaceSignal` | `OBSERVED_IN_SESSION` | `SessionContext` | auth/session 文脈 | 新規 |
| `AttackSurfaceSignal` | `NEARBY_TO` | `AttackSurfaceSignal` | 近傍/類似/連鎖候補 | 新規 |
| `SwarmDecision` | `BASED_ON` | `AttackSurfaceSignal` | 仮説の根拠 | 連携対象 |
| `RecipeRun` | `TRIGGERED_BY` | `AttackSurfaceSignal` | recipe 起動根拠 | 連携対象 |
| `RecipeRun` | `EXECUTED_AS` | `TaskExecution` | task 実行履歴との接続 | 連携対象 |
| `RecipeRun` | `PRODUCED_FINDING` | `Finding` | 結果脆弱性 | 連携対象 |
| `TaskExecution` | `BASED_ON` | `AttackSurfaceSignal` | task 起票根拠 | 連携対象 |
| `TaskExecution` | `RESULTED_IN` | `Finding` | 実行結果 | 連携対象 |
| `SuppressionDecision` | `SUPPRESSES` | `AttackSurfaceSignal` | 抑止対象 | 新規 |
| `Finding` | `CONFIRMED_FROM` | `AttackSurfaceSignal` | 確認元 signal | 連携対象 |
| `Finding` | `AFFECTS_ENDPOINT` | `Endpoint` | 影響対象 | 連携対象 |

#### 2.4.3 運用ルール
- runtime handoff の正本は `AttackSurfaceSignal` とし、KnowledgeGraph は永続メモリとして扱う。
- `Endpoint` や `Parameter` だけを正本にせず、「何を怪しいと見たか」は必ず `AttackSurfaceSignal` に乗せる。
- dedupe は静的 asset key だけでなく、`normalized_key`, `status`, `reason_code` を用いて行う。
- signal の根拠は `Evidence` ノードで分離し、長文全文ではなく snippet/hash/metadata 中心に保持する。
- Swarm / Recipe / MC の判断理由は `SwarmDecision`, `RecipeRun`, `SuppressionDecision` に残し、後から「なぜそう動いたか」を追跡可能にする。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - discovery entries:
    - `url`, `method`, `headers`, `body`
    - `response.status`, `response.headers`, `response.body`
    - `forms`
    - `auth_context`
    - `subdomain_context`
    - `source` (`katana`, `gau`, `httpx`, `caido`, `playwright`)
  - tagging / taxonomy results:
    - `TagMatch`
    - `primary_tag`
    - `confidence`
    - matched parameter names / headers / response snippets
  - MC context:
    - `tech_stack`
    - auth headers / cookies / bearer token
    - previously seen assets / findings / KG lineage
- **出力/結果 (Output):**
  - 成功時:
    - `AttackSurfaceSignal[]` のような normalized signal 集合
    - MC に渡す summary context
    - Swarm / Recipe が使う raw evidence 参照
    - category/count だけでなく、parameter / endpoint / auth flow 単位の判断材料
  - 失敗時:
    - signal 化できない raw entry は evidence として残しつつ `unknown` / `needs_swarm_review` に退避
    - taxonomy mismatch や schema 欠損は fail-soft とし、情報を捨てずに低信頼 signal として扱う
- **制約・ルール:**
  - Recon は raw evidence を捨てず、normalization は「圧縮」ではなく「昇格」にする。
  - MC handoff は `count/tag/file` だけで終わらせず、signal-level evidence を参照できること。
  - 1つの endpoint / parameter が複数 attack label を持てる multi-label 契約にする。
  - `auth`, `callback`, `refresh`, `token`, `file`, `redirect`, `object reference`, `workflow` など、bug bounty で優先度の高い attack surface を first-class に扱う。
  - 既存の `tagged_urls` / `classified_files` / `targets_file` ワークフローとは互換を保ち、段階移行可能にする。
  - 旧来の `discovered_urls`, `form_params`, `query_params`, `js_files` 前提ロジックが残る期間でも、正本は normalized signal 側に寄せる。
  - Recipe selector が後続で使う vocabulary と、Swarm が受ける vocabulary を分断しない。

### 3.1 正規化対象の最小単位
- `endpoint_signal`: URL / method / response class / auth requirement / source lineage
- `param_signal`: parameter name / location(query, body, header, form) / candidate labels / supporting evidence
- `auth_surface_signal`: login, callback, refresh, reset-password, token exchange, session mutation
- `js_surface_signal`: DOM route, sink candidate, dynamic fetch/XHR, route hints
- `file_surface_signal`: upload, download, backup, traversal candidate
- `workflow_signal`: basket/order/payment/realtime/csrf など multi-step 前提の surface

### 3.2 現状の主なギャップ
- Recon 側には豊かな raw 情報があるが、MC 返却の本流は `category / count / file / tags` 中心で圧縮が強い。
- `TaggingFilter.process_to_rich_contexts()` と `SwarmDispatcher.dispatch_rich_url()` の rich path があるのに、本流 handoff で十分に活用されていない。
- `URLClassifier` の extended taxonomy はファイル出力されるが、MC の正本 context へ昇格していない。
- 旧来の `_inject_matching_recipes()` は `target_info.discovered_urls/form_params/query_params/js_files` 前提だが、Recon 本流との接続が弱い。
- `target_info` と `phase_gate` と `tagged_urls` と `targets_file` の間で、どれが正本 signal なのかが曖昧。

### 3.3 v1 の完了条件
- Recon の通常実行で `endpoint_signal_bundle` と `host_surface_summary` が生成され、旧 `file/count/tags` payload がなくても MC の主判断が成立すること。
- `candidate_labels[]`, `why_suspicious`, `source_observations[]`, `auth/session metadata`, `interaction_kind`, `lineage` を含む signal が、少なくとも endpoint / parameter / auth surface の3系統で生成されること。
- `TaggingFilter` / `URLClassifier` / raw collector の結果が signal bundle に統合され、`extended_taxonomy_tags.json` は互換 artifact に降格すること。
- `MasterConductor` が signal bundle を第一優先で読んで routing / priority / follow-up 材料を構築し、`tagged_urls` 再読込は fallback 時だけに限定されること。
- KnowledgeGraph に、MC へ渡したのと同粒度の signal/evidence が保存され、再参照時に signal の理由を追跡できること。
- 旧 handoff と新 handoff の併存期間でも、二重起票・seed 欠落・evidence 消失が回帰テストで防止されること。

## 4. 実装ステップ（AIに指示する手順）
### 4.0 実装フェーズ
- **Phase A: 現状固定**
  - 実コードの current-state と既存 handoff 形式を棚卸しし、どの経路が本流かを固定する。
- **Phase B: 契約追加**
  - `AttackSurfaceSignal` 相当の最小契約を additive に導入し、collector / tagging / taxonomy を signal bundle に寄せる。
- **Phase C: 消費側切替**
  - MC / Swarm / phase gate / recipe selector が signal bundle を第一優先で読むようにする。
- **Phase D: 永続化と縮退**
  - KG 永続化、互換 payload の監視、旧経路縮退の gate 条件を揃える。

### 4.0.1 フェーズ進行ゲート

| Phase | 実行コマンド | 通過条件 | ロールバック条件 |
|---|---|---|---|
| A: 現状固定 | `rg -n "step8_return_to_mc|process_to_rich_contexts|dispatch_rich_url|store_recon_result|set_classified_files" src/recon/pipeline.py src/core/intel/tagging_filter.py src/core/engine/master_conductor.py src/core/engine/swarm_dispatcher.py src/core/infra/knowledge_graph.py src/core/engine/phase_gate.py`<br>`.venv/bin/pytest tests/recon/test_step6_8_final.py tests/recon/test_step8_tagged_url_dedup.py -q` | 現行の writer / reader / fallback 経路が 1 本の棚卸しとして説明でき、Step 8 の基準テストが緑であること。 | 既存テストがこの時点で赤、または本流 handoff と fallback handoff を区別できない場合はコード変更を止め、棚卸し文書化だけで打ち切る。 |
| B: 契約追加 | `.venv/bin/pytest tests/core/intel/test_tagging_filter.py tests/core/validation/test_url_classifier.py tests/recon/test_tagged_uncategorized_promotion.py -q` | `RichUrlContext` / classifier / tagged artifact の既存契約を壊さずに signal 項目を additive に追加でき、targeted テストが緑であること。 | 既存 `tagged_urls` / `classified_files` / sidecar artifact の互換を壊す場合は新契約の field 追加まで戻し、reader 切替に進まない。 |
| C: 消費側切替 | `.venv/bin/pytest tests/core/engine/test_master_conductor_api_candidate_routing.py tests/e2e/test_swarm_routing.py tests/e2e/test_pipeline_mc_handoff.py -q` | MC が signal bundle を第一優先で読んで routing でき、fallback path も維持され、task 作成の正本が `MasterConductor` のみであることをテストと decision trace で説明できること。 | pipeline 側の direct enqueue を残さないと回帰が通らない、または multi-label / suppression の順序が不安定な場合は signal-first reader を feature-compatible な段階まで戻す。 |
| D: 永続化と縮退 | `.venv/bin/pytest tests/core/recon/test_recon_orchestrator.py tests/recon/test_authbypass_replay_enrichment.py tests/recon/test_tagged_uncategorized_promotion.py -q` | KG の追加 writer が既存 `store_recon_result()` を壊さず、legacy handoff 共存中も二重起票と seed 欠落が起きないことを targeted テストで確認できること。 | KG 書き込み追加で runtime 正本が揺れる、または sunset 前に legacy fallback が必要なケースを失う場合は、新 writer と sunset 条件を無効化して互換 payload 優先へ戻す。 |

### 4.0.2 AI にそのまま渡せる実装指示文（コピペ用）

```text
あなたは /home/bbb/Documents/App/Shigoku の実装担当 AI です。
対象タスクは SGK-2026-0261 です。

目的:
- Recon の raw entry を、MC / Swarm / KG が共通利用できる signal bundle に昇格する
- ただし一気に全面刷新せず、既存の tagged_urls / classified_files / file-count-tags 互換を維持する

今回の作業方針:
- additive migration を守る
- Phase C 以降、task 作成の正本は MasterConductor のみとする
- SGK-2026-0260 は consume only、SGK-2026-0262 は補助参照 only とし、schema / vocabulary の変更要求は 0261 に返す
- 既存の tagged_urls 読み戻しや legacy heuristic は fallback として当面残す

今回の実装スライス:
1. current-state を棚卸しし、writer / reader / fallback 経路をコード参照つきで固定する
2. RichUrlContext をベースに、最小の AttackSurfaceSignal 相当 field を additive に追加する
3. pipeline.step8_return_to_mc() が endpoint_signal_bundle と host_surface_summary を返せるようにする
4. MasterConductor が signal bundle を第一優先で読み、旧 tagged_urls 読み戻しは fallback 条件時だけ使うようにする
5. 既存 direct enqueue を縮退させ、task 作成は MasterConductor 正本へ寄せる

今回やらないこと:
- Recipe scoring の詳細設計
- Swarm routing core の全面刷新
- KG 全面再設計

必須ファイル:
- src/recon/pipeline.py
- src/core/intel/tagging_filter.py
- src/core/models/url_context.py
- src/core/engine/master_conductor.py
- 必要に応じて src/core/engine/phase_gate.py, src/core/infra/knowledge_graph.py

必須制約:
- 既存 public behavior を壊さない
- file/count/tags 互換 payload を残す
- sidecar の extended_taxonomy_tags.json は互換 artifact として残してよい
- low-value/static 除外で high-value surface を落とさない
- raw evidence を捨てない

必須検証:
- Phase A: .venv/bin/pytest tests/recon/test_step6_8_final.py tests/recon/test_step8_tagged_url_dedup.py -q
- Phase B: .venv/bin/pytest tests/core/intel/test_tagging_filter.py tests/core/validation/test_url_classifier.py tests/recon/test_tagged_uncategorized_promotion.py -q
- Phase C: .venv/bin/pytest tests/core/engine/test_master_conductor_api_candidate_routing.py tests/e2e/test_swarm_routing.py tests/e2e/test_pipeline_mc_handoff.py -q
- Phase D: .venv/bin/pytest tests/core/recon/test_recon_orchestrator.py tests/recon/test_authbypass_replay_enrichment.py tests/recon/test_tagged_uncategorized_promotion.py -q

完了条件:
- MC が signal bundle を第一優先で読める
- fallback path が壊れていない
- task 作成の正本が MasterConductor に一本化されている
- targeted tests が通る

最終報告:
- 何を変えたか
- なぜ変えたか
- 実行した検証コマンドと結果
- 残リスク
```

### 4.0.3 最短着手順（最初の 1 スライス）

1. `src/recon/pipeline.py` と `src/core/engine/master_conductor.py` の現行 handoff を棚卸しし、`step8_return_to_mc()` と `_create_attack_tasks_from_recon()` のつながりを固定する。
2. `src/core/models/url_context.py` と `src/core/intel/tagging_filter.py` に、signal 化で必須な最小 field だけを additive に足す。
3. `src/recon/pipeline.py` に `endpoint_signal_bundle` と `host_surface_summary` を追加しつつ、旧 `file/count/tags` payload は残す。
4. `src/core/engine/master_conductor.py` を signal-first reader に切り替え、旧 `tagged_urls` 読み戻しは fallback 条件時のみ使う。
5. pipeline 側の direct enqueue を縮退させ、task 作成の正本を `MasterConductor` に寄せる。
6. Phase A/B/C の targeted tests を順に実行し、赤になった地点で止めて原因を直す。

### 4.0.4 最初の完了線

- この 1 スライスでは KG の新 writer まで進まなくてよい。
- まずは `step8_return_to_mc()` が新旧 payload を併存返却し、MC が新 payload を優先読取できる状態を最初の完了線とする。
- ここで緑にした後に、KG 永続化と legacy sunset 条件は次の差分で進める。

- [ ] ステップ1: Recon の current-state を棚卸しし、`src/recon/pipeline.py`・`src/core/intel/tagging_filter.py`・`src/core/engine/master_conductor.py`・`src/core/infra/knowledge_graph.py` の現行責務を確認して、raw entry -> tagged file -> MC seed / KG 保存の実経路を明文化する。
- [ ] ステップ2: v1 の正本 signal は新規の大規模 schema から始めず、`RichUrlContext` を最小拡張した `AttackSurfaceSignal` 相当として扱う方針を固定し、`candidate_labels[]`, `confidence`, `why_suspicious`, `source_observations[]`, `auth/session metadata`, `subdomain_context`, `interaction_kind`, `actor/session label`, `lineage` を必須項目として定義する。あわせて `RichUrlContext` は移行用入力契約、`AttackSurfaceSignal` は正本出力契約であることを明文化し、reader/writer ごとの責務、生成元、参照元を 1 枚の契約表にまとめる。
- [ ] ステップ2.1: `host_surface_summary` と `endpoint_signal_bundle` の責務を分離し、それぞれの必須フィールド、粒度、件数上限、summary/詳細の責務境界を表形式で定義する。加えて「入れてよい項目 / 入れてはいけない項目」を列として持たせ、host 粒度と endpoint 粒度の責務混在を禁止する。
- [ ] ステップ2.2: `run_id`, `observation_id`, `signal_id` の追跡ID規約を定義し、raw entry -> signal -> task -> finding まで一意に辿れる trace contract を決める。あわせて各 ID をどの artifact / log / decision trace / KG node に必ず残すかの伝播表を追加する。
- [ ] ステップ2.3: `SGK-2026-0260` と `SGK-2026-0262` との依存境界を固定し、0261 が凍結する schema / vocabulary、0260 が consume のみ行う範囲、0262 が補助参照に留める範囲を明文化する。変更要求の返し先もここで決める。
- [ ] ステップ3: signal の dedupe 方針を先に固定し、`method + normalized_url` の先着勝ちで潰すのではなく、同一 endpoint に対する Katana / GAU / Httpx / Caido / Playwright の観測を `source_observations[]` に束ねる設計へ変更する。特に Katana は URL 一致だけで method / form signature / interaction 差分を捨てないこと、Caido の認証付き観測や Playwright の動的観測が静的ソースに上書きされて消えないことを設計条件にする。
- [ ] ステップ3.5: multi-label signal の優先順位、tie-break、routing reason の表現形式を定義し、同じ signal が複数 specialist 候補へ流れる場合でも説明順と抑制順が一定になるようにする。decision trace に出す並び順、文字列表現、top-N 制御、suppression 適用順もここで固定する。
- [ ] ステップ4: `src/core/intel/tagging_filter.py` と `src/core/models/url_context.py` を起点に、entry 直下の `auth_context`, `subdomain_context`, `forms`, `response_headers`, `response_body_snippet`, `TagMatch.param_name`, `matched_on`, `matched_value` を落とさず signal に昇格させる。parameter-level の根拠と endpoint-level の根拠を分けて保持する。
- [ ] ステップ4.5: static/low-value 抑止の例外条件を定義し、JS asset, signed URL, callback, websocket/realtime, upload/download, admin port, token exchange などは単純除外しないルールへ整理する。また `unknown` / `needs_swarm_review` に入る条件と再評価条件もここで決める。
- [ ] ステップ5: `src/recon/pipeline.py` の raw collector 正規化を揃え、Katana / GAU / Httpx / Caido / Playwright から入る entry を同じ観測契約へ寄せる。GAU は履歴 URL を host 抽出だけで終わらせず、`observed_method` が不明な history-derived surface として扱う。特に Caido は authenticated runtime evidence source、Playwright は dynamic interaction evidence source として扱い、`seed_url`, `discovered_via`, `form_exercised`, `route_hint`, `fallback_used` を保持する。
- [ ] ステップ5.5: signal 生成失敗時の fail-soft 契約を実装し、entry を黙って捨てず `unknown` / `needs_swarm_review` / suppression reason / replay_hint とともに残す。あわせて `reason_code`, `dropped_fields`, `source_stage`, `evidence_ref` を持つ失敗封筒を定義し、再評価キューへ戻す条件を決める。
- [ ] ステップ6: `src/recon/pipeline.py` で `URLClassifier` を sidecar ファイル扱いにせず、primary signal へ統合する。`extended_taxonomy_tags.json` は互換用に残してよいが、MC に渡す正本は `candidate_labels[]` / `primary_label` / `confidence` を含む signal bundle とする。callback, presigned URL, websocket, admin port, token exchange などの高価値 surface を taxonomy 回帰ケースへ追加する。
- [ ] ステップ7: `src/recon/pipeline.py` で、既存の `tagged_urls` 出力を維持しつつ、MC handoff を `host_surface_summary` と `endpoint_signal_bundle` に分離する。あわせて `sources_attempted`, `errors`, `fallback_used`, `budget_exhausted`, `coverage_confidence` を持つ `exploration_report` を返し、MC が「何が見つかったか」だけでなく「どこまで掘れたか」も判断できるようにする。
- [ ] ステップ7.2: `exploration_report` と signal/evidence の保持期間、件数上限、要約条件、圧縮条件を定義し、fallback 件数・source別失敗率・coverage_confidence 逸脱を監視できるメトリクス項目を追加する。`raw` / `summary` / `signal` ごとの retention matrix、容量超過時の圧縮開始条件、削減順序、監視対象を表で固定する。
- [ ] ステップ7.3: `fallback_reason_code`, source 別成功率、`coverage_confidence` の警戒しきい値と hard gate 条件を定義し、本流劣化が発生したときに「警告だけで流す」のか「完了扱いを止める」のかを明文化する。
- [ ] ステップ7.5: Recon 実行プロファイルを `single_url` / `host` / `wildcard_bugbounty` などのモードで切り替えられるようにし、単一 URL テストでは現行の軽量フローを維持しつつ、広域探索モードでは subdomain / asset inventory / historical replay / dynamic replay の breadth を段階的に拡張できるようにする。
- [ ] ステップ7.6: 認証付き Recon では `anon`, `user`, `elevated` の観測プロファイルを比較可能にし、資格情報の値自体を含む cache key と失効時の再観測ルールを定義する。credential fingerprint の作り方、401/302/権限差分/導線差分が出たときの invalidation 条件、再観測の優先順位もここで固定する。
- [ ] ステップ8: `src/core/engine/master_conductor.py` は signal bundle を第一優先で読み、`target_info`, phase gate, priority boost, swarm params, recipe selection input を `candidate_labels`, `why_suspicious`, `source_count`, `auth_required`, `interaction_kind`, `actor/session label` などの構造化 field から組み立てる。既存の `tagged_urls` 読み戻し経路と文字列ヒューリスティクスは fallback / replay 用として当面維持する。
- [ ] ステップ8.2: MC では happy path 時に signal bundle のみで routing し、fallback path に入った場合だけ `tagged_urls` 再読込や legacy heuristic を使う gate 条件を実装する。multi-label の並び順、suppression 適用順、routing reason を task params と decision trace に残し、trace の最小出力例も固定する。
- [ ] ステップ9: `src/core/infra/knowledge_graph.py` には既存の `store_recon_result()` を置き換えず、signal 永続化専用の入口を追加し、`Endpoint` / `Parameter` / `Evidence` と signal の関連だけを最小スコープで保存する。v1 では `AttackSurfaceSignal` の全文正規化よりも「MC に渡した signal bundle を同じ粒度で保存・再参照できること」を優先する。
- [ ] ステップ9.2: KG の read precedence を定義し、同一実行中はメモリ上の signal bundle を正本、再実行時や cross-run 比較時は KG を補助参照に使う順序を固定する。MC -> Swarm -> Recipe の reader 切替順と、reader が判断に使ってよい source の優先順位もここで揃える。
- [ ] ステップ10: `src/core/engine/swarm_dispatcher.py` と既存の tag taxonomy は全面刷新せず、signal から抽出した tag 群を現行 dispatcher に渡す互換経路を先に通す。`dispatch_rich_url()` 系の本流化や新 routing core は v1 完了後の差分課題として切り出す。
- [ ] ステップ10.5: `SuppressionDecision` の最低契約として `reason_code`, `evidence_ref`, `replay_hint` を必須化し、unknown/suppressed signal の再評価条件と task 再生成条件を Swarm/MC 間で共有する。
- [ ] ステップ11: legacy keys (`discovered_urls`, `form_params`, `query_params`, `js_files`) との互換層を定義し、旧 handoff と signal handoff が同時に存在しても二重起票や seed 欠落が起きないことを確認する。JS surface は static asset として単純除外せず、route leak / API leak / schema leak source として残す方針を明文化する。
- [ ] ステップ11.1: 旧 handoff と新 handoff の共存期間における dedupe key、decision trace 必須項目、0260/0262 への受け渡し境界、schema freeze 条件を文書化し、同時並行で別方言が増えない migration rule を定義する。
- [ ] ステップ11.2: legacy handoff の sunset 条件を定義し、何回の正常 run / どの回帰テスト / どのメトリクス水準を満たしたら fallback-only に縮退するか、どんな失敗で rollback するかを明文化する。
- [ ] ステップ11.5: full port scan や新規 web port 発見後に、その host / port を再度 `httpx -> katana -> dynamic recon` へ戻す再帰フローを課題化し、`8080/8443/admin port` などの新規 web surface が Recon の本流から取りこぼされないようにする。
- [ ] ステップ12: tests / docs で Recon breadth、source 観測統合、Caido の auth 付き evidence 保持、Playwright の dynamic evidence 保持、parameter-level signal、MC handoff、coverage report、KG 永続化、Swarm routing の回帰観点を固定する。
- [ ] ステップ12.1: fallback メトリクス、credential invalidation、trace IDs、happy path / fallback path の分離、unknown 再評価、suppression reason、callback/presigned URL/websocket/admin port などの高価値ケースを回帰テストへ追加する。
- [ ] ステップ12.2: fail-soft 失敗封筒、decision trace の並び順、retention / hard gate 条件、legacy sunset 条件、0260/0262 依存境界が崩れた場合の検知テストを追加し、「終わったと言える線」を自動で検証できるようにする。

### 4.1 テスト観点
- 同じ parameter から `sqli`, `xss`, `ssrf`, `redirect`, `idor` の複数候補が signal 化されること。
- 同一 endpoint に対する Katana / GAU / Httpx / Caido / Playwright の観測が `source_observations[]` として統合され、先着勝ちで evidence が欠落しないこと。
- `TaggingFilter` と `URLClassifier` の結果が sidecar ファイルだけでなく primary signal に統合されること。
- `auth_context`, `subdomain_context`, `response_headers`, `forms`, `response_body_snippet`, `TagMatch.param_name` が signal evidence として保持されること。
- low-value static URL を落としつつ、本当に攻撃面がある動的 endpoint は捨てないこと。
- `exploration_report` に `sources_attempted`, `errors`, `fallback_used`, `budget_exhausted`, `coverage_confidence` が入り、探索の深さと限界を後続が判断できること。
- `target_info` legacy keys が必要な旧経路でも破綻しないこと。
- Recipe selector / direct swarm router が同じ normalized vocabulary を見て判断できること。
- signal 生成に失敗した entry が黙って消えず、`unknown` / `needs_swarm_review` / suppression reason とともに追跡可能であること。
- fail-soft 時に `reason_code`, `dropped_fields`, `source_stage`, `evidence_ref` が失敗封筒として残り、後から再現調査できること。
- happy path では MC が `tagged_urls` 再読込なしで signal bundle のみから routing でき、fallback path では旧経路が壊れていないこと。
- 旧 payload と新 payload の両方が存在する移行期間に、同一 evidence から二重 task が起きないこと。
- `fallback_reason_code`, source 別成功率、`coverage_confidence` しきい値が `exploration_report` と監視メトリクスで一致し、hard gate 条件を自動判定できること。
- legacy handoff の sunset 条件と rollback 条件が文書と回帰テストの両方で一致していること。

## 5. 懸念点と対策 / 既知のリスクと次回の申し送り
### 5.1 懸念点と対策
#### 5.1.1 SRE / インフラ視点
- [ ] 懸念: `exploration_report` や signal/evidence が増えたときの保持期間、上限件数、圧縮条件が未定で、保存量が膨らみやすい。【発生確率:高】【影響度:中】
  - 対策: `exploration_report`、signal、evidence の retention、件数上限、summary 化条件、圧縮条件を定義し、`raw` / `summary` / `signal` ごとの retention matrix と容量超過時の圧縮開始条件を計画書へ追記する。
- [ ] 懸念: fallback を使った回数、source 別失敗率、coverage 低下が見えないと、本流が壊れても気づきにくい。【発生確率:高】【影響度:大】
  - 対策: `fallback_used` 件数、source 別失敗率、`coverage_confidence` 逸脱を監視項目として `exploration_report` とメトリクスへ追加し、警戒しきい値と hard gate 条件を「警告で継続」「完了停止」に分けて定義する。
- [ ] 懸念: 認証付き Recon で資格情報が失効・変更しても cache key が粗いと stale な結果を再利用してしまう。【発生確率:中】【影響度:大】
  - 対策: `anon/user/elevated` ごとに資格情報の値を含む cache key と失効時の再観測ルールを定義し、credential fingerprint、401/302/権限差分による invalidation 条件、再観測優先順位を計画書に追加する。

#### 5.1.2 ソフトウェアアーキテクト視点
- [ ] 懸念: `RichUrlContext` と `AttackSurfaceSignal` の責務境界が曖昧だと、移行期に別方言が増える。【発生確率:高】【影響度:大】
  - 対策: `RichUrlContext` は移行用入力契約、`AttackSurfaceSignal` は正本出力契約と定義し、reader/writer・生成元・参照元を 1 枚の契約表に固定する。
- [ ] 懸念: `host_surface_summary` と `endpoint_signal_bundle` のフィールド境界が曖昧だと、host 粒度と endpoint 粒度の責務が混ざる。【発生確率:中】【影響度:中】
  - 対策: 両 payload の必須フィールド表、件数上限、summary/詳細の境界を計画書で定義し、「入れてよい項目 / 入れてはいけない項目」を明示する。
- [ ] 懸念: KG 保存後に、実行中メモリと KG のどちらを正本として読むかが曖昧だと、reader が揺れる。【発生確率:中】【影響度:大】
  - 対策: 同一実行中はメモリ上の signal bundle を正本、cross-run 参照時は KG を補助参照とする read precedence を固定し、MC -> Swarm -> Recipe の reader 切替順も明文化する。

#### 5.1.3 デバッガー視点
- [ ] 懸念: raw entry から task/finding までを辿る追跡IDが弱いと、原因調査が難しい。【発生確率:高】【影響度:中】
  - 対策: `run_id`, `observation_id`, `signal_id` の trace contract を追加し、すべての主要 artifact に残す。どの log / task / KG / decision trace に残るかの伝播表も併記する。
- [ ] 懸念: multi-label signal の並び順や suppression 適用順が固定されないと、同じ入力でも説明が揺れる。【発生確率:中】【影響度:中】
  - 対策: label priority、tie-break、routing reason の表現形式を定義し、decision trace に残す。並び順、top-N 制御、suppression 適用順、trace 出力例まで固定する。
- [ ] 懸念: suppression が起きても `reason_code` だけでは不足し、何を見て止めたか再現しにくい。【発生確率:中】【影響度:中】
  - 対策: `SuppressionDecision` に `reason_code`, `evidence_ref`, `replay_hint` を必須化し、fail-soft 失敗封筒にも `dropped_fields`, `source_stage` を残す。

#### 5.1.4 CTO 視点
- [ ] 懸念: v1 の完了条件はあるが、「どこまでできたら完了と言えるか」の gate がまだ定量化しきれていない。【発生確率:高】【影響度:大】
  - 対策: normal run での signal-first routing、`tagged_urls` fallback-only 化、hard gate 条件、回帰テスト一致を完了判定の必須 gate として計画書に追記する。
- [ ] 懸念: `SGK-2026-0260` / `SGK-2026-0262` との境界が揺れると、schema 凍結前に後続タスクへ影響が広がる。【発生確率:中】【影響度:大】
  - 対策: 0261 が凍結する schema / vocabulary、0260 が consume のみ行う範囲、0262 が補助参照に留める範囲、変更要求の返し先を依存境界表として追加する。
- [ ] 懸念: legacy handoff と signal handoff の共存期間が長引くと、運用コストと複雑さが固定化する。【発生確率:高】【影響度:大】
  - 対策: legacy handoff の sunset 条件、rollback 条件、正常 run 回数、必要な回帰テスト、許容メトリクス水準を計画書に追加し、縮退判断を人依存にしない。

#### 5.1.5 ハッカー視点
- [ ] 懸念: taxonomy が callback, presigned URL, websocket, admin port, token exchange を弱く扱うと、高価値の攻撃面を見逃す。【発生確率:高】【影響度:大】
  - 対策: これらを high-value surface として taxonomy と回帰ケースへ明示追加する。
- [ ] 懸念: `unknown` / `needs_swarm_review` に入った対象の再評価ルールが弱いと、有望な signal が埋もれる。【発生確率:中】【影響度:大】
  - 対策: unknown 系 signal を再評価キューへ戻す条件と、task 再生成条件を定義する。
- [ ] 懸念: static/low-value 抑止が強すぎると、JS 由来の API leak や signed URL、download/upload 面を捨てる。【発生確率:中】【影響度:大】
  - 対策: static 除外の例外条件を定義し、JS asset、signed URL、download/upload、realtime 導線を単純除外しない。

### 5.2 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] signal schema を急ぎで作ると、TaggingFilter / URLClassifier / MC / Recipe で別方言が残る - 正本 vocabulary を 1 つに固定してから配線する。
- [ ] [重要度:高] breadth を維持したまま evidence を増やすと context サイズが肥大化する - summary と raw evidence 参照を分離する。
- [ ] [重要度:高] GAU は実質 `GET` 中心の履歴 surface であり、method 不明のまま `GET` 正本に昇格させると誤学習を招く - history-derived observation と live-observed method を分離して扱う。
- [ ] [重要度:中] multi-label 化で specialist fan-out が増えすぎる - suppression key, confidence threshold, top-N policy を同時に設計する。
- [ ] [重要度:中] legacy handoff と新 handoff の共存期間に二重起票が起こる - migration 期間は decision trace と dedupe を必須にする。
- [ ] [重要度:中] MC 主体と Swarm 主体の責務境界が曖昧なままだと設計がぶれる - MC final gate を基本線にしつつ、Swarm は suggestion に寄せる前提で比較する。
- [ ] [重要度:中] bug bounty 観点の意味づけが URL taxonomy に偏ると、workflow / authz / token trust boundary の表現力が不足する - endpoint 以外の signal 型を first-class に追加する。
- [ ] [重要度:中] 単一 URL テスト用の軽量 Recon と wildcard bug bounty 用の広域 Recon が同一設定だと、探索 breadth と速度のどちらかが不自然に犠牲になる - Recon profile / mode で切り替える。
- [ ] [重要度:中] full port scan で見つかった新規 web service が URL Recon に再投入されないと、高価値の管理ポートや別 origin を取りこぼす - port->URL recon 再帰を追跡課題にする。
- [ ] [重要度:中] takeover_candidates が NXDOMAIN 列挙で止まると、provider fingerprint / reclaimability / dangling CNAME まで届かない - 自動 fingerprint と AI 補助判定の分界を設計する。

### 5.3 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0261-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
