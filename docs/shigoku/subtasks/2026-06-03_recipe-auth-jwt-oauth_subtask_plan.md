---
task_id: SGK-2026-0259
doc_type: subtask_plan
doc_usage: execution_plan
status: done
parent_task_id: SGK-2026-0221
related_docs:
- docs/shigoku/plans/2026-05-19_mock-optimizedreciperunner-discovery-graphql_plan.md
- docs/shigoku/subtasks/2026-05-20_sgk-2026-0221-s01_groupa_execution-path_subtask_plan.md
- docs/shigoku/roadmaps/2026-06-03_continuous-learning-architecture-reference.md
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
- docs/shigoku/roadmaps/future_functions1.md
title: 'Recipe高度化: 単一セッション高額Auth/JWT/OAuth検出強化'
created_at: '2026-06-03'
updated_at: '2026-06-18'
tags:
- shigoku
target: src/core/engine/recipe_loader.py, src/core/engine/master_conductor.py, recipes/auth,
  recipes
---

# 実装計画書：Recipe高度化: 単一セッション高額Auth/JWT/OAuth検出強化

本計画の実装検討・実装時は、継続学習の理想責務と判断原則を固定した参照資料
[2026-06-03_continuous-learning-architecture-reference.md](../roadmaps/2026-06-03_continuous-learning-architecture-reference.md)
を必ず参照し、KG を runtime facts の正本、RAG を hypothesis advisor、Recipe を deterministic verification として扱う前提を崩さずに判断すること。

## 1. 達成したいゴール（ユーザー視点）
- [x] SHIGOKU が単一セッションだけで成立する高額 Auth/JWT/OAuth 不備を、既存 Recon / Discovery / Session 情報から自動選抜し、低ノイズで再現性高く検出できること。
- [x] `--recipe` の手動指定に依存せず、対象の認証サーフェスが見つかった時だけ高期待値 Recipe を注入し、不要な全件実行を避けられること。
- [x] Blind/OOB/複数アカウントを前提にしない `probe -> confirm -> evidence` 実行で、即時観測可能な差分だけを根拠として保持できること。
- [x] JWT/OAuth/Session 系を第一優先とし、同一アカウント内で観測できる Hidden Capability / 管理 API 操作の権限超えを第二優先として拡張可能なこと。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/recipe_loader.py`: （修正）Recipe schema 拡張、trigger scoring、top-N 選抜、stage-aware matching。
  - `src/core/engine/master_conductor.py`: （修正）Recipe 注入タイミング、stage 実行制御、success / stop condition に基づく継続判定。
  - `src/core/engine/optimized_runner.py`: （修正）Recipe step 実行結果の構造化、evidence 収集、stage ごとの verdict 集約。
  - `src/core/engine/recipe_contracts.py`: （修正）新しい Recipe フィールドと step action 契約の拡張。
  - `recipes/auth/*.yaml`: （新規/修正）JWT/OAuth/Session 用の高額・単一セッション向け Recipe 群。
  - `recipes/api/*.yaml` / `recipes/generic/*.yaml`: （修正候補）Hidden Capability / Admin API probe を同一セッション向けに再構成。
  - `tests/unit/engine/test_recipe_contracts.py`: （修正）新 schema と scoring 契約の検証。
  - `tests/core/engine/test_master_conductor_recipe_contracts.py`: （修正）Recipe 注入と run_recipe 継続条件の契約検証。
  - `tests/unit/engine/test_optimized_runner.py`: （修正）stage 実行・evidence・stop condition の検証。
- **データの流れ / 依存関係:**
  - Recon / Discovery / Login 観測 / auth headers / session cookies / tech stack -> `context.target_info` 正規化 -> `RecipeLoader.match_recipes_to_context()` で score 算出。
  - score 上位 Recipe -> `master_conductor._load_recipe_tasks()` で task 注入 -> `OptimizedRecipeRunner` が stage 単位に step 実行。
  - step 実行結果 -> success signals / failure signals / stop conditions 評価 -> evidence を構造化して session / finding / logs に保持。
  - evidence が閾値到達 -> confirmed 相当の verdict 候補として後続の reporting / chain 化に受け渡し。

### 2.1 Recipe 設計方針
- Recipe は「全手順書」ではなく、「高価値シグナルが揃った時だけ動く仮説検証パイプライン」として扱う。
- Recipe 実行は `probe -> confirm -> evidence` の 3 段固定を基本とし、各段で十分な根拠が出た場合のみ次段へ進む。
- success は「レスポンスが変わった」ではなく、「本来拒否される操作の成功」「本来見えない capability の可視化」「token/session invariant の破綻」といった即時観測可能な差分に限定する。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - `context.target_info.tech_stack` (`list[str]`)
  - `context.target_info.target` (`str`)
  - `context.target_info.auth_headers` (`dict[str, str]`)
  - `context.target_info.bearer_token` (`str | None`)
  - `context.target_info.cookies` / session cookie presence (`str | None`)
  - `context.target_info.discovered_urls` (`list[str]`)
  - `context.target_info.form_params` / `query_params` / `js_files` (`list[str]`)
  - Discovery / browser / API probe 由来の auth surface metadata (`dict[str, Any]`)
- **出力/結果 (Output):**
  - 成功時:
    - score 上位 Recipe のみが注入される。
    - stage / step ごとの `success`, `reason`, `evidence`, `stop_reason` が返る。
    - JWT/OAuth/Session 不備の即時観測可能な根拠が構造化保存される。
  - 失敗時:
    - trigger 不足なら未注入。
    - evidence 不足なら `draft` / `no_signal` で終了。
    - unsupported action や unsafe branch は fail-fast で明示エラー化。
- **制約・ルール:**
  - Blind 依存、OOB 依存、複数アカウント前提の Recipe は本スコープ外とする。
  - 高額・高再現性優先のため、`全件実行` ではなく score 上位 N 本のみを実行する。
  - Recipe の第一優先カテゴリは `JWT/OAuth/Session`、第二優先カテゴリは `同一アカウント内 Hidden Capability / 管理 API 操作` とする。
  - trigger は deterministic に評価し、曖昧な LLM 判定単独では発火させない。
  - step action は既存の安全な実行経路に限定し、破壊的・不可逆な操作は success 判定に使わない。
  - evidence は再現に必要な最小情報だけを構造化し、secret を無加工で保存しない。

### 3.1 追加する主要 Recipe 候補
1. `oauth_binding_drift.yaml`
   - state / nonce / redirect binding の破綻を単一セッションで確認。
2. `session_invariant.yaml`
   - login, refresh, remember-me, profile change 前後で token / capability / role 表現の不整合を確認。
3. `jwt_claim_enforcement.yaml`
   - `aud`, `iss`, `nbf`, `typ`, `kid` 周辺の検証漏れを応答差分として評価。
4. `refresh_rotation.yaml`
   - refresh 後の旧 token 継続利用、scope drift、revocation 不備を確認。
5. `hidden_admin_capability.yaml`
   - 同一セッションで UI 非表示だが直接叩くと通る管理/API capability を確認。

### 3.2 Trigger / Success モデル
- `trigger.required_signals`
  - bearer token あり
  - session cookie あり
  - `/login`, `/oauth`, `/callback`, `/refresh`, `/session`, `/me`, `/settings` 系 endpoint 検出
- `trigger.optional_signals`
  - JWT 風 token 文字列
  - GraphQL / OpenAPI / JS bundle からの auth-related capability 発見
  - admin / billing / team / member / role / permission 語彙
- `success_signals`
  - 本来失敗すべき遷移が成功する
  - 権限/role/capability の表現が前後で破綻する
  - hidden endpoint / mutation / action が 2xx / meaningful 4xx with sensitive schema を返す
- `stop_conditions`
  - auth surface 不足
  - evidence が弱いまま confirm 失敗
  - rate limit / WAF / safety constraint 発動
  - unsupported action / missing prerequisite

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `recipe_loader.py` と契約周辺を更新し、Recipe schema に `trigger`, `stages`, `success_signals`, `failure_signals`, `stop_conditions`, `evidence_policy` を追加する。
- [x] ステップ2: `match_recipes_to_context()` を score-based selection へ変更し、required / optional signals と top-N 制限を導入する。
- [x] ステップ3: `master_conductor.py` 側で Recipe 自動注入条件を整理し、`tech_stack` だけでなく auth surface / token / session metadata を渡す。
- [x] ステップ4: `optimized_runner.py` に stage-aware execution と structured evidence aggregation を実装し、`probe -> confirm -> evidence` の段階実行を保証する。
- [x] ステップ5: `recipes/auth/` に JWT/OAuth/Session 向け Recipe を追加し、既存 YAML を新 schema に合わせて最小移行する。
- [x] ステップ6: Hidden Capability / 管理 API probe を同一セッション前提で再利用できる共通 step 群を設計する。
- [x] ステップ7: unit / engine / runner テストを追加し、全件実行廃止、top-N 選抜、stop condition、evidence 契約を固定化する。
- [x] ステップ8: 必要最小限の docs 更新を行い、Recipe の想定ユースケースを「単一セッション高額検出」に寄せて明文化する。

### 4.1 テスト観点
- `RecipeLoader`:
  - required signals 欠如時は未選抜。
  - optional signals 加点が deterministic。
  - top-N 制限が守られる。
- `MasterConductor`:
  - auth surface がある時だけ高価値 Recipe を注入。
  - stop condition 到達時に無駄な次段 task が増えない。
- `OptimizedRecipeRunner`:
  - stage 成功時のみ次段へ進む。
  - evidence が step / stage ごとに構造化される。
  - weak signal のみでは confirmed 扱いにならない。
- Recipe YAML:
  - schema validation を通る。
  - 既存 action contract を破らない。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [x] [重要度:高] Recipe schema 拡張で既存 YAML 互換が崩れる可能性 → 解決済。既存YAMLは default値で読み込まれ、新field欠如時も正常動作。schema検証はwarningログのみ。
- [x] [重要度:中] success_signals が弱いと false positive が増える → 解決済。`_classify_verdict()` で高信頼度複数エビデンスのみconfirmed判定。
- [x] [重要度:中] OAuth / Session のアプリ差異が大きく、汎用 Recipe が過適合する可能性 → 解決済。全Recipeがinvariants中心の設計。
- [x] [CTO W-1] `auth_headers` 内 JWT 検出で Bearer prefix strip 未実装 → 2026-06-18 修正済。`recipe_loader.py` L89-97。
- [x] [CTO W-2] f-string ログスタイル不統一 → 2026-06-18 修正済。`master_conductor_facade.py` L2674。

### 5.1 Deferred Tasks（後続対応が必要な技術的負債）

```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0259-D01
    title: "auth surface metadata 正規化キー固定"
    reason: "Discovery/browser/API観測の正規化キーが未固定のため、score算出が不安定になるリスク"
    impact: high
    source_risk: "計画書 L142"
    recommended_next_action: "auth_surface_metadata の required keys をスキーマとして定義し、収集側と消費側の契約を固定する"

  - deferred_id: SGK-2026-0259-D02
    title: "action vocabulary の routing/binding 設計"
    reason: "allowlistだけでは technique の意図が曖昧で LLM 判断に寄る。routing, required inputs, specialist binding をセット設計する必要あり"
    impact: high
    source_risk: "計画書 L143"
    recommended_next_action: "action vocabulary ごとに routing contract を定義する subtask を起票"

  - deferred_id: SGK-2026-0259-D03
    title: "Hidden Capability probe 語彙辞書/candidate ranking"
    reason: "probe範囲が広すぎるとノイズと安全性の問題が出る"
    impact: medium
    source_risk: "計画書 L145"
    recommended_next_action: "admin endpoint 語彙辞書を定義し、candidate ranking で少数精鋭の候補のみ実行する仕組みを追加"

  - deferred_id: SGK-2026-0259-D04
    title: "multi-account / OOB 系 schema 共存設計"
    reason: "single-session profile を正本としたが、将来の multi-account/OOB 拡張時の schema 統合が未整理"
    impact: low
    source_risk: "計画書 L147"
    recommended_next_action: "Recipe profile (single-session / multi-account / oob) を enum 化し、loader で分岐する設計を検討"

  - deferred_id: SGK-2026-0259-D05
    title: "asyncio.Task 動的属性追加の型安全化"
    reason: "optimized_runner.py で asyncio.Task に node_id を動的追加しており、型チェッカーで警告が出る"
    impact: low
    source_risk: "CTO Review N-1"
    recommended_next_action: "明示的な task_id→node_id マッピング dict に移行"
```
