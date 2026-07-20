---
task_id: SGK-2026-0259
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0221
related_docs:
- docs/shigoku/subtasks/2026-06-03_sgk-2026-0260_recipe-recon-swarm_subtask_plan.md
- docs/shigoku/plans/2026-05-19_sgk-2026-0221_mock-optimizedreciperunner-discovery-graphql_plan.md
- docs/shigoku/subtasks/2026-05-20_sgk-2026-0221-s01_groupa_execution-path_subtask_plan.md
- docs/shigoku/roadmaps/2026-06-03_continuous-learning-architecture-reference.md
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
- docs/shigoku/roadmaps/future_functions1.md
title: 'Recipe高度化: 単一セッション高額Auth/JWT/OAuth検出強化'
created_at: '2026-06-03'
updated_at: '2026-07-21'
tags:
- shigoku
target: src/core/engine/recipe_loader.py, src/core/engine/master_conductor.py, recipes/auth,
  recipes
---

# 実装計画書：Recipe高度化: 単一セッション高額Auth/JWT/OAuth検出強化

本計画の実装検討・実装時は、継続学習の理想責務と判断原則を固定した参照資料
[2026-06-03_continuous-learning-architecture-reference.md](../../roadmaps/2026-06-03_continuous-learning-architecture-reference.md)
を必ず参照し、KG を runtime facts の正本、RAG を hypothesis advisor、Recipe を deterministic verification として扱う前提を崩さずに判断すること。

## 0. `SGK-2026-0260` との前後関係
- `SGK-2026-0260` が先に selector / runner / vocabulary の共通契約を固める。
- 本タスクはその後段として、Auth/JWT/OAuth 向けの具体 Recipe 内容、trigger 値、evidence 条件を載せる。
- 同一スプリントで連続実施してよいが、共通契約の再設計が必要になった場合は 0259 で抱え込まず 0260 に返す。

## 1. 達成したいゴール（ユーザー視点）
- [ ] SHIGOKU が単一セッションだけで成立する高額 Auth/JWT/OAuth 不備を、既存 Recon / Discovery / Session 情報から自動選抜し、低ノイズで再現性高く検出できること。
- [ ] `SGK-2026-0260` で整備する自動選抜経路の上で、対象の認証サーフェスが見つかった時だけ高期待値 Recipe を注入し、不要な全件実行を避けられること。
- [ ] Blind/OOB/複数アカウントを前提にしない `probe -> confirm -> evidence` 実行で、即時観測可能な差分だけを根拠として保持できること。
- [ ] JWT/OAuth/Session 系を第一優先とし、認証不変条件に直結する周辺ケースへ段階的に広げられること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/recipe_loader.py`: （最小追従）`SGK-2026-0260` で固定した trigger vocabulary 上で auth/jwt/oauth recipe を登録する。
  - `src/core/engine/master_conductor.py`: （最小追従候補）`SGK-2026-0260` の選抜経路から auth recipe 群が呼ばれる配線を確認する。
  - `src/core/engine/optimized_runner.py`: （追従候補）`SGK-2026-0260` の stage / evidence 契約で auth recipe が流れることを確認する。
  - `src/core/engine/recipe_contracts.py`: （原則参照）`SGK-2026-0260` で凍結した共通契約を利用する。新規共有フィールド追加は原則しない。
  - `recipes/auth/*.yaml`: （新規/修正）JWT/OAuth/Session 用の高額・単一セッション向け Recipe 群。
  - `tests/unit/engine/test_recipe_contracts.py`: （修正）固定済み schema 上で auth recipe 定義が成立することを検証する。
  - `tests/core/engine/test_master_conductor_recipe_contracts.py`: （修正）auth surface 入力時に auth recipe が適切に候補化されることを検証する。
  - `tests/unit/engine/test_optimized_runner.py`: （修正）auth recipe の stage 実行・evidence・stop condition を検証する。
- **データの流れ / 依存関係:**
  - `SGK-2026-0260` で整備する auth surface signal / token / session metadata / supporting context -> auth recipe metadata と照合。
  - score 上位の auth Recipe -> `master_conductor._load_recipe_tasks()` で task 注入 -> `OptimizedRecipeRunner` が stage 単位に step 実行。
  - step 実行結果 -> success signals / failure signals / stop conditions 評価 -> evidence を構造化して session / finding / logs に保持。
  - evidence が閾値到達 -> confirmed 相当の verdict 候補として後続の reporting / chain 化に受け渡し。

### 2.1 Recipe 設計方針
- Recipe は「全手順書」ではなく、「高価値シグナルが揃った時だけ動く仮説検証パイプライン」として扱う。
- Recipe 実行は `probe -> confirm -> evidence` の 3 段固定を基本とし、各段で十分な根拠が出た場合のみ次段へ進む。
- success は「レスポンスが変わった」ではなく、「本来拒否される操作の成功」「本来見えない capability の可視化」「token/session invariant の破綻」といった即時観測可能な差分に限定する。
- 共通の selector / runner / vocabulary 契約は `SGK-2026-0260` を正本とし、本計画ではそれを再設計しない。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - `SGK-2026-0260` で固定する `AttackSurfaceSignal` / `AuthSurface` / `supporting_context`
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
  - `SGK-2026-0260` 側の score / top-N / injection policy を前提にし、本計画で別ロジックを増やさない。
  - 中心スコープは `JWT/OAuth/Session` とし、認証不変条件の確認に直結しない Hidden Capability / 管理 API probe は必須作業から外す。
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

### 3.2 Trigger / Success モデル
- `trigger.required_signals`
  - bearer token あり
  - session cookie あり
  - `/login`, `/oauth`, `/callback`, `/refresh`, `/session`, `/me`, `/settings` 系 endpoint 検出
- `trigger.optional_signals`
  - JWT 風 token 文字列
  - GraphQL / OpenAPI / JS bundle からの auth-related capability 発見
  - callback / token / consent / remember-me / mfa / role / scope 語彙
- `success_signals`
  - 本来失敗すべき遷移が成功する
  - 権限/role/capability の表現が前後で破綻する
  - refresh / callback / session introspection / profile change 前後で整合しない応答を返す
- `stop_conditions`
  - auth surface 不足
  - evidence が弱いまま confirm 失敗
  - rate limit / WAF / safety constraint 発動
  - unsupported action / missing prerequisite

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `SGK-2026-0260` で凍結した recipe schema / selector / runner 契約を前提に、auth/jwt/oauth recipe authorship に必要な metadata 項目を埋める。共通契約の追加変更は原則行わない。
- [ ] ステップ2: `recipes/auth/` に `oauth_binding_drift`, `session_invariant`, `jwt_claim_enforcement`, `refresh_rotation` の Recipe を追加/更新する。
- [ ] ステップ3: 既存 auth 関連 YAML を fixed contract へ最小移行し、`required_signals` / `success_signals` / `stop_conditions` / `evidence_policy` を auth invariants 中心に整える。
- [ ] ステップ4: `recipe_loader.py` / `master_conductor.py` の最小配線を確認し、`SGK-2026-0260` の自動選抜経路から auth recipe 群が正しく候補化されるようにする。
- [ ] ステップ5: `optimized_runner.py` とテストで、各 Recipe の `probe -> confirm -> evidence` が共通 stage 契約に収まることを確認する。契約不足があれば 0259 で拡張せず 0260 へ返す。
- [ ] ステップ6: docs とテストで auth/jwt/oauth 用途を明文化し、Hidden Capability / 管理 API probe は後続候補として backlog 扱いにする。

### 4.1 テスト観点
- `RecipeLoader`:
  - auth surface signal と token/session metadata がある時だけ auth Recipe が候補化される。
  - unrelated Recipe が auth 入口だけで昇格しない。
- `MasterConductor`:
  - `SGK-2026-0260` の自動選抜経路から auth surface がある時だけ高価値 Recipe を注入する。
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
- [ ] [重要度:高] `SGK-2026-0260` の shared contract が未凍結のまま 0259 を進めると、YAML と配線が往復修正になる - 0260 完了条件に selector / runner / vocabulary 固定を含め、0259 はその後に着手する。
- [ ] [重要度:高] auth surface metadata の収集が不十分だと score が不安定になる - Discovery / browser / API 観測の正規化キーを先に固定する。
- [ ] [重要度:高] `action` を allowlist に追加しただけでは technique の意図や実行方法が十分伝わらず、キーワード依存の曖昧な LLM 判断に寄りやすい - `action vocabulary` ごとに routing、required inputs、success signals、stop conditions、specialist/tool binding をセットで設計する。
- [ ] [重要度:中] success_signals が弱いと false positive が増える - confirmed 判定は evidence 密度の閾値制にして、単一差分のみでは昇格しない。
- [ ] [重要度:中] OAuth / Session のアプリ差異が大きく、汎用 Recipe が過適合する可能性 - provider 固有ではなく invariants 中心で Recipe を記述する。
- [ ] [重要度:低] Hidden Capability / 管理 API probe は本スプリント主スコープ外になる - 必要なら auth invariant と切り分けて別 task/subtask として追加する。
- [ ] [重要度:低] 将来の multi-account / OOB 系と schema をどう共存させるか未整理 - 本計画では single-session profile を正本とし、別 profile として後日拡張する。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0259-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
