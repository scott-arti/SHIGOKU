---
task_id: SGK-2026-0283
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0278
related_docs:
- docs/shigoku/plans/2026-06-20_sgk-2026-0278_ver-2-planning-bundle-dev-mode-recon_plan.md
- docs/shigoku/specs/bug_bounty_enhancements.md
- docs/shigoku/roadmaps/bug_bounty_enhancements_2026.md
title: Subdomain Takeover高度化計画
created_at: '2026-06-21'
updated_at: '2026-07-02'
tags:
- shigoku
target: src/recon/pipeline.py, src/core/agents/swarm/discovery/takeover.py, src/tools/custom/subjack.py,
  src/commands/intel.py, src/core/engine/recipe_loader.py, src/core/engine/master_conductor.py,
  src/core/engine/optimized_runner.py, src/core/engine/recipe_contracts.py, recipes/recon/takeover.yaml
---

# 実装計画書：Subdomain Takeover高度化計画

## 0. 状態メモ
- 2026-06-24 時点で Phase 1-4 の基盤実装報告を作成。
- 2026-06-25 に全18ステップ (Phase 5-8) の実装を完了。subtask は `done` に移行。
- 継続監視: provider matrix 定期更新 (D01)、aiohttp/dnspython optional deps (D04)。

## 1. 達成したいゴール（ユーザー視点）
- Recon で見つけた死んだサブドメインから、takeover 候補を自動で絞り込める。
- `dead_subs.txt` や `takeover_candidates.json` の単純列挙で終わらず、`dangling CNAME`, `provider fingerprint`, `reclaimability` を段階的に評価できる。
- SHIGOKU が「候補列挙」と「確度の高い検証」を分けて扱い、誤検知だらけの運用から脱却できる。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/recon/pipeline.py`: 現在は `dead_subs` から `takeover_candidates.json` を `NXDOMAIN` 列挙で生成
  - `src/core/agents/swarm/discovery/takeover.py`: `dead_subs.txt` と target から `subjack` を呼んで Finding 化
  - `src/tools/custom/subjack.py`: 既存 takeover ラッパー
  - `src/commands/intel.py`: `subzy` ベースの CLI 実行口
  - `src/core/engine/recipe_loader.py`: takeover Recipe を候補化する selector 契約
  - `src/core/engine/master_conductor.py`: `run_recipe` への task 注入と step dispatch
  - `src/core/engine/optimized_runner.py`: Recipe step 実行、失敗/blocked 判定
  - `src/core/engine/recipe_contracts.py`: Recipe action allowlist
  - `recipes/recon/takeover.yaml`: takeover 用 Golden Recipe
  - 将来候補: provider fingerprint 用モジュール、DNS / HTTP 検証ヘルパ、provider matrix データ
- **データの流れ / 依存関係:**
  - Recon 結果 -> `dead_subs`
  - `dead_subs` + freshness metadata + DNS / CNAME / HTTP 応答 -> fingerprint enrichment
  - enrichment 結果 -> `required_signals` / provider matrix / score
  - score 上位 candidate -> `run_recipe` または `TakeoverSpecialist` / `intel takeover`
  - Recipe 実行結果 + raw evidence + HITL verdict -> normalized `Finding` / report

## 3. 具体的な仕様と制約条件
- **現状整理:**
  - `ReconPipeline` は `dead_subs` から `{\"subdomain\": \"...\", \"status\": \"NXDOMAIN\"}` を書くのみ。
  - `TakeoverSpecialist` は `dead_subs.txt` を読んで `subjack` 実行し、標準出力を regex で解析している。
  - `intel takeover` は `subzy` の raw output を返すが、構造化パースは未実装。
  - `RecipeLoader` は現状 loaded recipe 全件返しに近く、takeover 向け signal selection 契約を持たない。
  - `recipes/recon/takeover.yaml` の step schema と `RecipeLoader` / `OptimizedRecipeRunner` / action allowlist の契約が揃っておらず、選ばれても走らない Recipe になり得る。
- **入力情報 (Input):**
  - `dead_subs`, CNAME, DNS 応答, HTTP status / body / headers
  - provider fingerprints
  - candidate freshness (`first_seen_dead`, `last_seen_dead`, `last_dns_probe`, `last_http_probe`)
  - provider ごとの claim 前提条件、典型 error token、manual verification checkpoint
  - scope 制約と再検証可否
- **出力/結果 (Output):**
  - `dead_only`, `dangling_cname`, `provider_match`, `likely_reclaimable`, `confirmed`
  - provider 名、根拠、再検証URL、必要に応じて HITL 要否
  - `required_signals`, `score_reasons`, `success_condition`, `stop_condition`
  - `cname_chain`, `rcode`, `http_status`, `body_excerpt`, `provider_error_token`, `claim_url_hint` などの raw evidence
  - SHIGOKU 内部で使う normalized evidence
- **制約・ルール:**
  - 次期Ver.では外部 proxy 依存を前提にしない
  - 誤検知を避けるため、`confirmed` へ上げる条件は保守的にする
  - takeover 判定は DNS だけで決めず、provider fingerprint と HTTP 応答を組み合わせる
  - AI は候補の優先順位付け補助に限定し、主軸は手続き的シグナルに置く
  - Recipe trigger の正本は `signal + provider matrix + freshness` とし、LLM は primary trigger に使わない
  - Recipe は deterministic steps を前提とし、各 step に `success condition` と `stop condition` を持たせる
  - claim 可否の最終判断は provider ごとの checkpoint で HITL を許容し、report には automation と HITL の境界を残す

## 3.1 Recipe成功率を上げるための前提契約
- takeover Recipe を走らせる最低条件を `required_signals` として定義する。例:
  - `dns_dead`
  - `cname_dangling`
  - `provider_error_token_detected`
  - `fresh_dead_candidate`
- Recipe は `success_condition` と `stop_condition` を持つ。
  - `success_condition`: provider 判別、dangling 証拠、manual follow-up 先が揃った
  - `stop_condition`: provider 不明、signal stale、claim prerequisite 不足、tool disagreement が大きい
- provider ごとに `claim_prerequisites`, `error_tokens`, `verification_urls`, `manual_checkpoints` を matrix 化し、selector と verifier が同じ正本を参照する。
- `likely_reclaimable` は「自動で乗っ取れる」意味ではなく、「トップバグハンターが次に時間を投下する価値が高い」状態を指す。

## 3.2 HITLを前提にした確認段階
- HITL は最終段だけでなく、中間 checkpoint として使う。
- 例:
  - provider は一致したが claim prerequisite が UI/契約依存
  - tool 間で結果が割れた
  - HTTP error token は強いが CNAME / DNS 系の裏取りが弱い
- この場合は `manual_claim_review_required=true` を持つ候補として残し、Recipe が silent fail しないようにする。

## 3.3 Bounty向けの判定境界
- Subdomain Takeover は、サブドメイン名そのものを取得できるかではなく、CNAME / provider 側の未割当リソースを再確保できるかが本質である。
- SHIGOKU の automation は「取れそうな確信度が高い候補」を絞るところまでを担当し、provider 側で実際に claim / reclaim 可能かの確認は原則 HITL とする。
- bounty 提出前の最終確認では、少なくとも次を人間が確認する:
  - 対象 program の takeover 検証ルールと許可範囲
  - provider 側で該当 resource name / bucket / app / page が作成可能か
  - claim 操作が対象外リソース作成や第三者影響を起こさないか
  - PoC として許される最小限の証跡範囲
- automation は provider UI / CLI 上の作成操作をデフォルトでは実行しない。実行が必要な場合は明示的な HITL 承認と scope 証跡を要求する。
- verdict の意味は次で固定する:
  - `candidate`: dead / dangling / provider hint の一部がある
  - `likely_reclaimable`: provider fingerprint と未割当 error token が揃い、優先確認に値する
  - `manual_review_required`: bounty 化のために provider 側 claim 可否の人手確認が必要
  - `confirmed`: provider matrix 上の高確度条件を満たし、かつ HITL または許可済み read-only 証跡で裏取り済み
  - `no_finding`: takeover として扱える証跡が不足している

## 3.4 懸念点と対策

### 3.4.1 SRE / インフラ視点
- `[発生確率:高][影響度:大]` Fresh-Resolvers 取得が外部依存であり、取得失敗時の運用が不明確。
  - **対策 / 計画書への修正案:** `fetch_resolvers()` 相当の前提として「resolver cache」「TTL」「offline fallback 順序」「fallback 発動時の metric / log」を定義し、read-only 実行でも resolver source を再現できるようにする。
- `[発生確率:高][影響度:大]` stale candidate と tool cache の組み合わせで古い証跡を再利用し、`confirmed` を誤判定する恐れがある。
  - **対策 / 計画書への修正案:** cache key に `candidate_id`, `provider_guess`, probe 時刻帯を含め、stale candidate は cache bypass または再検証必須とする方針を success gate に追加する。
- `[発生確率:中][影響度:大]` `subjack` / `subzy` / `nuclei` 未導入や一時障害時の degrade mode が未定義。
  - **対策 / 計画書への修正案:** provider-aware tool chain の節に「per-tool timeout」「missing binary 時の downgrade」「retryable / non-retryable error code」「preflight 必須条件」を追記する。
- `[発生確率:高][影響度:大]` DNS resolver / HTTP probe / external tool の失敗が、候補なし (`no_finding`) と混同される恐れがある。
  - **対策 / 計画書への修正案:** `no_finding` と `tool_unavailable` / `probe_failed` / `resolver_degraded` を分離し、report と trace に `infrastructure_state` を残す。
- `[発生確率:中][影響度:大]` parallel recon と takeover Recipe が同一 target へ重複 probe し、rate limit や scope guard の予算を過剰消費する。
  - **対策 / 計画書への修正案:** `per-target probe budget`, `dedupe window`, `shared probe cache` を定義し、同一 candidate / provider / probe 種別の再実行を抑制する。
- `[発生確率:中][影響度:中]` provider matrix 更新後の rollback 方針が弱く、品質劣化時に旧挙動へ戻しにくい。
  - **対策 / 計画書への修正案:** provider matrix に `version`, `updated_at`, `source_note`, `rollback_target` を持たせ、shadow mode で旧版比較する手順を追加する。

### 3.4.2 ソフトウェアアーキテクト視点
- `[発生確率:高][影響度:大]` 既存実装済みの `TakeoverCandidate` / provider matrix / success gate を未着手前提で再設計し、差分が不鮮明になる。
  - **対策 / 計画書への修正案:** 状態メモか実装ステップの冒頭に「Implemented / Exists but not wired / Not started」の棚卸しを追加し、本 subtask の主目的を新規設計ではなく統合と契約固定に言い換える。
- `[発生確率:高][影響度:大]` selector は `context["takeover_candidates"]` を前提にするが、MasterConductor 側の文脈投入が不足し end-to-end で未接続になる。
  - **対策 / 計画書への修正案:** `ReconPipeline -> artifact hydrate -> MasterConductor -> match_recipes_to_context()` を明示した統合フローと、legacy JSON 互換期間の移行方針を追加する。
- `[発生確率:高][影響度:中]` Recipe action 名と実際の dispatcher / executor の対応が曖昧で、「allowlist 済みだが動かない action」が残る。
  - **対策 / 計画書への修正案:** `cname_resolve`, `http_probe`, `check_takeover` などの action-to-executor 対応表を作り、未バインド action は selection 前 reject とする契約を明記する。
- `[発生確率:高][影響度:大]` `TakeoverCandidate` schema の置き場が曖昧なままだと、recon / agent / report 間で別々の型が増える。
  - **対策 / 計画書への修正案:** `TakeoverCandidate` を共有 domain model へ昇格するか、adapter DTO として限定するかを先に決める判断ステップを追加する。
- `[発生確率:高][影響度:中]` `RecipeLoader` が generic loader と takeover 固有 selector の両方を抱え込み、責務が広がりすぎる。
  - **対策 / 計画書への修正案:** `RecipeLoader` は generic matching に寄せ、takeover 固有判定は `TakeoverCandidateSelector` などの小さな helper へ分離する方針を追加する。
- `[発生確率:中][影響度:大]` legacy `takeover_candidates.json` 互換を長く残すと、schema が二重化して report 品質がぶれる。
  - **対策 / 計画書への修正案:** 互換期間、warning log、低スコア扱い、削除予定条件を明記し、移行完了後は新 schema へ一本化する。

### 3.4.3 ハッカー視点
- `[発生確率:高][影響度:大]` `likely_reclaimable` が強すぎる表現になり、実際には claim 不可の provider でも期待値を過大評価する恐れがある。
  - **対策 / 計画書への修正案:** `likely_reclaimable` を `high_priority_manual_check` 相当に再定義するか、report 表示で「未claim / 未PoC」を強制表示する。
- `[発生確率:高][影響度:大]` provider の偽陽性パターンが浅いと、GitHub Pages / S3 / Azure の generic 404 を takeover 候補として拾い続ける。
  - **対策 / 計画書への修正案:** `false_positive_twins` に negative evidence, redirect chain, tenant ownership hint, known parked/error page fingerprint を追加する。
- `[発生確率:中][影響度:大]` bounty program ごとの takeover 検証ルールを無視すると、良い候補でも提出不能または危険な検証になる。
  - **対策 / 計画書への修正案:** `scope_policy.takeover_allowed`, `proof_limit`, `claim_action_allowed=false by default` を candidate 判定前の blocking signal として追加する。

### 3.4.4 デバッガー視点
- `[発生確率:高][影響度:大]` `candidate_id`, provider, tool chain, verdict reason が全段で揃わず、失敗時の追跡が困難になる。
  - **対策 / 計画書への修正案:** selector から report までに残す trace schema として `candidate_id`, `provider_guess`, `tool_chain`, `verdict_reason_codes`, `artifact_paths` を必須化する。
- `[発生確率:高][影響度:中]` `subjack` / `subzy` / `nuclei` / `manual_curl` の正規化回帰を検知できる fixture 群が不足する。
  - **対策 / 計画書への修正案:** 正規化層に対して golden fixture, malformed output, timeout, provider ambiguity の各テスト観点を追加し、snapshot 比較を受け入れ条件へ入れる。
- `[発生確率:中][影響度:大]` `takeover_verdict` を report 側が読まないまま実装が進むと、runner での区別が利用されない。
  - **対策 / 計画書への修正案:** report 正規化層の節に `confirmed`, `manual_review_required`, `no_finding`, `blocked`, `failed` の表示契約と formatter / gate 回帰テストを追加する。
- `[発生確率:高][影響度:大]` 失敗時に「どの入力 artifact から候補化されたか」が追えない。
  - **対策 / 計画書への修正案:** `raw_evidence.source_files` に加えて `source_line`, `producer_step`, `session_id`, `artifact_hash` を trace schema に追加する。
- `[発生確率:高][影響度:中]` parser が正常系 fixture に寄り、空出力・warning 混入・複数行 JSONL で壊れる可能性がある。
  - **対策 / 計画書への修正案:** fixture に empty output, stderr-only, mixed warning, partial JSON, duplicate provider hit を追加する。
- `[発生確率:中][影響度:大]` `confirmed` 昇格失敗の理由が粗いと、provider 問題か tool 問題か scope 問題かを切り分けにくい。
  - **対策 / 計画書への修正案:** `verdict_reason_codes` を `missing_cname`, `stale_candidate`, `tool_disagreement`, `provider_no_auto_confirm`, `scope_policy_blocks_claim` などで固定する。

### 3.4.5 CTO視点
- `[発生確率:高][影響度:大]` active subtask の完了条件が弱く、どこまで終えたら `done` にできるかが曖昧。
  - **対策 / 計画書への修正案:** 実装順の節に「完了条件」「deferred へ送る条件」「今回スコープ外」を追加し、継続監視項目は backlog と切り分ける。
- `[発生確率:高][影響度:大]` recon artifact, recipe, tool normalization, report semantics を同時に変えるため、段階 rollout なしではノイズが急増しうる。
  - **対策 / 計画書への修正案:** shadow mode 比較、feature flag / kill switch、fixture corpus と実 artifact の比較ゲートを持つ rollout step を新設する。
- `[発生確率:中][影響度:大]` takeover 専用 `confirmed` が全体レポートの confirmed 件数と混同され、上位 gate の意味を汚染する恐れがある。
  - **対策 / 計画書への修正案:** `takeover_verdict` と global finding state を分離し、HITL または許可済み read-only 証跡がない限り global confirmed に昇格させない方針を追記する。
- `[発生確率:高][影響度:大]` 計画範囲が広く、完了判定が「全部やる」になりやすい。
  - **対策 / 計画書への修正案:** Phase を `MVP integration`, `provider quality`, `report/gate`, `rollout` に分け、各 phase の `done` 条件を3つ以内で明記する。
- `[発生確率:中][影響度:大]` 自動化が進むほど legal / platform policy リスクが増える。
  - **対策 / 計画書への修正案:** `provider resource creation is never automated` を安全境界として `3.3` と `4.12` の両方に重複明記する。
- `[発生確率:中][影響度:中]` provider matrix の保守が属人化すると、実装後に検知品質が落ちる。
  - **対策 / 計画書への修正案:** matrix 更新レビュー手順、最低サンプル fixture、更新時に必ず走る tests を完了条件に入れる。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: 既存実装の棚卸しを行い、`Implemented / Exists but not wired / Not started` の3区分で対象ファイルごとの差分表を作成する
- [ ] ステップ2: `TakeoverCandidate` を共有 domain model へ昇格するか adapter DTO に限定するかを決め、`RecipeLoader` と takeover 固有 selector の責務境界を固定する
- [ ] ステップ3: resolver 取得、tool availability、timeout、offline fallback、`infrastructure_state` を含む運用ガードレールを定義し、preflight 条件と degrade mode を固定する
- [ ] ステップ4: `per-target probe budget`, `dedupe window`, `shared probe cache` を設計し、parallel recon と takeover Recipe の重複 probe を抑制する
- [ ] ステップ5: `dead_subs -> takeover_candidates` の成果物を `TakeoverCandidate` 互換 schema へ拡張し、legacy NXDOMAIN JSON の後方互換期間、warning log、低スコア扱い、削除予定条件を定義する
- [ ] ステップ6: `scope_policy.takeover_allowed`, `proof_limit`, `claim_action_allowed=false by default` を blocking signal として candidate 判定前に評価する
- [ ] ステップ7: `MasterConductor` が recon artifact から `takeover_candidates` を hydrate し、selector へ `context["takeover_candidates"]` を渡す統合経路を実装する
- [ ] ステップ8: takeover Recipe の `required_signals` / `blocking_signals` / trace metadata を固定し、`run_recipe` に流す最低条件と理由説明を揃える
- [ ] ステップ9: `recipes/recon/takeover.yaml` の step schema と action-to-executor 対応を揃え、未バインド action を selection 前 validation で reject する
- [ ] ステップ10: provider matrix の fingerprint / claim prerequisite / negative evidence / false positive twin / tool_preference / HITL checkpoint を正本化し、`version`, `updated_at`, `source_note`, `rollback_target` を持つ更新運用を定義する
- [ ] ステップ11: `likely_reclaimable` の表示名と意味を見直し、未claim / 未PoC の状態が report で必ず見えるようにする
- [ ] ステップ12: `TakeoverSpecialist` と `intel takeover` と `nuclei` / `manual_curl` の出力を共通正規化層へ集約し、tool chain と verdict 仲裁ルールを provider-aware に統一する
- [ ] ステップ13: stale candidate, cache key, tool disagreement, evidence minimum, `verdict_reason_codes` を success gate と trace schema に組み込み、`confirmed` の昇格条件を厳格化する
- [ ] ステップ14: `source_line`, `producer_step`, `session_id`, `artifact_hash`, `artifact_paths` を trace schema に追加し、入力 artifact から report まで追跡できるようにする
- [ ] ステップ15: report 正規化層で `takeover_verdict` と global finding state を分離し、automation と HITL の境界を明示した evidence 表現を追加する
- [ ] ステップ16: shadow mode 比較、feature flag / kill switch、fixture corpus と実 artifact の比較ゲートを用意して段階 rollout できる形にする
- [ ] ステップ17: unit / integration / real artifact 検証を行い、empty output / stderr-only / mixed warning / partial JSON / duplicate provider hit を含む正規化 fixture を追加する
- [ ] ステップ18: Phase を `MVP integration`, `provider quality`, `report/gate`, `rollout` に分け、各 phase の `done` 条件を3つ以内で明記し、残件は backlog / deferred に送る

## 4.1 provider fingerprint 強化の意味
- `NXDOMAIN` を並べるだけでなく、「この CNAME はどの SaaS / CDN / hosting provider を向いているか」を機械的に推定する
- HTTP 応答の典型エラーメッセージや DNS 状態から、「未割当っぽい」「 reclaim できそう」「ただ死んでいるだけ」を分離する
- ここでいう `reclaimability` は自動取得までやる意味ではなく、人間が次に手で確認すべき価値が高い候補を上位に出す意味

## 4.2 takeover Recipe のスコアリング方針
- 候補優先度は最低でも次で説明可能にする:
  - provider error token の強さ
  - claim prerequisite の軽さ
  - dead / dangling 状態の freshness
  - CNAME 鎖の明瞭さ
  - 複数ツールの一致度
- `likely_reclaimable` に上げる条件は、単一シグナルではなく複数シグナルの合算で決める。
- `confirmed` は automation 単独で乱用せず、provider matrix で高確度条件を満たすか、HITL verdict がある場合に限定する。

## 4.3 これで何ができるようになるか
- いまは dead_subdomain の列挙と subjack 実行が疎結合だが、将来は Recon の成果をそのまま高精度な takeover triage に流せる
- 候補の優先順位が付くので、false positive だらけの takeover scan になりにくい
- Recipe が「走ったつもりだが何も検証していない」状態を避けやすくなる
- provider ごとの勝ち筋に寄せて人手投入ポイントを絞れる
- report に provider と根拠を残せるので、再現・レビューがしやすくなる

## 4.4 実装具体化1: schema整合
- **対象ファイル:**
  - `recipes/recon/takeover.yaml`
  - `src/core/engine/recipe_loader.py`
  - `src/core/engine/recipe_contracts.py`
  - `src/core/engine/master_conductor.py`
- **やること:**
  - takeover Recipe YAML を現行 loader/runner が理解できる `name`, `agent`, `trigger`, `steps[].id`, `steps[].name`, `steps[].action`, `steps[].params`, `steps[].dependencies` 契約へ寄せる
  - `check_takeover` のような takeover 専用 action を追加するか、既存 action vocabulary (`run`, `analyze`, `verify_scope` など) へ安全に落とし込む
  - selection 前に `schema_valid`, `action_supported`, `step_count > 0` を検証し、不正 Recipe を候補集合へ入れない
- **受け入れ条件:**
  - takeover Recipe を load したとき `steps` が空にならない
  - unsupported action を含む Recipe は、実行時ではなく選抜時または事前検証で理由付きに落ちる
  - `run_recipe` task 化された候補が「選ばれたが走れない」状態にならない

## 4.5 実装具体化2: selector契約
- **対象ファイル:**
  - `src/core/engine/recipe_loader.py`
  - `src/core/engine/master_conductor.py`
  - `src/recon/pipeline.py`
- **やること:**
  - `match_recipes_to_context()` の返り値を単純 `List[Recipe]` ではなく、`RecipeCandidate(score, reasons, required_signals, supporting_evidence, freshness, manual_review_required)` 相当へ拡張する
  - takeover 向け selector 入力を `dead_subs` 直読みではなく、正規化済み candidate schema から受ける
  - selector は最低でも `required_signals` と `blocking_signals` の両方を見る
  - `run_recipe` 注入時に `score_reasons`, `candidate_id`, `manual_claim_review_required` を trace できるようにする
- **候補 schema の最小案:**
  - `subdomain`
  - `candidate_id`
  - `observed_at`
  - `first_seen_dead`
  - `last_seen_dead`
  - `cname_chain`
  - `provider_guess`
  - `required_signals`
  - `blocking_signals`
  - `raw_evidence`
  - `freshness_score`
  - `manual_claim_review_required`
- **受け入れ条件:**
  - unrelated Recipe が loaded されていても takeover signal が弱ければ候補化されない
  - 同一 candidate に対して同一 Recipe が無秩序に再注入されない
  - selector が「なぜ選んだか / なぜ弾いたか」を説明できる

## 4.6 実装具体化3: provider matrix データ化
- **対象ファイル候補:**
  - `src/core/adapters/external/` 配下の新規 provider matrix loader
  - `src/core/agents/swarm/discovery/takeover.py`
  - `src/commands/intel.py`
  - `recipes/recon/takeover.yaml`
- **やること:**
  - provider ごとに `fingerprint_domains`, `error_tokens`, `claim_prerequisites`, `verification_urls`, `false_positive_twins`, `tool_preference`, `hitl_checkpoint_types` を持つデータ構造を定義する
  - `subjack / subzy / nuclei / manual curl` のどれを優先するかを provider 別に定義する
  - automation で弱い provider は早めに `manual_claim_review_required=true` へ落とし、人の時間を無駄にしない
- **provider matrix の最小項目案:**
  - `provider_id`
  - `fingerprint_domains`
  - `error_tokens`
  - `claim_prerequisites`
  - `verification_urls`
  - `tool_preference`
  - `false_positive_twins`
  - `hitl_checkpoint_types`
  - `supports_auto_confirm`
- **受け入れ条件:**
  - provider が一致したとき、どのツール/手順で再検証するかが一意に決まる
  - provider ごとの差で success path が分岐しても、report 側では同じ evidence vocabulary に正規化される
  - provider 固有の偽陽性パターンを明示的に減点・停止できる

## 4.7 実装具体化4: success gate 強化
- **対象ファイル:**
  - `src/core/engine/optimized_runner.py`
  - `src/core/agents/swarm/discovery/takeover.py`
  - `src/commands/intel.py`
  - report 正規化層
- **やること:**
  - Recipe success 判定に `total_steps > 0`, `minimum_evidence_types`, `major_failure == false`, `stale_candidate == false` を組み込む
  - `blocked`, `failed`, `manual_review_required`, `confirmed` を takeover 用に区別して report へ残す
  - `subjack` / `subzy` / `manual curl` の結果が割れた場合の仲裁ルールを provider matrix 経由で決める
  - `0-step success`, `low-evidence success`, `stale-result cache hit` をテストで防ぐ
- **受け入れ条件:**
  - 1件も証拠が取れていない Recipe は success にならない
  - stale な candidate からの古い結果再利用で `confirmed` にならない
  - HITL へ渡した候補と automation で確定した候補が report 上で区別される

## 4.8 実装順と依存関係
1. 現状棚卸し、モデル配置判断、運用ガードレール固定
2. probe budget / scope policy / candidate schema 拡張
3. conductor wiring、selector 契約、recipe action binding
4. provider matrix、表示語彙、tool 正規化
5. success gate / cache / trace / verdict reason 強化
6. report semantics、shadow rollout、phase done 判定
- 現状棚卸し前に schema を動かすと、既存実装の再設計と未接続箇所の修正が混在して差分が読めなくなる。
- conductor wiring 前に selector だけ固めても、`context["takeover_candidates"]` が供給されず実データで候補化できない。
- provider matrix と tool 正規化は action binding 後に進めることで、どの executor に何を渡すかを先に固定できる。
- success gate と cache policy は upstream の evidence vocabulary と trace schema が決まってから締める。
- report semantics と rollout は verdict 契約が固まってから最後に結線し、shadow mode で旧挙動との差分を比較する。
- `MVP integration`, `provider quality`, `report/gate`, `rollout` の各 phase は、それぞれ最大3つの done 条件で完了判定し、残件を backlog / deferred へ分離する。

## 4.9 テスト観点の具体化
- takeover Recipe YAML を load したとき `steps` が 1件以上構築されること。
- unsupported action を含む takeover Recipe が selection 前 validation で理由付き reject されること。
- stale candidate は score が下がるか stop condition へ落ちること。
- provider matrix により `tool_preference` が変わると再検証経路も変わること。
- tool disagreement 時に `manual_claim_review_required` が立つこと。
- `OptimizedRecipeRunner` が 0-step / blocked-only / evidence-empty を success 扱いしないこと。
- report 出力で `confirmed` と `manual_review_required` が混同されないこと。
- resolver / tool / HTTP probe 失敗が `no_finding` ではなく `infrastructure_state` として report / trace に残ること。
- `scope_policy.takeover_allowed=false` または `claim_action_allowed=false` の candidate が `confirmed` に昇格しないこと。
- `empty output`, `stderr-only`, `mixed warning`, `partial JSON`, `duplicate provider hit` の fixture で正規化層が壊れないこと。
- provider matrix 更新時に `version`, `updated_at`, `source_note`, `rollback_target` が欠けていれば validation で落ちること。

## 4.10 D02詳細設計: ReconPipeline -> TakeoverCandidate 統合
- **目的:**
  - `takeover_candidates.json` を `{"subdomain": "...", "status": "NXDOMAIN"}` の単純列挙から、Recipe selector がそのまま使える `TakeoverCandidate` 互換 schema に拡張する。
- **既にある入力源:**
  - `dead_subs`: `ReconPipeline.step3_live_check()` の `all_subs - resolved`
  - `resolved`: `shuffledns` または single URL fallback の DNS 解決結果
  - `httpx`: live host / status / URL / title などの HTTP probe 結果
  - `whatweb`: tech / HTTP fingerprint の補助情報
  - `dns.json`: `amass` 由来の DNS record 情報があれば CNAME 抽出に使う
- **必要に応じて足す probe:**
  - `cname_resolve`: dead candidate に対して CNAME chain を再確認する read-only DNS query
  - `manual_curl` / lightweight HTTP probe: provider error token を read-only で確認する
- **出力 schema:**
```json
{
  "candidate_id": "takeover_<stable_hash>",
  "subdomain": "dead.example.com",
  "status": "candidate",
  "observed_at": "2026-06-25T00:00:00Z",
  "first_seen_dead": "2026-06-25T00:00:00Z",
  "last_seen_dead": "2026-06-25T00:00:00Z",
  "last_dns_probe": "2026-06-25T00:00:00Z",
  "last_http_probe": null,
  "cname_chain": ["dead.example.com", "example.github.io"],
  "provider_guess": "github_pages",
  "required_signals": {
    "dns_dead": true,
    "cname_dangling": true,
    "provider_match": true
  },
  "blocking_signals": [],
  "raw_evidence": {
    "dns": {},
    "http": {},
    "source_files": ["*_dns.json", "*_takeover_candidates.json"]
  },
  "manual_claim_review_required": true
}
```
- **設計ルール:**
  - `candidate_id` は subdomain + provider_guess + cname_chain から安定生成し、同じ候補を重複注入しない。
  - `first_seen_dead` は既存 session/history に同一 candidate があれば引き継ぎ、初回は `observed_at` と同じにする。
  - `provider_guess` は CNAME suffix と HTTP body token を provider matrix で照合して決める。
  - `freshness_score` は保存値ではなく selector 側で時刻から再計算する。
  - `TakeoverCandidate` へ変換できない薄い legacy JSON も後方互換として受け付けるが、score は低くする。
- **受け入れ条件:**
  - `takeover_candidates.json` に `candidate_id`, `observed_at`, `last_seen_dead`, `raw_evidence`, `required_signals` が含まれる。
  - `master_conductor._load_recipe_tasks()` が `context["takeover_candidates"]` を渡し、takeover Recipe が実データで候補化される。
  - NXDOMAIN だけの候補は `candidate` までに留め、`likely_reclaimable` / `confirmed` には上げない。

## 4.11 D03詳細設計: takeover tool result 正規化
- **目的:**
  - `subjack`, `subzy`, `nuclei`, `manual_curl` の出力を共通 schema に揃え、provider-aware verdict に渡せるようにする。
- **現状の役割:**
  - `subjack`: `TakeoverSpecialist` から自動フローで呼ばれるが、現在は regex 直パースで `Finding` 化している。
  - `subzy`: `intel takeover` / `--takeover` CLI から呼ばれるが、現在は raw output を返すだけで自動判定には統合されていない。
  - `nuclei`: 既存の外部ツール基盤と CLI はあるが、takeover 専用テンプレート実行結果を provider verdict へ接続していない。
  - `manual_curl`: provider error token と HTTP status を確認する read-only fallback として新規に扱う。
- **共通 schema:**
```json
{
  "tool": "subzy",
  "subdomain": "dead.example.com",
  "provider": "github_pages",
  "matched": true,
  "evidence_type": "provider_error_token",
  "confidence": "tool_signal",
  "http_status": 404,
  "error_token": "There isn't a GitHub Pages site here",
  "cname_chain": ["dead.example.com", "example.github.io"],
  "raw_excerpt": "...",
  "tool_error": null,
  "manual_review_required": true
}
```
- **adapter 配置:**
  - 新規正規化層は `src/core/adapters/external/takeover_tool_result_adapter.py` に置く。
  - `SubjackTool`, `SubzyTool`, `NucleiTool` / `NucleiAdapter`, `manual_curl` の結果を `NormalizedTakeoverToolResult` に変換する。
  - 外部ツール実行 wrapper 自体は既存を再利用し、takeover 固有の解釈だけをこの adapter に集約する。
- **tool chain 実行方針:**
  - `TakeoverSpecialist` は provider matrix の `tool_preference` を読んで `subjack -> subzy -> nuclei -> manual_curl` などの順序を決める。
  - provider 不明時は安全側で `subjack`, `subzy`, `manual_curl` の順に read-only 判定を行う。
  - `nuclei` は takeover / misconfig / dns / cname 系テンプレートに限定し、汎用 deep scan には広げない。
  - `manual_curl` は body excerpt, status, headers, redirect chain の取得だけを行い、provider 側 resource 作成はしない。
- **verdict 仲裁ルール:**
  - 複数 tool が同じ provider と error token を示す場合は `likely_reclaimable` へ上げる。
  - tool が割れた場合、または provider が `supports_auto_confirm=false` の場合は `manual_review_required` にする。
  - `subjack` 単独 hit、`subzy` 単独 hit、または `nuclei` 単独 hit は `confirmed` にしない。
  - provider 側 claim prerequisite が UI / account / subscription 依存なら、必ず HITL checkpoint を残す。
- **受け入れ条件:**
  - `TakeoverSpecialist` が直接 `Finding` を作る前に normalized result を生成する。
  - `intel takeover` の JSON 出力が raw output だけでなく normalized result を含む。
  - `nuclei` takeover template の結果を normalized result に変換できる。
  - `manual_curl` fallback が read-only evidence として保存される。
  - report には tool 別 raw evidence と normalized verdict の両方が残る。

## 4.12 Provider-aware Takeover Agent 設計
- `TakeoverSpecialist` は単一ツールの実行役ではなく、次の順で動く orchestration agent とする。
1. `TakeoverCandidate` を受け取る。
2. provider matrix で `provider_guess`, `tool_preference`, `claim_prerequisites`, `supports_auto_confirm` を解決する。
3. read-only tool chain (`subjack`, `subzy`, `nuclei`, `manual_curl`) を provider ごとに実行する。
4. 各 tool result を `NormalizedTakeoverToolResult` に変換する。
5. evidence count, provider agreement, error token agreement, freshness, claim prerequisite を使って verdict を出す。
6. `manual_review_required` の場合は provider 側で何を確認すべきかを `manual_checklist` として report に残す。
- agent は provider 側 resource 作成を自動実行しない。claim 可否確認が必要な場合は `manual_review_required` として止める。
- bounty 用 report には「自動で乗っ取り済み」と誤読されないよう、`likely_reclaimable` と `confirmed` を明確に分ける。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] provider fingerprint はサービス側仕様変更に影響されやすい - シグネチャ更新しやすいデータ駆動設計にする
- [ ] [重要度:高] takeover Recipe の YAML schema と runner/action 契約が不整合だと、success 以前に実行不能候補が混ざる - selection 前 validation を必須化する
- [ ] [重要度:高] stale な `dead_subs` を高優先度候補へ残すと成功率が急落する - freshness TTL と再観測ポリシーを持つ
- [ ] [重要度:中] `subjack` と `subzy` の出力差で finding 品質がぶれやすい - 正規化層を一枚入れる
- [ ] [重要度:中] provider ごとの claim prerequisite が変わると automation が古い勝ち筋を追う - provider matrix に更新しやすい versioned data source を持つ
- [ ] [重要度:中] reclaimability は完全自動化が難しい - 最終段階は HITL または manual confirmation 前提にする
- [ ] [重要度:中] Recipe が 0 step 実行や blocked のまま success 扱いになると triage を誤る - success 判定に最低 evidence 件数を要求する
- [ ] [重要度:低] main target を無差別に takeover 対象へ足すとノイズが増える - candidate source と eligible host class を制約として定義する

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0283-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
