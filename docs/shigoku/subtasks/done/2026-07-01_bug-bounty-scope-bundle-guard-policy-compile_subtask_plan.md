---
task_id: SGK-2026-0335
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0282
related_docs:
- docs/shigoku/subtasks/2026-06-21_sgk-2026-0282_bug-bounty-scope-control_subtask_plan.md
- docs/shigoku/specs/2026-07-01_sgk-2026-0335_bug-bounty-program-bundle-guard-policy-contract.md
- docs/shigoku/specs/2026-07-02_sgk-2026-0335_enforcement-points-and-killswitch.md
- docs/shigoku/specs/2026-07-02_sgk-2026-0335_metrics-and-negative-fixtures.md
- docs/shigoku/specs/2026-07-02_sgk-2026-0335_v1-acceptance-criteria.md
- docs/shigoku/manuals/2026-07-02_sgk-2026-0335_bugbounty-bundle-operator-runbook.md
- docs/shigoku/specs/bug_bounty_enhancements.md
- docs/shigoku/specs/modules/ETHICS_GUARD.md
- docs/shigoku/roadmaps/bug_bounty_enhancements_2026.md
title: Bug Bounty向けScope Bundle入力正規化とGuard Policy Compile計画
created_at: '2026-07-01'
updated_at: '2026-07-02'
tags:
- shigoku
target: src/core/security/, src/core/engine/, src/core/intelligence/, src/core/infra/, src/core/tools/, src/core/adapters/external/, src/core/agents/swarm/, docs/shigoku/
---

# 実装計画書：Bug Bounty向けScope Bundle入力正規化とGuard Policy Compile計画

## 1. 達成したいゴール（ユーザー視点）
- HackerOne / Bugcrowd の program guideline と scope 情報を `program bundle` として渡すと、SHIGOKU が V1 で安定して解釈できること。
- 実行時は自然文や CSV をその場で読み直さず、`compiled_guard_policy.yaml` だけを参照して一貫した guard 判定を行えること。
- scope やルールが曖昧な場合は自動で危険側へ進まず、`manual_review_required` として fail-closed できること。
- 同じ policy を MC、manager、worker、外部アクセスモジュールが共有し、どの層でも同じ `reason_code` で止められること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `program bundle`（新規概念）: 原文、構造化 scope、補正ファイルをまとめて受け渡す単位
  - `scope parser系コンポーネント`: platform別入力の正規化、抽出結果の compile 入口
  - `src/core/security/ethics_guard.py`: 現行の legacy scope guard。V1 では compatibility 層として残しつつ、compiled policy evaluator の移行先候補とする
  - `src/core/engine/master_conductor.py`: run preflight、task 生成前の一次判定、dispatch 直前の phase 制御
  - `src/core/infra/smart_request.py` / `src/core/infra/network_client.py`: HTTP 実行前の共通ガード
  - `src/core/tools/context_runner.py` / `src/core/adapters/external/base_external_adapter.py` / `src/core/agents/swarm/base_manager.py`: subprocess / external tool / manager dispatch 前の共通ガード
  - `program override` 接続点: compile 済み policy の注入経路整理
- **データの流れ / 依存関係:**
  - HackerOne / Bugcrowd の生入力 -> platform adapter -> normalized facts
  - normalized facts + `review_findings.yaml` + `overrides.yaml` -> compiler -> `compiled_guard_policy.yaml`
  - `compiled_guard_policy.yaml` -> MC / manager / worker / 外部アクセスモジュール -> allow / block / requires_hitl / degrade
  - 判定結果 -> audit trace / reason code / operator向け説明

## 2.1 V1 の基本方針
- 実行時に専用 AI が raw policy を再解釈しない。V1 は deterministic compile を正本にする。
- AI を使う場合も import 支援や曖昧点抽出までに限定し、実行可否の最終決定は構造化 policy で行う。
- MC だけに guard を置かず、manager / worker / 外部アクセスモジュールまで多層で再判定する。
- compile 不能、または critical ambiguity 未解消なら Bug Bounty モードでは開始しない。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - 推奨受け渡し単位は `program_bundle/` ディレクトリ
  - 最低限の入力候補は次のとおり

```text
program_bundle/
  source_manifest.yaml
  policy.md            # または raw_policy.txt
  scope_assets.csv     # HackerOne系の構造化scopeがある場合
  scope_assets.txt     # Bugcrowd系のinline scopeを抽出した場合
  review_findings.yaml
  overrides.yaml
```

  - `source_manifest.yaml`: provider, program_name, fetched_at, source_urls, bundle_version, hash などの provenance
  - `policy.md` / `raw_policy.txt`: program guideline 原文
  - `scope_assets.csv`: TikTok のような HackerOne ケースで与えられる asset scope 一覧
  - `scope_assets.txt`: Fireblocks のような Bugcrowd ケースで本文から切り出した scope block
  - `review_findings.yaml`: 機械抽出の曖昧点、要確認事項、採否
  - `overrides.yaml`: 人手による最終補正。最上位優先
- **出力/結果 (Output):**
  - `compiled_guard_policy.yaml`: runtime が参照する唯一の実行正本
  - `compile_audit` 相当の trace: どの入力から何を採用したかを説明する監査情報
  - `ready / manual_review_required / compile_failed` などの compile status
  - runtime 判定結果: `allow / block / requires_hitl / degrade_to_report`
- **優先順位 (Precedence):**
  - `source_manifest` と provider種別で adapter を選ぶ
  - 構造化 scope (`scope_assets.csv` など) は asset境界の正本候補
  - policy 原文は behavioral rule の正本候補
  - `review_findings.yaml` は曖昧点の解消状態を保持する
  - `overrides.yaml` は最終的な人手補正として最優先
  - runtime は raw source ではなく `compiled_guard_policy.yaml` のみ参照する
- **制約・ルール:**
  - V1 では HackerOne / Bugcrowd API 同期は行わない
  - V1 では報酬単価ベースの ROI 優先度付けは行わない
  - compile 時に unresolved critical ambiguity が残る場合は fail-open しない
  - human correction は自由記述メモではなく、構造化 YAML で保持する
  - raw policy 変更、scope CSV 更新、override 変更のいずれかがあれば compile 済み policy を再生成する
  - 同じ out-of-scope 条件が MC では block、worker では allow のように食い違わない設計にする

## 3.1 V1 で正規化したい guard 軸
- host / domain / path の in-scope / out-of-scope
- cross-host / pivot 可否
- post-exploit と phase 遷移可否
- attack class 単位の許可/禁止/要承認
- rate limit、request budget、time budget、tool budget
- auth 条件、テストアカウント条件、破壊的操作禁止
- manual review が必要な条件と停止理由

## 3.2 人手補正ファイルの扱い
- `review_findings.yaml` は「機械抽出が迷った点」を残す。例: wildcard host の境界、`read-only` の意味、`no social engineering` の attack class への写像
- `overrides.yaml` は「最終的にこう扱う」を明示する。runtime は review note ではなく override 反映後の compile 結果だけを使う
- 例としては次のような形を想定する

```yaml
review_findings:
  - finding_id: H1-AMB-001
    subject: "*.tiktok.com"
    issue: "wildcardの適用境界が本文だけでは不明確"
    resolution: manual_review_required

overrides:
  hosts:
    allow:
      - api.tiktok.com
    deny:
      - internal.tiktok.com
  attack_classes:
    post_exploit: deny
    destructive_post: deny
```

## 3.3 実行時の強制ポイント
- MC: task を作る前に target / phase / attack_class / budget を判定
- manager: MC から流れてきた task を再確認し、変形や派生 task の逸脱を防ぐ
- worker: 実行直前に actual target / actual action を再確認する
- 外部アクセスモジュール: HTTP、browser、subprocess、external tool 呼び出し前に最終チェックする
- 監査ログ: `policy_version`, `reason_code`, `evidence_ref`, `enforcement_layer` を残す

## 3.4 現行コード差し込み点の棚卸し
- `src/core/security/scope_parser.py`: YAML / text から `ScopeDefinition` を作り、`apply_to_ethics_guard()` で singleton `EthicsGuard` へ直接適用している。bug bounty bundle 導線では compile 前 raw scope を直接 runtime に流さないよう分離が必要
- `src/core/security/ethics_guard.py`: 現状の判定軸は `in_scope_domains`, `out_of_scope_domains`, `out_of_scope_paths`, `max_requests_per_minute`, `allow_post_exploit` に限定されている。`guard_input` / `guard_decision` 契約とは別物なので、V1 では compatibility facade として扱う
- `src/core/engine/master_conductor.py`: `verify_scope` fast-path で target から即席 `ScopeDefinition` を作って `EthicsGuard` に注入している。また `_dispatch()` と `_trigger_post_exploit()` は `allow_post_exploit` bool だけで post-exploit を止めている
- `src/core/infra/smart_request.py`: `ExecutionSafeguardService` により method / payload / HITL を見ているが、compiled policy による host / path / phase / bundle 判定はまだ持っていない
- `src/core/infra/network_client.py`: 実際の HTTP 送信はここで行われるため、scope guard を `SmartRequest` だけに置くと bypass 余地が残る。最終的な HTTP fail-closed はここで担保する
- `src/core/tools/context_runner.py`: subprocess 実行前に `EthicsGuard.check_action(ActionType.SHELL_COMMAND, f"{tool_name} on {target}")` を使っているが、program bundle / attack class / tool budget は見ていない
- `src/core/agents/swarm/base_manager.py`: `_execute_tool()` が manager から tool 関数を直接呼んでおり、共通 scope evaluator を通していない
- `src/core/adapters/external/base_external_adapter.py`: `run_with_validation()` が全外部ツール実行の共通入口になっているため、ここへ shared evaluator を差し込むと複数 adapter をまとめて覆える
- `src/core/intelligence/chain_builder.py`: tactical policy override は持つが、bundle 解決や compiled guard policy の正本解決はまだ持っていない

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `program bundle` の受け渡し契約を定義し、必須/任意ファイル、provider 判定、更新時の再compile条件、`bundle_id` / `program alias` の命名規約を固定する
- [x] ステップ2: adapter / compiler / evaluator / MC / manager / worker / 外部アクセス層の責務分離を表で固定し、shared evaluator API と `guard_input` / `guard_decision` の単一契約を定義する
- [x] ステップ3: HackerOne 用 adapter と Bugcrowd 用 adapter の責務を切り分け、`policy.md + scope_assets.csv` と `policy.md + inline scope` の両経路を正規化できるようにする。`Targets/structured scope` を authoritative にし、`Focus Areas/Safe Harbor` のような非guard本文を runtime allow rule と混同しない
- [x] ステップ4: `review_findings.yaml` と `overrides.yaml` の schema、manual review の blocking 条件、override skeleton、recompile 導線を設計する
- [x] ステップ5: `compiled_guard_policy.yaml` の schema、compile precedence、schema compatibility、deterministic hash/snapshot、`decision_trace_id` / `rule_origin_id` / `source_ref` の追跡契約を定義する
- [x] ステップ6: CLI lifecycle を固定し、`import / compile / activate / run / update / rollback / resume` の意味、`--mode bugbounty` における legacy `--scope` の preflight block、run ごとの `bundle_id` 固定ルールを定義する
- [x] ステップ7: bundle 保存先、`active_bundle.json` 整合確認、artifact integrity check、復旧導線、credential 実値の保存拒否、data governance、named/ephemeral retention と prune 条件を定義する
- [x] ステップ8: MC / manager / worker / 外部アクセスモジュールの enforcement point を棚卸しし、shared evaluator の差し込み順、layer ごとの fail-closed 条件、rollback/kill switch 接続点を決める
- [x] ステップ9: rollout strategy を `shadow read-only -> MC only enforcement -> worker/external hard enforcement` の段階で定義し、metrics、SLO、alerts、block reason 集計、active bundle read failure 検知を追加する
- [x] ステップ10: TikTok(HackerOne) と Fireblocks(Bugcrowd) の正例 fixture に加えて、timezone parse failure、wildcard/deny conflict、secret 混入、active bundle 欠落、negative N-day 解釈などの負例 fixture を設計し、same bundle => same policy hash の snapshot 検証条件を定義する
- [x] ステップ11: bundle import から run までの operator runbook、manual review runbook、orphan bundle / prune 運用、shadow から enforcement への移行条件を文書化する
- [x] ステップ12: V1 受け入れ条件を最終確定し、compile 成功率、manual review 比率、unsafe dispatch 予防件数、false block 許容率、bundle import -> ready までの時間などの評価軸を明文化する

## 4.1 この計画で作るもの
- Step 1 正本 spec: `docs/shigoku/specs/2026-07-01_sgk-2026-0335_bug-bounty-program-bundle-guard-policy-contract.md`
- `program bundle` の入力契約
- 責務分離マトリクスと shared evaluator API 契約
- provider別 adapter の役割分担
- `review_findings.yaml` / `overrides.yaml` の運用ルール
- `compiled_guard_policy.yaml` の schema と precedence matrix
- bundle lifecycle / rollback / resume 契約
- storage / integrity / data governance 方針
- runtime guard の強制ポイント一覧
- rollout / metrics / kill switch 方針
- 正例 / 負例 / snapshot を含む fixture ベースの受け入れ条件

## 4.2 V1 の受け入れ条件
- TikTok の HackerOne ケースで、program guideline text と scope CSV から compile 可能である
- Fireblocks の Bugcrowd ケースで、program text 内 scope から compile 可能である
- `compiled_guard_policy.yaml` が `ready` でない限り Bug Bounty 実行を開始しない
- 同一の out-of-scope host / action が MC、manager/worker、外部アクセス層で一貫して block される
- 判定結果に `reason_code` と evidence 参照が残り、後から「なぜ止まったか」を説明できる
- `--mode bugbounty` で legacy `--scope` を渡すと preflight error になり、bundle 導線へ誘導される
- 同一 bundle を再compileしたとき、normalized facts hash と compiled policy hash が安定して一致する
- active bundle / compiled artifact が破損・欠落している場合は fail-closed し、rollback または再activate 導線が提示される
- manual review が必要な bundle では pending finding 一覧、source refs、override skeleton、recompile コマンドが提示される
- shadow rollout 中に compile failure、block reason、active bundle read failure、manual review 比率を観測できる
- resume / retry が既定で同一 `bundle_id` / `policy_id` を引き継ぎ、明示 rebind 時のみ新 bundle を使う

## 4.3 この計画でやらないこと
- HackerOne / Bugcrowd API からの自動同期
- 報酬額や bounty 履歴を使った ROI ランキング
- runtime 中に自然文ルールを再解釈する専用 AI judge
- full自動で曖昧性を解消する仕組み

## 4.4 shared evaluator / active bundle の実装分解
- **実装ユニットA: guard contract / loader / evaluator を `src/core/security/` に新設する**
  - `compiled_guard_models.py` または同等モジュール: `LoadedGuardPolicy`, `GuardInput`, `GuardDecision`, `GuardFailure` などの DTO を定義する
  - `compiled_guard_loader.py` または同等モジュール: `--program` / `--bundle-id` / `active_bundle.json` から active policy を解決し、`compile_status=ready`、hash 一致、schema 互換を確認する
  - `compiled_guard_evaluator.py` または同等モジュール: pure function で `guard_input -> guard_decision` を返す。host / path / attack_class / phase / budget / auth / post_exploit をここで一元評価する
- **実装ユニットB: MC preflight と dispatch に policy を固定する**
  - `src/core/engine/master_conductor.py` の run 開始前で active bundle を解決し、`bundle_id` / `policy_id` / `compiled_policy_hash` を run context へ凍結する
  - `verify_scope` fast-path の bug bounty 用分岐は、即席 `ScopeDefinition` 注入ではなく loader 経由の bundle 解決へ寄せる
  - `_dispatch()` の post-exploit block は `allow_post_exploit` bool 直参照から、shared evaluator に `phase=post_exploit` を渡す判定へ置き換える
  - `_trigger_post_exploit()` の task 生成前にも shared evaluator を呼び、task を作る前に deny できるようにする
- **実装ユニットC: HTTP 実送信は `network_client` で fail-closed にする**
  - `src/core/infra/network_client.py` を HTTP 実送信の最低レイヤ enforcement point とし、送信直前に `guard_input` を評価する
  - `src/core/infra/smart_request.py` は method / payload / HITL 判定を継続しつつ、`bundle_id` / `policy_id` / `phase` / `requested_action` / `source_agent` を network layer へ渡す薄い adapter に寄せる
  - これにより `SmartRequest` を経由しない direct HTTP call が残っていても、最終送信前に block できる
- **実装ユニットD: subprocess / external tool は共通入口で止める**
  - `src/core/adapters/external/base_external_adapter.py` の `run_with_validation()` に tool 実行前 guard を追加し、adapter 個別実装へ分散させない
  - `src/core/tools/context_runner.py` では legacy `EthicsGuard` による shell pattern block を defense-in-depth として残しつつ、shared evaluator の `requested_action=external_tool_exec` を先に評価する
  - `src/core/agents/swarm/base_manager.py` の `_execute_tool()` では manager 層の `guard_input` を作ってから tool 関数を呼ぶ
- **実装ユニットE: legacy scope path は compatibility layer として閉じ込める**
  - `src/core/security/scope_parser.py` と `src/core/security/ethics_guard.py` は非 bug bounty モードや既存軽量 scope 互換のために残す
  - bug bounty mode では `ScopeDefinition` を runtime 正本に昇格させず、bundle compiler の出力だけを正本とする
  - `allow_post_exploit` のような legacy field は compiled policy へ写像した上でのみ runtime 判断に使う

### 4.4.1 最初の実装順（推奨）
- 1. `src/core/security/` に contract / loader / evaluator を追加し、TikTok / Fireblocks fixture ベースの unit test を先に作る
- 2. `src/core/engine/master_conductor.py` の run preflight に loader を差し込み、`bundle_id` / `policy_id` / `compiled_policy_hash` を context へ固定する
- 3. 同じく `master_conductor.py` の `_dispatch()` / `_trigger_post_exploit()` を shared evaluator ベースへ移行し、post-exploit bool 直参照を減らす
- 4. `src/core/infra/network_client.py` に HTTP fail-closed を入れ、`smart_request.py` は guard context 受け渡し adapter に寄せる
- 5. `src/core/adapters/external/base_external_adapter.py`、`src/core/tools/context_runner.py`、`src/core/agents/swarm/base_manager.py` に tool / subprocess guard を順次追加する
- 6. 最後に `scope_parser.py` / `ethics_guard.py` の bug bounty 依存分岐を compatibility layer として整理し、legacy `--scope` bug bounty 導線の内部撤去準備へつなぐ

## 5. 懸念点と対策

### 5.1 SRE / インフラ視点
- [ ] [発生確率:中 / 影響度:大] active bundle / compiled artifact の破損や参照切れが起きると run 開始前に安全に止められない懸念
  対策: ステップ7とステップ11で `active_bundle.json`、manifest、compiled policy の整合確認、fail-closed、rollback / re-activate runbook を定義する
- [ ] [発生確率:高 / 影響度:大] audit log だけでは compile failure や block 偏りを早期に検知できず、運用異常の発見が遅れる懸念
  対策: ステップ9とステップ12で `compile_failed率`、`manual_review_required率`、`active bundle read failure`、`block reason top-N` を metrics / alert 条件として定義する
- [ ] [発生確率:中 / 影響度:中] bundle retention と prune 条件が曖昧だと orphan artifact やディスク膨張が発生する懸念
  対策: ステップ7とステップ11で named/ephemeral の保存先、TTL、最大保持方針、`prune --dry-run` と orphan 検知運用を定義する

### 5.2 ソフトウェアアーキテクト視点
- [ ] [発生確率:高 / 影響度:大] adapter / compiler / evaluator / MC / runtime guard の責務が曖昧なままだと、既存 `scope_parser` / `ethics_guard` / `chain_builder` と責務重複が発生する懸念
  対策: ステップ2で責務分離マトリクスを作り、「抽出」「compile」「実行判定」「orchestration」の ownership を固定する
- [ ] [発生確率:高 / 影響度:大] MC / manager / worker / 外部アクセス層が別々の判断 API を持つと、同一 policy でも layer ごとに挙動がズレる懸念
  対策: ステップ2とステップ8で `guard_input` / `guard_decision` の shared evaluator API を唯一の契約として定義し、各層はラッパーのみ許可する
- [ ] [発生確率:中 / 影響度:中] schema version はあっても互換・migration ルールがないと、将来の field 追加や rename で reader が壊れる懸念
  対策: ステップ5で schema compatibility policy、additive change 原則、migration helper がない breaking change 禁止を明記する

### 5.3 デバッガー視点
- [ ] [発生確率:高 / 影響度:中] raw source -> normalized facts -> compiled policy -> runtime block の因果を一意に辿れず、deny 理由の解析が難航する懸念
  対策: ステップ5で `decision_trace_id`、`rule_origin_id`、`source_ref` を compile / runtime の必須追跡キーとして定義する
- [ ] [発生確率:高 / 影響度:中] 正例 fixture だけでは曖昧文、timezone parse failure、secret 混入、artifact 欠落などの失敗系を潰し切れない懸念
  対策: ステップ10で negative fixture を明示追加し、failure path も受け入れ条件に含める
- [ ] [発生確率:中 / 影響度:中] deterministic processing order を定義しても snapshot / hash 回帰がないと、微妙な parser 変更を検出できない懸念
  対策: ステップ5とステップ10で same bundle => same normalized facts hash / compiled policy hash の snapshot 検証を固定する

### 5.4 CTO視点
- [ ] [発生確率:中 / 影響度:大] 変更範囲が MC から外部アクセス層まで広いのに、段階導入がないと一括導入リスクが高い懸念
  対策: ステップ9で `shadow read-only -> MC only enforcement -> worker/external hard enforcement` の rollout 段階と kill switch を定義する
- [ ] [発生確率:高 / 影響度:中] 完了条件が compile 成功中心で、運用品質や誤 block コストを測る経営レベルの評価軸が不足する懸念
  対策: ステップ12で false block 許容率、manual review 比率、unsafe dispatch 予防件数、import -> ready 所要時間を受け入れ指標として追加する
- [ ] [発生確率:中 / 影響度:中] `policy.md`、review note、credential ref の保存区分とログ出力禁止項目が曖昧だと、将来のデータガバナンス事故につながる懸念
  対策: ステップ7で data governance 節を追加し、bundle の保存区分、secret-adjacent 項目、ログ禁止項目、削除/保持ルールを定義する

### 5.5 共通Backlog / 技術的負債
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] provider ごとに文面の癖が強く、deterministic parser だけで 100% 自動化しきれない - V1 は manual review 前提の compile gate を置く
- [ ] [重要度:高] enforcement point の漏れがあると compiled policy があっても bypass される - 実送信 path の棚卸しを先に終えて shared evaluator に寄せる
- [ ] [重要度:中] human correction schema を複雑にしすぎると運用負荷が高い - まずは host / attack_class / post_exploit / budget に絞る
- [ ] [重要度:中] raw program 更新を見落とすと stale policy が残る - source hash と compiled_at を保持し差分検知する
- [ ] [重要度:中] audit trace が弱いと「なぜ deny されたか」を説明できない - evidence ref と rule origin を compile 時に保存する

### 5.6 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0335-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```

## 5.7 `--scope` 内部撤去の素案

この撤去は V1 完了条件には含めない。bug bounty mode での入口封鎖を先行し、
内部コード削除は別フェーズで段階実施する。

- Phase A: `--mode bugbounty` で `--scope` を preflight error にする
- Phase B: help / examples / manuals から bug bounty 用 `--scope` 例を削る
- Phase C: `rg` で bug bounty 文脈の `--scope` 参照を棚卸しし、互換影響を確認する
- Phase D: bundle 導線へ migration 済みを確認してから、bug bounty 専用の legacy parser 分岐を削除する
- Phase E: 最後に他モードでの `--scope` 利用有無を再確認し、共通コードの完全撤去可否を判断する
