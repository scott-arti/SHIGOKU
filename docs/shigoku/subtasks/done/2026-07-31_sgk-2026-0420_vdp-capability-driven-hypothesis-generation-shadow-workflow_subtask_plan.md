---
task_id: SGK-2026-0420
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/plans/2026-07-31_vdp-capability-benchmark-and-evidence-contract_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0419_vdp-evidence-schema-safety-budget-and-recovery-foundation_subtask_plan.md
- docs/shigoku/reports/2026-08-03_sgk-2026-0420_vdp-capability-driven-hypothesis-generation-shadow-workflow_work_report.md
- docs/shigoku/worklogs/2026-08-03_sgk-2026-0420_vdp-capability-driven-hypothesis-generation-shadow-workflow_work_log.md
title: VDP capability driven hypothesis generation shadow workflow
created_at: '2026-07-31'
updated_at: '2026-08-03'
tags:
- shigoku
target: src/core/engine,src/core/intelligence
---

# 実装計画書：VDP capability driven hypothesis generation shadow workflow

## 1. ゴール

- [ ] 製品名、既知URL、既知脆弱性を使わず、観測された機能と信頼境界から攻撃仮説を生成する。
- [ ] 正常条件、攻撃条件、逆条件、必要証拠、反証条件を持つHypothesisRecordを作る。
- [ ] 最初はrecord-onlyで保存し、既存task queueや通信動作を変えない。
- [ ] LLM出力を未信頼提案として扱い、決定論的schema/action/scope検証を通過した仮説だけを候補にする。

## 2. 依存と対象

SGK-2026-0419のschema、ProgramCapabilityMatrix、ExecutionBudget、scope admission完成後に開始する。

- src/core/engine/recipe_loader.py: attack surface signalを能力意味へ正規化。既存の正規化関数は変更せず、VDP専用の変換を独立pipeline（vdp_hypothesis_generator.py）で実装する。
- src/core/intelligence/strategy_selector.py: 既存StrategySelector.select()の出力は変更しない。evidence付きpriority traceは独立VDP pipeline（vdp_hypothesis_generator.py）で新規実装し、既存attack taskの優先順位に影響を与えない。
- src/core/engine/task_expander.py: 既存TaskExpander.expand()の出力は変更しない。URL単位の観測からactor/capability単位への展開は独立VDP pipeline（vdp_hypothesis_generator.py）で新規実装する。
- src/core/engine/recipe_contracts.py: action allowlist、stop condition、decision reason codeを再利用。
- src/core/engine/master_conductor.py: recon結果の統合後・既存attack task生成前の独立した加算的hookで、record-only hypothesis artifactの保存だけを接続する。
- src/core/models/vdp_contract.py: SGK-2026-0419のHypothesisRecordをadditive拡張し、0420専用validator（validate_hypothesis_record_v0420）を新設する。既存v1 validatorは変更しない。
- src/core/engine/vdp_observation_adapter.py: 観測源→typed Observation変換の安全な境界adapterを新設する（UUID/時刻/秘密値の除去）。
- tests/unit/engine と tests/core/engine: 決定論、scope、重複、shadowの試験。

## 3. 仮説生成仕様

観測源はcrawler、form、JavaScript、API schema、GraphQL、browser traffic、proxy historyとする。各観測はsourceとfreshnessを保持する。

### 3.1 観測の安全な取り込み（ObservationAdapter）

- 観測源は `vdp_observation_adapter.py` のObservationAdapter境界でtyped Observationへ変換する。
- signal_bundleの `signal_id`（実行ごとのUUIDを含む）と `created_at`（現在時刻）は決定処理の入力から除外し、別フィールドのprovenanceとしてのみ保持する。
- Authorization、Cookie、token等の秘密値は生成器へ渡す前に値を完全に破棄し、「has_auth_header」「has_cookie」等の安全な真偽値だけに変換する。保存時redactは二重防御であり、入力境界での破棄に代わるものではない。
- 観測源は `ObservationSourceKind` で識別する（recon_signal_bundle、crawler、form、javascript、api_schema、graphql、browser_traffic、proxy_history、unavailable）。SGK-2026-0420ではrecon_signal_bundleのみ接続し、その他の観測源はgeneration status traceへ `unavailable` 理由付きで記録する。未接続adapterの拡張はSGK-2026-0421の追跡タスクへ紐付ける。
- 観測IDは正規化データ（scheme+hostname検証済みURL、method、entity_type、param名ソート、auth真偽値）のcanonical JSONからSHA-256ハッシュで生成する。区切り文字連結（`|`等）は値に区切り文字が含まれると衝突するため使用しない。

### 3.2 決定論的IDとキー

- 仮説ID・dedup key・verdict ID・next action IDは、固定キー・型・配列順を持つcanonical JSONのバイト列をSHA-256へ渡して生成する。
- `dedup_key` は本当に同じ仮説だけをまとめるキーとし、resource_ownerとvariantも含める。
- `diversity_bucket` は似た仮説の件数を予算内に抑える内部キーとし、dedup_keyとは分離する。
- raw signal_id・時刻・乱数は決定的snapshotに含めない。
- UUID、現在時刻、乱数を決定結果へ混ぜない。LLM出力は信用せず、決定論的validatorを通す（LLM呼出し自体は行わない。`validate_proposal_dict()` を偽の辞書入力で検証する）。

### 3.3 scope_verdictとbudget_estimate

- `scope_verdict` は既存のscope/admission機構（`revalidate_scope_for_request` / `ScopeRevalidationResult`）から作り、文字列を推測で設定しない。判定不能は `scope_revalidation_blocked` 相当とし、admittedにしない。
- `budget_estimate` は既存のExecutionBudgetV1のフィールド（max_requests、max_follow_ups、max_retries等）と対応する形の辞書にする。record-onlyだからといって根拠なくallowedにしない。

能力分類は固定URLではなく次の意味分類を使う。

- object read/write/delete。
- authentication/session/token。
- role/permission/ownership。
- state transition/approval/invite/refund。
- file upload/transform/publish。
- external URL fetch/callback/redirect。
- render/store/search/template。
- asynchronous job/webhook。
- time/order/concurrency/idempotency。

各HypothesisRecordは次を必須とする。

- observation IDs、capability、trust boundary。
- unauth/authA/authB/adminなどのactorsとresource owner。
- preconditionsと不足時の解除方法。
- baseline、attack、inverse control。
- success condition、falsification condition、required evidence。
- risk class、scope verdict、budget estimate。
- priority trace、dedup key、generator version。

## 4. 品質向上ロジック

1. 複数観測源が一致する仮説を強化し、単一源の推測を区別する。
2. HTTP statusや本文長だけでなく、owner、actor ID、permission、state、sensitive fieldの意味差分を使う。
3. schema型、位置、JSON階層、array、multipart、header、Cookie、GraphQL variableを変異設計へ含める。
4. 状態機械と業務不変条件から順序違反、再送、期限、競合仮説を生成する。
5. 単体候補間の入力/出力と信頼境界が接続するときだけchain hypothesisを作る。
6. 高信頼仮説だけでなく未知領域用の探索枠をbudget内に確保する。
7. 同じURL/parameterの類似仮説を抑え、capability/actor/trust boundaryの多様性を優先する。
8. expected impactだけでなくinformation gain、証拠取得可能性、前提充足度、必要request数で順位付けする。
9. LLM提案はallowlist actionとtyped schemaへ変換できない限り保存のみ、実行不可とする。
10. 固有URLやknown answerが入力へ混入した場合はlabel_leakage_detectedで拒否する。

## 5. Record-onlyとshadow

- M1 record-onlyではHypothesisRecordをartifactへ保存するがtaskを作らない。
- 既存task planと並行して仮説差分を取得し、生成理由、抑制理由、未生成理由を比較する。
- M2 shadowではNextAction提案まで作るがqueueへ投入しない。
- record-only/shadow中に通信数、既存finding、既存reportを変えてはならない。
- deterministic input snapshotとgenerator versionを保存し、同じ入力から同じ仮説集合を再現する。
- LLMを使う場合はrole-based LLMClientのみとし、model直指定やsystem prompt直書きを行わない。SGK-2026-0420ではruntime LLM呼出しを行わず、純粋関数で実装する。LLM提案の検証は偽の辞書入力に対する決定論的validator（validate_proposal_dict）で行う。
- 仮説が0件（観測なし、全拒否、全失敗）の場合はvdp_active=Falseのままとし、VDP sectionへrun_health等のデータを入れない。生成失敗理由と観測源のunavailable記録は既存のdecision trace（_shadow_decisions / decision_tracer）へ保存する。これはM0 gateがinactive+dataを拒否するためである。

## 6. 実装順序

0. 計画書修正（P-0）を文書検証（sync_shigoku_updated_at.py → validate_shigoku_docs.py 0エラー）で固定してからコード実装を開始する。計画書の変更はこのタスクの「最初の編集対象」であり、commit対象ではない（本タスク中はcommit・push・branch切替を禁止する）。
1. Observationからcapabilityへ変換する純粋関数とtyped resultを追加する。
2. HypothesisRecord builderとschema validator（v0420専用）を追加する。
3. actor/owner、state machine、type-aware mutation、control条件を生成する。
4. diversity dedupとpriority traceを追加する。
5. record-only artifactへ接続する。
6. shadow NextAction提案を追加し、queue非投入を保証する。
7. 対象非依存fixtureとpermuted endpoint fixtureでgolden/evalを実行する。

### 作業手順（コード実装時）

- T-0開始時に `git status --short` を再記録し、既存の無関係な変更を戻さない。
- 各必須テストに対応する失敗テストを先に追加し、最小実装で通す。
- 未接続の観測源adapterは「0421以降」等の曖昧な表記にせず、具体的な追跡タスクID（SGK-2026-0421）へ紐付けて記録する。
- コード変更後は `graphify update .` を実行してgraphを最新化する。
- 完了時には work_report・work_log・台帳（task_registry.yaml / task_ledger）の更新と plan/subtaskのdone/移動を実施する。本タスク中は status を active のまま維持し、done/移動は文書クローズフェーズで行う。
- 新規ファイルは `git diff --no-index --check /dev/null <file>` でも検査する（未追跡ファイルは `git diff --check` では検査できないため）。

## 7. 必須テスト

- URL、parameter名、順序を変えても同じ能力意味から同等仮説が生成される。
- 製品名、既知脆弱性ラベル、flagがruntime入力に含まれると拒否する。
- 同一入力でHypothesisRecord集合とpriority traceが決定的に一致する。
- malformed LLM output、未知action、scope不明でtaskが生成されない。
- authA/authB/resource ownerが欠ける認可仮説はprecondition不足になる。
- baseline/attack/inverse/falsificationが欠ける仮説はadmittedにならない。
- diversity budgetが同一URLの類似仮説を抑制する。
- record-only/shadowでnetwork clientとtask queueが呼ばれない。
- secretを含む観測値がartifactでredactされる。
- generator失敗が既存実行を壊さずdegraded reasonを残す。
- 入力のUUIDと現在時刻だけを変えても、仮説ID・dedup・並び順が同じ（決定論）。
- Authorization/Cookie値がgenerator入力にもartifactにも存在しない（秘密値不在）。
- 仮説0件ではvdp_active=FalseかつVDP run_healthなし、M0 gateはPASS。
- 一部成功・全部失敗の両方で既存実行が継続する。
- 0419形式の旧HypothesisRecordが引き続きM0を通る（旧v1互換）。
- 不正なVDP modeが安全にoffになる。
- runtime LLM、network client、task queueが一度も呼ばれない。
- 実際のrun()接続点→session保存→M0 gateまで通る（実経路統合）。
- resumeまたは同一hookの再実行で重複recordが増えない（べき等）。
- canonical JSON（区切り文字を含む値）でID衝突が起きない。

## 8. 完了条件

- M1 record-onlyとM2 shadowの受入条件を満たす。
- 対象非依存fixtureで仮説の能力意味が維持される。
- known answer leakage、scope逸脱task、理由不明仮説が0件。
- 既存通信数と既存finding判定に差がない。
- SGK-2026-0421が消費できるHypothesisRecord/NextAction候補がversion付きで保存される。
- 決定論: 同一正規化入力から仮説ID・dedup key・priority trace・並び順が常に一致し、入力のUUID・時刻・順序の変化に影響されない。
- 秘密値不在: 生成器入力・HypothesisRecord・artifactのいずれにもCookie/Authorization/tokenの生値が存在しない。
- 旧v1互換: 既存v1 validator（validate_hypothesis_record）は不変更で、0419形式の旧HypothesisRecordが引き続きM0を通過する。0420生成recordは0420専用validator（validate_hypothesis_record_v0420）で全項目必須を検証する。
- scope_verdictとbudget_estimateは既存のscope/admission機構とExecutionBudgetV1から導出し、推測値や根拠のないallowedを使用しない。

## 9. NOT in scope

- follow-upの実通信。
- confirmed判定。
- report/gate変更。
- hidden holdoutの最終判定。
- target固有recipeやpayload追加。

