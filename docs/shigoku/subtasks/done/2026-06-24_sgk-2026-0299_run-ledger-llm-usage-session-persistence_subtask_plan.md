---
task_id: SGK-2026-0299
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0298
related_docs:
- docs/shigoku/plans/2026-06-24_sgk-2026-0298_internal-behavior-visibility-governance_plan.md
- docs/shigoku/specs/visibility_and_metrics.md
title: '内部挙動可視化 S1: Run Ledger・LLM使用量・セッション永続化'
created_at: '2026-06-24'
updated_at: '2026-06-30'
tags:
- shigoku
target: DecisionTrace, TaskExecutionLog, AuditLogger, session payload, LLM usage
---

# 実装計画書：内部挙動可視化 S1: Run Ledger・LLM使用量・セッション永続化

## 1. 達成したいゴール（ユーザー視点）
- [ ] SHIGOKUの実行後、どのAI/Swarm/ツールがどれだけLLMトークンを使い、何を判断材料にして、何を実行したかがsession一次証跡として残ること。
- [ ] MC判断、Swarm委譲、ツール実行、失敗、再試行、HITL、Finding生成を同じ相関IDで追跡できること。
- [ ] 既存の `DecisionTrace`、`TaskExecutionLog`、`AuditLogger` を捨てずに、足りない永続化とusage集計だけを追加すること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/models/decision_trace.py`: 修正候補。`source_event_ids`、`confidence`、`inference_level` など追加余地を確認する。
  - `src/core/models/task_execution_log.py`: 修正候補。Swarm/tool/LLM usage参照をmetadataへ保存できる契約を固定する。
  - `src/core/utils/audit_logger.py`: 修正候補。イベント種類に `decision_made`, `swarm_dispatched`, `llm_called` 相当を追加するか、detailsで表現する。
  - `src/core/engine/master_conductor_session_service.py`: 修正。session payloadに `decision_traces`, `task_execution_records`, `run_ledger`, `llm_usage_summary` を追加する。
  - `src/core/engine/master_conductor.py`: 修正候補。MC判断・リプラン・prioritizer選択・coverage backfill生成時にrun ledgerへ記録する。
  - `src/core/engine/swarm_dispatcher.py`: 修正。tags -> swarm選択、SwarmTask作成、result merge、failureをrun ledgerへ記録する。
  - `tests/core/engine/`、`tests/unit/core/`: 新規/修正。session payload互換とledger生成の回帰を固定する。
- **データの流れ / 依存関係:**
  - MC decision -> `DecisionTracer.trace()` -> run ledger event -> session payload
  - MC task execution -> `TaskExecutionRecord` -> run ledger event -> session payload
  - Swarm dispatch -> `SwarmResult.execution_log` -> run ledger event -> session payload
  - LLM client response usage -> normalized usage record -> per-agent/per-model summary -> session payload
  - EventBusはリアルタイム通知、RunLedgerRecorderは永続化の正本とする。EventBusのdropや購読失敗があっても、session一次証跡の最小イベントは失われない設計にする。
  - `DecisionTrace` / `TaskExecutionRecord` / `AuditEvent` はdomain record、`RunLedgerEvent` は時系列相関index、session payloadはreader contractとして扱う。既存recordの重複コピーではなく、`source_refs` で参照関係を保持する。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - `DecisionTrace`: decision_type, input_context, available_options, selected_option, reasoning, outcome
  - `TaskExecutionRecord`: task_id, agent_type, action, result, duration_seconds, vulnerabilities_found, metadata
  - `AuditEvent`: event_type, action, target, details, result
  - LLM usage: model, caller, input_tokens, output_tokens, input_cache_tokens, cost estimate, request_id if available
- **出力/結果 (Output):**
  - `session_*.json.run_ledger_schema_version`: 初期値 `1`
  - `session_*.json.llm_usage_summary_schema_version`: 初期値 `1`
  - `session_*.json.run_ledger[]`: event_id, timestamp, phase, actor_type, actor_name, task_id, decision_id, parent_event_id, event_type, input_summary, input_fingerprint, action, result, error, source_refs, inference_level, redaction_status
  - `session_*.json.llm_usage_summary`: by_model, by_actor, totals, cache_hit_ratio, unknown_count, estimated_count
  - `session_*.json.decision_traces[]` と `task_execution_records[]` の永続化
- **制約・ルール:**
  - 既存session readerが壊れないよう、新規フィールドは任意扱いで追加する。
  - prompt全文やsecretは保存しない。必要な場合はマスク済みsummaryとhash/fingerprintにする。
  - LLM usageを取得できないproviderでは `unknown` とし、推定値をraw usageとして扱わない。
  - `LLMUsageRecord` は `model`, `actor`, `input_tokens`, `output_tokens`, `input_cache_tokens`, `request_id`, `raw_provider`, `usage_source`, `usage_status: measured|estimated|unknown`, `cache_status: hit|miss|bypass|unknown`, `cost_estimate_status: exact|estimated|unavailable` を持つ。
  - `estimated` はraw usage totalsに混ぜず、summaryでは別カウントにする。
  - event_idはMarkdown出力側が参照できる安定IDにする。形式は `ledger_evt_<run_id>_<monotonic_seq>` を基本にし、同一run内で単調増加・衝突なしを保証する。
  - session内の `run_ledger` は重要イベント最大N件 + summaryを基本とし、詳細全量が必要な場合はJSONL spoolへ逃がす。spoolを使う場合は `spool_path`, `spool_sha256`, `spool_event_count` をsessionへ保存する。
  - 既存 `AuditLogger` detailsやtool commandを取り込む場合も、run ledger投入前に共通redactorを通し、Cookie/API key/token/raw prompt/raw responseを保存しない。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `RunLedgerEvent` / `LLMUsageRecord` / `RunLedgerSummary` の最小モデルを定義し、`DecisionTrace` / `TaskExecutionRecord` / `AuditEvent` との責務境界をdocstringと単体テストで固定する。
  - `RunLedgerEvent` は既存recordのコピーではなく、`source_refs` と相関IDを持つ時系列indexとして扱う。
  - `run_ledger_schema_version` / `llm_usage_summary_schema_version` を定義する。
  - `event_id` 生成器を作り、同一run内の単調増加・衝突なし・`parent_event_id` 参照を単体テストで固定する。
- [ ] ステップ2: session肥大化対策を先に実装する。
  - session内に保持する重要イベントの上限N、summary項目、JSONL spool切替条件を決める。
  - spoolを使う場合は `spool_path`, `spool_sha256`, `spool_event_count` をsession payloadへ保存する。
  - spoolなし・spoolあり・上限超過時の古い詳細イベント扱いをテストする。
- [ ] ステップ3: redaction / fingerprint境界を実装する。
  - prompt全文、raw response、Cookie、API key、token、secretを保存禁止にする。
  - `input_summary`, `input_fingerprint`, `redaction_status`, `redacted_fields_count` をledger eventへ入れる。
  - `AuditLogger` detailsやtool commandを取り込む場合も再マスクする。
  - secretを含むfixtureでsession / spool / stdoutに漏れないことをテストする。
- [ ] ステップ4: `master_conductor_session_service.py` に新規フィールドを追加し、旧session reader互換を固定する。
  - `decision_traces`, `task_execution_records`, `run_ledger`, `llm_usage_summary`, schema version, spool metadataをpayloadに追加する。
  - 旧session fixture、schema version欠落、新規未知フィールド、空ledger、spool metadataありの読み込みテストを追加する。
  - `session_interrupted_*.json` 相当の中断保存でも同じ追加フィールドが保持されることを確認する。
- [ ] ステップ5: MC判断、Swarm dispatch、tool/error/finding/HITLの代表イベントをrun ledgerへ記録する。
  - MC判断、リプラン、prioritizer選択、coverage backfill生成時に `decision_made` 系イベントを記録する。
  - Swarm単位で `swarm_dispatched`, `swarm_completed`, `swarm_failed`, `swarm_merged`, `swarm_skipped` を記録し、merge前status配列とfinding countをsource_refsに残す。
  - tool/error/finding/HITLは `tool_executed`, `error_occurred`, `finding_created`, `hitl_requested`, `hitl_resolved` として相関IDを付ける。
  - EventBusは通知用途、RunLedgerRecorderは永続化正本として、EventBus drop時も最小ledger eventが残るようにする。
- [ ] ステップ6: LLM client境界でusageを正規化し、input/output/input_cacheをactor別・model別に集計する。
  - LiteLLM応答、provider fallback、retry、timeout、authentication error、usage未取得を `usage_status` で区別する。
  - cache hitは `llm_cache_hit` eventとして記録し、raw usageは `unknown`、`cache_status=hit` にする。
  - `llm_called`, `llm_retry`, `llm_failed`, `provider_fallback` を記録する。
  - `estimated` usageとcost estimateはraw totalsに混ぜず、summaryで別カウントする。
- [ ] ステップ7: 中断・保存失敗・flushの回復動作を実装する。
  - 例外、KeyboardInterrupt、session保存失敗時にledger/usageがflushされるか、失敗理由が明示されるようにする。
  - session保存に失敗してもJSONL spoolが残る、またはfail-closedで欠落を明示するテストを追加する。
- [ ] ステップ8: downstream contract fixtureを作る。
  - S2-S4が読む最小fixtureとして、decision、Swarm、tool、LLM cache hit、LLM measured usage、finding、HITL、中断を含む合成sessionを用意する。
  - `event_id`, `timestamp`, `actor_type`, `event_type`, `result`, `source_refs`, `inference_level` の必須/任意をfixtureで固定する。
- [ ] ステップ9: targeted testsを先に実行し、実sessionがあれば `shigoku-ops` 経由のsession inspect/consistency関連コマンドで破壊がないことを確認する。
  - 最低限: session payload互換、ledger ID、retention/spool、redaction、LLM usage、Swarm merge、中断flushの単体テストを実行する。
  - 実sessionがある場合: `.venv/bin/shigoku-ops ...` または `python3 scripts/shigoku_ops_cli.py ...` を優先して検証する。
  - report pathが与えられた場合のみ、`python3 scripts/verify_report_session_consistency.py --report <absolute-report-path>` を実行する。

## 5. 懸念点と対策

### 5.1 SRE / インフラエンジニア視点
- [ ] 【発生確率:高】【影響度:大】session肥大化で保存・読み込み・レポート生成が遅くなる。
  - 対策: session内は重要イベント最大N件 + summaryに限定し、詳細全量は任意JSONL spoolへ逃がす。spool使用時は `spool_path`, `spool_sha256`, `spool_event_count` をsessionへ保存する。
- [ ] 【発生確率:中】【影響度:大】session保存失敗時に一次証跡だけ欠落する。
  - 対策: session保存失敗時もledger/usage spoolをflushするか、fail-closedで欠落理由を明示する。保存失敗fixtureで回復動作をテストする。
- [ ] 【発生確率:高】【影響度:中】EventBusのキュー溢れや購読失敗とrun ledgerの完全性が食い違う。
  - 対策: EventBusは通知用途、RunLedgerRecorderは永続化正本と定義する。EventBus drop時も同期的に最小ledger eventを残す。
- [ ] 【発生確率:中】【影響度:中】実行中断時のflush条件が未定義で、`session_interrupted_*.json` だけ証跡が薄くなる。
  - 対策: 例外、KeyboardInterrupt、中断保存でも通常sessionと同じ追加フィールドをflushするテストを追加する。

### 5.2 ソフトウェアアーキテクト視点
- [ ] 【発生確率:高】【影響度:大】`DecisionTrace` / `TaskExecutionRecord` / `AuditEvent` / `RunLedgerEvent` の責務境界が曖昧になる。
  - 対策: 既存モデルはdomain record、`RunLedgerEvent` は時系列相関index、session payloadはreader contractと明記する。重複コピーではなく `source_refs` で参照する。
- [ ] 【発生確率:高】【影響度:大】`event_id` の安定性が実装任せになり、Markdownや後続formatterが参照できなくなる。
  - 対策: `ledger_evt_<run_id>_<monotonic_seq>` 形式を基本にし、同一run内の単調増加・衝突なし・親子参照を単体テストで固定する。
- [ ] 【発生確率:中】【影響度:大】schema追加がreader互換だけで、S2-S4のwriter/formatter契約が不足する。
  - 対策: `run_ledger_schema_version` / `llm_usage_summary_schema_version` とdownstream contract fixtureを追加し、必須/任意フィールドを固定する。
- [ ] 【発生確率:中】【影響度:中】LLM usage集計モデルがprovider固有フィールドに引きずられる。
  - 対策: `usage_status`, `usage_source`, `raw_provider`, `cache_status`, `cost_estimate_status` を持つ正規化モデルを作り、provider差分を境界で吸収する。

### 5.3 デバッガー視点
- [ ] 【発生確率:高】【影響度:大】LLM cache hit時のusageが0扱いされ、実コストや挙動分析を誤る。
  - 対策: cache hitは `llm_cache_hit` eventとして記録し、raw usageは `unknown`、`cache_status=hit` とする。0 tokenとは区別する。
- [ ] 【発生確率:高】【影響度:中】失敗・再試行の相関がLLM retry内で見えなくなる。
  - 対策: `llm_retry`, `llm_failed`, `provider_fallback` をattempt単位で記録し、最終結果とsource_refsでつなぐ。
- [ ] 【発生確率:中】【影響度:大】prompt全文を保存しない方針により、デバッグに必要な入力差分まで消える。
  - 対策: raw promptは保存せず、`input_summary`, `input_fingerprint`, `redaction_status`, `redacted_fields_count` で比較可能性を残す。
- [ ] 【発生確率:中】【影響度:中】SwarmDispatcherの複数Swarm mergeで、どのSwarmの失敗が最終statusに寄与したか追えない。
  - 対策: `swarm_dispatched`, `swarm_completed`, `swarm_failed`, `swarm_merged`, `swarm_skipped` をswarm単位で記録し、merge前status配列とfinding countを残す。

### 5.4 CTO視点
- [ ] 【発生確率:高】【影響度:大】S1の契約が曖昧なまま進むと、S2-S4のMarkdown/Neo4j/Haddixが作り直しになる。
  - 対策: downstream contract fixtureをS1で作り、`event_id`, `timestamp`, `actor_type`, `event_type`, `result`, `source_refs`, `inference_level` の必須/任意を固定する。
- [ ] 【発生確率:中】【影響度:大】可視化のための証跡が、秘匿情報・認証情報漏えいの経営リスクになる。
  - 対策: run ledger投入前に共通redactorを通し、既存AuditLogger detailsを取り込む場合も再マスクする。secret fixtureで漏えいしないことを検証する。
- [ ] 【発生確率:中】【影響度:中】usage cost estimateが不正確だと、意思決定指標として信頼されない。
  - 対策: 初期S1ではtoken countsを優先し、costは `cost_estimate_status` と `pricing_source` を付けた任意情報にする。`estimated` はraw totalsと分ける。
- [ ] 【発生確率:中】【影響度:中】運用受け入れ基準が「テストを実行」だけで、成果物品質の判定が弱い。
  - 対策: 完了条件に「旧session互換テストPASS」「新sessionに4フィールドが出る」「secret fixtureで漏えいなし」「合成または実sessionを `shigoku-ops` 経由でinspectできる」を入れる。

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] providerごとにusageフィールド名が違う。 - LLM client境界で正規化し、未取得と0を区別する。
- [ ] [重要度:中] すべてのイベントをsessionに入れると肥大化する。 - sessionにはsummaryと重要イベント、詳細はJSONL spoolを検討する。
- [ ] [重要度:中] 判断理由にLLMの内部推論を過剰に期待しない。 - 保存対象は入力要約、選択肢、選択理由の説明、結果に限定する。

### 6.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0299-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
