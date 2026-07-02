---
task_id: SGK-2026-0338
doc_type: spec
status: active
parent_task_id: SGK-2026-0001
related_docs:
  - docs/shigoku/plans/done/2026-07-02_sgk-2026-0338_user-manual-and-internal-spec_plan.md
  - docs/shigoku/manuals/2026-07-02_sgk-2026-0338_operator-user-manual.md
  - docs/shigoku/manuals/2026-07-02_sgk-2026-0337_detailed-command-reference.md
  - docs/shigoku/specs/TECHNICAL_SPEC_JA.md
  - docs/shigoku/specs/ARCHITECTURE.md
title: SHIGOKU 内部仕様書 2026-07 アーキテクチャとデータフロー
created_at: '2026-07-02'
updated_at: '2026-07-02'
tags:
  - shigoku
  - spec
  - architecture
target: SHIGOKU runtime architecture and dataflow
---

# SHIGOKU 内部仕様書 2026-07 アーキテクチャとデータフロー

この仕様書は、SHIGOKU がどの入口から起動し、内部でどのモジュールが何を担当し、どのデータがどこへ渡され、どの成果物として保存されるかをまとめた現行版です。旧仕様の [`TECHNICAL_SPEC_JA.md`](TECHNICAL_SPEC_JA.md) と [`ARCHITECTURE.md`](ARCHITECTURE.md) には過去設計も含まれるため、2026-07 時点の運用理解では本書を優先します。

## 1. 全体像

SHIGOKU は、CLI から受け取った対象・モード・認証情報・reporting 指示を、ProjectManager の workspace、MasterConductor のタスク制御、ReconPipeline の資産発見、Swarm/Agent 群の検証、Reporting/Gate の成果物化へ流す構成です。

```text
User / Docker
  -> src.main argparse
  -> ProjectManager
  -> MasterConductor
  -> ReconPipeline / Swarm Managers / External Tool Adapters
  -> Finding / TaskResult / ExecutionContext
  -> Session JSON / Project artifacts
  -> Reporting formatters / shigoku-ops gates
```

運用確認系は別入口です。

```text
User / CI
  -> shigoku-ops
  -> report/session/validate/gate command
  -> report_session_consistency / finding_inspector / initial_release_gate
  -> checker verdict / quality gate result
```

## 2. 入口と責務

| 入口 | 実装 | 主な責務 |
|---|---|---|
| 実行 CLI | `src/main.py` | argparse 定義、mode/profile/target/recon/report/RAG/HITL オプションの受付 |
| Ops CLI | `scripts/shigoku_ops_cli.py` | report/session/gate/loop などの運用確認コマンド |
| Docker | `Dockerfile`, `docker-compose.yml` | Kali ベース実行環境、Neo4j、ChromaDB、workspace volume |
| Project workspace | `src/core/project/project_manager.py` | プロジェクトディレクトリ作成、scan/finding/session/report の保存 |
| Orchestration | `src/core/engine/master_conductor.py` | タスク計画、dispatch、handoff、session 保存、finding 処理 |
| Recon pipeline | `src/recon/pipeline.py` | subdomain/history/live/url/WAF/port/classification/save/return の Step 1-8 |
| Task contract | `src/core/domain/model/task.py` | Task/TaskState/TaskResult の共有モデル、metadata redaction |
| Findings | `src/core/models/finding.py` | severity/vuln_type/evidence/repro/impact などの finding モデル |
| Reporting | `src/reporting/*` | Haddix、ja-en、run narrative、target profile、attack path、gate |

## 3. 実行データフロー

### 3.1 CLI から実行開始まで

1. ユーザーが `.venv/bin/python -m src.main ...` または Docker 経由で `python3 -m src.main ...` を実行する。
2. `src/main.py` が `--mode`, `--profile`, `--target`, `--recon`, `--log`, `--cookie`, `--bearer-token`, `--format` などを argparse で受け取る。
3. 対象 URL や scope 情報からプロジェクト名を決め、ProjectManager が `workspace/projects/<target>/` を準備する。
4. MasterConductor が mode/profile/target/context を持って起動し、必要に応じて ReconPipeline、Swarm Manager、reporting 処理へ制御を渡す。

### 3.2 Recon Step 1-8

`src/recon/pipeline.py` の ReconPipeline は、次のユーザー向け Step を checkpoint 可能な単位として扱います。

| Step | 完了 marker | 役割 |
|---|---|---|
| 1 | `subdomain_discovery` | サブドメイン発見 |
| 2 | `historical_discovery` | 履歴 URL / archive 情報 |
| 3 | `live_check`, `url_discovery` | live 確認と URL 発見 |
| 4 | `waf_detection` | WAF/保護層の検出 |
| 5 | `port_scan_phase1`, `port_scan_phase2` | ポート確認 |
| 6 | `classification` | URL/資産の分類 |
| 7 | `save_to_project` | ProjectManager への保存 |
| 8 | `return_to_mc` | MasterConductor への返却 |

`ReconState` は `current_step`, `completed_steps`, `parallel_task_progress`, `all_subs`, `live_subs`, `dead_subs`, `tech_stack`, `results`, `schema_version` などを持ち、中断・再開と差分確認の基礎になります。

### 3.3 MasterConductor と Task

MasterConductor は `Task` を単位に作業を管理します。`Task` は `id`, `name`, `agent_type`, `action`, `phase`, `params`, `target`, `state`, `result`, `error`, `priority`, `parent_id`, `replan_depth`, `metadata` を持ちます。

`TaskState` は `pending`, `running`, `success`, `failed`, `replanned`, `skipped` です。`TaskResult` は `success`, `data`, `error`, `findings`, `execution_time` を保持します。

metadata には Cookie/token/API key などが入り得るため、`src/core/domain/model/task.py` の `_redact_secrets()` が serialization/deserialization 境界で秘匿キーを `[REDACTED]` に置換します。

### 3.4 ExecutionContext

`ExecutionContext` はエージェント間の handoff 用文脈です。主な項目は次の通りです。

- `total_attempts` / `successful_attempts`: 実行成功率の計算に使う。
- `bypass_methods`: 成功した bypass 手法。
- `discovered_assets`: 発見資産。
- `current_attack_chain`: 現在の攻撃チェーン。
- `triager_preferences`: プログラム別の傾向。
- `target_info`: target、start_time、recon 結果など。
- `metrics`: duration、estimated cost、phase duration、token usage。

## 4. セッション保存仕様

### 4.1 保存場所

ProjectManager はセッションを `workspace/projects/<target>/sessions/` に保存します。

- `session_YYYYMMDD_HHMMSS.json`: 時刻付き raw セッション。
- `latest.json`: 最新セッションの固定名コピー。

### 4.2 セッション payload

`src/core/engine/master_conductor_session_service.py` の `build_async_session_payload()` が保存用 payload を構築します。

主な root fields:

| field | 内容 |
|---|---|
| `task_queue` | 未完了タスクの list |
| `completed_tasks` | 完了・失敗・skip 済みタスクの list |
| `context` | attempts, bypass, discovered assets, target info, coverage, pending HITL |
| `start_time` | 実行開始時刻 |
| `timestamp` | 保存時刻 |
| `coverage_gate` | coverage 判定情報 |
| `scenario_coverage` | SCN 系 coverage |
| `pending_hitl` | 人間確認待ちチケット |
| `decision_traces` | 任意の判断 trace |
| `task_execution_records` | 任意の実行記録 |
| `run_ledger` | 任意の run ledger event |
| `llm_usage_summary` | LLM 利用サマリ |
| `spool_path` / `spool_sha256` / `spool_event_count` | run ledger spool 情報 |
| `adjacency_list` | `parent_id -> child task ids` |

`task_queue` と `completed_tasks` の各要素には、`id`, `name`, `agent_type`, `action`, `phase`, `params`, `state`, `priority`, `metadata` などが含まれます。completed task には `error`, `result`, `failure_phase`, `failure_reason`, `failure_reason_code`, `timeout_retry_count` も入ります。

### 4.3 Resume

session restore は `load_session_payload_from_path()` と snapshot helper 群で行います。主に次を復元します。

- task queue。
- completed tasks。
- ExecutionContext。
- pending HITL。
- legacy session queue。

## 5. Finding と証跡

`src/core/models/finding.py` の `Finding` は、脆弱性候補または確認済み finding の共通モデルです。

主要 fields:

- `vuln_type`, `severity`, `title`, `description`
- `target_url`, `target_program`
- `evidence`, `reproduction_steps`, `impact`
- `source_agent`, `confidence`
- `is_aggressive`, `recommended_followup`
- `tags`, `related_findings`, `cwe_id`, `cvss_score`

ProjectManager は finding を `workspace/projects/<target>/findings/<finding_id>_<vuln_type>.json` へ保存します。writer が利用可能な場合は DB/JSONL 側にも記録します。

## 6. Reporting データフロー

### 6.1 Finding 抽出

`src/reporting/finding_extractor.py` の `extract_all_findings()` は、複数 formatter で共有する finding 抽出ルールです。順序は次の通りです。

1. `completed_tasks[*].result.findings`
2. `completed_tasks[*].result.data.findings`
3. `completed_tasks[*].result.data.finding`
4. `completed_tasks[*].result.finding`
5. `completed_tasks[*].result.vulnerability`
6. fallback: `session.findings`
7. fallback: `session.partial_findings`

task 由来の finding には `_source_task_id` が注入され、どの task から来たかを追跡できます。

### 6.2 Formatter

| formatter | 主な成果物 | 役割 |
|---|---|---|
| `haddix_formatter.py` | `haddix_report_*.md` | バグバウンティ向け主報告 |
| `haddix_ja_en_formatter.py` | ja-en report | 日本語・英語併記 |
| `run_narrative_formatter.py` | `run_narrative.md` | 実行経過と判断の説明 |
| `target_profile_formatter.py` | `target_profile.md` | 対象プロファイル |
| `attack_path_formatter.py` | `attack_paths.md`, `attack_paths.json` | 攻撃パス整理 |
| `initial_release_gate.py` | gate verdict | リリース前品質判定 |

### 6.3 Report/Session Consistency

レポートは Markdown 成果物、セッションは raw 実行証跡です。レポートから結論を出す前に `report_session_consistency.py` で source session を解決し、scenario coverage や missing family が report と session で矛盾しないことを確認します。

この gate が失敗した場合は fail closed とし、古い report と新しい session を混ぜた結論を出しません。

## 7. ProjectManager の保存契約

`src/core/project/project_manager.py` は workspace の入出力境界です。

| method / path | 契約 |
|---|---|
| `FOLDER_STRUCTURE` | `scans/raw`, `scans/filtered`, `findings`, `screenshots`, `reports`, `hunting_log`, `sessions` を準備 |
| `save_session()` | `session_*.json` と `latest.json` を原子的に保存 |
| `save_raw_scan()` | 外部ツール raw output を `scans/raw/` へ保存 |
| `save_filtered_scan()` | 分類済み output を `scans/filtered/` へ保存 |
| `save_screenshot()` | 証跡画像を `screenshots/` へ保存 |
| `save_finding()` | finding JSON を `findings/` へ保存 |
| `get_reports_dir()` | report 出力先 `reports/` を返す |

ファイル名は原則 `{YYYY-MM-DD}_{tool_or_module}_{purpose}_{project}.{ext}` 形式です。

## 8. 内部モジュール責務

### 8.1 Orchestration / Engine

- `src/core/engine/master_conductor.py`: task planning、dispatch、finding handling、session persistence、HITL 管理。
- `src/core/engine/master_conductor_session_service.py`: session payload の build/load/legacy restore。
- `src/core/engine/master_conductor_state_snapshot.py`: session payload から context/task/pending HITL を復元。
- `src/core/engine/task_queue.py`: task queue / priority 関連。
- `src/core/engine/task_pruning_policy.py`: 無効化や重複抑制の policy。
- `src/core/engine/lane_policy.py`, `mutex_policy.py`, `admission_policy.py`: 並列化 lane と admission の安全制御。

### 8.2 Recon / External Tools

- `src/recon/pipeline.py`: recon Step 1-8、checkpoint、resume、classification。
- `src/core/adapters/external/*_adapter.py`: 外部ツール統合の標準配置。
- `src/tools/custom/*`: katana/httpx/gau/playwright などの実行 wrapper。

### 8.3 Swarm / Agents

- `src/core/agents/swarm/base_manager.py`: Swarm manager の共通基盤。
- `src/core/agents/swarm/discovery/manager.py`: discovery 系 agent。
- `src/core/agents/swarm/auth/manager.py`: auth/session/BAC 系検証。
- `src/core/agents/swarm/injection/*`: injection/API probe 系。
- `src/core/agents/swarm/logic/*`: IDOR/BOLA/BFLA/business logic 系。

Agent は Task を受け取り、TaskResult または dict 互換 result を返します。Finding は TaskResult 内または session fallback として reporting に渡されます。

### 8.4 Security / Guardrails

- `src/core/security/*`: scope、multi-account session、PII masking、guardrail。
- `src/core/preflight/*`: entry gate / preflight validation。
- `src/core/domain/model/task.py`: metadata redaction の最終境界。

### 8.5 Knowledge / RAG

- ChromaDB は RAG の vector store として使います。
- Neo4j は asset や attack path の graph 表現に使います。
- `src/reporting/attack_path_formatter.py` は session data から graph 風の Markdown/JSON を作ります。

### 8.6 LLM

LLM 設定は `config/shigoku.yaml` の `llm:` が正本です。新規利用は role ベースで行い、prompt template は `src/prompts/` 配下に置きます。Ollama 直接呼び出しや flat config の新規参照は非推奨です。

## 9. Docker 実行仕様

`Dockerfile` は Kali Linux をベースに、Python、Chromium、nmap/hydra/sqlmap/gobuster/ffuf/whatweb、ProjectDiscovery 系ツール、Playwright、各種 Python 依存を導入します。

`docker-compose.yml` は次を接続します。

- `shigoku`: `/app` と `/workspace` を mount し、host network で実行。
- `neo4j`: APOC 有効、`7474` と `7687` を公開。
- `chromadb`: container port `8000` を host `8003` に公開。

Docker 実行では host network によりホスト側の対象やローカル lab に接続しやすい一方、ローカルネットワークへの到達性が広くなるため、scope を明示して使います。

## 10. Gate と品質ポリシー

運用確認は CLI-first で `shigoku-ops` を使います。

| 操作 | コマンド系 |
|---|---|
| report/session 整合性 | `shigoku-ops report consistency --report ...` |
| finding 抽出確認 | `shigoku-ops session findings --session ...` |
| 初期リリース判定 | `shigoku-ops gate initial-release --report ...` |
| run narrative | `shigoku-ops report narrative --session ...` |
| target profile | `shigoku-ops report target-profile --session ...` |
| attack path | `shigoku-ops report attack-paths --session ...` |

report path が与えられた判断では、report が primary source ではなく、report と consistency checker が解決した source session の組が primary source of truth です。

## 11. 拡張時の注意

- 外部ツール追加は `src/core/adapters/external/*_adapter.py` を優先し、既存 wrapper との重複分類を避けます。
- 新しい report formatter は `extract_all_findings()` を使い、formatter ごとの finding 抽出差異を増やさないようにします。
- 新しい session field は additive に追加し、既存 reader を検索して互換性を確認します。
- Secret を metadata に入れる場合は redaction 対象キーを確認します。
- 新しい LLM role は `src/prompts/roles/<role>.md` と `config/shigoku.yaml` の `llm.roles` をセットで追加します。

## 12. 主要なデータ契約まとめ

| データ | 入力元 | 変換/処理 | 出力先 |
|---|---|---|---|
| CLI args | user / Docker | `src/main.py` argparse | ProjectManager / MasterConductor |
| ProjectConfig | target / workspace | ProjectManager 初期化 | `workspace/projects/<target>/meta.yaml` |
| ReconState | ReconPipeline | checkpoint/resume/diff | project workspace |
| Task | MasterConductor / agents | dispatch, state transition | session `task_queue`, `completed_tasks` |
| TaskResult | agents | success/error/findings 正規化 | completed task result |
| ExecutionContext | MasterConductor | handoff / metrics / target_info | session `context` |
| Finding | agents / scanner | save_finding / reporting extraction | `findings/*.json`, report |
| Session JSON | MasterConductor | `build_async_session_payload()` | `sessions/session_*.json`, `latest.json` |
| Report Markdown/JSON | reporting formatter | session/finding aggregation | `reports/` |
| Gate verdict | shigoku-ops | consistency/gate policy | CLI stdout / CI result |
