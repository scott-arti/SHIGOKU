---
task_id: SGK-2026-0337
doc_type: manual
status: active
parent_task_id: SGK-2026-0001
related_docs:
  - docs/shigoku/plans/done/2026-07-02_sgk-2026-0337_detailed-command-reference_plan.md
  - docs/shigoku/manuals/REFERENCE.md
  - docs/shigoku/manuals/USER_MANUAL.md
  - docs/shigoku/manuals/QUICK_START.md
  - docs/shigoku/reports/2026-07-02_sgk-2026-0337_work_report.md
  - docs/shigoku/worklogs/2026-07-02_sgk-2026-0337_work_log.md
created_at: '2026-07-02'
updated_at: '2026-07-02'
---

# SHIGOKU 詳細コマンドリファレンス

この文書は、現行の運用向け CLI である `shigoku-ops` と、実行系エントリポイントである
`python -m src.main` / `shigoku` をまとめた詳細版コマンドリファレンスです。

## 1. どの CLI を使うべきか

| 用途 | 推奨コマンド | 補足 |
| :--- | :--- | :--- |
| report / session / validate / gate / recon state の確認 | `.venv/bin/shigoku-ops ...` | AGENTS.md の CLI-first routing に従う標準入口 |
| `shigoku-ops` の import 解決が難しい環境 | `python3 scripts/shigoku_ops_cli.py ...` | 同等のフォールバック |
| 偵察・攻撃・RAG・interactive 実行 | `.venv/bin/python -m src.main ...` | 実行系 CLI。ヘルプ上の表示名は `shigoku` |

## 2. `shigoku-ops` 共通ルール

### 基本構文

```bash
.venv/bin/shigoku-ops [--json] [--json-envelope] <domain> <action> [options]
```

### グローバルオプション

| オプション | 説明 |
| :--- | :--- |
| `--json` | すべての出力を JSON 化する |
| `--json-envelope` | JSON 出力を `{"schema_version":"shigoku.ops.v1","command":"<domain>.<action>","payload":...}` 形式で包む |

### 終了コードの目安

| 終了コード | 意味 |
| :--- | :--- |
| `0` | 成功、または期待した `ok/pass/consistent` |
| `2` | 入力不足、session 未解決、blocked、整合性不足など「実行不能」 |
| `3` | gate 不合格、整合性 fail、resume 不可など「判定失敗」 |

## 3. `shigoku-ops report`

### 3.1 `report consistency`

Haddix report と source session の整合性を検査します。

```bash
.venv/bin/shigoku-ops --json report consistency --report <haddix_report.md>
```

主要オプション:

| オプション | 説明 |
| :--- | :--- |
| `--report` | 対象の `haddix_report_*.md` |
| `--session` | 明示的に対応づける `session_*.json` |
| `--sessions-dir` | session 探索ディレクトリ |

### 3.2 `report gate`

初期リリース gate を評価します。

```bash
.venv/bin/shigoku-ops --json report gate --report <haddix_report.md>
```

主要オプション:

| オプション | 説明 |
| :--- | :--- |
| `--baseline-report` / `--baseline-session` | 比較ベースラインを指定 |
| `--allowed-missing` | 欠落を許容する scenario ID 群 |
| `--confirmed-min` | confirmed の最小件数 |
| `--candidate-max` | candidate の最大件数 |
| `--required-confirmed-classes` | 必須 detection class の CSV |
| `--required-class-confirmed-min` | 各必須 class の最小件数 |
| `--schema-severity-*` | schema mismatch の許容条件 |
| `--set-locked-baseline` | report/session 組を `quality_baseline_lock.json` に記録 |

### 3.3 `report loop`

`consistency -> gate -> findings(optional)` を 1 コマンドで回します。

```bash
.venv/bin/shigoku-ops --json report loop \
  --report <haddix_report.md> \
  --include-findings \
  --finding-preset triage \
  --max-findings 20
```

主要オプション:

| オプション | 説明 |
| :--- | :--- |
| `--include-findings` | findings ステージも含める |
| `--max-findings` | findings 最大件数 |
| `--finding-fields` | 表示項目の CSV 射影 |
| `--finding-preset` | `minimal|triage|full` |
| `report gate` 系の閾値 | gate の閾値をそのまま上書き可能 |

### 3.4 `report narrative`

session から `run_narrative.md` 相当の Markdown を生成します。

```bash
.venv/bin/shigoku-ops report narrative --session <session.json> --output run_narrative.md
```

補足:
- `--report` を使う場合は内部で consistency check を行い、不整合なら `blocked` を返します。
- `--session` を直接渡すと report 整合性をバイパスして生成できます。

### 3.5 `report target-profile`

session から `target_profile.md` を生成します。

```bash
.venv/bin/shigoku-ops report target-profile --report <haddix_report.md> --output target_profile.md
```

主要オプション:

| オプション | 説明 |
| :--- | :--- |
| `--session` | source session を直接指定 |
| `--report` | report から source session を解決 |
| `--sessions-dir` | report 解決時の探索先 |
| `--output` | 出力ファイル。省略時は stdout |

### 3.6 `report attack-paths`

session から `attack_paths.md` と、必要なら Neo4j 取り込み用 JSON を生成します。

```bash
.venv/bin/shigoku-ops report attack-paths \
  --session <session.json> \
  --output-dir workspace/out \
  --json-output
```

主要オプション:

| オプション | 説明 |
| :--- | :--- |
| `--output` | Markdown 出力先を明示 |
| `--output-dir` | session ID 由来ファイル名で出力 |
| `--json-output` | `attack_paths.json` も併せて生成 |

## 4. `shigoku-ops session`

### 4.1 `session findings`

canonical findings を inspection 用に整形します。

```bash
.venv/bin/shigoku-ops --json session findings \
  --session <session.json> \
  --finding-preset triage
```

主要オプション:

| オプション | 説明 |
| :--- | :--- |
| `--detection-class` | detection class で絞り込む |
| `--max-findings` | 表示件数上限 |
| `--finding-fields` | 任意の項目射影 |
| `--finding-preset` | `minimal|triage|full` |

### 4.2 `session resolve-from-report`

report から source session を解決します。

```bash
.venv/bin/shigoku-ops --json session resolve-from-report --report <haddix_report.md>
```

返却 payload では `session_path`, `reason_codes`, `suggested_next_step` を確認します。

## 5. `shigoku-ops validate`

### 5.1 `validate pytest`

定義済み suite または個別 nodeid を安定 JSON 形式で実行します。

```bash
.venv/bin/shigoku-ops --json validate pytest --suite ops_cli --suite report_loop
```

主要オプション:

| オプション | 説明 |
| :--- | :--- |
| `--suite` | `ops_cli`, `phase1_smoke`, `phase_e2_minimal`, `report`, `report_loop`, `runtime_control`, `session` |
| `--test` | 追加の pytest path / nodeid |
| `--python` | pytest 実行に使う Python |
| `--fail-fast` | `pytest -x` |
| `--quiet` | `pytest -q` |
| `--dry-run` | 実行せず command を表示 |

## 6. `shigoku-ops phase1`

観測性 contract の補助コマンド群です。

| アクション | 主な用途 | 主要オプション |
| :--- | :--- | :--- |
| `correlation-ids` | correlation ID 生成 | `--build-id` |
| `check-event` | 1 event の必須 observability field 検証 | `--event-json` |
| `sample-guard` | `minimum_sample_size` gate 評価 | `--sample-size`, `--minimum-sample-size` |
| `runbook` | 障害切り分け用 runbook を出力 | `--request-id`, `--endpoint`, `--alert-type`, `--severity` |

例:

```bash
.venv/bin/shigoku-ops --json phase1 check-event --event-json '{"request_id":"r-1"}'
```

## 7. `shigoku-ops phase2`

品質分類と flaky 判定の補助コマンド群です。

| アクション | 主な用途 | 主要オプション |
| :--- | :--- | :--- |
| `classify-failure` | reason code / error message の failure category 分類 | `--reason-code`, `--error-message` |
| `schema-severity` | schema mismatch 重み付け | `--added`, `--removed`, `--type-changed`, `--nullability-changed`, `--missing-required-fields` |
| `flaky-evaluate` | 直近 outcome 列から quarantine 判定 | `--outcomes-csv`, `--window-size`, `--min-failures` |

例:

```bash
.venv/bin/shigoku-ops --json phase2 flaky-evaluate \
  --outcomes-csv success,fail,fail,success
```

## 8. `shigoku-ops runtime-control`

### 8.1 `runtime-control gate`

release gate evidence bundle を評価します。

```bash
.venv/bin/shigoku-ops --json runtime-control gate --evidence-file <gate_evidence.json>
```

主要オプション:

| オプション | 説明 |
| :--- | :--- |
| `--critical-gates` | waive 不可 gate 名の CSV |
| `--integrity-manifest` | evidence hash の整合性確認 |
| `--approval-evidence-file` | approval source-of-truth JSON |
| `--require-code-owner-reviews` | branch protection に code owner review を要求 |
| `--phase` | `generic` または `phase9` |

## 9. `shigoku-ops ops`

| アクション | 主な用途 | 主要オプション |
| :--- | :--- | :--- |
| `secret-audit` | config / `.env` の credential age 監査 | `--max-age-days`, `--config-dir`, `--project-root`, `--exit-nonzero-on-findings` |
| `learn-categories` | `other_category_log.jsonl` から top URL / alert 傾向抽出 | `--log-file`, `--top-n` |

例:

```bash
.venv/bin/shigoku-ops --json ops secret-audit --exit-nonzero-on-findings
```

## 10. `shigoku-ops recon`

偵察 checkpoint の状態確認と差分比較を行います。

| アクション | 主な用途 | 主要オプション |
| :--- | :--- | :--- |
| `status` | `recon_state.json` の resume 可否判定 | `--state`, `--target` |
| `diff` | 2 つの `recon_state.json` の差分比較 | `--prev`, `--current`, `--target` |

例:

```bash
.venv/bin/shigoku-ops --json recon status \
  --state workspace/projects/<target>/recon_state.json \
  --target https://target.example
```

## 11. `python -m src.main` / `shigoku`

### 11.1 基本構文

```bash
.venv/bin/python -m src.main [options]
```

ヘルプ表示上のプログラム名は `shigoku` です。

### 11.2 実行モード

| オプション | 説明 |
| :--- | :--- |
| `--recon`, `-r <URL>` | 偵察パイプラインを開始 |
| `--target`, `-t <URL>` | 対象 URL 指定。`--recon` のエイリアスとしても使う |
| `--log`, `-l <FILE>` | プロキシログからハイブリッドハントを実行 |
| `--watch`, `-w <OWNER/REPO>` | GitHub 監視 |
| `--demo`, `-d` | デモ実行 |
| `--mode`, `-m <MODE>` | `bugbounty|vulntest|ctf` |
| `--profile <PROFILE>` | `bbpt|ctf` |

### 11.3 偵察制御

| オプション | 説明 |
| :--- | :--- |
| `--skip-initial-recon` | MC 前の初回偵察をスキップ |
| `--recon-start-step <N>` | 偵察開始ステップ上書き |
| `--recon-end-step <N>` | 偵察終了ステップ上書き |
| `--recon-resume` | checkpoint から偵察再開 |
| `--fast-iterate` | `--skip-initial-recon --recon-start-step 6 --recon-end-step 8` のショートカット |
| `--import-recon <DIR>` | 過去偵察成果物を取り込んで利用 |

### 11.4 認証・入力コンテキスト

| オプション | 説明 |
| :--- | :--- |
| `--scope`, `-s <FILE>` | scope YAML |
| `--sessions-file <FILE>` | マルチアカウント session 設定 |
| `--cross-test-approved` | 承認済み IDOR クロステスト有効化 |
| `--recipe <FILE>` | recipe YAML |
| `--cookie <COOKIE>` | 認証済み Cookie |
| `--bearer-token <TOKEN>` | Bearer token |

### 11.5 解析・補助系コマンド

| オプション | 説明 |
| :--- | :--- |
| `--crawl`, `-c <URL>` | gospider/katana ベースの crawl |
| `--crawl-depth <quick|standard|deep>` | crawl 深度 |
| `--analyze`, `-a <URL>` | アプリ分析 |
| `--dns <DOMAIN>` | DNS 履歴取得 |
| `--fuzz <URL>` | パラメータ fuzz |
| `--openapi <URL>` | OpenAPI 自動テスト |
| `--takeover <DOMAIN>` | subdomain takeover チェック |

### 11.6 RAG 系

| オプション | 説明 |
| :--- | :--- |
| `--rag-ingest <PATH>` | ファイル/ディレクトリ取り込み |
| `--rag-query <QUESTION>` | ナレッジベース検索 |
| `--rag-stats` | 統計表示 |
| `--pdf-only` | ingest を PDF 限定 |
| `--reset-db` | ingest 前に DB 初期化 |
| `-n`, `--num-results <N>` | 検索結果件数 |

### 11.7 HITL / deferred / report replay

| オプション | 説明 |
| :--- | :--- |
| `--hitl-list` | 保留 HITL 一覧 |
| `--hitl-run` | 承認済み HITL 実行 |
| `--hitl-approve <TICKET_ID>` | HITL 承認。繰り返し可 |
| `--hitl-reject <TICKET_ID>` | HITL 却下。繰り返し可 |
| `--deferred-list` | deferred backlog 一覧 |
| `--deferred-checklist` | deferred checklist 生成 |
| `--deferred-status` | deferred status 集計 |
| `--deferred-resolve <SCENARIO_ID>` | deferred 解決マーク |
| `--deferred-note <TEXT>` | 解決メモ |
| `--deferred-resolved-by <NAME>` | 解決者ラベル |
| `--deferred-file <PATH>` | 対象 `haddix_deferred_*.json` |
| `--deferred-checklist-output <PATH>` | checklist 出力先 |
| `--report` | 前回 session report 表示 |
| `--report-replay` | canonical report replay を再処理 |
| `--report-retry-failed` | failed replay を pending に戻す |
| `--report-replay-list` | replay queue 一覧 |
| `--report-replay-platform <hackerone|bugcrowd>` | replay 対象 platform |
| `--report-replay-queue <PATH>` | replay queue ファイル上書き |
| `--report-replay-limit <N>` | replay 最大件数 |
| `--report-replay-queue-id <QUEUE_ID>` | replay 対象 queue ID |
| `--report-replay-status <STATUS>` | `pending|failed|completed` 絞り込み |

### 11.8 出力・運用・開発補助

| オプション | 説明 |
| :--- | :--- |
| `--format <FORMAT>` | `json|csv|pdf|markdown|html|haddix|haddix-ja-en` |
| `--export <DIR>` | エクスポート先 |
| `--json` | JSON 出力 |
| `--dry-run` | safe_mode で実行 |
| `--debug` | 判断トレースを含む詳細ログ |
| `--interactive`, `-i` | 対話モード |
| `--resume` | 前回 session 再開 |
| `--tools` | ツール一覧 |
| `--projects` | プロジェクト一覧 |
| `--live-dashboard` | ライブダッシュボード |
| `--focus-list` | focus group 一覧表示 |
| `--focus-tests` | focus regression 実行 |
| `--focus-group <GROUP>` | `density|report|hitl|fast_mc_recon|all` |
| `--focus-test <PATH>` | 追加 focus test |
| `--focus-fail-fast` | focus 実行時の fail-fast |
| `--quality-loop short` | 標準改善ループを短縮実行 |
| `--quality-loop-full-scan` | `quality-loop short` 後にフルスキャン追加 |

## 12. よく使う実行例

### report / session

```bash
.venv/bin/shigoku-ops --json report consistency --report workspace/projects/acme/reports/haddix_report_20260702_010203.md
.venv/bin/shigoku-ops --json report gate --report workspace/projects/acme/reports/haddix_report_20260702_010203.md
.venv/bin/shigoku-ops --json report loop --report workspace/projects/acme/reports/haddix_report_20260702_010203.md --include-findings --finding-preset triage
.venv/bin/shigoku-ops --json session findings --session workspace/projects/acme/sessions/session_20260702_010203.json --finding-preset triage
```

### validation / runtime-control

```bash
.venv/bin/shigoku-ops --json validate pytest --suite ops_cli --suite report
.venv/bin/shigoku-ops --json runtime-control gate --evidence-file artifacts/gate_evidence.json --phase generic
```

### recon state

```bash
.venv/bin/shigoku-ops --json recon status --state workspace/projects/acme/recon_state.json --target https://acme.example
.venv/bin/shigoku-ops --json recon diff --prev workspace/projects/acme/recon_state_prev.json --current workspace/projects/acme/recon_state.json
```

### 実行系 CLI

```bash
.venv/bin/python -m src.main --mode bugbounty --target https://acme.example
.venv/bin/python -m src.main --recon https://acme.example --recon-resume
.venv/bin/python -m src.main --log traffic.har --scope scopes/acme.yaml --cookie 'SESSION=...'
.venv/bin/python -m src.main --quality-loop short --focus-group report
```
