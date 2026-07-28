---
task_id: SGK-2026-0320-WR
doc_type: work_report
status: done
parent_task_id: SGK-2026-0320
related_docs:
  - docs/shigoku/plans/done/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md
  - docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0325_conversational-ops-chat-direction_subtask_plan.md
  - docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0326_flexible-report-generation-reinjection_subtask_plan.md
  - docs/shigoku/worklogs/2026-07-21_sgk-2026-0320_shared-schema-export-input-bridge_work_log.md
title: 'SGK-2026-0320 実装報告: 0325/0326 共通 schema 固定と single-session export/input bridge 最小版'
created_at: '2026-07-21'
updated_at: '2026-07-28'
---

# SGK-2026-0320 実装報告

## 実施サマリ

`0325/0326` 共有の正本 schema として `IntentCommand` / `AttackTargetSpec` / `ExportManifest` を `src/core/models/ops_artifacts.py` に固定した。
あわせて `0326` の single-session 最小版として `shigoku-ops session export-targets` / `report export-targets` を追加し、`0325` の入力側最小版として `--attack-targets` から既存 Attack タスク生成へ橋渡しする経路を実装した。
続けて `0325` の次段として `src/cli/intent_parser.py` と `shigoku-ops ops intent` を追加し、自然言語→allowlist command の preview/confirmation loop を実装した。
あわせて `0326` の report 起点運用拡張として `report findings`, `report/session endpoints` を追加し、real report artifact から preview/export まで一貫確認した。
さらに `0324` 依存だった `FindingsRepository` CLI 露出を取り込み、`shigoku-ops findings list/search/stats/export-targets` により cross-session export の最小版を解放した。
同時に `ops intent --execute --approve --main-dry-run` で安全な限定実行を通し、外部エージェント向け function schema / operator manual も補完した。
その後の hardening として、`ops intent` の `approval deny` / `command_timeout` / `ops_intent_kill_switch` と、bundle の `allowed_hosts mismatch` / `scope外 target` / export artifact の `redaction regression` を回帰テストで固定した。
さらに、structured target bundle の `generated_at` / `ttl_days` / `scope_snapshot` / source provenance を入力側で fail-closed 検証し、expired bundle を拒否するようにした。
加えて `import-recon` は `recon_state.json` の `saved_at` provenance を freshness 正本として使い、欠落時は `missing_provenance` で reject するようにした。
`malformed intent` が heuristic で解けず LLM fallback に入ったときも、依存初期化失敗で CLI 全体が落ちず `intent_llm_unavailable` として fail-closed するようにした。
本ロードマップは `0325/0326` 束の完了をもってクローズし、P3 downstream continuation は `SGK-2026-0324` として分離追跡する。

## 実装ユニット

| Unit | 内容 | ファイル |
|------|------|----------|
| 1 | 共通 schema / hash / allowed_hosts 検証 | `src/core/models/ops_artifacts.py` |
| 2 | single-session 抽出と artifact 出力 | `src/reporting/endpoint_extractor.py` |
| 3 | `shigoku-ops` export-targets CLI | `scripts/shigoku_ops_cli.py` |
| 4 | input bridge (`--attack-targets`, `wordlist` 受け渡し) | `src/core/conductor/interactive_bridge.py`, `src/main.py`, `src/cli/messages.py` |
| 5 | intent parser / preview-confirmation / non-TTY guard | `src/cli/intent_parser.py`, `src/prompts/roles/ops_intent.md`, `config/shigoku.yaml`, `scripts/shigoku_ops_cli.py`, `src/core/conductor/interactive_bridge.py` |
| 6 | report/session query 拡張 | `scripts/shigoku_ops_cli.py` |
| 7 | cross-session findings export / safe end-to-end | `src/reporting/endpoint_extractor.py`, `scripts/shigoku_ops_cli.py`, `src/main.py` |
| 8 | external agent manual / function schema | `docs/shigoku/manuals/2026-07-02_sgk-2026-0337_detailed-command-reference.md` |
| 9 | テスト | `tests/core/models/test_ops_artifacts.py`, `tests/unit/scripts/test_shigoku_ops_export_targets_cli.py`, `tests/unit/scripts/test_shigoku_ops_findings_cli.py`, `tests/unit/scripts/test_shigoku_ops_intent_cli.py`, `tests/unit/cli/test_intent_parser.py`, `tests/unit/core/conductor/test_attack_target_bundle_bridge.py`, `tests/unit/main/test_attack_targets_cli.py` |
| 10 | hardening: human-facing export redaction と失敗系追加検証 | `src/reporting/endpoint_extractor.py`, `tests/unit/reporting/test_endpoint_extractor.py`, `tests/unit/scripts/test_shigoku_ops_intent_cli.py`, `tests/core/models/test_ops_artifacts.py`, `tests/unit/core/conductor/test_attack_target_bundle_bridge.py` |
| 11 | hardening: bundle freshness/provenance と import-recon `saved_at` fail-closed | `src/core/models/ops_artifacts.py`, `src/reporting/endpoint_extractor.py`, `src/core/engine/recon_importer.py`, `src/core/engine/master_conductor.py`, `tests/unit/engine/test_recon_importer.py`, `tests/unit/engine/test_master_conductor_import_recon.py` |

## 検証結果

- targeted hardening suite: 45 passed
- broader related regression suite: 77 passed
- real artifact validation:
  - `workspace/projects/127.0.0.1:8888/reports/haddix_report_20260421_020448.md` の consistency が `consistent`
  - 同 report から `report export-targets` が `target_count=13` で成功
  - 同 DB に対する `findings export-targets --target 127.0.0.1:4280` は `target_count=4` で成功
  - 同 report を使う `ops intent` preview が `attack_target_count=13` を返し、heuristic 解決時は LLM 非依存で動作することを再確認
  - real TTY で `ops intent --execute --main-dry-run` を承認付きで通し、`report.export-targets -> main.attack-targets` の限定実行が returncode 0 で完了
  - 出力された `attack_targets.json` には `scope_snapshot` が含まれ、single-session / cross-session とも provenance が埋まることを確認

## deferred_tasks

- deferred_id: SGK-2026-0320-D05
  title: "P3 downstream continuation: attack-path UI / vulnerability management"
  reason: "`0325/0326` 束の shared CLI/export 導線は完了した一方、Neo4j UI と脆弱性管理は別 acceptance criteria で進める方が安全"
  impact: medium
  tracking_task_id: SGK-2026-0324
  recommended_next_action: "`SGK-2026-0324` を独立した active task として継続し、P3 の完了条件を満たした時点で別途クローズする"
