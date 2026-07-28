---
task_id: SGK-2026-0326-WR
doc_type: work_report
status: done
parent_task_id: SGK-2026-0326
related_docs:
  - docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0326_flexible-report-generation-reinjection_subtask_plan.md
  - docs/shigoku/plans/done/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md
  - docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0324_neo4j-attack-path-ui-vuln-management_subtask_plan.md
  - docs/shigoku/worklogs/2026-07-21_sgk-2026-0326_flexible-report-generation-reinjection_work_log.md
title: 'SGK-2026-0326 実装報告: 自由形式レポート生成と再投入最小版'
created_at: '2026-07-21'
updated_at: '2026-07-28'
---

# SGK-2026-0326 実装報告

## 実施サマリ

single-session を正本にした export / reinjection の最小版を完成させた。
`endpoint_extractor.py`、`shigoku-ops report/session export-targets`、`report/session endpoints`、`report findings` を通じて、実 report / session から `attack_targets.json` と human-facing `endpoints.{json,csv,md}` を生成し、`generated_at`, `ttl_days`, `scope_snapshot`, provenance, `manifest_hash`, `allowed_hosts` を検証した bundle だけを再投入できるようにした。
加えて `findings export-targets` により cross-session export の最小版も解放し、mixed-scope は fail-closed に固定した。

## 判断理由

- 0326 は「出力側」に責務を限定し、自由形式の人間向け表示と、再投入に使う machine-readable 正本を分離した。
- report 起点では consistency check を必須にし、古い report / 別 session 混在を防ぐ構成を優先した。
- cross-session は最小版だけを解放し、高度な集約/ランキングは別フェーズへ残すことで依存爆発を避けた。

## 検証結果

- real report artifact `workspace/projects/127.0.0.1:8888/reports/haddix_report_20260421_020448.md` に対して consistency が `consistent` になることを確認した。
- 同 report から `report export-targets` が `target_count=13` で成功し、`attack_targets.json` に `scope_snapshot` と provenance が含まれることを確認した。
- real findings DB に対する `findings export-targets --target 127.0.0.1:4280` が `target_count=4` で成功した。
- `empty export`, `invalid manifest`, `tampered hash`, `consistency blocked`, `out-of-scope host`, `redaction regression`, expired bundle を回帰テストで固定した。

## deferred_tasks

なし。本タスクの受け入れ範囲は single-session export/reinjection と cross-session 最小版であり、高度な集約/ランキングは別フェーズの拡張事項として扱う。
