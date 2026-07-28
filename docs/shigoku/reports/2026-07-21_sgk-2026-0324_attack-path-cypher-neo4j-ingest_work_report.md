---
task_id: SGK-2026-0324-WR
doc_type: work_report
status: done
parent_task_id: SGK-2026-0324
related_docs:
  - docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0324_neo4j-attack-path-ui-vuln-management_subtask_plan.md
  - docs/shigoku/plans/2026-06-25_sgk-2026-0307_attack-path-phase2-bundle_plan.md
  - docs/shigoku/worklogs/2026-07-21_sgk-2026-0324_attack-path-cypher-neo4j-ingest_work_log.md
created_at: '2026-07-21'
updated_at: '2026-07-28'
title: 'SGK-2026-0324 実装報告: attack_paths Cypher 生成と Neo4j ingest 導線'
---

# SGK-2026-0324 実装報告

## 実施サマリ

`SGK-2026-0307` と足並みをそろえ、`attack_paths.json` をそのまま Neo4j へつなぐ backend contract を追加した。
今回の実装で、`shigoku-ops report attack-paths` から Markdown だけでなく `attack_paths.json` と `attack_paths.cypher` を出力でき、必要時は `--neo4j-ingest` で同じ payload を Neo4j へ投入できるようになった。
あわせて、先行して完了・評価済みだった Step5/6 を完了扱いで計画書へ反映し、`SGK-2026-0324` の実装スコープ全体をクローズできる状態にそろえた。

## 実装内容

- `src/core/knowledge/attack_path_ingestor.py`
  - `build_attack_path_cypher(payload)` を追加し、`attack_paths.json` から standalone Cypher を生成
  - `ingest_attack_path_payload(payload)` を追加し、Node/Edge contract を Neo4j へ `MERGE` で保存
  - `Endpoint` は `display_label` ではなく raw URL を identity に使う fail-closed 正規化を実装
- `src/reporting/attack_path_formatter.py`
  - `build_json_payload()` を追加し、CLI と file export の正本 payload を一本化
  - Node/Edge export に `extra` を含め、Target/Endpoint の raw URL や chain metadata を保持
- `src/core/knowledge/schema.py`
  - `GraphSchema.apply_constraints(driver=...)` にして、ingest 時も既存制約をべき等適用できるようにした
- `scripts/shigoku_ops_cli.py`
  - `report attack-paths` に `--cypher-output` と `--neo4j-ingest` を追加
  - `VALIDATION_SUITES["ops_cli"]` に新規 CLI 回帰テストを追加

## 検証結果

- `.venv/bin/pytest tests/unit/core/knowledge/test_attack_path_ingestor.py -q`
  - 2 passed
- `.venv/bin/pytest tests/unit/scripts/test_shigoku_ops_attack_paths_cli.py -q`
  - 1 passed
- `.venv/bin/pytest tests/unit/reporting/test_attack_path_formatter.py tests/unit/core/knowledge/test_attack_path_ingestor.py tests/unit/scripts/test_shigoku_ops_attack_paths_cli.py tests/unit/scripts/test_shigoku_ops_cli.py -q`
  - 99 passed
- `.venv/bin/shigoku-ops --json report attack-paths --session workspace/projects/127.0.0.1:8888/sessions/session_20260413_090848.json --output /tmp/sgk-2026-0324/attack_paths_real.md --json-output --cypher-output`
  - `attack_paths_real.md`, `attack_paths_real.json`, `attack_paths_real.cypher` を生成
  - この実 session には attack chain finding がなく、`cypher` はヘッダのみだったため、「実チェーン入り session での Neo4j 保存確認」は次回に残した

## クローズ判断

- Step1 は今回の Cypher / Neo4j ingest backend contract 実装で完了
- Step2-4 は既存実装済み
- Step5/6 は 2026-07-21 時点で実装・評価済みとして反映
- よって `SGK-2026-0324` は done 化してよい

## deferred_tasks

deferred_tasks:
  - deferred_id: SGK-2026-0324-D01
    title: '実 attack chain session を使った Neo4j ingest / Web UI 妥当性確認'
    reason: '0324 の実装スコープは完了したが、0307 側で追う継続確認として、実チェーンを含む session artifact での end-to-end 保存と UI 探索確認を残す'
    impact: medium
    tracking_task_id: SGK-2026-0307
    recommended_next_action: 'attack chain を含む実 session で `report attack-paths --json-output --cypher-output --neo4j-ingest` を実行し、Neo4j 上のノード・関係と Web UI の探索導線を確認する'
