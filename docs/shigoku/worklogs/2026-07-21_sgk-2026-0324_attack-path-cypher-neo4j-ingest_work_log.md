---
task_id: SGK-2026-0324-WL
doc_type: work_log
status: done
parent_task_id: SGK-2026-0324
related_docs:
  - docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0324_neo4j-attack-path-ui-vuln-management_subtask_plan.md
  - docs/shigoku/reports/2026-07-21_sgk-2026-0324_attack-path-cypher-neo4j-ingest_work_report.md
created_at: '2026-07-21'
updated_at: '2026-07-28'
title: 'SGK-2026-0324 作業ログ: attack_paths Cypher 生成と Neo4j ingest 導線'
---

# SGK-2026-0324 作業ログ

## 2026-07-21

### Unit 1: 0307/0324 の依存関係を確認
- `SGK-2026-0307` の D03 (`attack_paths.json -> Neo4j ingest batch`) を、`0324 Step1` の正本 backend scope として採用
- `src/core/intelligence/chain_builder.py` を正本入力、旧 `attack/chain_builder.py` は新規導線では参照しない方針に固定

### Unit 2: TDD で Cypher / ingest 契約を固定
- `tests/unit/core/knowledge/test_attack_path_ingestor.py` を追加
- `tests/unit/scripts/test_shigoku_ops_attack_paths_cli.py` を追加
- 先に fail (`ModuleNotFoundError`, `--cypher-output` 未定義) を確認してから実装へ進んだ

### Unit 3: ingest 実装
- `src/core/knowledge/attack_path_ingestor.py` を追加
- `build_attack_path_cypher()` と `ingest_attack_path_payload()` を実装
- `Endpoint` identity は raw URL を優先し、CLI/export の見た目文字列に依存しないようにした

### Unit 4: formatter / CLI 接続
- `AttackPathFormatter.build_json_payload()` を追加し、file export と CLI ingest で同じ payload を再利用
- `report attack-paths` に `--cypher-output`, `--neo4j-ingest` を追加
- `VALIDATION_SUITES["ops_cli"]` に新規 CLI テストを登録

### Unit 5: 検証
- targeted tests: 2 passed + 1 passed
- broader regression: 99 passed
- real session artifact: `attack_paths_real.md/json/cypher` 生成成功
- 実 session に chain finding がなかったため、実 Neo4j ingest の end-to-end は `SGK-2026-0307` 側の follow-up へ残した

### Unit 6: クローズ判定
- ユーザー確認に基づき Step5/6 を「実装・評価済み」として計画書へ反映
- Step1-6 がすべて完了したため、`SGK-2026-0324` は done 化する
- 継続監視は `SGK-2026-0307` の deferred として分離し、0324 本体には残さない

### 参照ルール
- lessons.md
- codingrules.md
- reporting.md
- cli-ops-routing.md
- python-tests.md
- task-ledger.md
- shigoku-docs.md
