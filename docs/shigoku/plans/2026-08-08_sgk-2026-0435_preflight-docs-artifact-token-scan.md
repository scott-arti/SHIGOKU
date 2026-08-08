---
task_id: SGK-2026-0435
doc_type: plan
status: deferred
parent_task_id: SGK-2026-0432
related_docs:
- docs/shigoku/reports/2026-08-08_sgk-2026-0432_gap-closure-causal-diagnosis_work_report.md
created_at: '2026-08-08'
updated_at: '2026-08-08'
tags:
- shigoku
- anti-curve-fitting
- deferred
target: scripts/check_vdp_product_independence.py,tests
---

# SGK-2026-0435: product-independence preflight の docs 成果物 token-scan 拡張

SGK-2026-0432 の独立検証中に判明した preflight の scan 穴を、恒久対策として起票する。

## 背景 / 観測

- `scripts/check_vdp_product_independence.py` の `token_scan_changed_files` は
  `PRODUCTION_PREFIXES = ("src/", "scripts/", "config/", "recipes/", "prompts/", "data/")`
  に該当する変更ファイルのみを token-scan する。**`docs/` は対象外**。
- このため 0432 の work_report に混入した製品 token（product 名・固有パス・version 文字列）を
  preflight は検知せず exit 0 を返した（手動 redaction で対処済み）。
- 診断 report / worklog は run 由来の raw 応答から引用しやすく、**opaque 契約が最も破れやすい成果物**である
  にもかかわらず自動ゲートが無い、という穴。

## 完了条件（着手時に確定する）

1. 変更された `docs/shigoku/` 成果物（特に run 由来: `reports/`, `worklogs/`, `subtasks/`）を
   denylist token-scan の対象に加える（新規 check もしくは既存 check の scan 集合拡張）。
2. **DEFER/allowlist 機構**を用意する: sealed 製品名を正当に含むガバナンス/指示文書
   （`CLAUDE.md`, `rules/`, 製品名を NOT-in-scope 句で挙げる 0424/0425 等の計画）を誤検知させない。
   既存の legacy-hit DEFER 機構（plan §15 相当）と整合させる。
3. 新規成果物への leakage は FAIL、既知の正当参照は DEFER、を self-checking テストで検証する。
4. 既存の production token-scan の挙動は不変（回帰0）。

## NOT in scope

- session/artifact（raw evidence）自体の redaction 方針変更（secret redaction は既存契約のまま）。
- 製品 token denylist の内容変更。
- 検出パイプライン（runtime/model context）の scan ロジック変更。

## 参照

- `scripts/check_vdp_product_independence.py`（`PRODUCTION_PREFIXES`, `check_token_scan`, DEFER 機構）。
- SGK-2026-0432 work_report（穴の実例と手動 redaction の記録）。
