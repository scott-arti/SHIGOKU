---
task_id: SGK-2026-0505
doc_type: work_log
status: done
parent_task_id: null
related_docs:
- docs/shigoku/plans/done/2026-09-16_sgk-2026-0505_task-registry-ledger-repair.md
- docs/shigoku/reports/2026-09-16_sgk-2026-0505_task-registry-ledger-repair_work_report.md
tags:
- shigoku
- registry
- task-ledger
created_at: '2026-09-16'
updated_at: '2026-09-16'
---

# SGK-2026-0505 作業ログ（レジストリ/台帳の整合性修復）

## 1. 発見

- 0504 の登録作業中、EOF 追記が `status_allowed_values` 配下に落ちることに気付き、`yaml.safe_load`
  の `tasks` が 0464 で止まる（480件）ことを確認。mid-file の allowed_values 2ブロックが原因と特定。

## 2. reader/writer の全探索

- `rg` で `task_registry.yaml` の reader/writer を洗い出し、`create_shigoku_task.py` が
  registry を dict 全体 `yaml.safe_dump` で書き直す（＝正規ツールは常に正しい）こと、
  `write_task_ledger()` が台帳を registry から再生成する派生物であることを確認。
- `validate_shigoku_docs.py` が allowed_values キーを参照しない＝relocate は安全と確認。

## 3. 修復（Claude 直接）

- allowed_values 2ブロック（14行）を mid-file→EOF へ text relocate。0465〜0503 が `tasks:` へ復帰。
- 0505 エントリを `tasks:` 直下へ追加、registry `updated_at` を当日付へ。
- `write_task_ledger()` で `task_ledger.md`/`.csv` を再生成。

## 4. 検証（Claude・実出力）

- `safe_load` で 0465〜0505 全件・欠落/重複ゼロ・allowed_values は文字列リストのみを確認。
- 対 HEAD 差分で `lost from HEAD=[]`（519 DOC エントリ喪失ゼロ）。
- 「重複16件」は plan/report/log の別ドキュメント（正当・HEAD にも存在）と確認。
- `validate_shigoku_docs.py` → `REGISTRY_ENTRIES=521`・`REGISTRY_ISSUES=0`。

## 5. 完了

- 完了契約 CB-1〜CB-5 を満たし `in_scope_blocker` 0件。work_report/log 作成・計画書を `done/` へ移動・
  registry status を `done`・台帳再生成してクローズ。
- 再発防止はメモリ [[task-registry-midlist-corruption]] に記録（新タスクは `create_shigoku_task.py` を
  使う／手動追記は allowed_values の直前へ）。
