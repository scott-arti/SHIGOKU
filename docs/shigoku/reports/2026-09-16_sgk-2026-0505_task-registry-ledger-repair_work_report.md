---
task_id: SGK-2026-0505
doc_type: work_report
status: done
parent_task_id: null
related_docs:
- docs/shigoku/plans/done/2026-09-16_sgk-2026-0505_task-registry-ledger-repair.md
- docs/shigoku/worklogs/2026-09-16_sgk-2026-0505_task-registry-ledger-repair_work_log.md
- docs/shigoku/plans/done/2026-09-16_sgk-2026-0504_autonomous-detection-wiring.md
tags:
- shigoku
- registry
- task-ledger
- infra-hygiene
created_at: '2026-09-16'
updated_at: '2026-09-16'
---

# SGK-2026-0505 作業完了報告 — タスクレジストリ/台帳の整合性修復

## 何をしたか / なぜ

SGK-2026-0504 の作業中に `task_registry.yaml` の**コミット済み構造破損**を発見した。
`doc_type_allowed_values:`/`status_allowed_values:` のトップレベルキーが `tasks:` シーケンスの
途中に差し込まれ、そこで tasks 配列が打ち切られていたため、**0465〜0503 の39件が
`status_allowed_values` 配下に誤ネスト**され `yaml.safe_load(...)["tasks"]` に入らず、
`validate_shigoku_docs.py` の `check_registry`（`data["tasks"]` のみ検査）から見えず
＝実質未登録だった。`task_ledger.md`/`.csv` も 0470 で停止し 0471〜0503 が欠落していた。

破損の真因は「正規ツール `create_shigoku_task.py` を使わず registry の EOF へ手動 append した」こと
（同スクリプトの write 経路は dict 全体を `yaml.safe_dump` で書き直すため常に連続した正しい
ファイルを生成する＝スクリプト自体にバグはない）。さらに破損状態のまま正規ツールを実行すると
`registry["status_allowed_values"] = ALLOWED_STATUS` の上書きで誤ネスト39件が消える潜在データ損失が
あった。

## 実装（最小差分・relocate のみ・派生物は再生成）

- `task_registry.yaml`: allowed_values 2ブロック（14行）を mid-file から EOF へ**テキスト relocate**し、
  0465〜0503 を `tasks:` 直下へ復帰。task dict は削除・改変せず（`validate_shigoku_docs.py` は
  allowed_values キーを参照しないため relocate は安全＝reader 確認済み）。registry の top-level
  `updated_at` を当日付へ。
- `task_ledger.md`/`.csv`: 正規関数 `create_shigoku_task.py::write_task_ledger()` で registry から
  **全再生成**（派生物・単一正本＝registry）。

## 結果（独立検証・Claude が実測）

- 整合性（対 HEAD）: `lost from HEAD=[]`（HEAD の519 DOC エントリを1件も喪失せず）／追加は本作業の
  新規2件のみ。
- `REGISTRY_ENTRIES` 480→521・`REGISTRY_ISSUES=0`・`BROKEN_LINKS=0`・`DEFERRED_LINK_ISSUES=0`。
- 「重複 task_id 16件」は誤検知（同一 task_id の plan/work_report/work_log の別ドキュメント＝
  各 provisional_id 別の正当な既存パターン。HEAD にも同一16件が存在）と確認＝dedup 不要。
- 台帳: md 521行・csv 521行＋ヘッダ・全6列・整形正常。

## 完了条件の充足

- CB-1（0465〜0505 全件が `tasks:` に・欠落/重複ゼロ・allowed_values は文字列リストのみ）: 満たす。
- CB-2（`REGISTRY_ISSUES=0`・`REGISTRY_ENTRIES` 増・新可視化分の不整合ゼロ）: 満たす。
- CB-3（台帳 md/csv 再生成・全 task 反映）: 満たす。
- CB-4（0505 が `tasks:` 直下に登録）: 満たす。
- CB-5（sync+validate 0エラー）: 満たす（既存の無関係 FM を除く）。

`in_scope_blocker` は0件。完了契約を全て満たすため本タスクを `done` とする。

## 参考にしたルール

- `CLAUDE.md` §11〜§15（構造Map・CLI-first・スキーマ安全・台帳ワークフロー）
- `rules/task-ledger.md`・`rules/shigoku-docs.md`
- `rules/lessons.md`（reader/writer を全探索し `create_shigoku_task.py` を根拠に方針決定）
- メモリ [[task-registry-midlist-corruption]]

## deferred / 別件（非阻害）

- 未追跡ファイル `subtasks/2026-09-16_sgk-2026-0314_amass-bbot-execution-fix_instruction_manual.md` の
  `status: draft`（許可外）は別所有・別件のため本タスク対象外。
