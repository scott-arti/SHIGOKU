---
task_id: SGK-2026-0505
doc_type: plan
status: active
parent_task_id: null
related_docs:
- docs/shigoku/plans/2026-09-16_sgk-2026-0504_autonomous-detection-wiring.md
tags:
- shigoku
- registry
- task-ledger
- infra-hygiene
created_at: '2026-09-16'
updated_at: '2026-09-16'
---

# SGK-2026-0505 計画 — タスクレジストリ/台帳の整合性修復（誤ネスト是正＋台帳再生成）

## 背景・事実（コードとファイルで実測）

SGK-2026-0504 の作業中に、`docs/shigoku/registry/task_registry.yaml` の **HEAD にコミット済みの
構造破損**を発見した（0504 の作業起因ではない）。

### 問題1: allowed_values ブロックが tasks シーケンスを分断

- `tasks:` シーケンスの途中に `doc_type_allowed_values:` と `status_allowed_values:` の
  トップレベルキーが差し込まれており、そこで tasks 配列が打ち切られている。
- その結果、その後に手動 append された **SGK-2026-0465〜0503（39件）が `status_allowed_values`
  の値（リスト）の下に誤ネスト**され、`yaml.safe_load(...)["tasks"]` に含まれない。
- `scripts/validate_shigoku_docs.py` の `check_registry` は `data["tasks"]` だけを検査するため、
  誤ネストされた39件は**検証対象外＝実質未登録**。それでも `REGISTRY_ISSUES=0` で通る（見えない）。

### 問題2: task_ledger.md / .csv が 0470 で停止

- 人間可読の `task_ledger.md`（および `.csv`）は **0470 で止まり、0471〜0503 が欠落**。
- 真因: これらは派生物で、`scripts/create_shigoku_task.py::write_task_ledger()` が registry から
  **全再生成**する設計。だが 0471〜0503 は正規ツールを通さず手動 append されたため再生成が走らず、
  かつ誤ネストで `registry["tasks"]` にも入っていないため、今のまま再生成しても 39件は載らない。

### 根本原因と潜在データ損失リスク（重要）

- 破損の原因は「正規ツール `create_shigoku_task.py` を使わず registry の EOF へ手動 append した」こと。
  同スクリプトの write 経路は dict 全体を `yaml.safe_dump` で書き直すため、**使えば常に tasks が
  連続した正しいファイルを生成する**（スクリプト自体にバグはない）。
- **潜在データ損失**: `create_task()` は `registry["status_allowed_values"] = ALLOWED_STATUS` で
  上書きする。今この正規ツールを実行すると、`status_allowed_values` 配下に誤ネストされた
  0465〜0503 の39件が**丸ごと消える**。この地雷を除去するためにも本修復は急務。

## 対象（完了契約）

1. `task_registry.yaml` の allowed_values 2ブロックを全 task エントリの後（EOF）へ移動し、
   0465〜0503 を `tasks:` 直下へ復帰させる（誤ネスト是正）。データは削除・改変しない（relocate のみ）。
2. 復帰後に `validate_shigoku_docs.py` で新たに可視化される 0465〜0503 の registry 整合性
   （status/doc_type 許可値・primary_doc 実在・front matter の task_id/doc_type/status 一致）を検査し、
   不整合があれば**registry エントリ側を実ファイルの事実に合わせて是正**する（ドキュメント本体は
   本タスクでは変更しない。ファイル側が真に誤っている場合は個別に切り出す）。
3. `task_ledger.md` と `task_ledger.csv` を、正規関数 `write_task_ledger()` で registry から
   **再生成**する（手書き追記しない＝単一正本は registry）。0465〜0504 を含む全件が載る。
4. 本タスク自身（SGK-2026-0505）を `tasks:` 直下へ正しく登録する。

## 実装方針（最小差分・relocate のみ・派生物は再生成）

- registry: `doc_type_allowed_values`/`status_allowed_values` の14行を mid-file から EOF へ**テキスト
  relocate**（安全性: `validate_shigoku_docs.py` は allowed_values キーを参照しない＝reader 確認済み。
  dict 全体の再 dump はフォーマット総崩れになるため採らない）。0465〜0503 の task dict はそのまま。
- 検証は各段階で `yaml.safe_load` の `tasks` 件数と task_id 集合で確認（relocate 前後で dict 内容不変・
  件数のみ 481→520 相当に増える）。
- ledger 再生成は `scripts/create_shigoku_task.py::write_task_ledger()` を import して registry から実行
  （`.md`＋`.csv` の両方）。
- 変更後は §15 手順で `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py --repo-root .`。

## 完了条件

- CB-1: relocate 後 `yaml.safe_load(...)["tasks"]` に 0465〜0505 が全て含まれる（task_id 集合で確認・
  0465〜0503 の欠落ゼロ・重複ゼロ）。`doc_type_allowed_values`/`status_allowed_values` は許可値の
  文字列リストのみを保持（task dict の混入ゼロ）。
- CB-2: `validate_shigoku_docs.py --repo-root .` が `REGISTRY_ISSUES=0`・`DEFERRED_LINK_ISSUES=0`・
  `BROKEN_LINKS=0`。`REGISTRY_ENTRIES` が 481→約520 に増える。新たに可視化された 0465〜0503 の
  registry 不整合は 0 に是正済み。
- CB-3: `task_ledger.md`/`.csv` が registry から再生成され、0465〜0504 を含む全 task が反映。
- CB-4: SGK-2026-0505 が `tasks:` 直下に登録され検証で可視。
- CB-5: `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` の実コマンドと観測結果を報告。
- 既存の無関係な front-matter エラー（未追跡 `sgk-2026-0314_amass-bbot...instruction_manual.md` の
  `status: draft`）は本タスク対象外として明示（悪化させない）。

## NOT in scope

- `create_shigoku_task.py` のロジック変更（スクリプトにバグはない＝正規ツール利用の徹底は運用ルールで担保）。
- 0465〜0503 の**ドキュメント本体**の内容修正（front matter が真に壊れている等が判明した場合は
  個別タスクへ切り出す。本タスクは registry/ledger の整合のみ）。
- 未追跡 `amass-bbot instruction_manual` の `status: draft` 修正（別所有・別件）。
- 検出エンジンの自律走行配線（SGK-2026-0504 本体）。

## 参考にしたルール

- `CLAUDE.md` §11〜§15（構造Map・CLI-first・スキーマ安全・台帳ワークフロー）
- `rules/task-ledger.md`・`rules/shigoku-docs.md`（採番・front matter・台帳）
- `rules/lessons.md`（`[2026-08] ERROR: 一ファイルの局所挙動を仕様と断じない` → registry の
  reader/writer を全探索し `create_shigoku_task.py` を根拠に方針決定）
- メモリ [[task-registry-midlist-corruption]]
