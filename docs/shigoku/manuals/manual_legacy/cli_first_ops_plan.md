---
task_id: SGK-2026-0008
doc_type: manual
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# CLI-First Ops Plan (MCPなし)

## 目的
- Codexが毎回同じ手順で実行できる「コマンド面」を先に整える。
- 生データ直読みに頼らず、`--json` で再現可能な調査フローを作る。
- MCP連携は後回しにして、まず既存ローカル資産だけで運用を安定化する。

## 期待する効果
- 調査速度: 検索→絞り込み→再試行が速くなる。
- 精度: 中間結果をJSONで残せるため、検証しやすくなる。
- 再現性: 同じコマンドで同じ結果を再生成しやすくなる。
- 安全性: 破壊的操作をCLI側で持たないため誤操作を減らせる。

## 実装したCLI
- `scripts/shigoku_ops_cli.py`
- `shigoku-ops` (project script entrypoint)

### 1. report consistency
```bash
python3 scripts/shigoku_ops_cli.py --json report consistency --report <path/to/haddix_report_*.md>
```
- レポートとセッションの整合性を検証する。
- 終了コード: `0=consistent`, `3=inconsistent`, `2=blocked`

### 2. report gate
```bash
python3 scripts/shigoku_ops_cli.py --json report gate --report <path/to/haddix_report_*.md>
```
- Initial release gateを評価する。
- 終了コード: `0=pass`, `3=fail`, `2=blocked`

### 2.5 report loop（推奨）
```bash
python3 scripts/shigoku_ops_cli.py --json report loop --report <path/to/haddix_report_*.md>
python3 scripts/shigoku_ops_cli.py --json report loop --report <path/to/haddix_report_*.md> --include-findings --max-findings 20 --finding-fields title,target_url,vuln_type
python3 scripts/shigoku_ops_cli.py --json report loop --report <path/to/haddix_report_*.md> --include-findings --finding-preset triage --max-findings 20
python3 scripts/shigoku_ops_cli.py --json --json-envelope report loop --report <path/to/haddix_report_*.md>
```
- `consistency -> gate -> findings(optional)` を1コマンドで実行する。
- 終了コード: `0=ok`, `3=failed`, `2=blocked`
- AI Loop ではこのコマンドを第一選択にする（再試行時の分岐が安定）。
- `--json-envelope` を付けると `{schema_version, command, payload}` 形式で出力される（将来のスキーマ拡張に安全）。
- `status=blocked/failed` の場合は `next_commands` を使って次の再実行コマンドを機械的に選べる。

### 3. session findings
```bash
python3 scripts/shigoku_ops_cli.py --json session findings --session <path/to/session_*.json>
shigoku-ops --json session findings --session <path/to/session_*.json>
python3 scripts/shigoku_ops_cli.py --json session findings --session <path/to/session_*.json> --finding-preset minimal
python3 scripts/shigoku_ops_cli.py --json session findings --session <path/to/session_*.json> --finding-preset triage
```
- セッションから重複排除済みfinding一覧を抽出する。
- `--finding-preset`: `minimal|triage|full`（`--finding-fields` 指定時は `--finding-fields` を優先）。

### 3.5. session resolve-from-report
```bash
python3 scripts/shigoku_ops_cli.py --json session resolve-from-report --report <path/to/haddix_report_*.md>
shigoku-ops --json session resolve-from-report --report <path/to/haddix_report_*.md>
```
- reportを主ソースにして対応sessionを確定する。
- report summary前にsource sessionを固定したい時に使う。

### 4. validate pytest
```bash
python3 scripts/shigoku_ops_cli.py --json validate pytest --suite report --dry-run
python3 scripts/shigoku_ops_cli.py --json validate pytest --suite report --quiet
python3 scripts/shigoku_ops_cli.py --json validate pytest --suite report_loop --dry-run
```
- ターゲット検証を定型コマンド化する。
- `--dry-run` でコマンド生成のみ確認可能。

## 運用ルール（CLI先行）
- 第一経路は `report loop` を使う（`consistency -> gate -> findings` を1回で確定）。
- `report consistency` / `report gate` は、`report loop` の結果を深掘りする時だけ個別実行する。
- 分析が必要なら `session findings` を `--max-findings` / `--finding-fields` 付きで使い、payloadを絞る。
- 修正後は `validate pytest --suite report_loop` を先に実行する。
