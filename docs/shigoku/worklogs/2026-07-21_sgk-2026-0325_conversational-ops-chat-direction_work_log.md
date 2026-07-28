---
task_id: SGK-2026-0325-WL
doc_type: work_log
status: done
parent_task_id: SGK-2026-0325
related_docs:
  - docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0325_conversational-ops-chat-direction_subtask_plan.md
  - docs/shigoku/reports/2026-07-21_sgk-2026-0325_conversational-ops-chat-direction_work_report.md
title: 'SGK-2026-0325 作業ログ: 対話型オペレーション軽量版'
created_at: '2026-07-21'
updated_at: '2026-07-28'
---

# SGK-2026-0325 作業ログ

## 2026-07-21

### Unit 1: allowlist intent parser
- `IntentCommand` allowlist を正本 schema に固定
- `src/cli/intent_parser.py` を追加し、自然言語を構造化 command preview へ変換

### Unit 2: preview / confirmation loop
- `shigoku-ops ops intent` を追加
- preview 表示後に承認された時だけ `report.export-targets` / `main.attack-targets` へ接続する lightweight loop を実装

### Unit 3: 入力橋渡しと安全策
- `--attack-targets` / `--wordlist` を `src.main` と `InteractiveBridge` に接続
- non-TTY fail-closed、timeout、kill switch、budget、scope validation を追加

### Unit 4: 失敗系回帰
- `approval deny`, `timeout`, `unknown command`, `scope外 target`, `intent_llm_unavailable` をテスト化

### Unit 5: 実運用確認
- real TTY で `ops intent --execute --main-dry-run` を承認付きで実行し、preview/confirmation loop を確認
- 0326 artifact の `attack_targets.json` を入力正本として扱う運用導線を固定

### 次アクション
- なし。計画書、報告書、台帳を done 状態へそろえてクローズ。
