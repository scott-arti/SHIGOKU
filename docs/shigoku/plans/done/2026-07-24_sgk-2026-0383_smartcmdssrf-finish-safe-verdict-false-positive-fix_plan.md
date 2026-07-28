---
task_id: SGK-2026-0383
doc_type: plan
status: done
parent_task_id: SGK-2026-0382
related_docs:
- docs/shigoku/reports/2026-07-24_sgk-2026-0383_smartcmdssrf-finish-safe-verdict-false-positive-fix_work_report.md
- docs/shigoku/worklogs/2026-07-24_sgk-2026-0383_smartcmdssrf-finish-safe-verdict-false-positive-fix_work_log.md
title: SmartCmdSSRF finish safe verdict false positive fix
created_at: '2026-07-24'
updated_at: '2026-07-28'
tags:
- shigoku
target: src/core/agents/swarm/injection/smart_cmd_ssrf.py
---

# 実装計画書：SmartCmdSSRF finish safe verdict false positive fix

## 1. 達成したいゴール（ユーザー視点）

- [x] SmartCmdSSRFHunter が `{"status": "Safe", ...}` の完了判定を受けた場合に、本文中の `not vulnerable` という語だけで脆弱性として登録しないこと。
- [x] DVWA low の `exec/ip` 検出復旧確認中に見つかった `open_redirect/password` の安全判定誤登録を再発防止すること。

## 2. 全体像とアーキテクチャ

- **対象コンポーネント/ファイル一覧:**
  - `src/core/agents/swarm/injection/smart_cmd_ssrf.py`: `finish` アクションの最終判定を厳密化する。
  - `tests/core/agents/swarm/injection/test_specialist_parameter_hints.py`: 安全判定文が誤って脆弱扱いされない回帰テストを追加する。
- **データの流れ / 依存関係:**
  - LLM/ThoughtLoop の `finish` 入力 -> `SmartCmdSSRFHunter.act()` -> `self.vulnerable` / `self.evidence` -> finding 生成可否。

## 3. 具体的な仕様と制約条件

- **入力情報 (Input):** `action_input` (`str` / `dict`)
- **出力/結果 (Output):** `status` が明示的に `Vulnerable` / `confirmed` / `exploitable` の場合のみ脆弱扱いする。
- **制約・ルール:**
  - `Safe` / `clean` / `not vulnerable` / `does not ... vulnerable` は安全扱いする。
  - 既存の決定的 precheck による confirmed finding 生成は変更しない。
  - TDD で先に失敗テストを確認する。

## 4. 実装ステップ（AIに指示する手順）

- [x] ステップ1: `session_20260723_162936.json` の raw finding を確認し、`exec/ip` の復旧と `open_redirect/password` 誤検知を切り分ける。
- [x] ステップ2: `finish` の安全判定文が `self.vulnerable` を立てない失敗テストを追加する。
- [x] ステップ3: `finish` 判定を JSON `status` 優先・否定表現優先に修正する。
- [x] ステップ4: 対象テスト、周辺テスト、Docker compose run 内の挙動を確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）

- [x] [重要度:中] LLM の自由文 `finish` は今後も表現ゆれがあり得る。今回は JSON `status` と代表的な否定表現を厳密化し、誤検知を抑止した。

### 5.1 deferred_tasks

```yaml
deferred_tasks: []
```
