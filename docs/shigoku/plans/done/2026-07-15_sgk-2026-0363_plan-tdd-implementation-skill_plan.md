---
task_id: SGK-2026-0363
doc_type: plan
status: done
parent_task_id: null
related_docs:
- docs/shigoku/reports/2026-07-15_sgk-2026-0363_work_report.md
- docs/shigoku/worklogs/2026-07-15_sgk-2026-0363_work_log.md
title: Plan TDD Implementation Skill
created_at: '2026-07-15'
updated_at: '2026-07-21'
tags:
- shigoku
target: ~/.codex/skills/plan-tdd-implementation
---

# 実装計画書：Plan TDD Implementation Skill

## 1. 達成したいゴール（ユーザー視点）
- [x] 計画書を実装する際に、計画書を主ソースとして読み込み、TDDで最後まで進めるためのCodex SKILLを追加する。
- [x] 新規コード作成と既存コード修正の両方に対応し、独自機能追加を抑制する実装プロンプトをSKILL化する。
- [x] 計画書の `task_id` を使ってGitブランチを作成/切替する手順をSKILLに含める。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `/home/bbb/.codex/skills/plan-tdd-implementation/SKILL.md`: 新規SKILL本文。
  - `/home/bbb/.codex/skills/plan-tdd-implementation/agents/openai.yaml`: SKILL UIメタデータ。
- **データの流れ / 依存関係:**
  - ユーザーの実装方針 -> SKILL本文 -> 次回以降の計画書実装ワークフロー。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** 計画書パス、リポジトリ作業ツリー、計画書Front Matterの `task_id`。
- **出力/結果 (Output):** `plan-tdd-implementation` SKILLが自動検出可能な場所に追加される。
- **制約・ルール:**
  - 計画書とテストにない独自機能追加を禁止する。
  - TDDの red-green-refactor と実ロジック実装を明記する。
  - 対症療法ではなく全体影響と既存パターンを確認する。
  - 大きな判断・計画根幹の変更・危険なブランチ切替では停止してユーザーに確認する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: skill-creatorの正規スクリプトでSKILL雛形を作成する。
- [x] ステップ2: SKILL本文を、計画書読解、task_idブランチ、TDD、スコープ制限、停止条件を含む手順に置換する。
- [x] ステップ3: `agents/openai.yaml` の既定プロンプトを規約に合わせて更新する。
- [x] ステップ4: SKILL validator と SHIGOKU docs validator を実行する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [x] [重要度:低] 現在の作業ツリーには多数の既存未コミット変更があるため、この作業では実Gitブランチ切替は実施せず、SKILLの手順として追加した。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks: []
```
