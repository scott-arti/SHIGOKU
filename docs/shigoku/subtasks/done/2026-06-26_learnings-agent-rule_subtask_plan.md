---
task_id: SGK-2026-0319
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0289
related_docs:
- docs/shigoku/learnings.md
- rules/lessons.md
- rules/shigoku-docs.md
- rules/report-session-consistency.md
- rules/python-tests.md
- AGENTS.md
- docs/shigoku/reports/2026-06-26_sgk-2026-0319_learnings-rule-extraction_work_report.md
- docs/shigoku/worklogs/2026-06-26_sgk-2026-0319_learnings-rule-extraction_work_log.md
title: learnings の恒久ルール昇格と agent rule 接続
created_at: '2026-06-26'
updated_at: '2026-06-30'
tags:
- shigoku
target: docs/shigoku, rules, AGENTS.md
---

# 実装計画書：learnings の恒久ルール昇格と agent rule 接続

## 1. 達成したいゴール（ユーザー視点）
- [ ] `docs/shigoku/learnings.md` に溜まった知見から、繰り返し効く項目だけを恒久ルールとして抽出できること。
- [ ] 抽出したルールが `rules/*.md` と `AGENTS.md` に接続され、次回以降の作業で実際に参照されること。
- [ ] `docs/shigoku/learnings.md` 自体も SHIGOKU ドキュメント規約に適合し、validator を阻害しないこと。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `docs/shigoku/learnings.md`: raw learnings の一次保管と、昇格済みルールの索引。
  - `rules/lessons.md`: project-specific anti-pattern の恒久ルール正本。
  - `rules/shigoku-docs.md`: docs validator と task ledger に関する恒久ルール。
  - `rules/report-session-consistency.md`: report/session 判定の恒久ルール。
  - `rules/python-tests.md`: CLI/report 系テストの恒久ルール。
  - `AGENTS.md`: 非 trivial 変更時の rule-loading 接続点。
- **データの流れ / 依存関係:**
  - `docs/shigoku/learnings.md` の raw learning -> 再発頻度と汎用性で選別 -> `rules/*.md` / `AGENTS.md` へ昇格 -> 次回以降の実装・レビューで参照。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `docs/shigoku/learnings.md` の bullet 群, 既存 `rules/*.md`, 現行 `AGENTS.md`
- **出力/結果 (Output):** 恒久ルールへ昇格した記述、front matter を持つ `learnings.md`、関連 task/report/worklog
- **制約・ルール:**
  - learnings の全文を消さず、raw evidence は保持する。
  - 1回限りの workaround ではなく、将来の作業でも効く規則だけを恒久ルールへ昇格する。
  - `AGENTS.md` と `rules/*.md` の責務を保ち、topic-specific ルールは対応する rule file に置く。
  - ドキュメント変更後は `sync_shigoku_updated_at.py` と `validate_shigoku_docs.py` を通す。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `learnings.md` の各項目をレビューし、恒久ルールへ昇格すべき項目を topic ごとに分類する。
- [x] ステップ2: `rules/lessons.md` と必要な `rules/*.md` / `AGENTS.md` に最小差分でルールを追記し、`learnings.md` に昇格先を明記する。
- [x] ステップ3: task の report/worklog を作成し、docs validator を通した上で plan を `done/` へ移して台帳をクローズする。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] 一時的な workaround を恒久ルールへ誤昇格するリスク - rule 化は「再発頻度が高い」「複数領域に効く」「review failure を防ぐ」のいずれかを満たす項目に限定する。
- [ ] [重要度:低] 既存の `rules/*.md` と記述が二重化するリスク - `learnings.md` は索引と raw evidence に寄せ、最終的な行動規範は rule file 側を正本にする。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0319-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
