---
task_id: SGK-2026-0319
doc_type: work_report
status: done
parent_task_id: SGK-2026-0289
related_docs:
  - docs/shigoku/subtasks/done/2026-06-26_learnings-agent-rule_subtask_plan.md
  - docs/shigoku/learnings.md
  - rules/lessons.md
  - rules/shigoku-docs.md
  - rules/report-session-consistency.md
  - rules/python-tests.md
  - AGENTS.md
  - docs/shigoku/worklogs/2026-06-26_sgk-2026-0319_learnings-rule-extraction_work_log.md
title: 'SGK-2026-0319 作業報告書: learnings の恒久ルール昇格と agent rule 接続'
created_at: '2026-06-26'
updated_at: '2026-07-02'
tags:
  - shigoku
---

# SGK-2026-0319 作業報告書

## 完了サマリ

| 項目 | 内容 |
|---|---|
| タスクID | SGK-2026-0319 |
| 親タスク | SGK-2026-0289 |
| 作業日 | 2026-06-26 |
| ステータス | **done** |
| 目的 | `docs/shigoku/learnings.md` に溜まった知見から、将来の作業に効く恒久ルールを抽出して rule file と agent entrypoint へ接続する |

## 実施内容

1. `docs/shigoku/learnings.md` に YAML Front Matter を追加し、昇格済みルールの索引と raw learnings の役割分担を明記した。
2. `rules/lessons.md` に 2026-06 系の再発防止ルールを追記し、docs validation、report/session truth、LLM config、redaction、cache key、notification dedup、CLI/report test、fixer 並列実行などの project-specific な落とし穴を恒久ルール化した。
3. `rules/shigoku-docs.md` を validator の実挙動に合わせ、`status` / `parent_task_id` / `related_docs` を含む Front Matter 必須項目、`done/` 移動時のリンク更新、`deferred_tasks` の実ID必須を明文化した。
4. `rules/report-session-consistency.md` と `rules/python-tests.md` に、`extract_all_findings()` の正本化、consistency verdict fail-closed、report CLI の artifact 検証、`pytest.raises(match=...)` の実メッセージ基準を追記した。
5. `AGENTS.md` に `rules/lessons.md` の常時ロード条件を追加し、抽出したルールが次回以降の非 trivial な変更で参照される導線を作った。

## 判断理由

- learnings は一次保管場所として残し、繰り返し効く項目だけを topic-specific な rule file に昇格させる方が、将来の作業で再利用しやすい。
- `rules/shigoku-docs.md` と validator の不一致が再発原因だったため、単なるメモ追加ではなく正本ルール側を修正した。
- `rules/lessons.md` を `AGENTS.md` から読むようにしないと、せっかく抽出した rules が運用に乗らないため、参照導線まで含めて整備した。

## 変更ファイル

| ファイル | 変更内容 |
|---|---|
| `docs/shigoku/learnings.md` | Front Matter 追加、昇格済みルール索引追加、raw learnings 整形 |
| `rules/lessons.md` | 2026-06 の project-specific lessons 追記 |
| `rules/shigoku-docs.md` | docs validator 実態に合わせた恒久ルールへ更新 |
| `rules/report-session-consistency.md` | canonical extractor / consistency verdict ルール追加 |
| `rules/python-tests.md` | report CLI / `pytest.raises(match=...)` テストルール追加 |
| `AGENTS.md` | `rules/lessons.md` の常時ロード条件追加 |

## 検証

- `python3 scripts/sync_shigoku_updated_at.py`
  - `UPDATED=0`, `SKIPPED=138`, 変更対象ファイルはすべて `already_today`
- `python3 scripts/validate_shigoku_docs.py`
  - `FRONT_MATTER_ISSUES=0`
  - `BROKEN_LINKS=0`
  - `REGISTRY_ISSUES=0`
  - `DEFERRED_LINK_ISSUES=0`

## 残リスク

| リスク | 深刻度 | 緩和策 |
|---|---|---|
| raw learnings のうち一部はまだ rule 化候補のまま残る | Low | 同種の失敗が再発した時点で `rules/*.md` へ追加昇格する |
| `create_shigoku_task.py` のファイル命名と AGENTS の命名規約に差異がある | Low | 別タスクで generator の出力規約を見直す |

## 参照ルールファイル

本タスクのために以下のルールファイルを参照した:

- `rules/shigoku-docs.md`
- `rules/task-ledger.md`
- `rules/python-tests.md`
- `rules/lessons.md`
- `rules/report-session-consistency.md`
