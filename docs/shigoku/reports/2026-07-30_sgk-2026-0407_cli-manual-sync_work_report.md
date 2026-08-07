---
task_id: SGK-2026-0407
doc_type: work_report
status: active
parent_task_id: SGK-2026-0001
related_docs:
- docs/shigoku/plans/2026-07-30_cli_plan.md
- docs/shigoku/manuals/USER_MANUAL.md
- docs/shigoku/manuals/REFERENCE.md
- docs/shigoku/manuals/QUICK_START.md
- docs/shigoku/manuals/manual_legacy/2026-07-02_sgk-2026-0337_detailed-command-reference.md
- docs/shigoku/worklogs/2026-07-30_sgk-2026-0407_cli-manual-sync_work_log.md
created_at: '2026-07-30'
updated_at: '2026-08-07'
---

# 作業報告：CLIマニュアルと実装の同期

## 実施内容

- `shigoku` と `shigoku-ops` の `--help` 出力および引数定義を確認した。
- 削除済みの `--full-refresh`、`--vault`、`--verbose`、`--output` を現行 CLI の説明から除去した。
- 詳細コマンド一覧に `report expected-detections`、`report compare-findings`、`report decision-tree`、`report attack-review`、`--intervention-gate-mode` を追加した。
- マニュアル間のリンクを、実際の `manual_legacy/` 配下のファイル位置に合わせて修正した。

## 判断理由

実装に存在しないオプションを案内すると、利用者が操作を始められないためです。詳細な引数は一つの詳細リファレンスに集約し、他のマニュアルから正しいリンクで案内する形を維持しました。

## 検証

- `.venv/bin/shigoku --help` で本体 CLI の主要引数を確認した。
- `.venv/bin/shigoku-ops report --help` で追加済み report 操作を確認した。
- `scripts/validate_shigoku_docs.py` でリンク切れ 0 件、Front Matter 問題 0 件を確認した。

## 残るリスク

文書検証には今回と無関係な台帳参照切れが2件残っています。対象は `task_243_missing_file` と `task_268_missing_file` であり、本タスクでは台帳の過去記録を変更していません。

## 次のステップ

台帳の過去参照切れ2件を別タスクで解消後、文書全体の検証を再実行して本タスクを完了します。CLI 引数を追加・削除する変更では、`shigoku --help` と `shigoku-ops --help` を基にこの詳細リファレンスも同時に確認します。
