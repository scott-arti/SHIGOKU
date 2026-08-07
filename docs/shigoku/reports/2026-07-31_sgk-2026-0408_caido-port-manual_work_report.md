---
task_id: SGK-2026-0408
doc_type: work_report
status: done
parent_task_id: SGK-2026-0407
related_docs:
- docs/shigoku/subtasks/done/2026-07-31_caido_subtask_plan.md
- docs/shigoku/manuals/manual_legacy/2026-07-02_sgk-2026-0338_operator-user-manual.md
- docs/shigoku/worklogs/2026-07-31_sgk-2026-0408_caido-port-manual_work_log.md
created_at: '2026-07-31'
updated_at: '2026-08-07'
---

# 作業報告：Caido 接続ポート設定の運用マニュアル追記

## 実施内容

- 運用者マニュアルの Caido 連携節に、未設定時は `http://127.0.0.1:8080` を使うことを追記した。
- 別ポートを使う場合の `SHIGOKU_CAIDO__URL` と token 用の `SHIGOKU_CAIDO__TOKEN` の設定例を追加した。
- `settings.py` を書き換えずに接続ポートを変更できることを明記した。

## 判断理由

Caido が標準以外のポートで動作している場合でも、利用者が設定先と必要な操作をすぐ確認できるようにするためです。

## 検証

- 設定の既定値と環境変数名を `src/core/config/settings.py` および `docker-compose.yml` と照合した。
- `/usr/bin/python3 scripts/sync_shigoku_updated_at.py --docs-root <今回の各Markdown>` で、今回の4文書だけの `updated_at` を同期した。
- `/usr/bin/python3 scripts/validate_shigoku_docs.py` を実行し、Front Matter 問題 0 件、リンク切れ 0 件、今回のタスクに関する台帳問題 0 件を確認した。

## 残るリスク

- Caido 自体がどのポートで動くかは、利用者の Caido 側の設定に依存します。
- 文書検証は、今回と無関係な既存の台帳参照切れ2件（`task_243_missing_file`、`task_268_missing_file`）を報告して終了コード 1 になりました。

## 次のステップ

Caido を標準以外のポートで使う場合は、起動前のターミナルで `SHIGOKU_CAIDO__URL` を設定します。
