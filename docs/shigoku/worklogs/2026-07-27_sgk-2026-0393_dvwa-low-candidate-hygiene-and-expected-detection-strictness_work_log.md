---
task_id: SGK-2026-0393
doc_type: work_log
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/subtasks/done/2026-07-27_dvwa-low-candidate-hygiene-and-expected-detection-strictness_subtask_plan.md
- docs/shigoku/reports/2026-07-27_sgk-2026-0393_dvwa-low-candidate-hygiene-and-expected-detection-strictness_work_report.md
created_at: '2026-07-27'
updated_at: '2026-07-28'
tags:
- shigoku
---

# 作業ログ：DVWA low candidate hygiene and expected detection strictness

## 2026-07-27

- 最新実行 `haddix_report_20260727_083300.md` と source session の整合性を確認した。
- expected detections の現状を確認し、従来は `authbypass_idor` が candidate のみでも missing required にならないことを確認した。
- `expected_detection_matrix.py` に evidence quality verdict を接続した。
- required confirmed は confirmed match が無い場合に `missing_required` へ残すようにした。
- CSRF は `misconfiguration` 保存でも CSRF signal がある場合、evidence quality 評価では `csrf` として扱うようにした。
- `HaddixFormatter` に candidate dedup key / merge helper を追加した。
- `HaddixSubmissionInternalFormatter` で enforcement 後の candidate list を集約するようにした。
- 候補理由コードの内訳を複数 reason code 対応にした。
- API AuthZ候補重複の回帰テストを追加した。
- expected detections の required confirmed / candidate_to_confirm の回帰テストを追加した。
- targeted tests で `92 passed` を確認した。
- 同一 session から一時レポートを生成し、`Confirmed: 16 / Candidate: 5` を確認した。
- 一時レポートの gate は `candidate_above_maximum` で fail だが、残った5件は重複ではなく未確定候補であることを確認した。
- `graphify update .` を実行したが、待機中にプロセスが終了し、完了メッセージは確認できなかった。既存グラフ警告として `source_file` 欠落が出た。

次アクション:

- 次回の SHIGOKU 実行または report 再生成で `Candidate: 5` になることを確認する。
- 残る候補5件は、2アカウント証明・CSRF状態変化・CORS実害確認で個別に確定または除外する。
