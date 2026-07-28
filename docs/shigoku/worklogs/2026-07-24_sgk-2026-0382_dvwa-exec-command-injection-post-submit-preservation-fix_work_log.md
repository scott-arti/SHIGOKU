---
task_id: SGK-2026-0382
doc_type: work_log
status: done
parent_task_id: SGK-2026-0381
related_docs:
- docs/shigoku/plans/done/2026-07-24_sgk-2026-0382_dvwa-exec-command-injection-post-submit-preservation-fix_plan.md
- docs/shigoku/reports/2026-07-24_sgk-2026-0382_dvwa-exec-command-injection-post-submit-preservation-fix_work_report.md
created_at: '2026-07-24'
updated_at: '2026-07-28'
---

# 作業ログ：DVWA exec command injection POST submit preservation fix

## 2026-07-24
- 142431 report/session consistency を確認し、session を正として調査した。
- raw session では `os_command_injection` finding が無く、LLM思考文の「Found」は構造化findingではないことを確認した。
- DVWA exec のPOST実通信で `Submit=Submit` の有無が検知成否に影響することを確認した。
- REDテストを追加し、`Submit` が `context.params` に残らず失敗することを確認した。
- `SmartCmdSSRFHunter` を修正し、POSTフォーム制御値を送信本文に保持するようにした。
- 関連テスト57件と py_compile を確認した。

## 次アクション
- ユーザーの次回 DVWA low 実行結果で `os_command_injection / exec / ip` が raw finding に戻るか確認する。
