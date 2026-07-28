---
task_id: SGK-2026-0375
doc_type: work_log
status: done
parent_task_id: SGK-2026-0374
related_docs:
- docs/shigoku/plans/done/2026-07-22_sgk-2026-0375_scenario-probe-ownership-dedup-recovery_plan.md
- docs/shigoku/reports/2026-07-22_sgk-2026-0375_scenario-probe-ownership-dedup-recovery_work_report.md
created_at: '2026-07-22'
updated_at: '2026-07-28'
---

# SGK-2026-0375 作業ログ

## 2026-07-22

- `haddix_report_20260722_231221.md` を整合性チェックし、primary source を固定した。
- latest session を解析し、scenario probe は 9 本生成されているのに queue では 2 本に減っていることを確認した。
- synthetic 再現で `_check_and_claim_ownership()` が same-target probe を suppress していることを特定した。
- scenario probe task に scenario 単位の `selection_origin` を付与し、回帰テスト 14 件の成功を確認した。
- SHIGOKU の plan / report / worklog / registry / ledger を done 状態へ更新した。

次のアクション: 修正後ビルドで DVWA Security=low を rerun し、34 task / 5 scenario からどこまで回復したかを session で確認する。
