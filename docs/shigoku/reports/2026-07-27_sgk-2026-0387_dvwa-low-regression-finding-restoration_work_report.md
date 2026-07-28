---
task_id: SGK-2026-0387
doc_type: work_report
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/plans/2026-07-25_dvwa-low-detection-sufficiency-and-evidence-quality-recovery_plan.md
- docs/shigoku/subtasks/done/2026-07-25_dvwa-low-regression-finding-restoration_subtask_plan.md
- docs/shigoku/worklogs/2026-07-27_sgk-2026-0387_dvwa-low-regression-finding-restoration_work_log.md
created_at: '2026-07-27'
updated_at: '2026-07-28'
tags:
- shigoku
target: DVWA Security=low / regression finding restoration
---

# 作業報告書：DVWA low regression finding restoration

## 実装内容

- 過去実行と比較し、検知の有無をタスク数ではなく脆弱性種別・タイトル・正規化 URL で追跡した。
- AuthZ 文脈を BizLogic の差分確認へ渡す経路を残し、手動方針の token trust boundary と自動 IDOR/BAC 確認を混同しないようにした。
- 通常 SQLi は raw finding として残ることを確認し、確証化は証拠品質タスクへ分離した。
- Open Redirect と CRLF の個別分類を保持した。認証境界の影響を2アカウントなしで確定扱いしない方針を明確化した。

## 判断理由

以前の finding を機械的に復活させるのではなく、実アプリにも成立し得る問題だけを追跡した。認証・認可の影響は別利用者での証明がない場合、検知失敗や非脆弱と混同せず `untested_no_second_account` として扱う。

## 検証

- `.venv/bin/pytest tests/core/engine/test_master_conductor_scenario_probes.py -q`
- `python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260727_095226.md`
- `python3 scripts/shigoku_ops_cli.py --json report findings --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260727_095226.md`

## リスク

- 2つの独立した認証アカウントを用意しない限り、AuthBypass / weak_id の権限影響は確定できない。
- SQLi の confirmed 昇格、ブラウザ XSS、アップロード検証の証拠品質は後続タスクで扱う。

## deferred_tasks

- task_id: SGK-2026-0385
  reason: 認可影響の2アカウント証明と各クラスの確証化は親タスクの継続対象とする。
