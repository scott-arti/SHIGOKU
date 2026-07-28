---
task_id: SGK-2026-0387
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/plans/2026-07-25_dvwa-low-detection-sufficiency-and-evidence-quality-recovery_plan.md
- docs/shigoku/reports/2026-07-25_sgk-2026-0385_dvwa-low-task-ab-implementation_work_report.md
- docs/shigoku/reports/2026-07-27_sgk-2026-0387_dvwa-low-regression-finding-restoration_work_report.md
- docs/shigoku/worklogs/2026-07-27_sgk-2026-0387_dvwa-low-regression-finding-restoration_work_log.md
title: DVWA low regression finding restoration
created_at: '2026-07-25'
updated_at: '2026-07-28'
tags:
- shigoku
target: DVWA Security=low / authbypass weak_id open_redirect sqli regression restoration
---

# 実装計画書：DVWA low regression finding restoration

## 1. 目的

過去の DVWA low run で見えていたが、直近 107 tasks run で弱くなった、または消えた finding を復旧する。

ただし、過去に出ていたという理由だけでは復旧しない。実アプリにもありえる脆弱性、または分析済みなのに調査・証拠化できていないものだけを直す。DVWA 固有の教材仕様にしか見えないものは、復旧ではなく reason-coded non-finding または対象外として整理する。

## 2. 優先対象

| 対象 | 期待 |
|---|---|
| `/vulnerabilities/authbypass/get_user_data.php?id=2` | 権限昇格 / auth bypass finding を復旧する。 |
| `/vulnerabilities/weak_id/?id=2` | weak_id からの権限・セッション影響を復旧する。 |
| `/vulnerabilities/open_redirect/source/low.php?redirect=...` | open redirect と CRLF を分類して出す。 |
| `/vulnerabilities/sqli/` | 通常 SQLi を raw finding として安定して出す。 |

## 3. 調査候補

- `src/core/agents/swarm/auth_ninja.py`
- `src/core/agents/swarm/base_manager.py`
- `src/core/agents/swarm/injection/manager.py`
- `src/core/agents/swarm/injection/manager_internal/result_normalizer.py`
- `src/core/engine/master_conductor.py`
- `src/reporting/finding_extractor.py`
- `src/reporting/haddix_formatter.py`

## 4. 作業内容

- [x] 83 tasks / 57 tasks / 107 tasks の raw findings を canonical extractor で比較する。
- [x] 消えた finding が、タスク未生成・実行 skipped・result normalization・report formatting のどこで落ちたかを切り分ける。
- [x] 消えた finding が実アプリでも成立する問題か、DVWA 教材仕様に依存するものかを分類する。
- [x] AuthSwarm と weak_id の skipped / result None が手動方針によるものか、実行漏れかを確認する。
- [x] open_redirect と CRLF の分類が潰れていないか確認する。
- [x] 通常 SQLi `/vulnerabilities/sqli/` が raw finding として安定して残るようにする。
- [x] DVWA 固有のページ名や URL だけに合わせた復旧実装をしない。

## 7. 実装メモ

- `authbypass` は、107 tasks run では signal bundle から欠落し、history replay 後の `master_conductor.recon.auth` タスクが SCN07 手動 deferred に流れていた。
- 修正として、authz 文脈のある URL を BizLogic の `AuthZ Differential Check` companion にも流す。これにより token trust boundary の手動方針を保ったまま、IDOR/BAC の自動確認経路を残す。
- Open Redirect は現行コードで `redirect_param` の per-target 展開が有効であることをテストで固定した。107 tasks run の 1-target 化は、現在ソースでは再発しない想定。
- SQLi normal は 107 tasks run でも raw finding が出ていたため、Task B では復旧対象ではなく、Task C-1 の evidence promotion 対象として扱う。

## 5. 完了条件

- 最新 DVWA low run で、優先対象の raw finding が復旧する、または DVWA 固有の教材仕様として reason-coded non-finding / 対象外に整理される。
- 復旧した finding、または対象外判断が、実アプリ妥当性の観点で説明できる。
- 比較は `vuln_type + title + normalized target URL` で行う。
- 追加タスクが異常増殖しない。
- `verify_report_session_consistency.py` が PASS する。

## 6. リスク

- [重要度:高] 手動方針の scenario と、実行すべき AuthSwarm タスクを混同すると、実行漏れを仕様として隠してしまう。skipped reason を必ず確認する。
- [重要度:中] 過去 finding の復旧だけを優先すると、弱い evidence が増える可能性がある。confirmed への昇格は SGK-2026-0388 以降で扱う。
- [重要度:中] 過去 finding に DVWA 固有の教材仕様が混ざっている可能性がある。実アプリで成立しないものを無理に戻さない。
