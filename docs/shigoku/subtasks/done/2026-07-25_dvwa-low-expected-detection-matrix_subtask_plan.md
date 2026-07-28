---
task_id: SGK-2026-0386
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/plans/2026-07-25_dvwa-low-detection-sufficiency-and-evidence-quality-recovery_plan.md
- docs/shigoku/reports/2026-07-25_sgk-2026-0385_dvwa-low-task-ab-implementation_work_report.md
- docs/shigoku/reports/2026-07-27_sgk-2026-0386_dvwa-low-expected-detection-matrix_work_report.md
- docs/shigoku/worklogs/2026-07-27_sgk-2026-0386_dvwa-low-expected-detection-matrix_work_log.md
title: DVWA low expected detection matrix
created_at: '2026-07-25'
updated_at: '2026-07-28'
tags:
- shigoku
target: DVWA Security=low / expected detection matrix / acceptance criteria
---

# 実装計画書：DVWA low expected detection matrix

## 1. 目的

DVWA Security=low に対して、SHIGOKU が「何を検知できれば十分か」を固定する。以後の作業ではタスク数ではなく、この期待検知マトリクスと実際の raw finding / confirmed finding の差分で判断する。

ただし、DVWA は教材用の脆弱サーバーであり、現実のアプリには存在しにくい機能や設定も含む。この task では「DVWA にあるから検知必須」ではなく、「実アプリでも同じ問題が成立するか」を合格基準に含める。

## 2. 背景

会話中の調査で、83 tasks / 57 tasks / 107 tasks の比較だけでは正否を判断できないことが分かった。57 tasks は 0 finding ではなく、107 tasks は fuzzing 暴走ではないが Initial Release Gate は FAIL している。

このため、まず「期待する検知」と「許容する未検知」を明文化する。

## 3. 対象と入力

- 親計画: `SGK-2026-0385`
- 主な比較対象:
  - `haddix_report_20260717_222441.md` / `session_20260717_222441.json`
  - `haddix_report_20260723_162936.md` / `session_20260723_162936.json`
  - `haddix_report_20260724_164750.md` / `session_20260724_164750.json`
- 参照コマンド:
  - `python3 scripts/verify_report_session_consistency.py --report <report>`
  - `python3 scripts/shigoku_ops_cli.py --json report findings --report <report>`
  - `python3 scripts/shigoku_ops_cli.py --json report gate --report <report>`

## 4. 作業内容

- [x] DVWA low 期待検知マトリクスを確定する。
- [x] 各行に対象 URL、実アプリ妥当性、期待レベル、必要 evidence、confirmed/candidate 判定条件を記載する。
- [x] DVWA 固有の教材仕様にしか見えない項目は、確定必須ではなく「条件付き」または「対象外可」に分類する。
- [x] `scn_08_oob_external_channel_flow`, `scn_10_semantic_business_logic`, `scn_12_advanced_ssrf_internal_topology` は手動方針として明記する。
- [x] 比較単位を `vuln_type + title + normalized target URL` として定義する。
- [x] 83 tasks に戻すことを目的にしない、と明記する。
- [x] DVWA の URL やページ名にだけ反応する special case を禁止する、と明記する。

## 5. 完了条件

- 期待検知マトリクスが親計画または専用 spec に残っている。
- Task B〜E の作業者が、このマトリクスだけを見て「合格/不足」を判断できる。
- レポートとセッションの整合性確認を前提にした評価手順が書かれている。
- 実アプリにありえる見逃しと、DVWA 固有の教材機能を分けて判断できる。

## 6. リスク

- [重要度:高] 期待検知を広げすぎると DVWA 固有のカーブフィットになる。実アプリにありえる脆弱性クラスだけを必須扱いにし、教材機能だけに見えるものは条件付きまたは対象外可にする。
- [重要度:中] confirmed 数を増やす目的で弱い evidence を confirmed 扱いにすると、SHIGOKU の bug bounty 方針から外れる。証拠品質を優先する。

## 7. 2026-07-26 review addendum

Task C レビューで、期待検知マトリクスにも次の前提を追加する必要があると判断した。

- AuthBypass / IDOR / API BFLA は、2つの独立した認証アイデンティティを hard precondition とする。未設定時は `untested_no_second_account` とし、candidate / non-finding に混ぜない。
- blind SQLi / blind RCE / blind SSRF など OOB が強い証拠になる検知は、OOB チャネル稼働確認を前提として扱う。未稼働時は `oob_channel_unavailable` とし、OOB 不発だけで非脆弱扱いしない。
- confirmed 判定は、`proof_of_control` と `proof_of_impact` を分ける。control-only は原則 candidate。
- payload delivery telemetry がない negative result は、非脆弱ではなく `payload_not_delivered_*` として分離する。
- confirmed primitive は chain_builder へ渡せる形にする。ただし chain は session evidence で裏付けられるまで `chain_candidate` として扱う。

この addendum は計画上の追補であり、既存の `src/reporting/expected_detection_matrix.py` へ反映する場合は別途実装・テストを行う。
