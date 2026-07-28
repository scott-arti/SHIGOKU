---
task_id: SGK-2026-0393
doc_type: work_report
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/plans/2026-07-25_dvwa-low-detection-sufficiency-and-evidence-quality-recovery_plan.md
- docs/shigoku/subtasks/done/2026-07-27_dvwa-low-candidate-hygiene-and-expected-detection-strictness_subtask_plan.md
- docs/shigoku/worklogs/2026-07-27_sgk-2026-0393_dvwa-low-candidate-hygiene-and-expected-detection-strictness_work_log.md
created_at: '2026-07-27'
updated_at: '2026-07-28'
tags:
- shigoku
target: DVWA low / expected detections / AuthZ CORS CSRF candidate hygiene
---

# 作業報告書：DVWA low candidate hygiene and expected detection strictness

## 実装内容

- `expected-detections` が raw finding の存在だけで required confirmed を満たした扱いにしないよう、Haddix evidence quality verdict を使って `confirmed` / `candidate` を分けた。
- required confirmed の検知は、候補しか無い場合に `missing_required` へ残すようにした。
- candidate_to_confirm の検知は、候補があれば missing ではなく candidate match として扱うようにした。
- CSRF は `misconfiguration` として保存されていても、CSRF signal があれば evidence quality 評価では `csrf` として扱うようにした。
- Haddix report の enforcement 後 candidate list で、同一URL・同一シナリオの AuthZ / CORS / CSRF 候補だけを集約するようにした。
- 候補理由コードの内訳を、先頭1件だけではなく複数 reason code を数えるようにした。
- 候補詳細に `Merged duplicate raw candidates` を表示し、畳んだ件数が見えるようにした。

## 判断理由

直近の DVWA low 実行では、SQLi / XSS / LFI / File Upload は confirmed になっていた。一方で AuthBypass は2アカウント証明が無く、CORS は public data の wildcard-no-credentials、CSRF は状態変更の before/after 証明が無かった。

そのため、これらを confirmed に上げるのは過大評価になる。一方で、同じ API BFLA 候補が複数タスクから重複して candidate count を増やしていたため、これは集約すべきだった。

## 検証

- `.venv/bin/pytest tests/unit/reporting/test_expected_detection_matrix.py tests/unit/scripts/test_shigoku_ops_expected_detection_cli.py tests/unit/reporting/test_haddix_submission_internal_sections.py -q`
  - 結果: `92 passed`
- `python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260727_083300.md`
  - 結果: `status=consistent`, `rerun_required=false`
- `.venv/bin/python scripts/shigoku_ops_cli.py --json report expected-detections --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260727_083300.md`
  - 結果: `missing_required_count=1`
  - `authbypass_idor` は `match_status=candidate`, `reason_codes=["untested_no_second_account"]`
  - `sqli_normal`, `sqli_blind`, `xss_reflected`, `xss_stored`, `xss_dom`, `lfi`, `file_upload` は confirmed match
  - `csrf_state_change`, `api_bfla`, `cors` は candidate match
- 同一 `session_20260727_083300.json` から一時Haddix reportを生成
  - 結果: `Confirmed: 16 / Candidate: 5`
  - 旧レポートの `Candidate: 10` から、重複API AuthZ候補6件が1件へ集約された。
  - 候補理由内訳: `authz_impact_not_proven:1`, `payload_request_mismatch:1`, `public_data_cross_origin_read:1`, `state_change_not_verified:1`, `untested_no_second_account:2`
- `python3 scripts/check_initial_release_gate.py --report /tmp/tmp.JBnGR5EZJM/haddix_report_temp.md`
  - 結果: `status=fail`, `reason_codes=["candidate_above_maximum"]`
  - ただし candidate は 10 ではなく 5。残った候補は重複ではなく未確定の実候補。
- `python3 scripts/check_initial_release_gate.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260727_083300.md`
  - 結果: `status=fail`, `reason_codes=["candidate_above_maximum"]`
  - 既存レポートは過去生成物のため `Candidate: 10` のまま。整合性は consistent。

## リスク

- 一時生成レポートでも candidate は 5 件残る。これは重複ではなく、未確定証拠が残っているという正しい失敗状態。
- 既存レポートファイルは再生成していないため、ファイル内容は変わらない。
- AuthBypass / weak_id を confirmed にするには、2つの独立した認証アイデンティティが必要。

## deferred_tasks

- deferred_id: SGK-2026-0393-D01
  title: "AuthZ / CORS / CSRF の候補を実証で確定または除外する"
  reason: "今回の範囲は candidate hygiene と expected detection strictness まで。攻撃成功証拠の追加は別スライス。"
  impact: medium
  tracking_task_id: SGK-2026-0385
  recommended_next_action: "2アカウント設定、CSRF before/after state、CORS credentialed/sensitive impact の検証を続ける。"
