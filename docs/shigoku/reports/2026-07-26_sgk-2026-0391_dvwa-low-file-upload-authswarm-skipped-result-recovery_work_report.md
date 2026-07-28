---
task_id: SGK-2026-0391
doc_type: work_report
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/plans/2026-07-25_dvwa-low-detection-sufficiency-and-evidence-quality-recovery_plan.md
- docs/shigoku/subtasks/done/2026-07-25_dvwa-low-file-upload-and-authswarm-skipped-result-recovery_subtask_plan.md
- docs/shigoku/worklogs/2026-07-26_sgk-2026-0391_dvwa-low-file-upload-authswarm-skipped-result-recovery_work_log.md
created_at: '2026-07-26'
updated_at: '2026-07-28'
tags:
- shigoku
target: DVWA Security=low / File Upload safe canary and AuthZ preconditions
---

# 作業報告書：DVWA low File Upload and AuthSwarm skipped result recovery

## 実装内容

- File Upload は `safe_only=True` の安全canaryタスクだけ、SCN09 manual defer から除外して自動実行できるようにした。
- File Upload の自動検証は PHP / `.htaccess` ではなく、無害な canary ファイルのアップロードと取得確認だけにした。
- アップロード応答本文にファイル名入りの保存先パスがある場合、そのパスを取得候補として優先するようにした。
- File Upload finding に upload/retrieval evidence と delivery telemetry を保存するようにした。
- evidence quality gate に File Upload 専用条件を追加し、アップロード成功だけでは confirmed にしないようにした。
- AuthBypass / weak_id など2アカウント証明が必要な権限系 finding は、2アカウント未設定時に `untested_no_second_account` として分けるようにした。
- 2026-07-27 追補: `master_conductor.py` の recon 由来 File Upload task 生成にも `safe_only=True` と SCN09 を明示し、生成直後のタスクが manual defer に巻き込まれないようにした。
- 2026-07-27 追補: 2026-07-26 17:00 実行で残っていた `signal_bundle.upload` 経路の File Upload task にも `safe_only=True` と SCN09 を明示するよう追加した。
- 2026-07-27 追補: 2026-07-26 22:29 実行で File Upload の canary retrieval は成功したが、Finding evidence が `request_body=""` / `response_status=0` のため candidate に落ちていた。FileUploadSpecialist が request/response evidence と confidence を明示して保存するよう修正した。
- 2026-07-27 追補: 2026-07-26 23:31 実行では `extra_params` が JSON 文字列として渡り、FileUploadTester の dict 前提処理に合わず `findings_count=0` になっていた。LogicManager / FileUploadSpecialist 境界で JSON 文字列を dict に正規化するよう修正した。
- 2026-07-27 追補: 再点検で、正規化が上位境界だけだと FileUploadTester 直接呼び出し経路に同じ型ズレが残ることを確認した。正規化を FileUploadTester 境界へ移し、dict / JSON文字列 / Python dict 文字列 / query-string 形式を受けられるようにした。
- 2026-07-27 追補: 旧式の `params={...}` ツール呼び出しでフォーム追加パラメータが落ちないよう、BaseManager の `run_file_upload_check` 引数リマップを修正した。
- 2026-07-27 追補: 2026-07-27 07:33 実行で File Upload は `findings_count=1` になり、canary retrieval も成功した。ただし Haddix Report では `payload_request_mismatch` / `synthetic_response_evidence` により candidate に残った。
- 2026-07-27 追補: raw Finding には structured `evidence` と `file_upload_evidence.retrieved=true` が存在したため、HaddixFormatter が `Finding.evidence` から `poc_request` / `poc_response` を補完するよう修正した。
- 2026-07-27 追補: セッションCookie差し替えや weak_id 由来の権限系候補は、2アカウント証明が無い場合に `authz_impact_not_proven` ではなく `untested_no_second_account` へ分離するようにした。

## 判断理由

File Upload の `result=None` は、SCN09 の手動方針に巻き込まれて安全に実行できる範囲まで skipped されていたことが主因だった。一方で危険な upload/RCE 検証まで自動化すると実アプリでは強すぎるため、無害な canary の配送・取得確認に限定した。

AuthBypass / weak_id は、単一アカウントだけでは「別ユーザーのデータを取れた」と証明できない。2アカウントがない状態は「脆弱でない」ではなく「未検証」と分ける必要がある。

## 検証

- `.venv/bin/pytest tests/core/attack/test_file_upload_tester.py`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_scenario_probes.py::test_file_upload_probe_is_not_deferred_by_scn09_manual_policy tests/core/engine/test_master_conductor_scenario_probes.py::test_file_upload_probe_without_safe_only_stays_deferred_by_scn09_manual_policy`
- `.venv/bin/pytest tests/unit/reporting/test_haddix_evidence_quality_gate.py::TestVulnSpecificMatrix::test_authz_without_second_account_is_untested_not_impact_gap tests/unit/reporting/test_haddix_evidence_quality_gate.py::TestVulnSpecificMatrix::test_file_upload_requires_retrieval_or_execution_impact tests/unit/reporting/test_haddix_evidence_quality_gate.py::TestVulnSpecificMatrix::test_file_upload_with_retrieved_canary_is_confirmed`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_scenario_probes.py tests/core/agents/swarm/injection/test_smart_xss_logic.py tests/core/agents/swarm/test_auth_manager.py tests/unit/agents/swarm/test_biz_logic_hunter.py tests/unit/reporting/test_haddix_evidence_quality_gate.py`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_scenario_probes.py::test_create_attack_tasks_marks_signal_upload_tasks_safe_only`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_scenario_probes.py`
- `.venv/bin/pytest tests/core/agents/swarm/logic/test_file_upload_specialist.py::test_file_upload_specialist_records_real_request_and_response_evidence`
- `.venv/bin/pytest tests/core/attack/test_file_upload_tester.py tests/core/agents/swarm/logic/test_file_upload_specialist.py tests/unit/reporting/test_haddix_evidence_quality_gate.py::TestVulnSpecificMatrix::test_file_upload_requires_retrieval_or_execution_impact tests/unit/reporting/test_haddix_evidence_quality_gate.py::TestVulnSpecificMatrix::test_file_upload_with_retrieved_canary_is_confirmed`
- `.venv/bin/pytest tests/core/agents/swarm/logic/test_file_upload_specialist.py::test_file_upload_specialist_records_real_request_and_response_evidence tests/core/agents/swarm/logic/test_logic_manager.py::test_logic_manager_file_upload_normalizes_json_string_extra_params`
- `.venv/bin/pytest tests/core/agents/swarm/logic/test_logic_manager.py tests/core/agents/swarm/logic/test_file_upload_specialist.py tests/core/attack/test_file_upload_tester.py`
- `.venv/bin/pytest tests/core/attack/test_file_upload_tester.py::test_file_upload_tester_extra_params tests/core/agents/swarm/logic/test_logic_manager.py::test_logic_manager_file_upload_normalizes_json_string_extra_params tests/core/agents/swarm/logic/test_logic_manager.py::test_logic_manager_file_upload_legacy_params_become_extra_params`
- `.venv/bin/pytest tests/unit/reporting/test_haddix_formatter_quality.py::test_formatter_builds_poc_from_structured_file_upload_evidence`
- `.venv/bin/pytest tests/unit/reporting/test_haddix_formatter_quality.py tests/unit/reporting/test_haddix_evidence_quality_gate.py::TestVulnSpecificMatrix::test_file_upload_requires_retrieval_or_execution_impact tests/unit/reporting/test_haddix_evidence_quality_gate.py::TestVulnSpecificMatrix::test_file_upload_with_retrieved_canary_is_confirmed tests/core/agents/swarm/logic/test_file_upload_specialist.py tests/core/attack/test_file_upload_tester.py tests/core/agents/swarm/logic/test_logic_manager.py::test_logic_manager_file_upload_normalizes_json_string_extra_params tests/core/agents/swarm/logic/test_logic_manager.py::test_logic_manager_file_upload_legacy_params_become_extra_params`
- `.venv/bin/python - <<'PY' ... # session_20260727_073356 raw File Upload finding を新Haddix変換で評価し shadow_status=confirmed / reason_codes=[] を確認`
- `.venv/bin/shigoku-ops report consistency --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260726_151419.md`
- `.venv/bin/python scripts/check_initial_release_gate.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260726_151419.md`（古い実行結果なので `candidate_above_maximum` で fail。整合性は consistent）

## リスク

- 保存先推測が外れると、アップロードは成功しても retrieval evidence は取れず candidate のままになる。
- AuthBypass confirmed には2つの独立した認証アイデンティティが必要。未設定なら `untested_no_second_account` のままになる。
- redirect chain / login redirect / content-type mismatch の全 probe 共通 telemetry は未対応。

## deferred_tasks

- task_id: SGK-2026-0391
  reason: AuthSwarm 全体の `payload_not_delivered_*` reason taxonomy と、2アカウント設定時の AuthBypass confirmed 証明を後続スライスで扱う。
