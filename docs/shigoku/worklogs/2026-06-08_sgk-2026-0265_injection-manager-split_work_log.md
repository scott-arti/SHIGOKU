---
task_id: SGK-2026-0265
doc_type: work_log
status: done
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/plans/2026-06-05_injection-manager-split-plan_plan.md
title: "作業ログ: InjectionManager 分割"
created_at: "2026-06-05"
updated_at: '2026-06-08'
---

# 作業ログ

1. `manager.py` 内の定数群/helper群/specialist delegation群/builtin probe群を分類し、facadeに残すstate ownerを固定した。`manager_internal/` サブパッケージを作成し、ownershipを文書化した（手順1/10）。
2. observability/debug契約を `## 3.3`, `## 3.4` に明文化した（手順2/10）。
3. `DispatchContext`、`UrlExecutionRequest`、`UrlExecutionResult`、`NormalizationInput` をTypedDict DTOとして `models.py` へadditive導入した（手順3/10）。
4. `_classify_url` を `target_classifier.py` へ抽出した（手順4/10）。
5. `_score_target_priority`/`_prioritize_targets`/`extract_form_field_names` を `target_selection.py` へ抽出した（手順5/10）。
6. `resolve_per_url_timeout`/`cap_phase2_budget`/`is_lane2_score_eligible`/`should_force_phase2_by_risk`/`should_auto_early_return`/`resolve_risk_force_allowlist` を `execution_policy.py` へ抽出した（手順6/10）。
7. `run_csrf_minimal_check` を `builtin_probes.py` へ抽出した（手順7/10）。
8. API probe 系 helper 10モジュールを `api_probe_*.py` 群へ抽出した。
9. `run_admin_check` を `admin_check.py` へ抽出。抽出中に実バグ2件（target→target_url, title欠落）を発見・修正した（手順7.1/10）。
10. `build_hunter_task` テンプレートを `tool_runners.py` へ抽出し、7/10の run_*_hunter に適用した（手順7.5/10）。
11. `SPECIALIST_MAP` + `select_specialists` を `specialist_router.py` へ抽出した（手順8/10）。
12. `filter_manager_findings`/`validate_manager_findings`/`normalize_blind_correlation`/`sanitize_tested_params`/`infer_detection_class_for_finding`/`normalize_findings_additional_info`/`build_process_url_cache_entry`/`build_url_result_from_cache` を `result_normalizer.py` へ抽出した（手順9/10, 9.1/10, 9.2/10）。
13. `has_actionable_blind_signal`/`summarize_skip_reason_counts`/`summarize_skip_reason_unknown_counts`/`summarize_low_ssrf_score_breakdown`/`extract_max_ssrf_score`/`collect_phase1_vuln_types` を `phase1_results.py` へ抽出した。
14. `build_unknown_hypotheses`/`build_unknown_idor_candidate_finding` を `unknown_hypotheses.py` へ抽出した。抽出漏れ `unknown_profile` キーを修正した（手順9.5/10）。
15. 全抽出対象に対し character test + unit test を TDD で作成した（新規テスト84件）。
16. Full suite 回帰を実行し 412/414 passed を確認した。2件はpre-existing failure (blind_correlation normalization) （手順10/10）。
17. `_run_api_minimal_check` 本体、`dispatch`、`_run_unknown_hypothesis_scans` の3件を「着手しない」と確定した（手順11/10）。

## 次アクション
- 親タスク SGK-2026-0265 を done とする。
- 継続監視が必要な項目（validated/rejected ratio, timeout_rate, phase2_forced_count）は deferred task として別途追跡する。
- compatibility wrapper 削除は呼び出し元が多いため現時点では残置し、将来の一括リファクタリングで対応する。

## 実バグ修正（抽出中に発見）
1. `admin_check.py`: `Finding(target=url)` → `target_url=url` 修正
2. `admin_check.py`: `title` 必須パラメータ欠落を補完
3. `_infer_detection_class_for_finding`: detection_class 互換修正
4. `unknown_hypotheses.py`: `unknown_profile` キー抽出漏れ修正
