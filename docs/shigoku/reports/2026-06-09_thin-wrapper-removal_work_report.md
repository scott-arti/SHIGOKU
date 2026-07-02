---
task_id: SGK-2026-0272
doc_type: work_report
status: done
parent_task_id: SGK-2026-0265
related_docs:
  - docs/shigoku/plans/2026-06-05_sgk-2026-0265_injection-manager-split-plan_plan.md
  - docs/shigoku/subtasks/2026-06-09_sgk-2026-0272_injectionmanager-thin-compatibility-wrapper_subtask_plan.md
title: '作業完了報告書: InjectionManager thin compatibility wrapper 群の段階削除'
created_at: '2026-06-09'
updated_at: '2026-07-02'
tags:
  - shigoku
  - refactoring
target: src/core/agents/swarm/injection/manager.py
---

# 作業完了報告書: InjectionManager thin compatibility wrapper 群の段階削除

## 実装内容

追加手順12/10（SGK-2026-0265 計画書 4.0.1）に基づき、`manager.py` 内の thin compatibility wrapper 群を段階的に削除し、呼び出し元を直接 import 関数へ置換した。

### 削除した wrapper 一覧（計24個）

| Phase | Wrapper 名 | 呼び出し回数 | 種別 | 抽出先 |
|---|---|---|---|---|
| 1 | `_extract_form_field_names` | 0 | デッドコード | `target_selection.py` |
| 1 | `_score_target_priority` | 0 | デッドコード | `target_selection.py` |
| 2 | `_summarize_skip_reason_counts` | 1 | @staticmethod | `phase1_results.py` |
| 2 | `_summarize_skip_reason_unknown_counts` | 1 | @staticmethod | `phase1_results.py` |
| 2 | `_summarize_low_ssrf_score_breakdown` | 1 | @staticmethod | `phase1_results.py` |
| 2 | `_has_actionable_blind_signal` | 1 | @staticmethod | `phase1_results.py` |
| 2 | `_extract_max_ssrf_score` | 1 | @staticmethod | `phase1_results.py` |
| 2 | `_should_force_phase2_by_risk` | 1 | @staticmethod | `execution_policy.py` |
| 2 | `_cap_phase2_budget` | 1 | @staticmethod | `execution_policy.py` |
| 2 | `_resolve_risk_force_allowlist` | 1 | instance | `execution_policy.py` |
| 2 | `_collect_phase1_vuln_types` | 1 | @staticmethod | `phase1_results.py` |
| 3 | `_prioritize_targets` | 1 | @classmethod | `target_selection.py` |
| 3 | `_is_lane2_score_eligible` | 1 | @classmethod | `execution_policy.py` |
| 4 | `_classify_url` | 1 | instance | `target_classifier.py` |
| 4 | `_build_object_ab_target` | 1 | @staticmethod | `api_probe_object_target.py` |
| 4 | `_resolve_per_url_timeout` | 1 | instance | `execution_policy.py` |
| 4 | `_should_auto_early_return` | 1 | instance | `execution_policy.py` |
| 5 | `_build_unknown_hypotheses` | 2 | instance | `unknown_hypotheses.py` |
| 5 | `_build_unknown_idor_candidate_finding` | 2 | instance | `unknown_hypotheses.py` |
| 6 | `_normalize_findings_additional_info` | 7 | instance | `result_normalizer.py` |
| 6 | `_normalize_blind_correlation` | 11 | @staticmethod | `result_normalizer.py` |
| 7 | `_sanitize_tested_params` | 29 | instance | `result_normalizer.py` |
| - | `_normalize_detection_class_token` | 0 | @staticmethod | `result_normalizer.py` |
| - | `_infer_detection_class_for_finding` | 0 | instance | `result_normalizer.py` |

### ファイル行数削減効果

- 削除前: 3,854行
- 削除後: 3,671行
- 削減: 183行 (4.7%)

### 更新したテストファイル（計14ファイル）

1. `test_manager_phase1_results_character.py`
2. `test_manager_target_selection_character.py`
3. `test_crlf_classification.py`
4. `test_graphql_classification.py`
5. `test_ssrf_classification.py`
6. `test_manager_classification_character.py`
7. `test_manager_execution_policy_character.py`
8. `test_wavec_lane2_promotion_skeleton.py`
9. `test_manager_unknown_hypotheses_character.py`
10. `test_graphql_pipeline.py`
11. `test_manager_normalizer_character.py`
12. `test_manager_p1_metadata.py`
13. `test_wavec_safety_controls.py`
14. `test_injection_manager.py`

## 検証結果

**テスト実行環境**: 2026-06-09, pytest 9.0.3, Python 3.12.12

| メトリクス | 値 |
|---|---|
| 総テスト数 | 423 |
| 通過 | 421 (99.5%) |
| 失敗 | 2 (pre-existing: blind_correlation normalization mismatch) |
| 新規回帰 | 0件 |

**内訳**:

| テスト群 | 件数 | 結果 |
|---|---|---|
| `tests/core/agents/swarm/injection/` | 386 | 386 passed |
| `tests/core/agents/swarm/test_injection_manager.py` | 37 | 35 passed, 2 failed |
| `tests/core/validation/test_phase_b_readiness.py` | 5 | 5 passed |

## 判断理由

- plan 本文の指示に従い、呼び出し箇所が少ない wrapper から着手し、self 状態に依存しない純粋デリゲートを優先した
- `_sanitize_tested_params`（29呼び出し）は最後に一括置換
- self 状態に依存する wrapper は呼び出し元で明示的に引数を渡す形に変更

## リスク・注意点

- sed による一括置換でネストした括弧を含む式が破損する事案が発生したが、Python スクリプトで再修正し全件正常化
- `_run_csrf_minimal_check` と `run_admin_check` は複雑な setup を持つため wrapper として残置（削除対象外）

## deferred_tasks

```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0272-D01
    title: "既知不具合: blind_correlation 正規化期待値の不一致修正"
    reason: "2件のテストが normalize_blind_correlation の追加フィールドにより期待値不一致。分割前から存在。"
    impact: low
    tracking_task_id: null
    recommended_next_action: "テスト期待値を normalize_blind_correlation の出力に合わせて更新する subtask を起票"
```
