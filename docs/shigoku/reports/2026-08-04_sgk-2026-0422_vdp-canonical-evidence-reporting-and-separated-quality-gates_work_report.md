---
task_id: SGK-2026-0422
doc_type: work_report
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0422_vdp-canonical-evidence-reporting-and-separated-quality-gates_subtask_plan.md
- docs/shigoku/plans/done/2026-07-31_vdp-capability-benchmark-and-evidence-contract_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0419_vdp-evidence-schema-safety-budget-and-recovery-foundation_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0421_vdp-evidence-gap-driven-verification-and-safe-follow-up_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0423_vdp-hidden-holdout-evaluation-shadow-rollout-and-recovery_subtask_plan.md
- docs/shigoku/worklogs/2026-08-04_sgk-2026-0422_vdp-canonical-evidence-reporting-and-separated-quality-gates_work_log.md
title: VDP canonical evidence reporting and separated quality gates 作業完了報告
created_at: '2026-08-04'
updated_at: '2026-08-07'
tags:
- shigoku
target: src/core/models,src/core/engine,src/reporting,src/main.py,pyproject.toml,uv.lock,scripts,tests
---

# 作業完了報告書：SGK-2026-0422

## 1. 最終状態

**DONE**。固定済み計画書（SGK-2026-0422 subtask plan、2026-08-04最終監査版）の全ゴール・必須テスト・障害時動作・完了条件を再監査し、`in_scope_blocker` は0件。最終実測: VDP関連16ファイル **416 passed**、report+ops_cliスイート **294 passed（exit 0）**、engine/VDP系 **402 passed**、reporting系 **434 passed**、CLI系 **92 passed**、main系 **57 passed（0422起因失敗0）**、baseline 13ファイル **595 passed**。旧real artifact整合・new-schema integration artifact整合（formatter/gate/consistency）ともに合格。

## 2. 実装概要

- canonical extractor（`src/reporting/vdp_canonical.py`）が新旧schemaを同一正規形（`VdpCanonicalSummary`、source_kind=canonical_vdp|legacy）へ変換。観測本文は生成・推測せず、欠損は `observation_content_unavailable` 等のcompatibility reasonで明示。
- Evidence Validator（`src/core/engine/vdp_evidence_validator.py`）がconfirmedの唯一の署名境界。Ed25519 private keyはengine層のみが保持し、proofは `ed25519:<proof_key_id>:<base64url>`（3要素、64-byte署名、paddingなし）へ固定。content hash（`sha256(canonical_json_bytes(EvidenceRecordV1.to_dict()))`）を内部計算し、`evaluated_evidence_ids` と `evidence_content_sha256` のkey集合一致を必須化。
- 構造化marker契約（audit I-07 round 3-4）: executorは中立事実（response_received/http_status/request_count）のみ記録し、`success_condition_met` のblanket markerは廃止。validatorは `_REQUIREMENT_MARKERS`（gap token→構造化marker対応表）でrequired_evidenceの全要件を明示満足するまでcandidate維持。
- 全formatter（haddix / submission-internal / ja-en）が同一serializerから `vdp_canonical_index_v1` を出力。report/session consistency checkerがverdict ID集合・件数・evidence ID/hash・summary digestを機械比較。
- training capability gate / real VDP run-quality gateを `vdp_gates.py` で分離。`shigoku-ops vdp gate --profile training|real`、`check_initial_release_gate.py --profile legacy|vdp-training|vdp-real`。
- separated 3ファイルは全temp生成→全検証→os.replace→manifest最後。consumer側（CLI report gate/consistency/loop/vdp gate、check_initial_release_gate.py）が `verify_separated_group` でmanifest必須（キー集合3件完全一致・stem由来パス照合・3ファイルhash一致）。
- main.pyのhaddix/ja-en両経路が生成済みレポートに対してconsistencyを実測し、real VDP gateへ実測status/reason codesを渡す（index欠損・不一致はNo-Go）。

## 3. 固定済み完了条件の監査

| 条件 | 結果 | 主な証拠 |
|---|---|---|
| D1 同一sessionから各formatter/gateが同一verdict集合 | PASS | `test_all_formatters_emit_same_verdict_ids`（`test_vdp_formatter_projection.py`）+ `test_consistent_canonical_pair` |
| D2 confirmed全件がEvidenceVerdict/EvidenceRecordへ逆参照可能 | PASS | `test_confirmed_restored_with_public_key`、`test_attempt_carries_trigger_next_action_id`、`test_next_action_to_attempt_traceable` |
| D3 report生成の追加通信/queue/書換え0 | PASS | `test_formatters_import_no_network_modules`、`test_generate_does_not_mutate_session`、`test_input_session_not_mutated` |
| D4 training/real gate混在なし | PASS | `test_vdp_gate_profiles_independent_verdicts`相当（`test_vdp_gates.py` 全23件: labels必須・go/hold/no_go・legacy閾値不使用） |
| D5 旧artifact回帰・実artifact整合 | PASS | `test_legacy_report_has_no_index`、`test_legacy_session_with_legacy_report_stays_consistent` + real artifact実行（consistency consistent / gate exit 3既存理由3件） |
| D6 秘密平文出力0・理由不明confirmed 0 | PASS | `test_secret_content_rejected_no_file`、`test_production_write_then_extract_has_no_secret_markers`、`test_verdict_never_contains_private_key_material`、signer空reason_codes拒否 |
| D7 proof衝突・改変後検証成功・他経路confirmed生成0 | PASS | `test_delimiter_ids_do_not_collide`、`test_evidence_body_tamper_fails` ほかtamper 7種、`test_public_verifier_cannot_generate_proof`、`test_no_arbitrary_validator_name_api` |
| D8 正規confirmedの別process復元・不明時fail-closed | PASS | `test_subprocess_sign_parent_verify_with_public_key`、`test_signed_confirmed_verdict_restores_with_public_key`、`test_missing_proof_fails`、`test_unknown_proof_schema_version_fails`、`test_unknown_key_id_fails`、`test_key_unavailable_fails_closed` |
| D9 全formatter同一serializer・consistency機械比較 | PASS | `test_all_formatters_emit_same_verdict_ids`、`test_markdown_report_embeds_index`、`test_ja_en_report_embeds_index`、`test_consistent_canonical_pair`、new-schema artifact（compared=True） |
| D10 separated 3ファイルmanifest検証（存在・3ファイル・hash一致） | PASS | `test_successful_group_has_manifest_and_verifies`、`test_trimmed_manifest_*_rejected`、`test_report_gate_rejects_trimmed_manifest`、`test_check_initial_release_gate_rejects_trimmed_manifest`（実CLI exit 3） |

## 4. 実経路と実測値

`MasterConductor follow-up dispatch → executor（中立事実evidence）→ Evidence Validator（構造化marker→confirmed/candidate）→ verdict upsert → async_save_session → M0 gate → session復元 → 別process proof復元` を通した（`test_master_conductor_vdp_evidence_validator.py::test_full_path_confirmed_verdict_survives_save_and_m0`）。production plain 200→candidateは `test_production_plain_200_response_stays_candidate`。

- new-schema integration artifact: validator confirmed（`evidence_contract_satisfied`）/ plain 200→candidate / consistency **consistent**（compared=True）/ real gate **go** / separated manifest **verified** / cross-process restore **confirmed**。
- real legacy artifact（`workspace/projects/localhost:3000/reports/haddix_report_20260731_134246.md`）: consistency **consistent**（exit 0）、initial gate（legacy profile）**exit 3**（`confirmed_below_minimum`/`family_gate_not_passed`/`unexpected_missing_scenarios`、既知ベースライン維持）。

## 5. 検証コマンドと結果

| コマンド | 結果 |
|---|---|
| `.venv/bin/shigoku-ops --json validate pytest --suite report --suite ops_cli --quiet` | **294 passed, exit 0** |
| VDP新規・変更16ファイル | **416 passed** |
| engine/VDP系15ファイル（0421含む） | **402 passed** |
| reporting系13ファイル | **434 passed** |
| CLI系9ファイル | **92 passed** |
| main系+MC VDP | **57 passed**（`test_main_report_replay_requires_configured_platform`のみ既存失敗・0422差分外） |
| baseline 13ファイル | **595 passed** |
| `git diff --check` | **0 files changed** |
| mandatory skip/xfail/TODO | **0件**（rg該当なし） |
| `python3 scripts/sync_shigoku_updated_at.py` → `python3 scripts/validate_shigoku_docs.py` | 0エラー |
| `graphify update .` | exit 0、graph.json/GRAPH_REPORT.md更新 |

## 6. deferred_tasks

- SGK-2026-0423（`docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0423_vdp-hidden-holdout-evaluation-shadow-rollout-and-recovery_subtask_plan.md`）: 確認鍵の本番配布・ローテーション・失効・secret store運用、hidden holdout / shadow rollout / M4、実VDP攻撃（計画書§10 NOT in scope 記載どおり）。

## 7. 残存リスク

- 構造化marker（`authz_impact_proven` 等）を記録する観測レイヤーは0423以降の実配線対象。現状production executor単独ではconfirmedに到達しない（fail-closed）。
- 既存失敗3件（`test_session_resume` / `test_observability_slo_rollup` 日付依存 / `test_main_report_replay` 日本語化）は0422差分に含まれず、本タスク起因でないことを`git diff HEAD`で確認済み。
