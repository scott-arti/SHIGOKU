---
task_id: SGK-2026-0444
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-12_sgk-2026-0444_candidate-lifecycle-and-parked-store.md
- docs/shigoku/worklogs/2026-08-12_sgk-2026-0444_candidate-lifecycle-and-parked-store_work_log.md
title: 候補ライフサイクル＋棚上げ保管（candidate_ledger）＋復活（T2）作業完了報告
created_at: '2026-08-12'
updated_at: '2026-08-12'
tags:
- shigoku
- vdp
- security-sensitive
target: src/core/validation/candidate_lifecycle.py,src/core/validation/candidate_ledger.py,src/core/validation/__init__.py
deferred_tasks:
  - deferred_id: SGK-2026-0444-D01
    title: "予算パラメータの YAML 配線（config/shigoku.yaml）"
    reason: "T2 はコンストラクタ既定値（max_visits=3 / max_age_days=30 / human_promise_threshold=0.67 / run_budget=10）で完結。YAML 化は settings.py の model field 追加を伴うため T3 配線時に実施"
    impact: low
    tracking_task_id: SGK-2026-0442
    recommended_next_action: "SGK-2026-0445（T3・ロードマップ定義済み）で config/shigoku.yaml へ反映"
  - deferred_id: SGK-2026-0444-D02
    title: "swarm 経路への配線（新情報供給・revisit 呼び出し・active 列接続）"
    reason: "T2 はサービス/ストア単体（呼び出し元ゼロ）。revisit への new_information 供給と allocate_investigation_budget の適用は T3"
    impact: low
    tracking_task_id: SGK-2026-0442
    recommended_next_action: "SGK-2026-0445（T3・ロードマップ定義済み）で配線"
  - deferred_id: SGK-2026-0444-D03
    title: "needs_human の人間解決パス＋Haddix レポート明記"
    reason: "needs_human は T2 では保留状態（apply_verdict no-op・人間解決は未実装）。レポート明記は T4"
    impact: low
    tracking_task_id: SGK-2026-0442
    recommended_next_action: "SGK-2026-0446（T4・ロードマップ定義済み）"
---

# 作業完了報告: SGK-2026-0444（T2 候補ライフサイクル＋棚上げ保管＋復活）

## 0. 成果物サマリ

- **設計承認関門を通過**: ①状態機械（遷移表 T1〜T9・予算切れ→棚上げ/人間送り条件）②ledger スキーマとマスク方針
  ③復活条件（型付き世界状態トークン・盲目再試行防止）④予算・ランキングパラメータ — を提示しユーザー承認。
  決定事項 D1（INCONCLUSIVE 即棚上げ）・D5（evidence はマスク済サマリ投影）を含め、計画書 §設計付録 A〜F として固定。
- **新規 `src/core/validation/candidate_lifecycle.py`**: `LifecycleState`（5値）・`CandidateRecord`・
  `CandidateLifecycleManager`（`apply_verdict` 遷移表・`derive_triggers`・`revisit`・`allocate_investigation_budget`・
  `normalize_endpoint`・`hash_account_token`）。
  - D3 構造的保証: `refuted` は REFUTED verdict 経由のみ。INCONCLUSIVE/NEEDS_MORE からは決して生成されない。
  - invariant: `apply_verdict` は needs_more 以外 no-op。棚上げからは `revisit()` のみで復帰（盲目再試行なし）。
- **新規 `src/core/validation/candidate_ledger.py`**: `CandidateLedger` / `LEDGER_SCHEMA_VERSION=1`。
  原子的書込（recon_state パターン）・破損 JSON/非UTF-8/非オブジェクト → quarantine（`.corrupt-<ts>`）＋空 ledger fail-safe・
  schema 未知 best-effort・不正レコード skip・OSError 伝播。**最低層 write API マスキング境界**: URL は 0439
  `mask_url_query_values` → 全文字列 `mask()` 再帰・冪等。token_map 非永続（run スコープ）。
- **`__init__.py`**: additive export のみ（既存 export 無変更）。
- **テスト 48 件**（新規2ファイル・製品非依存 fixture）。**単体完結**（swarm 未配線・既存挙動ビット同一）。

## 1. 検証（実装後・実測・orchestrator 再確認込み）

| 項目 | 結果 |
|---|---|
| 対象単体（test_candidate_lifecycle.py + test_candidate_ledger.py） | **48 passed / 0.63s**（orchestrator 再実行確認） |
| T1 回帰（test_finding_validator + test_hybrid_verdict_selfcheck） | **39 passed / 0.67s**（orchestrator 再実行確認） |
| T1 判定・Evidence Validator diff 0 | `git diff --stat` で finding_validator.py / vdp_evidence_validator.py / payout_grade.py / src/reporting/** 出力なし |
| PCR-P1 diff 0 | task_queue.py 無変更（git status 確認） |
| preflight | `check_vdp_product_independence.py` → **verdict pass / exit 0**（6/6 checks・total_token_hits 0・files scanned 3）（orchestrator 再実行確認） |
| docs | sync_shigoku_updated_at.py 実行後 validate_shigoku_docs.py 0 エラー（BROKEN_LINKS 0・REGISTRY_ISSUES 0・DEFERRED_LINK_ISSUES 0） |
| 変更ファイル | 指定5ファイルのみ（lifecycle / ledger / __init__ / テスト2）＋ docs |

## 2. 完了条件判定（計画書対比・§19 スコープ固定）

| 完了条件 | 判定 | 根拠 |
|---|---|---|
| 1. 状態機械 self-checking（needs_more→予算内継続→予算切れ棚上げ／needs_human→人間送り／confirmed・refuted 終端／証明不足のみでは refute しない／promise_score 順ランキング） | PASS | 遷移表全行テスト（test_confirmed_transition〜test_max_age_force_park・test_lifecycle_never_refutes_without_refuted_verdict・test_ranking_cap_and_state_filter） |
| 2. 棚上げ round-trip（put→再ロード→get 復元）・マスク保存で生秘密ゼロ（secret-scan）・破損 JSON fail-safe | PASS | test_round_trip_equality_and_queries / test_no_raw_secrets_on_disk（fake secret 4種・ネスト含む） / test_masking_is_idempotent_no_drift / test_garbage_json_quarantined・test_non_utf8_quarantined・test_non_object_payload_quarantined |
| 3. revisit: 新情報合致で parked→活動列復帰・非合致では復帰しない | PASS | test_matching_token_resurrects / test_non_matching_stays_parked / test_consumed_token_cannot_retrigger（同一トークン再トリガー不可＝盲目再試行防止） |
| 4. 既存挙動 byte-identical（未配線・回帰0）・PCR-P1 diff 0・preflight exit 0・docs opaque・validator 0 | PASS | §1 参照 |

**in_scope_blocker 0 件**。deferred_followup: D01〜D03（T3/T4・親ロードマップ SGK-2026-0442 で追跡）。
本タスクを **done** とする。

## 3. 作業プロセス注記

- 初回 fixer セッションが「参照読了のみ・ファイル未作成」で空完了したため、同一セッションを再開して再指示
  （git status で未作成を確認 → コンテキスト再利用）。再開後に全ファイル作成・検証完了。回収・再開パターンとして有効。
- 実装は仕様どおり（fixer 報告の逸脱なし・テスト側のバグ2件のみ修正: id 衝突によるキー潰れ・遷移テストの適用漏れ）。
- 参考ルールファイル: rules/lessons.md（mask-and-restore 正本・最低層 write API で redact・[2026-08] 設計意図は正本照合）、
  rules/codingrules.md（OSError 伝播・例外境界・秘密非露出）、rules/task-ledger.md（完了契約・done 化条件）、
  rules/python-tests.md（.venv/bin 実行・分岐網羅）、rules/shigoku-docs.md（front matter 必須）。
