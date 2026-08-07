---
task_id: SGK-2026-0423
doc_type: work_log
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0423_vdp-hidden-holdout-evaluation-shadow-rollout-and-recovery_subtask_plan.md
- docs/shigoku/plans/done/2026-07-31_vdp-capability-benchmark-and-evidence-contract_plan.md
- docs/shigoku/reports/2026-08-04_sgk-2026-0423_vdp-hidden-holdout-evaluation-shadow-rollout-and-recovery_work_report.md
title: VDP hidden holdout evaluation shadow rollout and recovery 作業ログ
created_at: '2026-08-04'
updated_at: '2026-08-07'
tags:
- shigoku
target: tests,src/core/models,src/core/engine,src/reporting,config
---

# 作業ログ：SGK-2026-0423（オフライン実装フェーズ）

## 2026-08-04 オフライン実装フェーズ（コード・offline評価機構・failure drill・テスト）

### Wave 1（並列実装）
- 設定層: `VdpModeSettings` 拡張（stage/stage_flags/key_*/progression_records_path/thresholds_path/rollout_state_path）+ `VDP_STAGES`/`derive_stage_from_mode`/`is_enforce_stage`/`min_stage`。config/shigoku.yaml + example更新。テスト39件PASS。
- Lane A（鍵ライフサイクル）: `vdp_key_registry.py` 新規 + `vdp_evidence_validator.py` additive。41件PASS。signer境界allowlistに1箇所追記（SGK-2026-0423コメント付き）。
- Lane B（評価データ境界）: `vdp_dataset.py` + `vdp_holdout_runner.py` 新規。26件PASS。

### Wave 1（続）
- Lane C（段階導入）: `vdp_rollout.py` 新規 + master_conductor 5箇所 + session_service 1箇所。78件PASS。
- Lane D（drill+実経路統合）: drill 14本 + 実経路6本 + `vdp_canonical.py` のshadow_diff passthrough。20件PASS。
- graphify update（158,677 nodes）。VDP全対象 949件PASS（最終スイープはWave 2後に1010件）。

### Wave 2（監査指摘7項目の修正）
- Lane E: M3b-M4の進級証拠ベースraise経路 + rollout状態破損時M0 fail-closed。`derive_stage_from_mode` monkeypatchを全テストから排除。100件PASS。
- Lane G（初回は空レポートでノーオペレーション → 再ディスパッチ）: `assert_os_isolation`（owner≠runtime uid強制）+ コンテナ読取チャネル + ground_truthベースrecall/false_promotion + gaps。39件PASS（docker実EACCES含む）。
- Lane H: `FileKeyProvider._check_key_file`（lstat/所有者/権限0o077/通常ファイル）。51件PASS。
- Lane F: executor M3b実経路（`m3b_authorized`+HITL ticket、送信直後`mark_sent`、`state_change_already_sent`阻止）+ queue/dispatch配線 + drill 9/14・state-changeテストの本番経路書き換え。28件PASS。
- Lane I-a: 追加drill 8本（browser/OOB/proxy/auth失効/無限仮説/重複follow-up/旧session互換/report生成失敗）。8件PASS。

### 最終検証
- VDP全対象スイープ: **1010 passed**。
- artifact生成: session（M0 PASS）→ thresholds凍結 → root所有holdout labels（実EACCES確認）→ progression records → holdout評価（outcome=hold, leakage 0）→ decision records（m0-m3a go / m3b-m4 hold）→ consistency（production比較でconsistent）→ `shigoku-ops vdp gate --profile real`（pass/go）。
- ドキュメント: 本work report/work log作成。planは**active維持**（実通信検証未実施のためDoneにしない）。

### Wave 3（第2回監査指摘4項目の修正）
- Lane J-1: `_m4_go_evidence_ready()`（holdout結果=pass・eval_version一致・artifact hash照合・holdout段階decision record=go・real gate=go/終了状態既知/consistency pass を全て要求、未達は理由別cap_reasonsでm3cへ）。`ThresholdMetric.direction`（minimum/maximum明示+legacy fallback）。real gate: run_state unknown → Hold（`run_state_unknown_hold`）。141件PASS。
- Lane J-2: `_vdp_hitl_tickets_from_ledger`（実HITL台帳から承認済み・対象一致・有効なチケットのみ解決、`hitl_tickets=`パラメータ削除）。executor `hitl_ticket_validator`（任意文字列は承認扱いしない）。`StateChangeJournal`（`<checkpoint>.wal.json`、送信前durable begin→mark_sent/mark_failed、in_flight復旧は`state_change_outcome_unknown`でHold・自動再送禁止、checkpointなし状態変更は`state_change_journal_unavailable`）。66件PASS。
- 最終VDPスイープ: **1051 passed**。

### Wave 4（第3回監査 in_scope_blocker 2件の修正）
- Lane L-1（M4閾値fingerprint結び付け）: `_m4_go_evidence_ready()` に (1) 現在のthresholds fingerprint ≒ holdout結果の `threshold_fingerprint` **一致必須**（`m4_threshold_fingerprint_mismatch`、同一eval_versionでの後付け調整を本番gateが拒否）、(2) 判断記録は**最新エントリ（recorded_at順）のみ採用** — eval_version一致（`m4_decision_eval_version_mismatch`）・artifact_hash==holdout結果hash（`m4_decision_artifact_hash_mismatch`）・古いGoの後にHold/No-Goなら不採用。101件PASS。
- Lane L-2（WAL送信済み遷移）: `FollowUpExecutionResult.state_change_sent`（mark_sent呼出=HTTP送信完了の事実）を追加し、`_journal_transition_after_dispatch` で**送信事実ベース**のWAL遷移に変更: sent→mark_sent / 確定no-send（blocked・manual_review）のみmark_failed / **不明はin_flightのままHold**（`state_change_outcome_unknown`）。監査の実測ケース「送信成功→証拠保存失敗(evidence_write_backpressure)→新MC再開」をdrill 16で再現: WAL=sent・新MC通信**0件**。drill 17: in_flight復旧→Hold・再送0。50件PASS。
- 実artifact再生成: 判断記録のartifact_hashを**holdout結果hashへ結び付け**。実artifactでM4 gate実測: **effective_stage=m3a**（m4_holdout_outcome_not_pass / m4_decision_record_not_go / m4_requires_progression を本番gateが返却）— M4は安全側に維持。

### Wave 5（第4回監査 in_scope_blocker 1件の修正）
- Lane L-3（WAL network_error→in_flight Hold）: `_journal_transition_after_dispatch` の決定表から `reason=="network_error"` を `mark_failed` 条件から**除外**。network_errorは「通信先で変更完了後に応答喪失」の曖昧性があるため送信結果不明 → WALは **in_flightのまま** `state_change_outcome_unknown` でHold（自動再送禁止）。`mark_failed` は**通信開始前に証明可能な拒否**（blocked・manual_review: kill switch/readonly guard/scope/fingerprint/admission/idempotency/budget/prevent_double_send等）に限定。**drill 18**（監査の実測ケース: remote_applied=1→network_error→WAL=in_flight（not_sentではない）→checkpoint保存失敗→新MC再開→blocked state_change_outcome_unknown・新MC通信0件・Hold判断記録）+ `TestJournalTransitionDecisionTable`。34件PASS。
- 最終VDPスイープ: **1067 passed**。work reportの「network_error=確定no-send」記述を修正。

### 隔離検証フェーズ（Docker Compose、2026-08-04）
- 環境構築（Lane O-1）: `tests/fixtures/vdp_isolated_env/` — fixture_target.py（stdlib HTTP、POST/PUT/PATCH/DELETEは405）/ runtime_driver.py（production-path M3a: 実AsyncNetworkClient・実MC VDP hook・read-only crawl）/ evaluator_job.py（一回限りholdout評価、network: none）/ docker-compose.yml（iso internal network、holdoutはruntimeに非mount、evaluatorのみread-only mount）/ Dockerfile / holdout_labels/labels.json。host側smoke test `test_vdp_isolated_env.py` 4本。
- **統合検証での重大欠陥発見と修正**: O-1の閾値構成が偽装pass（recallをdirection=maximum/1.0、全指標を0.0/1.0の自明境界）だったため、方向正しい実質的閾値（recall minimum 0.5 / fp maximum 0.2 / untested maximum 0.5 / funnel・completeness minimum 0.2 / budget minimum 0.8）へ修正し、smoke testの期待値をhonestなholdへ更新。修正後 **4 passed（49.93s）**。
- コンテナ実行（修正後閾値・全rc=0）: runtime M0 **pass** / hypotheses=7 / attempts=2 / evidence=1 / verdicts=**confirmed 0・candidate 7** / executed=[/rate-limited] / degraded=[/slow:network_error] / **fixture_log_non_get=0**（30行全てGET）。evaluator outcome=**hold**（recall 0.0<0.5 unmet・completeness 0.143<0.2 unmet、その他met）、leakage=0。
- 実物検証: 実レポート生成（separated 4ファイル）→ consistency **consistent / reason_codes: []**。`shigoku-ops vdp gate --profile real` → status=pass / decision=**go** / run_state=degraded。漏洩rg検査: raw label probe 3種がruntime out/logs/resultに**0件**。M4拒否実測: ISO artifactで **effective_stage=m3a**（6理由）。閾値上書き試行: 同一eval_versionで改変→**EvalVersionMismatchで拒否**。
- 判断記録: `iso/out/eval/decision_records.json` — m0-m3a=go（隔離M3a実行証拠）、holdout/m3b/m3c/m4=hold。composeは撤去済み（disposable）。
- 最終VDPスイープ: **1071 passed**（isolated envテスト含む）。**完了条件6（評価に合格、strict reading）は未達（holdout=hold）→ planはactive維持**。work report §6-7 に完了監査表と未達整理を記録。
- session再生成（run_health=run_state:succeeded）+ 方向付きthresholds + メタデータ付きholdout結果（untested_rate met=True実証）。
- **実レポート生成**（separated 3ファイル+manifest）→ 公式consistency checker **consistent / reason_codes: [] / rerun_required: False**。
- real gate再実行: **decision=go / run_state=succeeded**。
- 鍵ライフサイクル証跡（配布/rotation/verify-only/revoke/復旧、秘密鍵なし）。
- 判断記録: m0-m3a go / holdout・m3b・m3c・m4 hold（オフライン未達・実通信未許可を理由に明示）。
- work report更新。planは**active維持**（holdout合格・実VDP検証が未達のためDoneにしない）。

### 最終クローズ（ランダムopaque holdout、2026-08-05）→ DONE
- P-1（cross-account比較観測レイヤー）: `VdpFollowUpExecutor` に `account_credentials` / `_COMPARISON_GAPS`（authz_impact_not_proven・semantic_diff_owner_permission_sensitive_field・untested_no_second_account）/ `_send_with_auth` / 実観測のみからのmarker記録（authz_impact_proven・semantic_diff_observed・second_account_compared。denied/public/比較不能はmarkerなし）。秘密はsend時のみ解決・spec/session/evidenceに非含有。84件PASS（2セッション合流・sensitive-field真理表修正含む）。
- P-2（ランダムopaque holdout環境）: `tests/fixtures/vdp_holdout_env/` — 起動時ランダム15-hex不透明URL 3本（granted/denied/public）+ ランダムアカウント秘密。secrets/ground truthは**repo外$PRIV（mktemp -d, chmod 700）**。runtimeはsrc/config/.venv/uv-python/driver/private out/logsのみmount（**tests非mount・secrets非mount**）。ドライバはroute非依存（source scanで検証）。MC配線（`_vdp_account_credentials` env由来・specへのauth id付与）。CLIに`--vdp-key-registry`（公開鍵のみ）をadditive追加。13件PASS。
- 実行実測: runtime confirmed 1 / candidate 2 / POST 0 / non_get 0。**隔離実証**: runtimeコンテナ内 `cat /secrets/secret.json`→ENOENT・`ls /repo/tests`→ENOENT。evaluator **outcome=pass**（recall 1.0 ≥ 0.5 / completeness 0.333 ≥ 0.2 / leakage 0、iso-v2閾値=iso-v1と同値）。consistency **consistent** / real gate **go**（run_state=succeeded）/ M4 **m3a維持**（progressionなし・rollout延期）。
- 完了監査: **全8条件PASS、in_scope_blocker 0件 → DONE**。planをdone/へ移動、task_registry.yaml / task_ledger.md / task_ledger.csv をdone＋新パスへ更新、関連docs（0418/0421/0422/0423）のrelated_docsを一括更新。最終VDPスイープ **1090 passed**。sync→validate 0エラー。

### 作業規律
- `git reset/checkout/clean/stash/commit/branch` は一切使用せず。ネットワーク操作なし（全drill/artifactはfake transport・ローカルコンテナのみ）。
- 各レーンはTDD（失敗テスト先行→実装→グリーン）で実施し、monkeypatchによる本番処理置換は排除。
