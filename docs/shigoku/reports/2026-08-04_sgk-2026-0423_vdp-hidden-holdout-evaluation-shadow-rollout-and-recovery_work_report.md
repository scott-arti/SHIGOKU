---
task_id: SGK-2026-0423
doc_type: work_report
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0423_vdp-hidden-holdout-evaluation-shadow-rollout-and-recovery_subtask_plan.md
- docs/shigoku/plans/done/2026-07-31_vdp-capability-benchmark-and-evidence-contract_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0419_vdp-evidence-schema-safety-budget-and-recovery-foundation_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0420_vdp-capability-driven-hypothesis-generation-shadow-workflow_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0421_vdp-evidence-gap-driven-verification-and-safe-follow-up_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0422_vdp-canonical-evidence-reporting-and-separated-quality-gates_subtask_plan.md
- docs/shigoku/worklogs/2026-08-04_sgk-2026-0423_vdp-hidden-holdout-evaluation-shadow-rollout-and-recovery_work_log.md
- docs/shigoku/subtasks/2026-08-05_sgk-2026-0424_vdp-m3a-readonly-pilot_subtask_plan.md
title: VDP hidden holdout evaluation shadow rollout and recovery 作業完了報告（オフライン実装フェーズ）
created_at: '2026-08-04'
updated_at: '2026-08-07'
tags:
- shigoku
target: tests,src/core/models,src/core/engine,src/reporting,config
deferred_tasks:
  - deferred_id: SGK-2026-0423-D01
    title: "実VDPまたは承認済み評価データセットでのM4全面運用検証"
    reason: "SGK-2026-0423は完了済み。M4はm3b/m3cの進級記録が揃った後のrollout判断であり、将来段階の追跡事項"
    impact: high
    tracking_task_id: SGK-2026-0424
    recommended_next_action: "SGK-2026-0424（承認済みVDPでのM3a読み取り専用パイロット）の結果を踏まえ、許可済み環境のM4全面運用と進級gateを検証する"
  - deferred_id: SGK-2026-0423-D02
    title: "WALとcheckpointの多重喪失時のwrite-ahead保証強化"
    reason: "SGK-2026-0423は完了済み。送信前durable WALとin_flight→Hold・自動再送禁止は実証済み。多重障害時のjournal化は将来段階の追跡事項"
    impact: low
    tracking_task_id: SGK-2026-0424
    recommended_next_action: "SGK-2026-0424のパイロットで安全境界（二重送信防止）を運用確認し、write-ahead journal化は後続タスクで設計・検証する"
---

# 作業完了報告書：SGK-2026-0423（オフライン実装フェーズ + 隔離検証フェーズ）

## 1. 最終状態

**DONE（2026-08-04 確定）**。固定済み計画書の全完了条件がPASSし、in_scope_blocker 0件。

**隔離検証フェーズ（2026-08-04 追記）**: Docker Compose 3コンテナ（fixture-target / shigoku-runtime / holdout-evaluator）によるM3a read-only検証を実施。runtime 1回・evaluator 1回・POST 0件・consistency consistent・real gate go を実物artifactで確認。静的fixtureによるholdout評価は outcome=hold であり、**完了条件6は「ランダム不透明URL holdout環境」（下記§9）で達成**。

**最終クローズ（2026-08-05 追記、§9）**: ランダム不透明URLのcross-account holdout環境で holdout評価 **outcome=pass**（recall 1.0 ≥ 0.5 / evidence_completeness 0.333 ≥ 0.2 / leakage 0、凍結閾値iso-v2）。runtimeは技術的にholdoutを読めず（コンテナ内でENOENT実証）、runtimeソースに固有URL・ground truthなし。**完了条件1・6がPASS → DONE**。M4は未有効化（effective m3a、m4=hold: progression/rollout延期）。

## 2. 監査指摘への対応（第1回7項目 + 第2回4項目、すべて本番経路で修正）

### 第1回（完全解消3 / 部分解消4 → 第2回で完全解消）

| 指摘 | 修正 | 本番経路の証拠 |
|---|---|---|
| M3b-M4が本番設定から到達不能 | 進級証拠ベースのraise経路（enforce mode + 全先行stage progression合格 + m4はfrozen threshold必須。mode=off絶対） | `TestProductionRaisePath` |
| rollout状態破損時に安全側へ停止しない | 破損時 effective M0 + `rollout_state_unreadable`（通信禁止） | `TestCorruptRolloutStateFailClosed` |
| holdoutが実隔離していない | owner≠runtime uid強制 + runtime読取API常時拒否 + コンテナ読取チャネル | `test_real_permission_denied_from_runtime`（実EACCES） |
| holdout評価が正解ラベル不使用 | ground_truth突合のrecall/false_promotion_rate（host非依存） | `test_recall_matches_ground_truth` 等 |
| FileKeyProviderが所有者・権限未検査 | lstat/所有者/権限0o077検査（fail-closed） | `TestFileKeyProviderHardening` |
| executorがmark_sent未呼出・M3b実経路なし | 認可済み単一送信 + 送信直後mark_sent + 再送阻止 | `test_vdp_m3b_executor.py` 8本 |
| artifact・drill不足、報告なし | 追加drill 8本 + artifact一式 + work report/log | `test_vdp_drill_extended.py` |

### 第2回（部分解消4項目の完全解消）

| 指摘 | 修正 | 証拠 |
|---|---|---|
| M4がGo証拠なしで有効化される | `_m4_go_evidence_ready()`: holdout結果(outcome=pass・eval_version一致・artifact hash再計算一致) + holdout段階のdecision record(go) + real gate結果(decision=go・終了状態既知・consistency pass) を全て要求。未達は理由別cap_reasonsでm3cへ | `TestM4GoEvidenceGate`（12本。手書きprogression+thresholdのみではm4到達不可を実測） |
| HITLチケットが通常経路で渡らない・文字列だけで承認される | `_vdp_hitl_tickets_from_ledger`: 実HITL台帳から承認済み・対象(next_action_id)一致・有効なチケットのみ解決（`hitl_tickets=`パラメータはproductionから削除）。executorは `hitl_ticket_validator` callbackで検証（台帳なし・不一致・任意文字列は拒否） | 台帳ベースqueueテスト + `hitl_ticket_invalid`/`m3b_not_authorized` |
| プロセスクラッシュ跨ぎの非再送未保証 | `StateChangeJournal`（`<checkpoint>.wal.json`）: **送信前に** durable `begin`(in_flight) → 送信後 `mark_sent`/`mark_failed`。復旧時: in_flight → `state_change_outcome_unknown`（Hold記録、自動再送禁止）、sent → `state_change_already_sent`。checkpointなしの状態変更は `state_change_journal_unavailable` で拒否 | `test_vdp_state_change_journal.py` 12本 + drill 15（crash復旧で再送0） |
| untested_rateの閾値方向が逆 | `ThresholdMetric.direction`（minimum/maximum明示、legacy fallback付き）。実artifactで untested_rate=0.0 vs 上限0.5 → **met=True** を確認 | `TestThresholdDirection` |
| 実artifactが計画書条件未達 | run_health=succeededのsession・方向付きthresholds・メタデータ付きholdout結果・**実レポート生成**（separated 3ファイル+manifest）・公式consistency checker **consistent**・real gate **decision=go（run_state=succeeded）**・鍵ライフサイクル証跡（配布/rotation/verify-only/revoke/復旧）・holdout段階decision record | 下記§4 |

### 第3回（in_scope_blocker 2件の完全解消）

| 指摘 | 修正 | 証拠 |
|---|---|---|
| M4がholdout結果と凍結閾値を完全に結び付けていない（eval_versionのみ比較、fingerprint未照合、判断記録未検証、古いGoを採用しうる） | `_m4_go_evidence_ready()`: (1) **現在のthresholds fingerprint ≒ holdout結果の`threshold_fingerprint`一致必須**（`m4_threshold_fingerprint_mismatch`。同一eval_versionでの後付け調整をgateが拒否）、(2) 判断記録は**最新エントリ（recorded_at順）のみ採用**: decision=go・eval_version==thresholds.eval_version・**artifact_hash==holdout結果hash**（`m4_decision_eval_version_mismatch` / `m4_decision_artifact_hash_mismatch`）。**古いGoの後にHold/No-Goがあれば不採用** | `TestM4GoEvidenceBinding`（8本: 監査の実測ケース「評価後・同一eval_versionで閾値変更→fingerprint不一致→m3c以下」を再現）。**実artifactで実測: effective_stage=m3a**、cap_reasons=[m4_holdout_outcome_not_pass, m4_decision_record_not_go, m4_requires_progression] |
| WALが送信済み状態変更を「未送信」に戻す（executed以外一律mark_failed → 送信済み+証拠保存失敗でnot_sent化 → 再送の可能性） | `FollowUpExecutionResult.state_change_sent`（**mark_sent呼出=HTTP送信完了の事実**）を追加し、`_journal_transition_after_dispatch` で**送信事実ベース**の遷移へ: sent→`mark_sent` / **通信開始前に確定した拒否（blocked・manual_review）のみ**`mark_failed` / 不明はin_flightのままHold（`state_change_outcome_unknown`、not_sentへ戻さない） | `test_evidence_writer_failure_marks_state_change_sent` + **drill 16**（送信成功→evidence_write_backpressure→WAL=sent→**新MCで再開→blocked state_change_already_sent・新MC通信0件**）+ drill 17（in_flight復旧→Hold・再送0） |

### 第4回（in_scope_blocker 1件の完全解消）

| 指摘 | 修正 | 証拠 |
|---|---|---|
| WALがnetwork_errorを「確実に未送信」と判断してnot_sent化（応答喪失=通信先で変更完了済みのケースで再送発生: remote_applied=1→新プロセスが再送） | `_journal_transition_after_dispatch` の決定表から `reason=="network_error"` を `mark_failed` 条件から**除外**。**network_errorは応答喪失の曖昧性により送信結果不明** → WALは **in_flightのまま**、`state_change_outcome_unknown` でHold（復旧は自動再送禁止）。`mark_failed` は**通信開始前に証明可能な拒否**（kill switch・readonly guard・scope・fingerprint・admission・idempotency・budget/concurrency・prevent_double_send等: blocked/manual_review）に限定 | **drill 18**（監査の実測ケース: `_RemoteAppliedThenTimeoutNet` で remote_applied=1→network_error→WAL=**in_flight**（not_sentではない）→checkpoint保存失敗→**新MC再開→blocked state_change_outcome_unknown・新MC通信0件・Hold判断記録**）+ `TestJournalTransitionDecisionTable`（network_error→in_flight / blocked・manual_review→not_sent / sent-fact→sent） |

## 3. 実装内容（レーン別・Wave 1〜3）

- **設定層（orchestrator）**: `VdpModeSettings` に stage/stage_flags/key_*/progression_records_path/thresholds_path/rollout_state_path/**holdout_result_path/decision_records_path/gate_result_path** を追加。`VDP_STAGES`/`derive_stage_from_mode`/`is_enforce_stage`/`min_stage` を共有真理として設定層に配置。
- **Wave 1**: 鍵ライフサイクル（registry/provider/鍵ファイル検査）/ 評価データ境界（manifest/OS隔離/正解ラベルrunner）/ 段階導入（rollout gate/rollback/shadow diff）/ drill 14本+実経路6本 / canonical shadow_diff passthrough。
- **Wave 2**: M3b-M4進級証拠raise / holdout OS隔離+ground_truth指標 / FileKeyProvider検査 / executor M3b実経路+mark_sent / 追加drill 8本。
- **Wave 3**: M4 Go証拠gate（holdout pass・decision go・gate go・consistency・hash照合）/ 閾値方向 / real gate unknown→Hold / HITL台帳解決+validator / write-ahead journal（crash跨ぎ非再送）。

## 4. 実artifact（`workspace/projects/vdp-eval-0423/`、全てオフライン・fake transportのみ）

| artifact | パス | 内容 |
|---|---|---|
| オフラインsession | `sessions/session_20260804_vdp_0423_offline.json` | 実MC hook+fake transport、M0 gate PASS、**run_health=run_state:succeeded**、hypotheses=3/attempts=1/evidence=1/verdicts=3/shadow_diff=4、input_hash+artifact_hash付き |
| 実レポート | `reports/haddix_20260804_154630_{submission,internal}.md` + `internal.json` + `manifest.json` | production formatter（separated 3ファイル+manifest検証）で生成 |
| consistency | 公式checker実行 | **status: consistent, reason_codes: [], rerun_required: False** |
| frozen thresholds | `eval/thresholds_v1.json` | eval_version=vdp-eval-2026-08-04-1、**direction明示**（recall=minimum, false_promotion_rate/untested_rate=maximum）。holdout閲覧前に凍結 |
| holdout labels | `eval/holdout/labels.json` | root所有0700/0600。runtime読取は実測PermissionError。評価はコンテナチャネル |
| progression records | `eval/progression_records.json` | m0〜m3a passed（オフラインdrillスイート合格証拠） |
| holdout評価結果 | `eval/holdout_result_v1.json` | outcome=**hold**（recall 0.0: オフラインconfirmed 0）、**untested_rate met=True**（方向修正の実証）、leakage 0、**code_version/config_version/feature_flags/input_hash/termination_state付き**、hash照合で再主張不可 |
| 判断記録 | `eval/decision_records.json` | m0/m1/m2/m3a=**go**、**holdout/m3b/m3c/m4=hold**（理由: holdout_outcome:hold / real_state_change_communication_not_authorized 等。M4はGo証拠未達を明示） |
| real gate結果 | `reports/gate_real_20260804.json` | `shigoku-ops vdp gate --profile real` → status=pass / **decision=go / run_state=succeeded**（M4証拠チェックでm4_gate_termination_unknownは解消） |
| 鍵ライフサイクル証跡 | `eval/key_lifecycle_evidence.json` | 配布(register)→rotation(A→verify_only)→旧artifact検証OK→revoke(B拒否)→復旧(新active C)。**秘密鍵は一切含まず**（公開指紋・状態・時刻のみ） |

## 5. 検証コマンドと実測結果

| コマンド | 結果 |
|---|---|
| VDP全対象スイープ（engine/reporting/config/scripts/main 37ファイル） | **1067 passed** |
| `verify_report_session_consistency.py --report <internal.md> --session <session>` | **consistent / reason_codes: [] / rerun_required: False** |
| `shigoku-ops vdp gate --profile real` | status=pass / decision=go / run_state=succeeded |
| **実artifactでのM4 gate実測**（`VdpRolloutGate` + 実artifactパス設定） | **effective_stage=m3a** / cap_reasons=[m4_requires_progression, m4_holdout_outcome_not_pass, m4_decision_record_not_go] — M4は安全側で維持 |
| 第1〜4回監査対応テスト | 全グリーン（L-1: 101 / L-2: 50 / L-3: 34 実測） |
| docker OS境界negative test | RUN・PASS（実EACCES） |
| `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` | 全0エラー |
| `git diff --check` + 新規ファイルno-index check | 0 error |
| `graphify update .` | exit 0 |

## 6. 隔離検証フェーズ（Docker Compose、2026-08-04）

### 6.1 構成（`tests/fixtures/vdp_isolated_env/`、使い捨て）

| コンテナ | 役割 | ネットワーク |
|---|---|---|
| fixture-target | stdlib HTTPサーバー: /readonly-ok(200) /items/<id>(200) /rate-limited(429) /server-error(500) /slow(30s) /redirect-out-of-scope(302→127.0.0.1:9) /search?q=(200)。**POST/PUT/PATCH/DELETEは全て405**。アクセスログ出力 | iso（internal: true、外部egressなし） |
| shigoku-runtime | production-path M3aドライバ（`runtime_driver.py`）: 実`AsyncNetworkClient`・実MC VDP hook・read-only crawl→仮説生成→follow-up dispatch→session保存→M0 gate。**holdoutラベルをmountしない** | iso（internal） |
| holdout-evaluator | 一回限りジョブ（`evaluator_job.py`）: holdoutラベル（read-only mount）＋凍結閾値＋runtime session→評価→匿名化結果保存 | network_mode: none（runtimeから到達不能） |

### 6.2 A〜D in_scope_blocker候補の検証結果

| 項目 | 結果 | 根拠 |
|---|---|---|
| A. holdout隔離 | 解消 | OS境界（owner≠runtime uid、実EACCESテスト）、runtimeコンテナにholdout非mount、evaluatorのみread-only mount＋network none、評価結果は匿名化（ID/件数/種別/閾値hash/PASS-FAILのみ）、漏洩rg検査0件（`holdout-internal.example` / `holdout-payload-token-xyz` / `holdout-product-name` がruntime out/logs/resultに存在しないことを確認） |
| B. 閾値固定とM4拒否 | 解消 | 閾値は評価前にhost側で凍結（fingerprint 9706f9cd…）。**同一eval_versionでの閾値改変はEvalVersionMismatchで拒否（実測）**。M4はISO artifactで **effective_stage=m3a**（m4_holdout_outcome_not_pass / m4_decision_record_not_go / m4_decision_eval_version_mismatch / m4_decision_artifact_hash_mismatch 等6理由）。M4実運用は有効化していない |
| C. 鍵ファイル権限 | 解消 | FileKeyProvider（lstat/所有者/0o077/通常ファイル）、registry権限検査、revoked/unknown/outage fail-closed、秘密鍵非出力（コンテナ内鍵ファイルは0600） |
| D. failure drill網羅 | 解消 | ユーザー列挙18カテゴリを既存26 drill＋journal/m3b/scopeテストでカバー（429/500/timeout/遅延、browser/OOB/proxy/auth停止、redirect/derived/OOB scope変更、queue飽和/disk full/部分書込/hash不一致、interrupt/resume、malformed LLM/無限仮説/重複follow-up、state-change送信前、legacy session、formatter/backfill、kill switch、key rotate/revoke/outage） |

### 6.3 実行実測（コンテナ、全rc=0）

- runtime: M0 gate **pass**、hypotheses=7、attempts=2、evidence=1、verdicts=**confirmed 0 / candidate 7**、executed=[/rate-limited]、degraded=[/slow:network_error]、**fixture_log_non_get=0**
- fixtureアクセスログ: **30行全てGET（NON_GET=0）**
- evaluator: **outcome=hold**（正直）、leakage=0、metric別: recall 0.0<0.5 unmet・evidence_completeness 0.143<0.2 unmet・funnel 0.286≥0.2 met・untested 0≤0.5 met・fp 0≤0.2 met・budget 1.0≥0.8 met
- 実レポート（separated 4ファイル）→ `verify_report_session_consistency.py`: **consistent / reason_codes: [] / rerun_required: False**
- `shigoku-ops vdp gate --profile real`: status=pass / decision=**go** / run_state=degraded（/slowのnetwork_errorを正直に記録した上での判定。termination gateはfail表示）
- 判断記録: `iso/out/eval/decision_records.json` — m0/m1/m2/m3a=go（隔離M3a実行証拠）、holdout/m3b/m3c/m4=hold
- 閾値上書き試行: 同一eval_versionでrecall閾値を0.5→0.1に改変→**EvalVersionMismatchで拒否（実測）**

### 6.4 固定完了条件の監査表（隔離検証フェーズ終了時）

| 完了条件 | 判定 | 根拠 |
|---|---|---|
| 1 アクセス境界＋漏洩0 | PASS | OS境界実EACCES・runtime非mount・漏洩rg 0件 |
| 2 閾値固定・後付け調整なし | PASS | 評価前凍結・fingerprint照合・tampered拒否実測 |
| 3 M0-M3必須test+drill合格、M4 Go/Hold/No-Go根拠保存 | PASS | 26 drills＋全テスト合格、ISO decision records（m4=hold） |
| 4 scope逸脱/secret漏洩/二重状態変更/理由不明confirmed 0 | PASS | POST=0・漏洩0・WAL/drill 15-18・confirmed 0 |
| 5 kill switch/rollback/中断再開/旧artifact互換 | PASS | 両点kill・rollback・drill 9/10・回帰 |
| 6 特定製品・既知URL・既知payload・既知challengeを使わず評価に合格 | **FAIL（未達）** | holdout outcome=hold（recall 0.0<0.5）。評価プロセスは製品非依存で完走（leakage 0・凍結閾値・real gate go）だが、holdout PASSは未達。隔離M3a環境ではconfirmedが構造的に発生しない（全capabilityのrequired_evidenceが観測不能トークン: authz_impact_not_proven / semantic_diff / state_change_readback / untested_no_second_account 等を含む） |
| 7 鍵配布・最小権限・再起動検証・rotation・revoke・outage fail-closed 実artifact | PASS | key_lifecycle_evidence.json・鍵テスト群・コンテナ内0600鍵 |
| 8 秘密鍵露出0・未知/失効鍵受理0 | PASS | rg 0件・fail-closedテスト群 |

**in_scope_blocker: 1件（完了条件6、strict reading）→ 本タスクはACTIVE維持。**

### 6.5 残存（deferred_followup）

- 構造化marker観測レイヤーの実配線（exact-replayの`request_fingerprint_matched`・repeated-controlsの`timing_difference_observed`記録、およびsemantic/cross-account比較follow-upの実装）→ confirmed可能なrunでholdout PASS → M4 Go証拠チェーン完備。
- 許可後の実VDP（または承認済み評価データセット）でのM4検証。

## 7. 未達・残存の整理（最終クローズ後）

- **完了条件6（評価に合格）: 達成（2026-08-05）** — ランダム不透明URL holdout環境（§8）で holdout評価 **outcome=pass**（recall 1.0 ≥ 0.5 / evidence_completeness 0.333 ≥ 0.2 / leakage 0、凍結閾値 iso-v2 = iso-v1と同値）。runtimeは固有URL・ground truth・fixture固有分岐を持たず、cross-account実レスポンス比較（P-1観測レイヤー）からconfirmedを正規経路で生成。
- 計画書§7 step 7（隔離M3a検証）: **実施済み**（§6.3 + §8.2）。step 8（Go/Hold/No-Go記録）: **実施済み**（decision records §8.4、M4=Hold）。
- 静的fixture（`tests/fixtures/vdp_isolated_env/`）はM3a安全試験として温存。holdout評価には**再利用しない**（runtimeがrepo全体をmountする設計のため）。

## 8. 最終クローズ（ランダムopaque holdout環境、2026-08-05）

### 8.1 構成（`tests/fixtures/vdp_holdout_env/`、静的fixtureと完全分離）

| 要素 | 内容 |
|---|---|
| holdout_fixture_target.py | 起動時に**ランダム15-hex不透明URL**を3本生成（1 granted record / 1 denied record / 1 public）+ ランダムアカウント秘密。ground truthとsecretsは**リポジトリ外のmktemp private dir**（`$PRIV`、chmod 700）へ出力。indexはgeneric anchorのみ（resource-1..3）。POST/PUT/PATCH/DELETEは405 |
| holdout_runtime_driver.py | **route非依存**（"records"/"/public"/"owner"リテラルなし — source scanで検証）。indexをGET→リンク発見→generic観測。アカウントIDはenv（`VDP_ACCOUNT_*`）、秘密はenvのみでspec/sessionに非含有。run_health=succeededを正直に記録 |
| holdout_evaluator.py | network_mode: noneの特権reader。ground truth（evaluatorのみ保持）からlabelsを構築（probeは派生値）。run_holdout_evaluation → 匿名化result保存 |
| docker-compose.yml / run_holdout_eval.sh | runtimeは**src/config/.venv/uv-python/driver/private out/logs のみmount**（tests/・labels・secretsは非mount）。iso2 internal network。evaluatorはnetwork: none。secrets/logsは`$PRIV`（repo外） |
| master_conductor.py | `_vdp_account_credentials()`（env由来、未設定は{}）、比較対象gapのspecへ`auth_a_id`/`auth_b_id`付与、executorへ`account_credentials`配線 |
| vdp_follow_up_executor.py（P-1） | cross-account比較観測レイヤー: A/B 2回の認証GET→status+key-sort JSON比較→**実観測からのみ**marker（authz_impact_proven / semantic_diff_observed / second_account_compared）。denied/public/比較不能はmarkerなし（candidate）。秘密はsend時のみ解決・never記録 |
| CLI（additive） | `verify_report_session_consistency.py` / `shigoku-ops vdp gate` に `--vdp-key-registry`（公開鍵のみ・engine importなし）。providerなしはfail-closed（confirmed未検証扱い） |

### 8.2 実行実測（コンテナ、全rc=0）

- runtime: M0 gate **pass** / hypotheses=3 / attempts=3 / verdicts=**confirmed 1 / candidate 2** / requests=6（比較×2）/ **non_get_violations=0 / fixture_log_non_get=0**（不透明URL 3本をindexから発見、分岐なし）
- **隔離実証（runtimeコンテナ内コマンド）**: `cat /secrets/secret.json` → **No such file or directory**（secrets非mount）、`ls /repo/tests` → **No such file or directory**（tests非mount）、`/repo` = config/holdout_runtime_driver.py/src のみ
- evaluator: **outcome=pass** / leakage=0 / gaps=[] / metrics: **recall 1.0 ≥ 0.5 met** / evidence_completeness 0.333 ≥ 0.2 met / untested 0 ≤ 0.5 met / fp 0 ≤ 0.2 met / funnel 1.0 met / budget 1.0 met / threshold_fingerprint+artifact_hash記録
- 漏洩検査: session/report/result/logに認証値・product probe・ground truth **0件**（"acct-a"は観測応答ボディ内の所有者帰属 — runtime観測でありholdout正解ではない）
- **閾値固定**: iso-v2（iso-v1と**同値**、eval_versionのみ新規）を評価前に凍結。同一eval_version改変 → **EvalVersionMismatch拒否（実測）**
- consistency（CLI + `--vdp-key-registry`）: **consistent / reason_codes: []**
- `shigoku-ops vdp gate --profile real`: status=pass / **decision=go** / run_state=succeeded / confirmed=1
- **M4: 未有効化** — `VdpRolloutGate`実測: effective_stage=**m3a**（m4_requires_progression: m3b/m3cの進級記録なし。rollout延期をm4=holdで記録）

### 8.3 完了条件監査（最終）

| 完了条件 | 判定 | 根拠 |
|---|---|---|
| 1 アクセス境界＋漏洩0 | **PASS** | コンテナ内ENOENT実証（/secrets・/repo/tests非mount）、leakage 0、認証値・probe 0件 |
| 2 閾値固定・後付け調整なし | **PASS** | iso-v2事前凍結（iso-v1と同値）、fingerprint照合、tampered拒否実測 |
| 3 M0-M3必須test+drill合格、M4 Go/Hold/No-Go根拠保存 | **PASS** | 全スイープ1090 passed、decision records（holdout=go / m4=hold） |
| 4 scope逸脱/secret漏洩/二重状態変更/理由不明confirmed 0 | **PASS** | POST=0・non_get=0・WAL drill群・confirmed 1はproof検証済み（registry） |
| 5 kill switch/rollback/中断再開/旧artifact互換 | **PASS** | 前フェーズ実証＋回帰維持 |
| 6 製品固有情報なしで評価に合格 | **PASS** | **ランダムopaque holdoutでoutcome=pass**（recall 1.0・completeness 0.333・leakage 0）。runtimeに固有URL/payload/製品名なし、ground truthはevaluatorのみ |
| 7 鍵配布・最小権限・再起動検証・rotation・revoke・outage fail-closed 実artifact | **PASS** | key_lifecycle_evidence.json＋鍵テスト群＋コンテナ内0600鍵・registry |
| 8 秘密鍵露出0・未知/失効鍵受理0 | **PASS** | rg 0件・fail-closedテスト群・公開registryのみ耐久保存 |

**in_scope_blocker: 0件 → DONE確定。** M4は未有効化のまま（m3a、進級証拠なし）。

### 8.4 保存artifact（`workspace/projects/vdp-eval-0423/holdout2/`）

- `sessions/session_vdp-holdout-1785859506.json`（M0 PASS、confirmed 1 / candidate 2、run_health=succeeded）
- `reports/haddix_20260805_010525_{submission,internal}.md` + `internal.json` + `manifest.json`
- `eval/thresholds_v1.json`（iso-v2、iso-v1と同値）・`eval/holdout_result_iso.json`（outcome=pass・fingerprint/hash）・`eval/key_registry.json`（公開鍵のみ）・`eval/decision_records.json`（m0-m3a go / holdout go / m3b-m4 hold）・`eval/run_summary.json`
- `reports/gate_real_holdout2.json`（status=pass / decision=go / run_state=succeeded）
- secrets・ground truth・アカウント秘密はrepo外（$PRIV、実行後trap削除済み）

## 9. 残存リスク

- WALは送信前のdurable記録でcrash跨ぎの非再送を保証（in_flightはHold）。journalとcheckpointの両方が失われる多重障害時の保証は次段階の追跡課題。
- オフライン評価のrecall=0.0は「オフラインではconfirmedが生じない」fail-closed設計の当然の帰結であり、能力欠如を意味しない（実VDP検証は未実施）。
- 既存失敗2件（`tests/core/test_config_yaml.py` のEvidenceモデル起因2件）はdirtyツリー既存で本タスク差分外。
