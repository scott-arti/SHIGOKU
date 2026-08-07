---
task_id: SGK-2026-0426
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/subtasks/done/2026-08-05_sgk-2026-0425_vdp-causal-attack-funnel-diagnosis_subtask_plan.md
- docs/shigoku/subtasks/2026-08-05_sgk-2026-0424_vdp-m3a-readonly-pilot_subtask_plan.md
- docs/shigoku/plans/done/2026-07-31_vdp-capability-benchmark-and-evidence-contract_plan.md
title: VDP product-independent improvement loop and hidden re-evaluation readiness
created_at: '2026-08-05'
updated_at: '2026-08-07'
tags:
- shigoku
target: proven-cause-driven generic improvement, unseen hidden-holdout re-evaluation,
  and diagnostic readiness handoff to the M3a pilot
---

# 実装計画書：VDP proven原因ベースの一般改善と、新規hiddenでの再評価・readiness引き渡し

## 0. 本タスクの位置づけ（SGK-2026-0425からの分割）

本タスクは SGK-2026-0425 から切り出した後続タスクである。0425は「攻撃ファネルのどこで・なぜ落ちたか」を再現可能に診断する**基盤の構築と診断結果の産出**（M0–M5）までを完了契約とする。本タスクは、その診断が `proven` とした原因だけを入力に、**製品非依存の一般改善**を行い、**新規hidden generic holdout**で改善を検証し、SGK-2026-0424へ `diagnostic_readiness=go|hold` を引き渡す。

分割の理由: 診断基盤の正しさ（0425）と、実際の品質改善が hidden holdout の floor を満たすまで完了できない open-ended な改善ループ（本タスク）を1つの完了契約に束ねると、`rules/lessons.md [2026-08] CRITICAL` が警告する「将来段階のhardeningを現タスクのblockerへ昇格させ続ける endless moving target」に陥る。基盤の受け入れ判定と改善の受け入れ判定を別契約に分離する。

## 1. 達成したいゴール

- [ ] SGK-2026-0425が出力した `proven`（単一変数反証で再現）原因だけを改善対象にし、`supported`/`suspected` のまま prompt・model・loop・threshold・routing を変更しない。
- [ ] 各改善は `proven cause -> generic failing test（先に失敗させる）-> 最小修正 -> 未見hidden generic holdoutでの改善delta` の順で因果を証明する。
- [ ] 改善の合否は、外部監査（Juice Shop/DVWA）で使っていない**新seed・新caseのhidden generic holdout**でのみ判定し、両製品の検出件数を完了条件・release gateにしない。
- [ ] 改善による既存VDP回帰・report/session consistency破れ・安全境界違反・製品リークを0件に保つ。
- [ ] SGK-2026-0424へ `diagnostic_readiness=go|hold` とhash付き根拠artifactを引き渡す。Goでも0424固有の許可・scope・予算・kill switchゲートを省略しない。

本タスクの目的も「Juice Shop/DVWAで何件見つけるか」ではない。0425が特定した first-failure の proven原因を、製品情報を含まない一般fixtureで再現・修正し、未見の対象非依存holdoutで一般化を確認することである。

## 2. 前提（0425完了を要する）

- SGK-2026-0425が `done` になり、次のartifactがhash整合込みで存在すること。
  - `first_failure_<run_id>.json`（case別first-failureとconfidence）。
  - `counterfactual_<experiment_id>.json`（`proven` 判定を伴う単一変数反証）。
  - `external_audit_<eval_version>.json`（Juice Shop/DVWAのopaque case別stage診断。固有URL/payloadを含まない）。
  - `product_independence_manifest_v1.json`（clean profile隔離証拠）。
  - `taxonomy_v1.json` と `thresholds_<eval_version>.json`（凍結済み）。
- 0425の完了契約・anti-curve-fitting禁止契約（0425 §6）・データ区分（0425 §6.1）を本タスクでもそのまま継承する。
- 0425の診断が `proven` 原因を1件も出さなかった場合は、本タスクは改善を行わず、readinessを `hold`（理由: `no_proven_cause`）として0424へ引き渡す。0425側の計測改善（telemetry不足の解消）を追跡タスクへ回す。

## 3. スコープ（本タスクで有効化するmilestone）

本タスクは 0425 §8 の **M6 と M7 のみ**を実装・実行対象とする。0425の M0–M5（telemetry、analyzer/CLI、counterfactual harness、generic benchmark基盤、sealed audit）は再構築せず、成果物を入力として再利用する。

### M6: 一般改善と新規hidden再評価

- [ ] `proven` 原因だけを選び、製品情報を含まない generic reproduction test を**先に失敗**させてから最小修正する。1変更=1原因を原則とし、複数原因の同時修正で因果を曖昧にしない。
- [ ] target固有文字列・分岐・閾値変更がないことを source scan と review で確認する（`scripts/check_vdp_product_independence.py`、denylist scan、構造scan）。
- [ ] 外部監査（Juice Shop/DVWA）で使っていない**新seed・新case**のhidden holdoutを新eval versionとして凍結し、改善前後を比較する。閲覧前にthresholdを凍結し1回評価する。
- [ ] 既存VDP全回帰、report/session consistency、safety drill、secret scanを通す。
- [ ] real first-failureが generic grammarで再現できない場合は 0425 §10 の分岐規則（grammar拡張 or C13計測改善）に従い、製品合わせ込みで代替しない。

### M7: readiness決定と文書化

- [ ] 改善ごとに `first failure -> proven cause -> generic failing test -> change -> unseen holdout delta` をwork reportへ記録する。
- [ ] SGK-2026-0424へ `diagnostic_readiness=go|hold` と理由artifact（hash付き）を渡す。Goでも0424の許可・scope・予算ゲートを省略しない。
- [ ] 本計画の固定完了条件だけで最終監査し、計画外hardeningを新blockerへ昇格させず追跡タスクへ送る。

## 3.1 実装契約（SGK-2026-0427実測first-failure対応・W1〜W4＋FO）【ユーザー承認済み・変更不可】

SGK-2026-0427の実測（run_id 9908371a、session_20260806_105634.json、completed_tasks[1].error="PCR-P1: task_queue mutation must be on main thread"）が確定した真因（PCR-P1 thread-confinement: MCタスク実行はSharedLoopManagerのbackground daemon thread上で行われ、`_queue_vdp_follow_ups`（:11383）のtask_queue mutationが `task_queue.py` のPCR-P1 assert（:382/:426/:554/:603/:648）に違反）に基づき、本タスクの改善対象を以下に固定する。すべて**製品非依存**（Juice Shop固有情報を新規コード/config/prompt/recipe/fixtureへ入れない。preflight exit 0維持）。Juice Shop再runは参考回帰であって合格ゲートにしない。

- **W1（C13 telemetry）**: S05 failed event（`master_conductor.py:11702`）へ機構reason codeを付与。thread-confinementに該当する語彙が `taxonomy_v1.json` に無いため、新mechanism `queue_mutation_off_main_thread`（C10配下）を追加し**taxonomy v1→v2 bump**（3ファイル連動: `taxonomy_v1.json` / `vdp_diagnostic_trace.py::DIAGNOSTIC_TAXONOMY_VERSION` / `vdp_counterfactual.py::TAXONOMY_VERSION_V1`）。v1/v2 event混在はreject（既存section検証の等値比較を維持）。redaction-safe（生exception/secret非搭載）・additive・flag-off時no-op維持。
- **W2（C10 proven化→修正・linchpin）**: ①generic再現テスト（実MCのfollow-up enqueue経路をworker thread上で実行しPCR-P1→S05 failedを再現。修正前FAIL→修正後PASS）②単一変数counterfactual（`changed_variable: "thread_confinement"` を `ALLOWED_CHANGED_VARIABLES` へ追加。0425 §4の単一変数マトリクス拡張。2変数変更・hash不一致はattribution不成立で拒否）でC10を supported→**proven** に昇格③修正: **deferred injection buffer + main-thread drain**。`_queue_vdp_follow_ups` はworker側でgate評価・spec構築・pending NextAction checkpoint（constraint H）・thread-safe buffer追記までとし、queue mutationはmain-thread位相（`_apply_post_batch_feedback`（:6686・LB-2契約）／`execute_single_task`（:9090）／resume経路（:15206））の `_drain_vdp_pending_follow_up_injections()` で実行。drain冒頭にPCR-P1同等のmain-thread assert（fail-closed）。**PCR-P1 assertの削除・緩和は禁止**（SGK-2026-0421安全不変条件）。VDP off時は全経路no-opで既存attack task経路bit不変。`__new__`最小インスタンス・hasattr guard尊重。
- **W3（fail-open修正）**: enqueue失敗（attempts=0・follow_up_enqueue_failed）時に、shadow verdict（`generated_candidate`）を正常最終結果として提示しない。`_vdp_state['run_outcome']='follow_up_stage_failed'`＋verdict非final化＋reportへfailure marker（stage・reason・attempts=0明示）＋consistency新reason `vdp_run_failed_not_reflected`（sessionがfailedを保持するのにreportにmarkerが無ければfail-closed。旧sessionはadditive-absent）。`diagnostics.required=true` 時は**プロセスkillでなくHold**（checkpoint保存後、decision trace＋session markerで表現。MCのtask失敗処理と整合、run不正終了なし）。
- **W4（analyzer reach意味修正）**: `CANONICAL_STAGE_MAP` のS09/S10/S11到達に **attempts>0 を要求**（shadow verdictによる偽S11 reachを排除）。first_failure=Sxx のときdownstream_not_reachedがS(xx+1)〜S12（not_applicable除く）を一貫して含む。S12はreport投影層で判定（canonical map外）を明記。製品非依存table test追加。
- **FO flow**: 修正後にfail-openが塞がれたことを FO-1（修正前baseline: attempts=0なのにverdicts 6＋report生成＋consistency PASSを1行で固定）→FO-2（修正）→FO-3（修正後fail-closed検証: 同一fault-injectionでfail-closed assert・report marker必須・healthy path回帰0・`{enqueue ok→normal complete}×{enqueue fail→fail-closed}` matrix test）→FO-4（before/after実出力をwork_reportへ添付。fault-injection実PASSなしに「修正済み」と主張しない）で検証。
- **Readiness**: `diagnostic_readiness` artifact（hash付き根拠）の産出は実施するが、**0424（m3a read-only pilot）のreadiness依存充足は本タスクの完了条件に含めない**（future-stage。0424計画書側へ記載）。

**必須条件4点（実装契約・着手順）**:
1. 【最優先・前倒し証明】drain地点（`_apply_post_batch_feedback` 想定）が真のmain threadであることを、buffer機構実装前に `assert threading.current_thread() is threading.main_thread()` を置いたテストで先に証明する。worker threadならmarshal設計自体が崩れるため、着手直後のgate。
2. W4のreach意味変更は全診断runに波及する。0425 fixture eval（accuracy 1.0）と既存analyzerテストを壊さない回帰テスト必須。
3. taxonomy v1→v2 bumpは3ファイル連動＋v1/v2混在reject。旧session（v1）互換テスト必須。
4. W3のrequired=true時の失敗表現はプロセスkillでなくHold（decision trace＋session marker）。MCのtask失敗処理と整合させ、runを不正終了させない。

## 4. カーブフィッティング禁止契約（0425から継承）

- 本タスクの新規・変更コード、config、prompt、recipe、runtime driverへ製品名、既知URL、既知parameter、challenge名、payload、expected finding countを入れない。
- Juice Shop/DVWAの結果を見て、同じeval versionのthreshold、prompt、recipe、priority、budget、capability mappingを変更して合格を主張しない。
- 特定製品でconfirmed件数が増えたことを、本タスクの成功・VDP準備完了・model優位の根拠にしない。
- 同じ対象へ変更と再実行を反復する最適化loopを作らない。
- 改善後の合否は新seedのhidden generic holdoutで決める。同じJuice Shop/DVWAの再実行は参考回帰であり合格証拠にしない。

## 5. 指標と事前固定threshold

0425 §9 の floor を本タスクの改善評価にも適用する。単一の総合点は作らず、case/capability family/stage単位で分ける。改善評価で特に必須とするのは次のとおり。

- 改善対象stageの `*_reach_macro` が改善前baselineに対して有意に上昇し、他stageの回帰0。
- `false_promotion_rate` = 0%、`safety_violation_count` = 0件、`product_leakage_count` = 0件を維持。
- `regression`（feature flag offの既存session/report、旧reader、gate、attack task出力差分）= 0件。
- thresholdはhidden閲覧前に凍結し、eval versionを更新する。過去resultを再利用しない。

## 6. 必須テスト

1. `proven` でない原因（`supported`/`suspected`/`unattributable`）を改善対象に選べないことを拒否するtest。
2. generic reproduction testが修正前に失敗し、修正後に成功する before/after test。
3. 改善差分に製品名・既知route・probe tokenが0件で、clean profileのimport closure・model-facing context・execution traceに製品固有hitが0件である構造/実行test。
4. 新seed・新caseのhidden genericで §5 floorを満たし、false promotion/safety/product leakageが0のintegration評価。
5. same eval versionのthreshold変更、code/config/prompt/taxonomy hash不一致を拒否するtest。
6. 既存VDP全回帰（canonical extractor、Evidence Validator、separated manifest、report/session consistency、rollout gate）。
7. `diagnostic_readiness` artifactのhash整合と、0424が `go` 以外で通信しないことのhandoff test。
8. real first-failureがgeneric再現不能なとき、製品合わせ込みへフォールバックせず grammar拡張 or C13記録になるtest。
9. drain地点が真のmain threadであることのgateテスト（必須条件1。併せてSharedLoopManager上のタスク本体が非main threadであることも実証し、非対称性を固定）。
10. W2 generic再現テスト（worker threadからのqueue mutation→PCR-P1再現→修正後はdeferred buffer経由main thread drainで成功。drainがmain threadでなければ自身のassertで赤＝自己検証）。
11. C10 counterfactual（`changed_variable=thread_confinement`・単一変数・frozen input hash整合・control/treatment config hash差分は当該変数のみ・repeat≥1・safety非悪化・taxonomy v2）でproven、2変数変更はattribution不成立で拒否。
12. FO-1（修正前fail-open固定: attempts=0＋verdicts 6＋report生成＋consistency PASS）→FO-3（修正後fail-closed・report failure marker必須・healthy path回帰0・`{ok→normal}/{fail→fail-closed}` matrix）。
13. W4 table test（S05 cut＋shadow verdicts→downstreamがS06〜S12全件、attempts>0時のみS11 reach、S03 cut→S04〜S12、full pass→[]、U00→[] 等）。
14. taxonomy v2連動bump・v1/v2 event混在reject・旧session(v1)互換・counterfactual taxonomy_version一致。

## 7. 検証コマンドと合格条件

実装で確定した実ファイル名に合わせて計画書を明示更新してから実行する。

### 7.1 targeted / 回帰

```bash
.venv/bin/pytest \
  tests/unit/reporting/test_vdp_diagnostic.py \
  tests/unit/reporting/test_vdp_counterfactual.py \
  -q

.venv/bin/pytest \
  tests/unit/engine/test_vdp_*.py \
  tests/unit/reporting/test_vdp_*.py \
  tests/unit/main/test_main_report_haddix_vdp_gate.py \
  -q

.venv/bin/shigoku-ops --json validate pytest --suite ops_cli --quiet
```

### 7.2 hidden再評価

```bash
bash tests/fixtures/vdp_diagnostic_env/run_diagnostic_eval.sh
```

合格条件は新seed・新caseのhidden generic holdoutで §5 floor全達成、改善対象stageの上昇、他stage回帰0、false promotion/safety/product leakage 0、manifest/hash一致。Dockerが利用不能な環境では完了扱いにせず阻害要因として報告する。

### 7.3 source・文書・差分

```bash
rg -n -i -f <sealed-product-denylist-path> <changed-production-files>
.venv/bin/python scripts/check_vdp_product_independence.py \
  --manifest <product-independence-manifest> \
  --profile clean-diagnostic \
  --denylist <sealed-product-denylist-path>
python3 scripts/sync_shigoku_updated_at.py
python3 scripts/validate_shigoku_docs.py
git diff --check
graphify update .
```

## 8. 完了条件（固定契約）

1. 改善対象が0425の `proven` 原因だけであり、`supported`/`suspected` 原因での prompt/model/loop/threshold/routing 変更が0件である。
2. 各改善が `first failure -> proven cause -> generic failing test -> change -> unseen holdout delta` の順で因果証拠を持つ。
3. 新seed・新caseのhidden generic holdoutで §5 floorを満たし、改善前後deltaが保存されている。
4. false promotion、scope逸脱、未承認状態変更、secret/product-label漏洩、二重送信、予算超過、既存経路回帰が0件である。
5. 本タスクの新規・変更コードに製品固有情報が0件で、clean diagnostic profileの依存closure・model-facing context・execution traceに製品固有hit/tokenが0件である。
6. SGK-2026-0424へ `diagnostic_readiness` artifact（hash付き根拠）を産出する。実VDP通信は本タスク完了前0件を維持。**0424のreadiness依存充足は本タスクの完了条件に含めない**（future-stage。0424計画書側へ記載）。
7. targeted test、VDP関連回帰、docs validator、git diff checkがすべて成功し、失敗を除外して成功宣言していない。
8. W1〜W4＋FOが§3.1のとおり完了する: S05 failed eventへmechanism reason code付与（taxonomy v2・3ファイル連動・v1互換・v1/v2混在reject）、C10が単一変数counterfactualでproven且つgeneric再現テスト修正前FAIL→修正後PASS、PCR-P1 assert 5箇所（task_queue.py:382/426/554/603/648）無改変、fail-openがFO-1→FO-3でfail-closed実証（healthy path回帰0・`vdp_run_failed_not_reflected` 導入）、analyzer downstream整合table test pass。
9. 新seed・新caseのhidden generic holdoutで§5 floor達成、既存VDP回帰0（0425 fixture eval含む）、preflight前後exit 0、docs validator 0、git diff --check clean。

固定済み完了条件がすべてPASSし、`in_scope_blocker=0`ならdoneにする。改善で新たに見つかった計画外hardeningは追跡タスクへ送り、本タスクの完了条件へ暗黙追加しない。hidden generic threshold未達、label漏洩、誤confirmed、通常経路回帰はin_scope blockerである。

## 9. NOT in scope

- Juice Shop/DVWAのconfirmed件数を増やすこと自体、または両製品だけに対するpass判定。
- 原因がsuspected/supportedのまま prompt、model、loop、threshold、agent routingを変更すること。
- 診断telemetry・analyzer・counterfactual harness・sealed audit基盤の再構築（SGK-2026-0425の範囲）。
- 実VDPへの通信、実ユーザーデータ取得、scope外探索、第三者OOB、未承認状態変更（SGK-2026-0424以降）。
- 製品監査後に同じ対象へ変更と再実行を繰り返す最適化loop。
- 新しい外部scanner、外部dependency、学習済みmodel、教師データ収集基盤の追加。
- 実装責任者、要員配置、工数見積り。

## 10. SGK-2026-0424との関係

- SGK-2026-0424の実VDP通信は、本タスクが `done` になり `diagnostic_readiness=go` artifactがhash整合込みで生成されるまで**実行不可**とする。
- 本タスクのreadinessが `hold` なら、0424は通信せずHold理由を受領する。
- readinessが `go` でも、0424固有のユーザー許可、VDP scope、ProgramCapabilityMatrix、予算、kill switchを別途固定する。
