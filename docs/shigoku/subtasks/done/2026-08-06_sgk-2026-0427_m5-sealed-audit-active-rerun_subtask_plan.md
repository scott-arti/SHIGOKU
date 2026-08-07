---
task_id: SGK-2026-0427
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/subtasks/done/2026-08-05_sgk-2026-0425_vdp-causal-attack-funnel-diagnosis_subtask_plan.md
- docs/shigoku/reports/2026-08-06_sgk-2026-0425_vdp-causal-attack-funnel-diagnosis_work_report.md
- docs/shigoku/subtasks/2026-08-05_sgk-2026-0426_vdp-product-independent-improvement-and-hidden-reevaluation_subtask_plan.md
title: M5 sealed audit active rerun（ローカルJuice Shop・m3a read-only計装実行）
created_at: '2026-08-06'
updated_at: '2026-08-07'
tags:
- shigoku
target: tests/fixtures/vdp_juiceshop_sealed,tests/unit/reporting,config/shigoku.yaml(一時変更),docs/shigoku
---

# 実装計画書: M5 sealed audit active rerun（SGK-2026-0427）

## 0. 位置づけ

SGK-2026-0425（診断基盤、done）の deferred **D01「M5 sealed audit active rerun」** を実施するタスク。診断計装ON（`diagnostics.enabled=true` + `required=true`）で、ローカルの使い捨てJuice Shopコンテナ（http://localhost:3000）へ `python -m src.main --target http://localhost:3000` を**1回**実行し、期待脆弱性ケースごとに「攻撃ファネルの最初の失敗地点（S00〜S12 or U00 or S05 ineligible）→ 原因候補 → confidence」を実測する。実測first-failureは SGK-2026-0426（一般改善）の proven 原因候補入力となる。

- 実VDP（SGK-2026-0424）・第三者・外部宛先へは**一切通信しない**。
- 既存swarm/injection経路（smart_xss等）はS00〜S12非計装であり本タスクの対象外。
- 本タスクの完了契約は0425 §8 M5相当（instrumented active rerunと診断artifact産出）まで。一般改善・hidden再評価・readiness発行は0426。

## 1. 承認済み確定事項（ユーザー承認済み・変更不可）

- (a) 代表脆弱性セット6件を sealed labels として承認。artifactへは `opaque_case_id` のみ。固有endpoint/payload/製品名は evaluator 境界外へ出さない。
- (b) **stage = m3a のみ**（mode=`readonly_enforce` + stage=`m3a`、read-only GET）。
  - **progression records の手書き生成によるm3b昇格は却下**。署名検証のない記録でenforce gateを開けることはfail-closed rollout gateの偽装であり規律違反。progression記録の捏造・validation緩和は一切行わない。
  - POST系3件（OPAQUE-AUTH-01 / OPAQUE-IDOR-01 / OPAQUE-PRIV-01）はm3aでは実行せず、**S05 ineligibleとして母数・理由付きで正直に記録**（0425 §3.1「capability gateによる正当拒否は検出不良と数えない」）。完了阻害にしない。
  - read-only系3件（OPAQUE-XSS-01 / OPAQUE-DATA-01 / OPAQUE-AUTH-02）を S00〜S12 で完全実測。
  - 将来POST系を実測する場合は、m0〜m3aを実runで正当に通し本物のprogression記録を獲得してからm3bへ上げる別フェーズ（本タスク外・別起票）。
- (c) egress = 「隔離network上で、対象(127.0.0.1:3000)以外はLLM provider宛TCPのみ許可、他は全DENY」。許可リスト（LLM provider host/port）をrun設定artifactに明示固定し、DENYログ・許可外接続試行0を実ログで証明。target由来データがLLM(Anthropic)へ出ることはローカルJuice Shopに限り許容（実VDP・実顧客データでは不可）。`daily_llm_budget(25)` 内であることをrun前後で確認。
- その他隔離契約（host secret mount 0、test account 2つをenv注入しsession/log非出力、per-case docker rollback、実行1回）は監査§5のとおり。

## 2. sealed case set（evaluator-only・6件）

`tests/fixtures/vdp_juiceshop_sealed/labels/expected_path_cases_v1.json` にgeneric ExpectedPathCaseV1として定義済み（製品tokenなし・DAG検証済み）。全ケースが線形 stage DAG（S00→S12、depends_on連鎖）を持つ。

| opaque_case_id | capability family | actor | action class | m3aでの扱い |
|---|---|---|---|---|
| OPAQUE-AUTH-01 | auth_bypass_injection | anonymous | state_changing | **S05 ineligible** |
| OPAQUE-IDOR-01 | object_level_authz | A(owner)/B(non-owner) | read+state_changing | **S05 ineligible** |
| OPAQUE-PRIV-01 | access_control_escalation | A(low)/B(high) | read+state_changing | **S05 ineligible** |
| OPAQUE-XSS-01 | client_side_injection | anonymous | read_only | S00〜S12実測 |
| OPAQUE-DATA-01 | sensitive_data_exposure | anonymous | read_only | S00〜S12実測（S10 optional） |
| OPAQUE-AUTH-02 | token_trust_boundary | anonymous+A | read_only | S00〜S12実測 |

## 3. 実行設定（ステップ2でユーザーへ提示し最終GO後に固定）

- VDP mode: `readonly_enforce` / stage: `m3a`（progression records不要。m3aはPROGRESSION_STAGES外）。
- **アプリmode: `vulntest`（実適用）**: bugbounty modeはcompiled guard policy必須（bundle無しはfail-closed `policy_unavailable`で全通信block）。ローカル使い捨て対象用のbundleは存在せず、**guard policyを捏造しない**（progression records捏造拒否と同一規律）。vulntestはbundle無しlab対象の正規mode（`network_client.py:344` はbugbountyのみguard評価、settings.py:835がvulntest/ctfのbundle無しを明示サポート）。scope enforcementはVDP admission/scope再検証＋ハーネスネットワーク隔離が代替保証。
- **Caido entry gate**: 実Caidoは環境に無いため、公式 `SHIGOKU_SKIP_ENTRY_GATE=1` でmain-level gateをskipし、MCセッション開始gateは**harness Caido stub**（identity probe応答のみ・トラフィックは一切経由しない・scan.proxyは空のまま）で通過。proxying機能は内部network＋allowlist proxy＋ログが代替保証。
- capability_rules: `follow_up_probe: allowed` のみ。unknownはprohibited（fail-closed維持）。OOBはmatrixに含めない。
- ExecutionBudget: engine既定値（max_requests=1000 / max_follow_ups=50 / max_retries=3 / max_concurrency=10 / max_runtime_seconds=3600 / per_asset_burst=50 / per_actor_burst=30 / per_hypothesis_burst=20 / cooldown 60s）＋harness timeout 3900s＋`max_concurrent_tasks: 4`。
- egress allowlist: LLM provider宛host/portのみ（run設定artifactに固定）。
- kill switch 3層: ①`diagnostics.required=true`のhook失敗→次通信前に停止・checkpoint・Hold（既存実装）②harness監視（scope外/予算超過/二重送信/timeout→SIGTERM+checkpoint）③手動kill。
- per-case rollback: run前 `docker commit` スナップショット → ケース間リセットはスナップショットimageから再生成（製品固有パス不使用）。
- 実行回数: eval version v1につき1回。
- config一時変更: run前snapshot(sha256) → run後に**作業ツリー状態へ厳密復元**（HEADへ戻さない、reset/checkout/revert禁止）→ `vdp.mode: off` / `diagnostics.enabled: false` の既定bit復帰をgit diffで確認。

## 4. ハードゲート（fail-closed）

通信開始条件3点が揃うまでJuice Shopへ通信0:
1. preflight `check_vdp_product_independence.py`（clean-diagnostic）exit 0
2. run設定（mode/stage/capability matrix/budget/egress allowlist/kill switch）の固定＋**ユーザー最終GO**
3. config/shigoku.yaml 一時変更のsnapshot取得

runtime code/config/prompt/recipe/driver にJuice Shop固有token 0（preflight前後exit 0で証明）。sealed casesは `tests/fixtures/vdp_juiceshop_sealed/` 配下でruntime import closure・model-facing contextから到達不能。redirect/OOB先は各通信直前に再検証しfail-closed。

## 5. 完了条件（m3a版・固定契約）

1. 6 opaque case全てが first-failure stage（S00〜S12）または U00 または S05 ineligible を持ち、trace_coverage 100%（ineligible 3件は母数・理由記録で充足。blockerにしない）。
2. read-only 3件が instrumented session の `vdp_diagnostics_v1` events から S00〜S12 で算出され、S12はcanonical summary＋公式report/session consistency（consistent）で判定。
3. report/session consistency = consistent。secret/scope逸脱/未承認state変更/二重送信/予算超過/egress違反 = 0、実行回数=1、preflight前後 exit 0、config既定bit復帰、docs validator 0。
4. 産出: `first_failure_juiceshop_v1.json`（opaque case別：first-failure stage・reason_codes・cause_candidates・confidence・evidence_refs・missing_artifacts・downstream_not_reached）＋ `external_audit_v2.json`（opaque case/stage/reason/confidenceのみ、製品情報なし）。0426へ cause_candidates＋confidence を proven化候補として引き渡し。
5. 期待ケースがVDP経路で拾えない（S03等で脱落）場合はそれ自体を一次診断結果として記録。generic再現不能時は0425 §10分岐（C13/telemetry_or_grammar_gap、製品合わせ込み禁止）。
6. work_reportが各opaque caseを first-failure → cause candidate → confidence の順で説明し、未実行・FAIL/UNKNOWNを成功扱いしない。

## 6. 検証コマンド

```bash
# 通信0実装段階
.venv/bin/pytest tests/unit/reporting/test_vdp_juiceshop_sealed_cases.py tests/unit/reporting/test_vdp_diagnostic.py -q
.venv/bin/python scripts/check_vdp_product_independence.py --manifest config/diagnostics/product_independence_manifest_v1.json --profile clean-diagnostic --denylist config/diagnostics/sealed_product_denylist.txt
python3 scripts/sync_shigoku_updated_at.py
python3 scripts/validate_shigoku_docs.py
git diff --check
graphify update .

# run後（実artifact検証）
.venv/bin/shigoku-ops --json report consistency --report <abs-path> --vdp-key-registry <path>
python3 scripts/verify_report_session_consistency.py --report <abs-path>
.venv/bin/python tests/fixtures/vdp_juiceshop_sealed/evaluate_m5.py --session <session> --labels tests/fixtures/vdp_juiceshop_sealed/labels/expected_path_cases_v1.json --output-dir <out> --eval-version v1 --run-mode m3a-readonly
```

## 7. NOT in scope

- Juice Shopの既知脆弱性・URL・payload・challengeをruntime/config/prompt/recipe/driverへ組み込むこと。
- m3b/m3c/m4の有効化、progression recordsの捏造・手書き昇格。
- 実VDP通信、第三者・OOB宛先、実ユーザーデータ。
- 一般改善・hidden holdout再評価・readiness発行（SGK-2026-0426）。
- 同一対象への変更・再実行の反復最適化loop。

## 8. 0426への引き渡し

`first_failure_juiceshop_v1.json`（opaque case別 first-failure → cause_candidates → confidence）を0426の proven化候補入力とする。0426はsupported/suspectedのままの改善を行わない（0425 §4の単一変数反証条件を満たした原因のみ）。`external_audit_v2.json` はopaque投影（0425 §12準拠）。

## 9. deferred / リスク

- m3aのためPOST系3件はS05 ineligible（意図的・承認済み）。POST系の実測は別フェーズ（m0〜m3aを実runで正当に通した後）。
- S04/S06のemitterは各1箇所。event欠落時はcanonical reach＋U00/C13でhonest記録（推測しない）。
- LLM API egressは許可リストに限定（§1(c)）。
