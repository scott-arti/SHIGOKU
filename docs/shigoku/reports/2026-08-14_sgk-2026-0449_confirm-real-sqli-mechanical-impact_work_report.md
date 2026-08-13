---
task_id: SGK-2026-0449
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-13_sgk-2026-0449_confirm-real-sqli-mechanical-impact.md
- docs/shigoku/plans/done/2026-08-13_sgk-2026-0448_confirm-real-bug-three-levers.md
- docs/shigoku/plans/2026-08-14_sgk-2026-0450_deterministic-error-based-sqli-detection.md
- docs/shigoku/worklogs/2026-08-14_sgk-2026-0449_confirm-real-sqli-mechanical-impact_work_log.md
created_at: '2026-08-14'
updated_at: '2026-08-14'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- confirmation
- sealed-run
deferred_tasks:
- id: SGK-2026-0449-D01
  summary: エラーベース SQLi の検出が非決定的（LLM Phase-2 が90sタイムアウトを繰り返し、run により sql_error 候補が生成されない）。0449 の充填機構は候補さえ出れば confirmed に至ることを end-to-end 実証済み。検出を決定的にして実 run で安定して confirmed=1 を出す作業は SGK-2026-0450 で実施。
  tracking_task_id: SGK-2026-0450
- id: SGK-2026-0449-D02
  summary: 決定的エラーベース payload プローブ（検出経路の決定性向上）の具体設計は 0450 の修正方針で扱う。
  tracking_task_id: SGK-2026-0450
---

# 作業完了報告: SGK-2026-0449 — D01: SQLi 候補への impact 機械充填

（親ロードマップ: SGK-2026-0442。0448 deferred D01 の実施。0448 で出た本物 SQLi 候補を、確定バーを下げずに初の confirmed にする機構を実装。）

## 1. 変更要約

### フェーズ0（STEP 1・コード変更なし・設計承認ゲート）
- 封印 run `session_20260814_001700`（本物 Caido 8081・本物 Juice Shop・GET-only・diagnostics ON・転送ガード通過＝canned ゼロ・consistent）。
- SQLi 候補 `b41d9c6e47cd`（0448 STEP 3 実 artifact `session_20260813_232923`）に実 gate コードを実行し、reason=`missing_impact` を機械確認。判定順序（missing_evidence→not_reproducible→unknown_category→no_firing_marker→missing_impact）の**前4条件は通過済み**（Evidence・再現性・カテゴリ・marker `sql_error` 一致）で、impact/reproduction_steps が空なことだけが確定を止めていた。
- 新規観測: `smart_sqli` の Evidence は `request_url=task.target`（payload 無し）・`request_method` 未設定のため、impact 充填だけでは再現チェッカーが `not_run`（request_fingerprint_mismatch）になる。→ Evidence への実観測リクエスト記録を含める**スコープ拡張をユーザー承認**（§19、2026-08-14）。

### STEP 2（実装・スコープ B）
- 新規 `src/core/agents/swarm/injection/manager_internal/injection_evidence_fields.py`: `build_sqli_observed_evidence` / `build_sqli_impact_and_reproduction_steps` ほか。発火条件（fail-closed）＝ `sql_error_observed=True` かつ parameter/payload 非空 かつ GET/HEAD/OPTIONS かつ有効 http(s) URL かつ status>0。欠落は `(None,None)`/`{}`。
- `smart_sqli.py`（+56/-2）: Finding 構築で Evidence に実観測リクエスト（`request_method=GET`・payload 付き実送信 URL・`response_status=500`）を記録し、impact/reproduction_steps を充填。値はすべて `poc_request`/`poc_response`/`response_differential` 由来の観測事実。
- 確定バー・再現チェッカー無変更: `payout_grade.py` diff 0・`sealed_reproduction_checker.py` diff 0。

### STEP 3（確定 run `session_20260814_014342`・本物 Caido・GET-only・オプトイン ON）
- **confirmed = 0**。正直に記録: (a) 不成立。理由は再現チェッカーの verdict ではなく**検出段階の非決定性**。当該 run では `SmartSQLiHunter` の LLM Phase-2 が `Phase 2 timed out after 90s`×5 で `sql_error_observed=True` の候補を生成せず（session で 0 件を実測）。0448 STEP 3 では同経路が発火＝検出は非決定的。ターゲット挙動は決定的（GET リプレイ 3/3 で 500+SQLITE_ERROR）。

## 2. 独立検証（オーケストレータ Claude・実 gate ＋ 実 checker で end-to-end 再現）

0448 の実 SQLi 候補に 0449 の新コードの充填を適用し、実コードで通した:
- observed evidence 構築: `request_method=GET`・`request_url=…/search?q=' OR '1'='1' --`・`response_status=500`。
- **実 `evaluate_payout_grade`（無変更）**: 未充填→`missing_impact` / 充填→`payout_grade_satisfied`（marker `sql_error`）。
- **実 `SealedReproductionChecker`（無変更）**: 新 evidence で fingerprint 一致 → payload URL へ GET 再送（use_proxy=True）→ 本物の 500+SQLITE_ERROR 本文（curl で 3/3 実測）で **`matched: reproduction_marker_matched:sql_error`**。
- ＝ **3条件 AND は充填により充足**。候補さえ run に出れば confirmed に至ることを実証。

その他の検証: 対象テスト（`test_injection_evidence_fields.py`）12 passed / 対象スライス 567 passed。`check_vdp_product_independence.py` exit 0（token 0）。`verify_report_session_consistency.py`（`haddix_report_20260814_014343.md`）consistent。session evidence の request_method は GET のみ・非 GET 0・secret 生値 0。`master_conductor.py` byte-exact 復元。`validate_shigoku_docs.py` 0 エラー。

## 3. 捏造なし自己確認

impact 文言は観測事実のみ（「GET parameter 'q' に payload 送信で HTTP 500 と SQL エラー marker を観測。`sql_error` はエラーベース注入の兆候でありデータ窃取の証明ではない」）。未観測の確証（データ抽出成功等）は一切なし。

## 4. 完了判定（完了契約対照）

- 条件1（フェーズ0裏取り）: PASS。
- 条件2（充填＋Evidence 記録・gate/checker 無変更 diff 0・PCR-P1 無変更）: PASS。
- 条件3（(a) confirmed=1 or (b) 正当な parked）: **本 run は (a)(b) いずれの厳密形にも該当せず**（候補未生成のため live 確定も live 再現 verdict も無し）。ただし 0449 の**成果物（充填機構）は完成・テスト済み・end-to-end で確定を実証**。confirmed=0 の直接原因は 0449 の対象外レイヤー（検出の非決定性）。
- 条件4（捏造なし）: PASS。条件5（安全境界）: PASS。条件6（docs）: PASS。
- **ユーザー判断（2026-08-14）**: 0449 は「機構完成・確定を実証済み」として done とし、検出の決定化を後続タスク SGK-2026-0450 で実施する。

## 5. §19 分類

- in_scope_blocker: 0 件（gate/checker 無変更・必須テスト全 pass・安全境界維持・回帰なし）。
- deferred_followup: D01/D02（検出の非決定性＝confirmed=0 の直接原因。追跡 SGK-2026-0450）。
- non_blocking_observation: LLM Phase-2 90s タイムアウト×5 ／ Haddix gate fail は fail-closed 設計どおり ／ run 副作用 `vuln_roi_db.json`（commit 対象外・revert 済み）。

## 6. リスク / 次

- confirmed は実 run ではまだ 0。**次タスク SGK-2026-0450 で検出を決定的にし、実 run で安定して confirmed=1 を出す**。
- 0449 の充填機構は 0450 の決定的プローブがそのまま乗る土台となる。
