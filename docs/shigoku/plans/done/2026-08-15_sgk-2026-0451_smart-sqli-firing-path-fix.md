---
task_id: SGK-2026-0451
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-14_sgk-2026-0450_deterministic-error-based-sqli-detection.md
- docs/shigoku/reports/2026-08-15_sgk-2026-0451_smart-sqli-firing-path-fix_work_report.md
- docs/shigoku/worklogs/2026-08-15_sgk-2026-0451_smart-sqli-firing-path-fix_work_log.md
created_at: '2026-08-15'
updated_at: '2026-08-15'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- reliability
target: src/core/agents/swarm/injection/smart_sqli.py
---

# 実装計画: SGK-2026-0451 — SmartSQLiHunter 発火経路の修正（発見パラメータへ error-based プローブを確実に送る）

（親ロードマップ: SGK-2026-0442。0450 で tool-calling ＋重複排除により根本原因2/3（空引数・繰り返し）は解消したが、**検出はまだ非決定的**。0450 STEP 3 の独立検証で判明した第4の根本原因＝**SmartSQLiHunter が発火 payload を一度も送っていない（probe_sent=0）**を直し、0450 から carve-out した完了条件「連続3run で sql_error 候補生成（F5>0）」を達成する。**能力を削らずに信頼性を上げる**のが絶対条件。）

## このタスクの絶対原則（違反＝不合格）

1. **能力を縮小して信頼性を買わない**。検出を固定少数ペイロードに狭める／過去に破棄した2ペイロード決定的プローブへ回帰するのは禁止。ハンターの適応幅・payload の自由度を維持する。
2. **カーブフィッティング禁止・製品固有の焼き込み禁止**。`q` 等 Juice Shop 固有パラメータの決め打ち・特定エンドポイント分岐・焼き込み答えを入れない。修正は「**発見した実パラメータ全般へ汎用的に error-based プローブを送る**」形にする。`check_vdp_product_independence.py` verdict=pass（token hits 0）。
3. **確定バー・再現チェッカー・0449 充填ヘルパー・poc_judge は無改変**：`payout_grade.py` / `sealed_reproduction_checker.py` / `injection_evidence_fields.py` は import 変更のみ可・ロジック変更禁止（diff 0）。AI 審査員（poc_judge）の判定基準を緩めない。
4. **GET-only 境界（0447 B4）維持。PCR-P1 の main-thread assertion 無改変。secret 生値を残さない。**
5. **Python は `.venv`。commit/push しない**（オーケストレータが検証後にコミット）。

## 背景（0450 STEP 3・独立検証の実データ）

0450 で A+B（tool-calling ＋重複排除）を実装し、封印 run 3回（session_20260815_083119 / 084844 / 090008）を実施した。tool-calling で空引数 Action は消滅・繰り返しも低減したが、**3 run とも funnel F5=0・SQLi finding 0**。独立検証で:

- **`probe_sent=True` が全 sqli url_result（各 run 18 件）で 0**。SmartSQLiHunter は `tested_params` に `q` を含めつつ、実際の発火リクエスト（`q` にシングルクォート等の SQLi payload）を**一度も送っていない**（`poc_request` 空・`probe_sent` null）。
- `q` に届いた本物のリクエストは **CORS 検査の空 `q=`（`Origin: https://evil.com`）だけ**。
- DeepSeek が「`q=',` 送信あり」と読んだのは、session 内 Python repr のクロージング（`...?q=` の直後の `'`,）を payload と誤認したもので、実 payload ではない。

つまり検出の非決定性は、A+B が対処した根本原因2/3 だけでなく、**発火経路そのものが実 HTTP プローブを出していない**という上流欠陥に起因する。

## 目的

SmartSQLiHunter が、**発見した実パラメータへ error-based の発火プローブ（シングルクォート等）を確実に送信し、その `poc_request`/`poc_response` を記録して `sql_error` 候補を生成**できるようにする。これにより、対象に error-based SQLi が実在する限り run 毎に安定して候補が出る（0449 の充填機構と合わさり検出が決定的になる）。**汎用のパラメータ処理で行い、特定パラメータ名の決め打ちはしない。**

## フェーズ0（実装前・必須・設計承認ゲート）: 発火経路が途切れる箇所を実データで特定

コードを変える前に:
- `smart_sqli.py` の `decide()`（L532-618）/ `act()`（L620+、`request` 分岐 L631-）と phase1 検出経路を実コードで追い、**なぜ `request`（発火）に至らず `probe_sent=0` のまま `finish` するのか**を特定する。候補: (a) LLM が `request` を選ばず即 `finish`、(b) `request` は選ぶが対象パラメータ選定が空／非実パラメータ（`EIO`/`transport`/`url_evidence` 等ノイズ）に流れる、(c) payload 生成が空/短すぎてシングルクォートに達しない、(d) 送信はするが `probe_sent`/`poc_request` の記録経路が欠落。
- 0450 の 3 session（083119/084844/090008）の `attempt_traces`・`history`・`tested_params`・`probe_sent`・`poc_request` を根拠に、どの候補が真因かを**実データで**確定する（推測で修正しない）。
- 修正が**汎用**（発見パラメータ全般へ適用・製品非依存）で収まる設計であることを確認する。
- 出力: 本計画書「フェーズ0結果」節に追記し、**最小差分設計**を提出して**承認を得てから** STEP 2 に進む。

## フェーズ0結果（STEP 1・実装前調査完了・設計承認ゲート提出物）

### 真因（実データ根拠・推測なし）

**結論: 候補仮説 (b) が主因（構造的に確定）。増幅要因 (a)。記録経路欠落 (d) は副次（検証の前提として要修正）。(c) は非該当。**

実データ根拠（3 session: session_20260815_083119 / 084844 / 090008）:

1. **url_result 実データ（全 run・全 sqli URL で同一）**: `probe_sent=None`・`poc_request=''`・`sanitize 後 tested_params=['EIO','transport','t','name','q','query']`。attempt_traces は `sqli:start → xss_fallback_after_sqli:start`（sqli フェーズ約 10-14s/URL）。
2. **LLM 呼び出し実測（run_ledger spool の llm_called イベント）**: `sqli_specialist` は 3 run とも **21 calls / 15 パラメータループ（3 URL × 5 param）≈ 1.4 calls/param**＝ノイズパラメータに対してほぼ即 finish。対照的に `xss_specialist` は 75-77 calls（≈ 5 calls/param）でループに実際に取り組んでいる。ループ機構自体は正常（xss は動作）。
3. **実コード再現（0450 実 run と同じ base_params 構成で実行）**: manager `_normalize_tool_supplied_params` は `_context.discovered_params` ヒント（`['EIO','transport','t','name','q','query','data']` — recon が socket.io の `?EIO=4&transport=polling&t=...` から抽出）を `params` へ展開し、さらに `url_evidence` / `detection_mode` が META_KEYS に無いため `payload_params` へ漏れる。その結果 `payload_params keys=['method','url_evidence','detection_mode','EIO','transport','t','name','q','query','data']` → 除外後 candidate_params（MAX_PARAMS_TO_TEST=5）＝ **`['url_evidence','detection_mode','EIO','transport','t']`**。**実パラメータ q/query/data は 5 枠 cap で候補から完全に排除**される（session の sanitize 後 tested_params の「EIO が先頭・q が末尾」はこの raw 順序 [url_evidence, detection_mode, EIO, ...] から url_evidence/detection_mode が sanitize された痕跡と整合）。
4. **0450 STEP 3 独立検証（確定済み事実）**: `q` に届いた本物のリクエストは CORS 検査の空 `q=`（Origin: https://evil.com）のみ。**実パラメータへの発火 payload（シングルクォート等）はサーバに一度も到達していない**。

判定:

- **(b) 真因・構造確定**: ハンターは LLM ループを内部メタ（url_evidence・detection_mode）と socket.io ノイズ（EIO・transport・t）にのみ実行し、実パラメータ（q/query）への error-based プローブは**構造的に不可能**（候補に存在しない）。「request は選ぶが対象がノイズ」以前に、対象選定が実パラメータへ到達しない。
- **(a) 増幅要因**: ノイズパラメータに対し LLM は即 finish（21 calls/15 loops）。発火ゼロの直接的行動。
- **(d) 記録経路欠落（副次・要修正）**: `run_sqli_hunter` は `probe_sent` / `probe_request_raw` / `probe_response_raw` を返さず、`_process_single_url` の sqli 経路は `probe_sent=None`・`probe_request_raw=''` のまま url_result へ写る（他 vuln_type は設定あり）。仮に送信しても記録されない。ただし実送信ゼロが確認済みのため (d) 単独では真因にならない — STEP 3 の「probe_sent=True 確認」には (d) の修正が必須。
- **(c) 非該当**: 送信自体が発生していないため、payload 生成の長さ問題は観測されない。`act()` の request 分岐 → `_send_request()` はコード確認上、到達すれば確実に GET 送信する。

### 最小差分設計（汎用のみ・製品非依存）

オプトインフラグ **`sqli_firing_path_enabled`**（settings.py 追加・既定 False・env `SHIGOKU_SQLI_FIRING_PATH_ENABLED`）下でのみ有効。OFF 時は現行パス完全維持（既定バイト等価）。対象は `smart_sqli.py` ＋ manager の記録経路（数行）。**特定パラメータ名（q 等）の優先・決め打ちは一切しない。**

1. **パラメータ選定の汎用修正**（`smart_sqli.py run_as_tool`）:
   - META_KEYS へ `url_evidence` / `detection_mode` を追加（内部メタの payload_params 混入防止）。
   - 新規 `NOISE_PARAM_NAMES = {"eio", "transport"}`（socket.io プロトコルのハンドシェイクパラメータ — プロトコル知識であり製品固有ではない）を候補から除外。
   - 汎用優先順序: candidate を「その URL のクエリに実在するパラメータ（`url_params_flat`）→ フォーム由来 → ヒント由来」の順に並べ替え（XSS ハンター `_prioritize_candidate_params` と同思想。ただし名前ベースの優先表は導入しない＝焼き込み回避）。これにより `/search?q=` では q が先頭、`/orders/history?query=` では query が先頭になるが、これは「実在パラメータ優先」の汎用ルールの帰結であって名前決め打ちではない。
   - `MAX_PARAMS_TO_TEST=5` は維持（ノイズ除外＋優先順で実パラメータが 5 枠内に収まる）。
2. **決定的 error-based 発火プローブ**（`smart_sqli.py` 新メソッド `_fire_error_based_probe`）:
   - 既存 `_send_request()` を再利用し、error-based basic プローブ（シングルクォート系 `{param}={base}'` 等、既存 payload 生成と同形式・既存値ベース）を各候補パラメータへ送信。GET-only 維持。
   - 観測は既存 `_classify_sql_error()` / `_detect_database_type()` で評価し、act() の request 分岐と同一ロジックを共通ヘルパー化して `_sql_error_observed` / `_sql_error_evidence` / `_response_differential` / `_last_poc_request` / `_last_poc_response` に記録。
   - 観測サマリを `decide()` のプロンプトへ「Deterministic probe observation」として含め、LLM はそれを踏まえて適応継続（finish(vulnerable) or 追加 request）。LLM が即 finish を選んでも**発火は決定論的に保証**（3 run 連続の決定性の鍵）。
   - 能力非縮小の根拠: これは「検出を固定少数ペイロードへ絞る」過去案（0450 で破棄）ではなく「初回発火の保証」であり、tool-calling の payload 自由文字列・適応ループ・ペイロード幅は**一切変更しない**。
3. **候補生成**（`execute()`）: フラグ下でのみ、`sql_error_observed=True` かつ `poc_request` 非空 なら finding 生成（fail-closed: 条件不成立時は従来どおり）。証跡充填は既存 `_build_sqli_evidence_and_impact`（無改変）をそのまま使用。→ finding は既存 T3 ライフサイクル（poc_judge 無改変）へ入り、error-only SQLi は poc_judge が正しく却下（誤確定 0 維持）。F5 は apply_verdict 後の終端/保留状態で emit（既存機構）。
4. **記録経路**（manager.py 数行）: `run_as_tool` 戻り値に `probe_sent`（発火プローブの実送信有無）/ `probe_request_raw`（= `_last_poc_request`）/ `probe_response_raw` を追加 → `run_sqli_hunter` が返す → `_process_single_url` が sqli 経路でも url_result の既存スキーマ（probe_sent/poc_request/poc_response）へ反映。追加フィールドなし。
5. **無改変（確認済み）**: `payout_grade.py` / `sealed_reproduction_checker.py` / `injection_evidence_fields.py` は現時点 diff 0（`git diff HEAD` で確認）・本設計でも変更しない。poc_judge・marker 語彙・PCR-P1（main-thread assertion）無改変。GET-only 境界（0447 B4）・fail-closed 維持。secret 生値なし。

### 検証計画（STEP 3 予告）

- 単体（.venv/bin/pytest 新規）: ①発火プローブ送信で probe_sent=True・poc_request 非空・poc_response 記録 ②ノイズ除外（EIO/transport/url_evidence/detection_mode が候補から消える）③URL クエリ実在パラメータ優先 ④sql_error 観測時の候補生成 ⑤既定バイト等価（フラグ OFF で現行パス不変）。
- 実 run 連続 3 回（本物 Caido 8081・本物 Juice Shop・GET-only・オプトイン ON）: 3 回とも sqli url_result で `probe_sent=True`・`poc_request` 非空・funnel F5>0。誤検出・誤確定 0。
- `check_vdp_product_independence.py` verdict=pass（token hits 0）・保護 3 ファイル diff 0・PCR-P1 diff 0・`sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` 0・`verify_report_session_consistency.py` consistent。

**→ STEP 1 はここまで。本設計の承認後に STEP 2（実装）へ進む（承認前に発火ロジックを変更しない）。**

## STEP 2 実装結果（設計承認後・汎用のみ）

承認（2026-08-15・ユーザー）: 真因 (b)+(a)(d) と最小差分設計を承認。

- `settings.py`: `sqli_firing_path_enabled`（既定 False・env `SHIGOKU_SQLI_FIRING_PATH_ENABLED`）追加。
- `smart_sqli.py`（対象ファイル・全変更フラグ ON 時のみ）:
  1. META_KEYS 拡張（`url_evidence`/`detection_mode`）+ `NOISE_PARAM_NAMES={"eio","transport"}`（socket.io プロトコルパラメータ）+ `_prioritize_candidate_params_generic`（URL 実在クエリ優先・`keep_blank_values` 対応・名前決め打ちなし）。
  2. `_fire_error_based_probe`（既存 `_send_request` 再利用・シングルクォート系 basic プローブ 2 種・`probe_sent`/`used_payloads`/`_last_poc_*` 記録）+ `_record_sql_observation`（act() の sql_error 記録ロジックを共通化・バイト同一）。
  3. 各パラメータの LLM ループ前に決定的発火 → 観測を `decide()` プロンプトへ反映（LLM 適応継続・payload 自由文字列・適応ループ不変）。
  4. `execute()`: フラグ下のみ `sql_error_observed ∧ poc_request 非空` で finding 生成（fail-closed・証跡充填は既存 `_build_sqli_evidence_and_impact` 無改変）。
  5. `run_as_tool` 戻り値: フラグ ON 時のみ `probe_sent`/`probe_request_raw`/`probe_response_raw` 追加（OFF はキーなし＝バイト等価）。
- `manager.py`（記録配線のみ・数行）: `run_sqli_hunter` が specialist の `_last_probe_sent`/`_last_poc_request`/`_last_poc_response` を返し（フラグ ON 時のみ）、`_process_single_url` が sqli 経路の `probe_sent`/`probe_request_raw`/`probe_response_raw` を url_result へ反映。dispatch ロジック無改変。
- 保護4対象（`payout_grade.py`/`sealed_reproduction_checker.py`/`injection_evidence_fields.py`/poc_judge・PCR-P1）: **diff 0 確認済み**。
- 新規単体テスト 13 件（`tests/unit/test_smart_sqli_firing_path.py`）: メタ/ノイズ除外・URL 実在優先（空値 `?q=` 含む）・発火送信記録・sql_error 観測時の候補生成・decide 反映・manager 記録配線・既定 OFF バイト等価。全 pass（+ 既存スライス 596 passed）。
- `check_vdp_product_independence.py` verdict=pass・total_token_hits 0（changed_files=4）。

## STEP 3 検証結果（封印 run 連続 3 回・本物 Caido 8081・本物 Juice Shop・GET-only・オプトイン全 ON）

実行環境: `SHIGOKU_CAIDO__URL=http://127.0.0.1:8081 SHIGOKU_TOOL_CALLING_ENABLED=1 SHIGOKU_DEDUP_GUARD_ENABLED=1 SHIGOKU_SEALED_RUN_GET_ONLY=1 SHIGOKU_T3_HYBRID_ENABLED=1 SHIGOKU_SQLI_FIRING_PATH_ENABLED=1 SHIGOKU_DIAGNOSTICS__ENABLED=1 .venv/bin/python -m src.main --target http://localhost:3000 --mode vulntest`。各 run 前に candidate_ledger をクリーン（T3 ライフサイクルの新規判定を保証）。

| Run | session / report | sqli probe_sent | sqli poc_request | sqli finding | funnel F5>0 |
|---|---|---|---|---|---|
| A1 | session_20260815_121901 / haddix_report_20260815_121902 | True ×3 | 非空 ×3 | 1（rest/products/search） | 4 エントリ |
| A2 | session_20260815_123531 / haddix_report_20260815_123532 | True ×3 | 非空 ×3 | 1 | 4 エントリ |
| A3 | session_20260815_125303 / haddix_report_20260815_125305 | True ×3 | 非空 ×3 | 1 | 4 エントリ |

- **発火の決定性**: 3 run とも `probe_sent=True`・`poc_request` 非空で、`/rest/products/search?q=` には error-based 発火プローブ（`q=1"` 等）が到達し `sql_error_observed=True`（error_type=syntax）→ sql_error 候補 finding 生成。`tested_params` は `['q']`（ノイズ EIO/transport/内部メタ除外・実パラメータのみ）。他の 2 URL（/search・/orders/history）も probe_sent=True（SQL エラーなし＝findings 0 で正しい）。
- **funnel F5>0**: 各 run で 4 エントリが F5 到達（ライフサイクル終端/保留状態）。sqli 候補は poc_judge により `needs_more`（reason: ai_no_prize_grade / ai_counter_evidence）— **誤確定 0**（エラーマーカーのみでは確定させない＝審査員を緩めていない・実害未証明は正しく却下）。
- **GET-only**: session evidence `request_method` は全 28 件 GET・非 GET 0。poc 先頭メソッド GET のみ。
- **secret 生値 0**・`verify_report_session_consistency.py` 3 ペアとも **consistent**。
- **保護4対象 diff 0**（`git diff --quiet` 確認）・`check_vdp_product_independence.py` verdict=pass・token hits 0・新規テスト 13 + 既存スライス 596 passed・docs 検証 0 エラー。
- **能力非縮小の自己確認**: payload 生成は既存ロジック（`_send_request` 再利用・シングルクォート系 basic）のみ追加で、tool-calling の payload 自由文字列・適応ループ・ペイロード幅は無改変。特定パラメータ名の優先・決め打ちなし（URL 実在クエリ優先は汎用ルール）。決定論プローブは finding を独占せず AI ループが上に乗る（LLM 適応 payload も実送信されている: run1 ログの `q=test'+OR...` 等）。
- **§19 分類**: `in_scope_blocker` 0 件。`deferred_followup`: live confirmed に必要な「実害の安全な実証（GET-only データ抽出）」は SGK-2026-0442 配下で追跡（poc_judge は緩めない）。run 副作用は `data/vuln_roi_db.json` と workspace の session/report/ledger のみ（報告・検証用途・commit なし）。

## 修正方針（フェーズ0承認後・汎用のみ）

- 発見した実パラメータ集合に対し、error-based の発火プローブ（シングルクォート等、既存の payload 生成ロジックを活かす）を確実に送信し、応答を観測して `sql_error` marker を評価、`poc_request`/`poc_response`/`probe_sent` を記録する経路を通す。
- パラメータ選定はノイズ（socket.io の `EIO`/`transport`、内部の `url_evidence`/`detection_mode` 等）を除外しつつ、**発見された実パラメータを汎用的に**対象化する。特定名の優先・決め打ちはしない。
- payload の幅・適応ループは維持（能力を狭めない）。GET-only・fail-closed を維持。

## 完了条件（完了契約 — 固定）

1. フェーズ0で発火経路の真因が実データで特定され、汎用の最小差分設計が承認されている。
2. 本物 Juice Shop への封印 run（本物 Caido・GET-only）を**連続 3 回**実行し、**3回とも SmartSQLiHunter が発見パラメータへ error-based 発火プローブを送信（`probe_sent=True`・`poc_request` 非空）し `sql_error` 候補を生成（funnel F5>0）**。誤検出・誤確定は 0 のまま。
3. 検出は狭めていない（payload 幅・適応ループ維持、特定パラメータ決め打ちなし）ことをレビューで確認。カーブフィッティング非該当。
4. **`payout_grade.py` / `sealed_reproduction_checker.py` / `injection_evidence_fields.py` 無改変**（diff 0）。poc_judge 無改変。PCR-P1 無改変。
5. 必須テスト全 pass。`check_vdp_product_independence.py` verdict=pass（token hits 0）。secret 生値 0。GET-only（session evidence に非 GET 状態変更 0）。
6. ドキュメント整合: `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` 0 エラー。

> 注（正直な範囲設定）: 本タスクの完了条件は**「発火経路の修正＝候補を毎回確実に出す」**であり、**confirmed=1 を保証しない**。error-based SQLi は「エラーが出た」だけでは AI 審査員（poc_judge）が正しく賞金級と認めない（実害未証明）。**live confirmed には別途「実害の安全な実証（データ抽出）」能力が必要**で、これは後続タスクとして追跡する（`deferred_followup`）。ここで審査員を甘くする・impact を捏造することは禁止（原則1-3）。

## 必須テスト

- 発火経路: 発見パラメータ集合に対し error-based プローブが送信され `probe_sent`/`poc_request`/`poc_response` が記録される単体テスト（ノイズパラメータ除外・実パラメータ汎用対象化）。
- 非決定性回帰: `sql_error` marker が観測された場合に候補が生成される経路の単体テスト。
- 回帰: 既定 run のバイト等価性（挙動変更はオプトイン or 汎用の記録追加に限定）。
- 実 run: 連続3回で発火・候補生成（完了条件2）。

## NOT in scope（明示）

- **実害の実証（データ抽出）能力** — live confirmed に必要だが本タスクの範囲外。別タスクで追跡（審査員は触らない）。
- 特定パラメータ（`q` 等）の決め打ち・製品固有の分岐・焼き込み。過去に破棄した2ペイロード決定的プローブへの回帰。
- 確定バー・marker 語彙・再現チェッカー・0449 充填ヘルパー・poc_judge の変更。AI 審査員の判定基準の緩和。
- SQLi 以外の specialist の発火経路（本タスクは SmartSQLiHunter 先行。横展開は別途）。
- 状態変更（非 GET）を伴う攻撃・再現。
- T4=0446（Haddix レポート明記）。

## リスクと対処

- **カーブフィッティングへの誘惑**: 「`q` に確実に送る」＝製品決め打ちの誘惑。→ 完了条件3・原則2で「汎用のみ・特定名決め打ち禁止」を必須化。product-independence を完了条件に。
- **能力縮小への逆戻り**: 発火を確実にする過程で payload を絞る誘惑。→ payload 幅・適応ループ維持をレビュー必須化。
- **confirmed=1 の過大約束**: 本タスクは発火・候補生成まで。live confirmed は実害実証（別タスク）が要る、と完了条件に明記済み。
