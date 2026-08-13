---
task_id: SGK-2026-0449
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-13_sgk-2026-0448_confirm-real-bug-three-levers.md
- docs/shigoku/plans/2026-08-14_sgk-2026-0450_deterministic-error-based-sqli-detection.md
- docs/shigoku/reports/2026-08-14_sgk-2026-0449_confirm-real-sqli-mechanical-impact_work_report.md
- docs/shigoku/worklogs/2026-08-14_sgk-2026-0449_confirm-real-sqli-mechanical-impact_work_log.md
created_at: '2026-08-13'
updated_at: '2026-08-14'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- confirmation
target: src/core/agents/swarm/injection/smart_sqli.py,src/core/agents/swarm/injection/manager_internal/authz_fields.py
---

# 実装計画: SGK-2026-0449 — D01: SQLi 候補に impact を機械充填し「本物の確定1件」を出す

（親ロードマップ: SGK-2026-0442。0448 の deferred D01 の実施。0448 で出た本物 SQLi 候補を、確定バーを下げずに初の confirmed にする。）

## 背景（なぜこのタスクが必要か）

- 0448 の封印 run（本物 Caido 経由・GET-only）で、**本物の SQLi 候補**が1件出た。
  - payload: `/rest/products/search?q=' OR '1'='1' --`、実応答 **HTTP 500**、firing marker **`sql_error` 発火**（`smart_sqli.py` 経路）。
- しかし `payout_grade` 判定は **`missing_impact`** で不合格 → 確定に届かず parked。
- `payout_grade.py` の判定順序は `missing_evidence → not_reproducible → unknown_category → no_firing_marker → missing_impact`（`missing_impact` が最後）。**`missing_impact` を返した＝前4条件（Evidence・再現可能性・カテゴリ・marker）はすべて通過済み**。つまり **impact と reproduction_steps が空**なことだけが確定を止めている。
- 根因: `smart_sqli.py:268-298` の SQLi Finding は `impact` も `reproduction_steps` も設定していない（0448 で認可系には `authz_fields.py` で機械充填したが、SQLi はスコープ外だった）。
- 確定への道は実在する: 再現チェッカー（`sealed_reproduction_checker.py`）は `sql_error` を **body 観測 marker**（`_NON_BODY_MARKERS` 外）として扱い、**GET リプレイで sql_error 再発火を確認**できる。SQLi の payload は GET クエリ（`?q=...`）なので **GET-only スコープ内で再現可能**。

## 目的

0448 と同じ「検出済み事実の機械的言語化（LLM なし・fail-closed・捏造なし）」を **SQLi finding にも適用**し、`impact` と `reproduction_steps` を埋める。これにより `payout_grade` が PASS し、**再現チェッカーが GET リプレイで `sql_error` を独立に再発火できれば 3条件 AND が揃って confirmed=1** になる。

**確定バーは一切下げない。** impact を埋めても、再現チェッカーが独立に再発火しなければ confirmed にはならない（parked のまま）。それが正しい fail-closed。

## スコープの切り分け（confirmed vs hypothesis）

- **[confirmed]** SQLi 候補は `missing_impact` のみで落ちている＝前4条件通過（判定順序から論理的に確定）。
- **[confirmed]** 再現チェッカーは `sql_error` を GET リプレイで再検出する経路を持つ（`sealed_reproduction_checker.py:143` `_detect_marker_in_response(category=="sql_error")`）。
- **[hypothesis — フェーズ0で要確定]** 0448 run の当該 SQLi 候補（`b41d9c6e47cd`）の payout_grade reason が実際に `missing_impact` である（DeepSeek 報告値。フェーズ0の実 run で再確認する）。
- **[hypothesis — フェーズ0で要確定]** Juice Shop の `/rest/products/search?q='...` が **リプレイでも安定して 500 + sql_error を返す**（決定的に再現する）。非決定的なら confirmed には至らず parked が正しい。

## フェーズ0（実装前・必須）: 1回の封印 run で確定条件を候補単位に確認

コードを変える前に、本物 Caido 経由・GET-only・`diagnostics.enabled=true` で1回封印 run を実行し、SQLi 候補について次を確認する。

- payout_grade reason が本当に `missing_impact` か（前4条件通過の裏取り）。
- Evidence / additional_info に再現に必要な情報（payload、request_url、GET メソッド、poc_request/response）が揃っているか。
- 再現チェッカーが当該 SQLi 候補に対して起動しているか、その verdict（not_run / marker_mismatch / matched のいずれか）。
- 出力: この計画書「フェーズ0結果」節に候補単位で追記。`missing_impact` 以外の理由で落ちているなら、本タスクのスコープ（impact 充填）では確定できないので**その旨を報告して停止**（推測でスコープを広げない）。

## フェーズ0結果（2026-08-14 封印 run: `session_20260814_001700`）

実行環境: 本物 Caido `127.0.0.1:8081`（エントリゲート ON。preflight: TCP 8081 reachable → GraphQL introspection succeeded → Forwarding PASS+WARNING（同一 200 body 75002B >512B、0447/0448 と同一挙動）→ all checks passed）・本物 Juice Shop `localhost:3000`（finding evidence は Score Board / Quantitys の実 JSON・CORS 実ヘッダ、canned 署名ゼロ）・GET-only（`SHIGOKU_SEALED_RUN_GET_ONLY=1`）・`diagnostics.enabled=true`・`SHIGOKU_CAIDO__URL=http://127.0.0.1:8081`（env のみ・config 無変更）。`verify_report_session_consistency.py` → **consistent**。実行は 1 回。

### 候補単位トレース（funnel `finding_funnel_v1`・5 候補）

| finding | vuln_type | funnel 到達段 | payout_grade 判定 + reason | 再現 checker |
|---|---|---|---|---|
| `d10a342af8f2` | broken_access_control | F0 blocked（task_suppressed_ownership）→F1→F2→F4 | FAIL / **missing_impact**（impact 空） | 機械フロアで停止（未到達） |
| `a222ae4fb040` | broken_access_control | F0→F1→F2→F3 skipped（phase2_skipped_early_return）→F4 | FAIL / **missing_impact** | 同上 |
| `438f9bac437c` | cors_misconfiguration | F0→F1→F3 skipped→F4 | FAIL / unknown_category（marker 語彙外・設計どおり） | 同上 |
| `b7aa7f57bce4` | cors_misconfiguration | F0→F1→F3 skipped→F4 | FAIL / unknown_category | 同上 |
| `67001d154ed0` | cors_misconfiguration | F0 blocked→F1→F3 skipped→F4 | FAIL / unknown_category | 同上 |

funnel summary: `by_stage {F0:5, F1:5, F2:2, F3:5, F4:5, F5:0, F6:0}`・`by_reason {phase2_skipped_early_return: 3, task_suppressed_ownership: 2}`・`total_candidates: 5`。evidence request_method 集計: **GET のみ 6 件・非 GET 0**。secret 生値パターン 0。0448 フェーズ0 と同一構成（当該 SQLi 候補は本 run では生成されず）。

### SQLi 候補 `b41d9c6e47cd` のトレース（0448 STEP 3 run `session_20260813_232923` 実 artifact から機械検証）

> 現行コード（0448 STEP 3 の一時オプトイン無し）の封印 run では Phase-2 が `phase2_skipped_early_return` で打ち切られ、SQLi 候補は生成されない（上記 run で再確認）。SQLi 候補は 0448 STEP 3 のオプトイン ON run でのみ生成された実 artifact であり、同一 HEAD（`cdf0eb4`）・同一環境（本物 Caido・GET-only・diagnostics ON）の run 記録。payout_grade 評価は実 gate コードで再実行。

- **payout_grade reason: `missing_impact` を機械確認**。`evaluate_payout_grade`（無変更 gate）を artifact 上の finding dict に実行 → `payout_grade=False, reason=missing_impact, evidence_refs=['additional_info.poc_request','additional_info.poc_response'], marker=sql_error`。判定順序（missing_evidence → not_reproducible → unknown_category → no_firing_marker → missing_impact）の**前 4 条件はすべて通過**（再現性: PoC 対完備 ✓ / カテゴリ: sqli は語彙内 ✓ / marker: `sql_error` 一致 ✓ / impact: 空 → **missing_impact のみで不合格**）。
- **Evidence / additional_info 充足**: parameter=`q` ✓・payload=`q=' OR '1'='1' --`（payloads_used: `q='`, `q=' OR '1'='1' --`）✓・request_url=`http://localhost:3000/rest/products/search` ✓・**GET メソッド**（poc_request 行 `GET /rest/products/search?q=%27+OR+%271%27%3D%271%27+--&method=GET HTTP/1.1`）✓・`sql_error_observed=True` ✓・sql_error_evidence（body_snippet `<title>Error: SQLITE_ERROR: incomplete input</title>`・db_detection sqlite）✓・poc_request ✓・poc_response（`HTTP/1.1 500` + SQLITE_ERROR body）✓・response_differential（`attack_status=500, diff_type=error`）✓。**不足は impact / reproduction_steps のみ**。
- **再現チェッカー**: 0448 run では機械フロア（missing_impact）で停止し未起動。同一配線（`network_client=AsyncNetworkClient`・`_build_sealed_reproduction_scope('http://localhost:3000')`）で deterministic 実行 → **`not_run / request_fingerprint_mismatch`**（evidence.request_method が空・evidence.request_url が payload 無しの基底 URL のため、リプレイ識別が一致しない。fail-closed 設計どおり）。→ **充填のみ（本計画スコープ）では confirmed には至らず (b) が予測結果**。
- **リプレイ決定性（hypothesis 確認）**: payload URL を本物 Caido 経由で GET リプレイ 3 回 → **3/3 とも HTTP 500 + `SQLITE_ERROR: incomplete input`（942B）**。当該挙動は決定的。→ 再現チェッカーが payload URL を再送できれば `matched` に至る。ただし checker は `evidence.request_url` のみ再送対象（additional_info.poc_request は使わない）ため、**evidence に実観測リクエスト（method/URL）が記録されない限り再発火しない**。

### hypothesis 判定（run 実データによる confirmed / 否定）

- **h1「reason が missing_impact」: confirmed**（実 gate コードで機械再確認。前 4 条件通過・impact 空のみ）。
- **h2「リプレイで安定して 500 + sql_error」: confirmed**（3/3 決定的再発火）。
- **新規観測（STEP 2 設計に影響）**: smart_sqli の Evidence 構築は `request_url=task.target`（payload 無し）・`request_method` 未設定のため、**impact/repro のみの充填では再現チェッカーは `not_run`（fingerprint mismatch）**となり (b) が正しい結果。`(a)` を目指すには evidence への実観測リクエスト記録（request_method=GET・request_url=実送信 URL）が追加で必要＝**計画の修正方針（impact/reproduction_steps 充填）を超えるスコープ拡張**であり、ユーザー承認ポイントとする（gate は無変更のまま・観測事実のみ・カーブフィッティングに非該当）。

## 修正方針（フェーズ0で hypothesis が confirmed の場合のみ）

> **スコープ拡張（2026-08-14 ユーザー承認済み・§19）**: フェーズ0で、impact/reproduction_steps の充填だけでは再現チェッカーが `not_run`（request_fingerprint_mismatch）になり confirmed に至らないことが判明した（`smart_sqli.py` の Evidence は `request_url=task.target`＝payload 無しの基底 URL・`request_method` 未設定のため、再現チェッカー `sealed_reproduction_checker.py:227,272-278` の送信対象・fingerprint 照合が成立しない）。当初スコープ（impact/repro 充填のみ）に加え、**Evidence へ「実際に送った観測リクエスト」（`request_method=GET`・payload 付き `request_url`・`response_status`）を正確に記録する修正**を承認スコープに含める。これは gate（payout_grade.py）と再現チェッカーを無変更のまま、`smart_sqli` が取りこぼしていた観測事実を正確に記録するだけであり、カーブフィッティングには非該当（本物 Caido 経由 GET リプレイ 3/3 で SQL エラー再発火を実測済み＝実在バグの真の確定）。

### 1) SQLi finding への impact/reproduction_steps 機械充填
- `authz_fields.py` と同じ設計思想（LLM なし・検出済み事実のみ・fail-closed）で、SQLi 用の機械充填を追加する。
  - **発火条件**: `sql_error_observed == True` かつ Evidence が揃っている場合に限る。満たさなければ `(None, None)` を返し、finding は従来どおり（バーは下げない）。
  - `impact`: 「param `<p>` に SQL エラーベースのインジェクションの兆候。payload `<payload>` で HTTP `<status>` と SQL エラー marker が観測された（sql_error はエラーベース注入の兆候でありデータ窃取の証明ではない）」等、**観測事実のみ**。未観測の確証は書かない。
  - `reproduction_steps`: 実際に送った **GET** リクエスト手順（method/url/payload/観測した status と marker）。
- ヘルパーの置き場所は中立名モジュール（例 `manager_internal/injection_evidence_fields.py`）に切り出す。**`payout_grade.py` は import も変更もしない。**

### 2) SQLi finding の Evidence 実観測記録（承認スコープ）
- `smart_sqli.py:268-298` の `Finding` 構築で、`Evidence` に**実際に送った攻撃リクエストの観測値**を記録する。
  - `request_method="GET"`（実際に送ったメソッド。poc_request 由来の観測事実）。
  - `request_url` = payload を含む**実送信 URL**（`poc_request` の GET 行から。現行の基底 `task.target` を置き換え）。
  - `response_status` = 観測した実 status（例 500。`response_differential.attack_status` / poc_response 由来）。
  - 既存の `response_body`（evidence_text）は保持しても可。値はすべて**既に観測済みの事実**であり、新たな確証を作らない。
- これにより再現チェッカー（無変更）の fingerprint（`request_method`＝GET・payload 付き url・param 名）が一致し、GET リプレイで `sql_error` を**独立に再発火**できれば `matched` → confirmed。再発火しなければ従来どおり parked（fail-closed）。
- **再現チェッカー `sealed_reproduction_checker.py` は無変更**（緩めない）。確定はチェッカーの独立再送が earned する。

## STEP 2 実装（2026-08-14 ユーザー承認後・スコープ B）

**新規 `manager_internal/injection_evidence_fields.py`**（+164 行・LLM なし・純ヘルパー）:
- `parse_observed_request_url(poc_request, fallback_url)` — PoC リクエスト行 + Host から実送信 URL を復元（解析不能は None、fail-closed）。
- `parse_observed_status(poc_response, fallback_status)` — fallback（response_differential.attack_status）>0 優先、無ければ PoC レスポンス status 行。無ければ None。
- `build_sqli_observed_evidence(...)` — `sql_error_observed=True` かつ GET/HEAD/OPTIONS・URL ・status が揃う場合のみ `{request_method, request_url, response_status}` を返す。欠落は `{}`（fail-closed）。
- `build_sqli_impact_and_reproduction_steps(...)` — 発火条件（sql_error_observed=True かつ parameter/payload 非空 かつ read-only method かつ有効 http(s) URL かつ status>0）充足時のみ impact/reproduction_steps を返す。impact 文言は観測事実のみ（「sql_error marker はエラーベース注入の兆候でありデータ窃取の証明ではない」を明記）。未達は `(None, None)`。

**`smart_sqli.py`**（+56/-2・`payout_grade.py` import なし）:
- `execute()` の Finding 構築（旧 268-298 行）を置換: `_build_sqli_evidence_and_impact(result, task.target)` の結果で Evidence を正確化（`request_url`=payload 付き実送信 URL・`request_method`=GET・`response_status`=500）し、`impact` / `reproduction_steps` を充填。additional_info は一字も不変。observed が空のときは従来と同一（fail-closed）。
- モジュール末尾に `_build_sqli_evidence_and_impact` を追加（循環 import 回避のため関数内 import）。

**新規テスト `test_injection_evidence_fields.py`**（12 件・0448 run 実測 fixture をリテラル記述）:
- 発火/欠落系 7 件（sql_error_observed=False・payload 欠落・parameter 欠落・status 0・不正 URL・非 GET → (None, None)）
- observed evidence 2 件（実送信 URL/GET/500 の記録・fail-closed）
- **fingerprint 一致**（`build_request_fingerprint(evidence.request_method, url, params)` == replay の `build_request_fingerprint("GET", url, params)`）
- payout_grade PASS / missing_impact 回帰（gate 無変更のまま）
- 0448 候補形状での配線統合

**検証**: 新規 12 passed・`tests/core/agents/swarm/injection/` 567 passed（回帰なし）・`git diff payout_grade.py` = 0 バイト・`git diff sealed_reproduction_checker.py` = 0 バイト・`check_vdp_product_independence.py` exit 0（3 ファイル走査・total_token_hits 0）。

## 完了条件（完了契約 — 固定）

1. フェーズ0のトレースが存在し、SQLi 候補が `missing_impact` のみで落ちていること（前4条件通過）が run 実データで裏取りされている。**（完了済み: フェーズ0結果節）**
2. SQLi finding の impact/reproduction_steps 機械充填＋Evidence 実観測記録（承認スコープ）が入り、**`payout_grade.py` の 3条件 AND・marker 語彙・impact 定義は無改変**（diff 0 で証明）。**`sealed_reproduction_checker.py` 無改変**（diff 0）。PCR-P1 assertion 無変更。
3. 本物 Juice Shop への封印 run（本物 Caido・GET-only）で **次のいずれか**:
   - (a) **confirmed=1 以上**（当該 SQLi が 3条件 AND を独立に満たす: payout_grade PASS ＋ 再現チェッカーが GET リプレイで `sql_error` を再発火 ＝ reproduction matched）。誤確定は 0 のまま。**← 承認スコープ B の目標。**
   - (b) confirmed は 0 だが、SQLi の impact/reproduction_steps は正しく充填され payout_grade は PASS し、**confirmed に至らない理由が再現チェッカーの正当な verdict**（marker_mismatch / not_run 等、再現が独立に成立しなかった）であることが候補単位で示される。この場合「Juice Shop の当該挙動が非決定的だった」等の事実を記録する。
4. impact/reproduction_steps および Evidence 記録の内容が**捏造でない**（すべて観測済みの事実で、未観測の確証を含まない）ことをレビューで確認。
5. 必須テスト全 pass。`check_vdp_product_independence.py` exit 0（製品トークン 0）。secret 生値 0。GET-only（session evidence に非 GET 状態変更 0）。
6. ドキュメント整合: `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` 0 エラー。

## 必須テスト

- SQLi 機械充填ヘルパーの単体テスト: `sql_error_observed=True`＋Evidence 揃い → impact/repro が埋まる／`sql_error_observed=False` or Evidence 欠落 → `(None, None)`（fail-closed）。
- 充填後の Finding が `payout_grade` で PASS すること（impact 空だと `missing_impact`、埋めると PASS）の単体テスト。**`payout_grade.py` は変更せず**、finding 側の充填だけで PASS することを示す。
- **Evidence 実観測記録テスト（承認スコープ）**: 充填後 Finding の `evidence.request_method=="GET"`・`request_url` が payload 付き実 URL・`response_status>0` であること。これで再現チェッカーの fingerprint（`build_request_fingerprint`）が replay と一致すること（`request_fingerprint_mismatch` にならない）を単体で示す。**`sealed_reproduction_checker.py` は変更せず**、evidence 側の記録だけで fingerprint が揃うことを示す。
- 回帰: 既定 run のバイト等価性を壊さない（充填・記録は既存 finding の field を正確化するのみ。既定挙動を変える場合はオプトイン）。

## NOT in scope（明示）

- 確定バー（3条件 AND）を下げること／marker 語彙を増やすこと／impact 定義を緩めること。
- 再現チェッカーのロジックを緩めて無理に matched にすること（再現が独立に成立しなければ parked が正しい）。
- SQLi 以外のカテゴリへの機械充填の一般化（本タスクは SQLi の1件確定に集中。他カテゴリは別途）。
- 状態変更（非 GET）を伴う攻撃・再現。
- 特定製品（Juice Shop）向けの分岐・スタブ・焼き込み答え（カーブフィッティング禁止）。
- T4=0446（Haddix レポート明記）。

## リスクと対処

- **カーブフィッティング圧**: 「confirmed=1」を目標にすると、答えを焼き込む／再現を緩める誘惑が生じる。→ 完了条件を (a) **または** (b)（正当な parked の説明）にし、`payout_grade.py` と再現チェッカーの無改変を diff で必須化。再現が独立に成立しなければ 0 のままで正しい、と明記。
- **impact 捏造**: 「データ抽出成功」等の未観測の確証を書く危険。→ 観測事実（payload・status・sql_error marker）のみに限定。sql_error は「エラーベース SQLi の兆候」であって「データ窃取の証明」ではないので、impact 文言もそのレベルに留める。
- **非決定的再現**: 500 が毎回出ない可能性。→ その場合は (b) で正直に parked。バーは触らない。

## STEP 3 確定 run（2026-08-14・本物 Caido・GET-only・オプトイン ON）

- 実行方法: `master_conductor.py` の 2 タスク生成箇所（scenario_probe params / signal_task_params）へ一時的に `phase1_early_return_require_payout_grade: True` を追加 → 封印 run 1 回（`session_20260814_014342`・本物 Caido 8081・GET-only・diagnostics ON）→ **byte-exact 復元**（sha256 `f923709f…` 一致・`git diff` 0）。`verify_report_session_consistency.py` → **consistent**（exit 0）。
- funnel: `by_stage {F0:5, F1:5, F2:2, F3:5, F4:3, F5:0, F6:0}`・`by_reason {task_suppressed_ownership: 2, phase2_skipped_early_return: 1}`（オプトイン効果: フェーズ0 の 3 → 1。0448 STEP 3 と同形）。evidence request_method は **GET のみ 6 件・非 GET 0**・secret 生値 0。authz 2 件は impact/repro 機械充填済み（0448 レバー2 配線が本 run でも稼働）。
- **結果: confirmed = 0**（F5:0・Haddix gate は fail-closed どおり fail）。**当該 SQLi 候補は本 run では再生成されなかった**: Phase-2 で SmartSQLiHunter は products/search 等に対して ThoughtLoop を実行したが、**sql_error 観測 0 件**（session 内 `sql_error_observed True` 0・sqli finding 0）。ログは **「Phase 2 timed out after 90s」×5** とパラメータ早期停止（low-signal normal responses）を示し、LLM 駆動の検出経路が 90 秒の Phase-2 予算内で sql_error を発火しなかった（0448 STEP 3 では同一経路が発火して候補生成、今回 run は非決定的に発火せず。ターゲット挙動自体は決定的＝GET リプレイ 3/3 で 500 + SQLITE_ERROR 再発火を実測済み）。
- **充填の有効性は実 artifact 上で機械的に実証済み**（無変更 gate・無変更 checker）: 0448 run の実候補 `b41d9c6e47cd` に充填・Evidence 記録を適用した finding に対し、① `evaluate_payout_grade`（無変更）→ **PASS / payout_grade_satisfied / marker=sql_error**（未充填は missing_impact）② `SealedReproductionChecker`（無変更・実配線: AsyncNetworkClient + sealed scope）→ **matched / reproduction_marker_matched:sql_error**（実 GET リプレイで sql_error 独立再発火）。＝ **3条件 AND は充填により機械的に充足**（gate・checker いずれも無変更のまま）。
- 完了判定: **(a) は不成立**（confirmed=0）。**計画 (b) の成立条件に最も近い結果** — ただし本 run の confirmed=0 の理由は「再現チェッカーの正当な非マッチ verdict」ではなく「**LLM 駆動 Phase-2 検出が本 run で候補を再生成しなかった**（Phase-2 90s タイムアウト ×5・早期停止、検出経路の非決定性）」であることを**正直に記録**する。バー（payout_grade.py）・再現チェッカーは無変更のまま、充填済み実候補で 3条件 AND の機械充足を実証済み（上記②）。ターゲット挙動の再現性（3/3）は決定的。
- 検証・安全境界: 必須テスト `.venv/bin/pytest tests/core/agents/swarm/injection/ -q` → **567 passed**（新規 12 含む・回帰なし）・`check_vdp_product_independence.py` → **pass / exit 0**（total_token_hits 0）・**payout_grade.py diff 0 バイト**・**sealed_reproduction_checker.py diff 0 バイト**・PCR-P1 対象ファイル無変更（既存テストファイルの変更なし）・secret 生値 0・evidence 非 GET 0・commit なし・master_conductor.py byte-exact 復元済み。
- run 副作用: `data/vuln_roi_db.json` が変更（報告のみ・commit 対象外）。
