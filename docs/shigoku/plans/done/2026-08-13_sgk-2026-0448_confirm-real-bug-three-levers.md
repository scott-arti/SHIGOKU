---
task_id: SGK-2026-0448
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-12_sgk-2026-0447_real-caido-rerun-and-fake-proxy-guard.md
- docs/shigoku/plans/done/2026-08-12_sgk-2026-0445_wire-hybrid-judge-into-swarm-live.md
created_at: '2026-08-13'
updated_at: '2026-08-13'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- confirmation
target: src/core/agents/swarm/injection/manager_internal/execution_policy.py,src/core/agents/swarm/injection/manager.py,src/core/agents/swarm/logic/idor.py
---

# 実装計画: SGK-2026-0448 — 本物の対象で「確定1件」を実際に出すための3レバー

（親ロードマップ: SGK-2026-0442。前提 0447=done で「攻撃が本物の的に届く」土台は固まった。本タスクは「届いた上で、なぜ確定が0のままか」を潰す。）

## 背景（なぜこのタスクが必要か）

- 0447 で偽プロキシ問題を解消し、**本物 Caido（`127.0.0.1:8081`）経由で本物 Juice Shop（`localhost:3000`）に攻撃が届くこと**を実測で確認した（finding 本文がパス依存の本物 JSON/HTML、funnel F0–F6 記録、GET-only を live で強制）。
- それでも `confirmed = 0` のまま。これは偽の的が原因ではなく、**パイプライン内の3つのゲート（レバー）が、証明可能な脆弱性を確定前に落としている**ためと考えられる。0447 の funnel も再び `phase2_skipped_early_return` を示した。
- Juice Shop には「本来 payout-grade で確定できるはずの易しいバグ」（例: ログインの SQLi 認可回避、反射 XSS 等）が存在する。したがって「確定=0」は現状では**検出能力ではなくパイプラインの取りこぼし**の疑いが濃い。これを証拠で切り分けて潰すのが本タスク。

### 用語（平易な言い換え）

- **レバー1「早期終了」**: Phase-1 で候補が出た瞬間に Phase-2（追加検証・裏取り）を打ち切る仕組み。打ち切ると再現裏取りに進めず確定できない。
- **レバー2「impact ゲート」**: 「賞金級」判定は `impact`（実害の説明）と `reproduction_steps`（再現手順）が空だと `missing_impact` で不合格になる。認可系の検出器が impact を空で出すと、ここで確定に届かない。
- **レバー3「再現裏取り」**: `SealedReproductionChecker`（0447/T3 で配線済み）で「もう一度やって本当に再現するか」を確認する工程。ここに到達しないと 3条件 AND の3つ目が埋まらない。

## 目的

本物 Juice Shop に対する封印 run（GET-only・本物 Caido 経由）で、**3条件 AND の確定バーを一切下げず・カーブフィッティングせず**に、少なくとも1件の「本物の確定 finding」を出せるようにする。もし正当な理由で0件のままなら、**各候補がどの実ゲートで・なぜ正しく（fail-closed で）止まったかを候補単位のトレースで示す**（＝バーを下げずに、取りこぼしと正当な保留を区別できる状態にする）。

## スコープを固定するための「現状の切り分け（confirmed vs hypothesis）」

lessons.md `[2026-08] ERROR`（1ファイルの挙動を仕様と断定しない）に従い、着手時点の理解を明示分類する。実装前に **各レバーの実データ根拠を1回の封印 run のトレースで確定**させてから修正する（下記フェーズ0）。

- **[confirmed]** 攻撃は本物の的に届いている（0447 で実測）。
- **[confirmed]** early-return には既に `payout_grade_hold` ゲートがある（`execution_policy.py:96 should_auto_early_return`、SGK-2026-0441 Lane A）。「候補が payout-grade PoC を持たない場合は Phase-2 を走らせる（fail-closed）」設計。`fast_types = {"lfi","redirect","csrf","api"}` は候補が出た時点で早期終了しうる。
- **[hypothesis — フェーズ0で要確定]** 0447 run で `phase2_skipped_early_return` が出たのは、`payout_grade_hold` が False と判定された（＝候補が payout-grade 扱いされた、あるいは hold 条件に該当しなかった）ため。真因は run のトレースで確定する。
- **[hypothesis — フェーズ0で要確定]** 認可系（`idor.py` / access-control）の finding が `impact=''` / `reproduction_steps=[]` で出て `missing_impact` に落ちる（0441 D02）。`idor.py:309/396/549` は `authz_differential` を組むが、impact/repro を埋めているかは要確認。
- **[hypothesis — フェーズ0で要確定]** `SealedReproductionChecker`（`manager.py:1256–1277` で配線）が候補に対して起動していない／起動しても signal 不足で確定に至らない。

## フェーズ0（実装前・必須）: 1回の封印 run で真因を候補単位に確定する

コードを変える前に、本物 Caido 経由・GET-only・`diagnostics.enabled=true` で1回封印 run を実行し、**候補ごとに「どのレバーで止まったか」を1件ずつ**表にする。

- 各 finding について記録: vuln_type / funnel 到達段（F0–F6）/ early-return したか（`phase2_skipped_early_return` の有無）/ payout_grade 判定と reason（`missing_impact` / `no_firing_marker` / `unknown_category` 等）/ reproduction checker が起動したか / 起動した場合の verdict。
- この表で 3レバーの各 hypothesis を confirmed / 否定に更新する。**否定されたレバーは本タスクのスコープから外す**（スコープを推測で広げない）。
- 出力: この計画書の「フェーズ0結果」節に追記し、確定した真因だけを以降の修正対象にする。

## 修正方針（フェーズ0で confirmed になったレバーのみ実施）

> どのレバーも「取りこぼしを止める」方向にのみ変更する。**確定バー（`payout_grade.py` の 3条件 AND）と firing marker 語彙・impact 定義は変更しない**。AI の断定だけで確定に至る経路を作らない。

### レバー1: early-return が Phase-2 を潰す場合
- `should_auto_early_return` の `fast_types`／`payout_grade_hold` 判定を精査し、「payout-grade PoC が未成立の候補があるのに Phase-2 を打ち切る」経路を fail-closed 側へ寄せる。
- 変更は「保留を増やす（Phase-2 を走らせる）」方向のみ。既定 run のバイト等価性が崩れる変更は task_params 越しのオプトインにする。

### レバー2: impact ゲートで認可系が落ちる場合
- 認可系検出器（`idor.py` 等）が `authz_differential` を確立できたケースで、**その差分そのものから** `impact` と `reproduction_steps` を機械的に（LLM なしで）埋める。
- ここでの impact は「認可差分が実在する」という**検出済みの事実**の言語化に限る。新しい確証を捏造しない。`authz_differential` が signals 要件（`auth_success` かつ `unauth_success` 等）を満たさない候補は従来どおり落とす（バーは下げない）。

### レバー3: 再現裏取りに到達しない場合
- Phase-2 に到達した候補で `SealedReproductionChecker` が起動するよう配線の欠落を埋める。
- reproduction が本物の的で成立するために必要な入力（request 再送の GET-only 範囲、scope）を確認する。**GET-only 境界（0447 B4）は維持**。状態変更を伴う再現は行わない。

## 完了条件（完了契約 — 固定）

1. **フェーズ0のトレース表が存在**し、3レバーの各 hypothesis が run 実データで confirmed / 否定に更新されている。
2. confirmed になったレバーの修正が入り、対象ファイルの**確定バー（`payout_grade.py` 3条件 AND）・firing marker 語彙・impact の定義は無改変**（diff で証明）。
3. 本物 Juice Shop への封印 run（本物 Caido・GET-only）で **次のいずれか**を満たす:
   - (a) 3条件 AND を独立に満たす**確定 finding が 1件以上**出る（証拠本文がパス依存の本物・再現 verdict あり）。**または**
   - (b) 依然 0件だが、**候補単位トレースで「各候補がどの実ゲートで・なぜ正しく止まったか」**が示され、いずれもバーを下げれば確定する類ではない（正当な fail-closed）ことが説明できる。
4. 必須テストが全 pass。
5. `check_vdp_product_independence.py` が exit 0（製品トークン 0）。PCR-P1 assertion の diff 0。secret の生値がアーティファクトに残らない。
6. ドキュメント整合: `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` が 0 エラー。

## 必須テスト

- `should_auto_early_return` の payout_grade_hold 分岐（レバー1を触る場合）: hold=True で早期終了しない／全候補 payout-grade で従来挙動、の単体テスト。
- 認可系 impact 埋め（レバー2を触る場合）: `authz_differential` が signals を満たす→impact/repro が埋まる、満たさない→従来どおり落ちる、の単体テスト。
- reproduction 到達（レバー3を触る場合）: Phase-2 到達候補で checker が起動する配線テスト。
- 回帰: 既定 run（オプトイン無効時）のバイト等価性を壊さない。

## NOT in scope（明示）

- 確定バー（3条件 AND）を下げること／firing marker 語彙を増やすこと／impact 定義を緩めること。
- CORS を payout-grade にすること（`cors_misconfiguration` は marker 語彙外＝設計どおり）。
- 状態変更（非 GET）を伴う再現・攻撃（0447 B4 境界を維持）。
- 特定製品（Juice Shop）向けの分岐・スタブ・焼き込み答え（カーブフィッティング禁止）。
- T4=0446（Haddix レポートへの確定/棚上げ/人間送り明記）— 本タスクの後段の別タスク。
- 6件の既存 `test_network_client.py` 失敗（テストスイート健全性、別追跡）。

## リスクと対処

- **カーブフィッティング圧**: 「確定1件」を完了条件(a)に置くと、答えを焼き込む誘惑が生じる。→ 完了条件を (a) **または** (b)（正当な fail-closed の説明）にし、バー無改変を diff で必須化することで、「確定を出す」より「取りこぼしを正す」を優先させる。
- **既定 run への回帰**: レバー1/2 の変更が既存挙動を変える。→ オプトイン化＋バイト等価性テストで隔離。
- **impact 捏造リスク**: レバー2で impact を機械生成する際、実在しない確証を書く危険。→ `authz_differential` の検出済み事実の言語化に限定し、signals 未達は落とす。

## フェーズ0結果（2026-08-13 封印 run: `session_20260813_223445`）

実行環境: 本物 Caido `127.0.0.1:8081`（preflight TCP / GraphQL identity / Forwarding 全 PASS。forward プローブは同一 200 body 75002B >512B → PASS+WARNING で 0447 と同一挙動）・本物 Juice Shop `localhost:3000`・GET-only（evidence の request_method は GET のみ・OPTIONS 17 件が B4 ネットワーク境界でブロック）・`diagnostics.enabled=true`・エントリゲート ON。`verify_report_session_consistency.py` → **consistent**。実行は 1 回。

### 候補単位トレース表（funnel `finding_funnel_v1`・5 候補）

| finding | vuln_type | funnel 到達段 | 早期終了 (F3 skipped / phase2_skipped_early_return) | payout_grade 判定 + reason | firing marker | impact / reproduction_steps | authz_differential (signals) | 再現 checker |
|---|---|---|---|---|---|---|---|---|
| `a222ae4fb040` | broken_access_control | F0→F1→F2→F3→F4（F5 到達なし） | **Y**（ログ: `Early return (phase1_early_return)`） | FAIL / **missing_impact** | `authz_diff`（一致） | 空 / 0件 | Y（`auth_success`+`unauth_success` ほか6） | 起動前に機械フロアで停止（NEEDS_MORE / floor reason） |
| `d10a342af8f2` | broken_access_control | F0 blocked（task_suppressed_ownership）→F1→F3→F4 | 非該当（F0 で抑制） | FAIL / **missing_impact** | `authz_diff`（一致） | 空 / 0件 | Y（同上） | 同上 |
| `438f9bac437c` | cors_misconfiguration | F0→F1→F3→F4 | **Y**（同上） | FAIL / **unknown_category**（設計どおり cors は marker 語彙外） | None | あり / 4件 | なし | 同上 |
| `b7aa7f57bce4` | cors_misconfiguration | F0→F1→F3→F4 | **Y**（同上） | FAIL / unknown_category | None | あり / 4件 | なし | 同上 |
| `67001d154ed0` | cors_misconfiguration | F0 blocked（task_suppressed_ownership）→F1→F3→F4 | 非該当 | FAIL / unknown_category | None | あり / 4件 | なし | 同上 |

funnel summary: `by_stage {F0:5, F1:5, F2:2, F3:5, F4:5, F5:0, F6:0}`・`by_reason {phase2_skipped_early_return: 3, task_suppressed_ownership: 2}`・`total_candidates: 5`。evidence request_method 集計: GET のみ（OPTIONS 17 ブロック・PATCH/POST/PUT/DELETE 0）。

### レバー判定（run 実データによる confirmed / 否定）

- **レバー1（早期終了）: confirmed**。3 候補が F3 skipped（phase2_skipped_early_return）で Phase-2 を打ち切られた。ログは `Early return (phase1_early_return)` ×3 を示し、**legacy フラグ経路**（`manager.py:3249-3252` の `early_return_enabled` 既定 `not phase1_coverage_mode` = bbpt で True → `manager.py:3292` の `(early_return_enabled or auto_early_return)`）が発火。早期終了時点で全候補が F4 evidence_insufficient（再評価でも全 FAIL）＝**payout-grade 未成立の候補があるのに Phase-2 を打ち切っている**。`payout_grade_hold` は `should_auto_early_return`（auto 経路）のみをゲートしており、legacy 経路はホールドされない。
- **レバー2（impact ゲート）: confirmed**。`broken_access_control` 候補 2 件は `authz_differential` が marker 要件（`auth_success` かつ `unauth_success`）を**満たし firing marker `authz_diff` が一致**するが、`impact=''` / `reproduction_steps=[]` のため `missing_impact`（`payout_grade.py:451`）で落ちる。ソース裏付け: `idor.py:300-319`（`_run_unauth_check`）・`387-407`・`540-561` はいずれも authz_differential を組むが Finding に impact / reproduction_steps を設定しない。検出済み事実（認可差分）は存在するのに実害記述が空＝機械フロアの条件3で fail。
- **レバー3（再現裏取り）: 否定**（データ上の配線欠落なし）。T3 hybrid pass は早期終了判定より前（`manager.py:3290`）に全 Phase-1 finding へ実行され、checker は `_t3_apply_hybrid_verdict` 経由で配線済み。今 run の全候補は機械フロア（条件1-3）で `NEEDS_MORE(floor reason)` に落ち、再現段階（`finding_validator.py:224-225`）に到達していない＝上流（レバー1/2）が原因。さらに `authz_diff` は封印単一 GET では再現不能（2 アカウント証明が必要・`sealed_reproduction_checker.py:287-290` marker_not_observable で fail-closed、設計どおり）なため、レバー3 の「配線の欠落」は観測されなかった。→ **本タスクのスコープから除外**。

### 修正設計（confirmed レバーのみ・STEP 2 承認後）

**レバー1**（`manager.py` + `manager_internal/execution_policy.py`）:
- オプトイン `task_params["phase1_early_return_require_payout_grade"]`（既定 False → 既存 run バイト等価）を追加。ON のとき「Phase-1 候補のいずれかが payout-grade 未成立（`payout_grade_hold=True`）」なら legacy 早期終了も保留し Phase-2 を走らせる（fail-closed 方向のみ）。判定ロジックは execution_policy 側に additive ヘルパーを置き、`manager.py:3292` の分岐条件で参照する。
- 単体テスト: hold=True + オプトイン ON → 早期終了しない／全候補 payout-grade + ON → 従来挙動／オプトイン OFF → バイト等価。

**レバー2**（`src/core/agents/swarm/logic/idor.py`）:
- 3 つの authz finding 構築箇所（`_run_unauth_check` / cross_session / id_manipulation）で、`authz_differential.signals` が要件（`auth_success` かつ `unauth_success`、または `status_improved_with_auth`）を**満たす場合に限り**、検出済み事実だけを機械的に言語化して `impact` と `reproduction_steps` を埋める（例: 「未認証で <method> <url> に到達でき、認証あり（status X）→ なし（status Y）の差分が確認された」。手順は実際に送信した GET の method/url/期待 status 差）。signals 未達は従来どおり埋めない（fail-closed・バー不変）。`payout_grade.py` は無変更。
- 単体テスト: signals 充足 → impact/repro が埋まる／未充足 → 従来どおり空のまま落ちる。

**payout_grade.py 無変更の確認**: 本タスクでソースは 1 行も変更していない（git status は run 副作用 `data/vuln_roi_db.json`・`wordlists/custom/learned_params.txt` のみ）。STEP 2 でも `git diff` で 0 を証明する。

## STEP 2 実装（2026-08-13 ユーザー承認後）

**レバー1**（`manager_internal/execution_policy.py` + `manager.py`）:
- `should_early_return_phase2()` を additive 追加。オプトイン `phase1_early_return_require_payout_grade`（既定 False → 既存 run バイト等価）。ON かつ `payout_grade_hold=True`（payout-grade 未成立候補あり）のとき legacy 早期終了（`phase1_early_return_on_findings`）も保留し Phase-2 を実行（fail-closed 方向のみ）。
- `manager.py:3292` の早期終了分岐を同関数へ置換（既定挙動不変）。テスト 5 件追加（hold+ON→早期終了しない／全 payout-grade+ON→従来挙動／OFF→バイト等価 等）。

**レバー2**（新規 `manager_internal/authz_fields.py` + `manager.py` + `idor.py`）:
- `authz_signals_satisfied()`（payout_grade の authz 分岐と同述語・gate ファイルは無変更）と `build_authz_impact_and_reproduction_steps()`（signals 充足時のみ、検出済み事実＝method/url/認証あり・なしの status だけを機械的に言語化。2 分岐: both_ok＝未認証アクセス許可 / status_improved_with_auth＝認証必須。未達は `(None,None)` fail-closed）を追加。
- 配線: manager.py の 3 箇所（`unauthenticated_api_access` / `unauthenticated_discovered_api_access` / `authenticated_overposting_requires_auth_context` — status 役割を明示渡し）。**object_ab_idor_probe は両プローブ認証済みのため配線しない**（`unauth_success` トークンが誤発火し偽の「未認証許可」impact を捏造するのを防ぐガード。実測で発見・修正）。idor.py は `_run_unauth_check` のみ配線（cross_session / id_manipulation は semantics 不一致のため配線せず）。
- テスト: 新規 `test_authz_fields.py`（helper 2 分岐・未達系・idor 配線）。**payout_grade.py diff 0**。

## STEP 3 確定 run（session_20260813_232923・本物 Caido・GET-only・オプトイン ON）

- 実行方法: `master_conductor.py` の 2 タスク生成箇所（scenario_probe params / signal_task_params）へ一時的に `phase1_early_return_require_payout_grade: True` を追加 → run 後 **byte-exact 復元**（sha256 `f923709f…` 一致・git diff 0）。`verify_report_session_consistency.py` → **consistent**。
- funnel: `by_stage {F0:5, F1:5, F2:2, F3:5, F4:3, F5:0, F6:0}`・`by_reason {task_suppressed_ownership: 2, phase2_skipped_early_return: 1}`（**フェーズ0 の 3 → 1**）。evidence request_method は GET のみ・OPTIONS 17 件境界ブロック。

### 候補単位のゲート変化（フェーズ0 → STEP 3）

| finding | vuln_type | フェーズ0 | STEP 3 | ゲートの理由 |
|---|---|---|---|---|
| `d10a342af8f2` | broken_access_control | FAIL missing_impact（F0 抑制） | **PASS payout_grade_satisfied**（impact+repro 3 機械埋め・実 URL `/api/Challenges/`・200/200） | F4 reached→T3 再現 not_run（authz_diff は2アカウント証明が必要・設計上 fail-closed）→ needs_more→parked |
| `a222ae4fb040` | broken_access_control | FAIL missing_impact・早期終了 | **PASS**（`/api/Quantitys/`・200/200）・F4 reached | 同上 |
| `438f9bac437c` / `b7aa7f57bce4` / `67001d154ed0` | cors_misconfiguration | early_return 2 / F0 抑制 1 | **Phase-2 実行**（F3 reached・早期終了なし。残 1 は全候補 payout-grade タスクのみ） | unknown_category（marker 語彙外・NOT in scope 設計） |
| `b41d9c6e47cd` | sqli | —（Phase-2 無効のため生成されず） | **Phase-2 で新規生成**。実 Payload（`/rest/products/search?q=' OR '1'='1' --`）で 500 実応答・marker `sql_error` 発火・PoC 対完備 | impact 空 → **missing_impact**（新規観測・deferred D01） |

### 完了判定（条件3）

- **(a) 確定 finding**: 0 件（F5:0・confirmed_count 0・誤確定ゼロ維持）。
- **(b) 候補単位 fail-closed 説明（採用）**: ① authz 2 件は 3条件AND のうち機械フロア（条件1-3）を満たすまで改善したが、**再現裏取り（条件3のAND 第3要素）は authz_diff が単一封印 GET では再現不能**（2アカウント証明・`sealed_reproduction_checker.py:287-290` 設計 fail-closed）→ needs_more→parked。バーを下げれば確定する類ではない。② cors 3 件は marker 語彙外（計画 NOT in scope 明示）。③ sqli 1 件は impact 欠落による missing_impact（正当な fail-closed 保留。機械的埋め拡張＝deferred D01 で同一バーのまま対処可能）。いずれも「バーを下げれば確定する」類ではない。
- Haddix 初期リリースゲート: **fail**（`confirmed_below_minimum` / `candidate_above_maximum` / `unexpected_missing_scenarios` 4 件＝phase-0 と同一セット）。ゲートは fail-closed 設計であり本タスク契約 (b) と整合（ゲートポリシー変更はスコープ外）。

### 検証・安全境界

- 必須テスト: `.venv/bin/pytest tests/core/agents/swarm/injection/ -q` → **555 passed**（test_execution_policy.py 5 件追加・test_authz_fields.py 新規・test_payout_grade.py 等無変更で全 pass）。
- `check_vdp_product_independence.py` → **pass / exit 0**（6/6・total_token_hits 0・変更 5 ファイル走査）。
- **payout_grade.py diff 0 バイト**・PCR-P1 対象ファイル無変更・secret 生値 0・evidence 非 GET 0・commit なし・master_conductor.py byte-exact 復元済み。
- run 副作用: `data/vuln_roi_db.json` / `wordlists/custom/learned_params.txt` が変更（報告のみ・commit 対象外）。

### 完了契約判定

| 条件 | 判定 | 証拠 |
|---|---|---|
| 1. フェーズ0トレース表 + 各レバー confirmed/否定更新 | ✅ | 本計画書「フェーズ0結果」節 |
| 2. confirmed レバー修正 + payout_grade.py 無改変 | ✅ | 上記 STEP 2・diff 0 |
| 3. 封印 run で (a) 確定1件以上 または (b) 候補単位 fail-closed 説明 | ✅ (b) | 上記 STEP 3 |
| 4. 必須テスト全 pass | ✅ | 555 passed |
| 5. 安全境界（vdp 独立 exit 0 / PCR-P1 diff 0 / secret 0） | ✅ | 上記 |
| 6. docs 整合（sync → validate 0 エラー） | ✅ | 閉鎖時実行 |
