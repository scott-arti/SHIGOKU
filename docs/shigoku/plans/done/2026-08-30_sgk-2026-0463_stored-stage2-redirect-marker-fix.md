---
task_id: SGK-2026-0463
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-30_sgk-2026-0462_canonical-save-endpoints-wiring.md
- docs/shigoku/reports/2026-08-30_sgk-2026-0462_canonical-save-endpoints-wiring_work_report.md
created_at: '2026-08-30'
updated_at: '2026-09-01'
tags:
- shigoku
- vdp
- detection
- xss
- stored
---

# SGK-2026-0463 計画書 — 保存型XSS第2段階の303-redirect誤早期リターン修正（検出側 smart_xss）

## 目的（Objective）

SGK-2026-0462 の実走行（session_20260830_050641）で第2段階（`_attempt_stored_revisit_validation`）は起動するようになったが、**ブラウザ dialog が未観測**のままである。この残ギャップ（検出側 smart_xss の marker チェックと練習台の 303-redirect 設計の相互作用）を修正し、練習台5008 フル走行で **formal confirmed=1（variant=stored・dialog_observed=True）** を到達させる。

## 背景・真因（2026-08-30 実走行＋コード引用で確定）

SGK-2026-0462 実装後フル走行（session_20260830_050641・練習台5008）:
- `xss_seed_d821ddcb` タスクの `_context` に save_endpoints（/comment POST・revisit_urls 6件）が実在 → method=POST 解決 ✓ → 第2段階起動 ✓（04:36:39 に marker POST + `GET /` `GET /account` `/account/profile` `/account/settings` `/dashboard` `/profile` の全6 revisit URL スイープを観測。旧 session_20260830_002046 では marker POST 0件）。
- しかし `Dialog detected` 0件・browser_execution 0件・variant=stored 0件・**Confirmed 0 / Candidate 129**（全件 real_http・browser_execution_missing）。

真因チェーン（引用）:
1. 練習台5008 の `POST /comment` は `redirect("/", code=303)` を返す（この応答自体には反射しない設計）。
2. `_attempt_stored_revisit_validation`（smart_xss.py:821-824）の marker チェック: `resp_body` に marker が含まれれば False（既存反射/同一URL保存経路へ委譲＝設計）。
3. smart_client は aiohttp 既定で 303 を follow → 実効レスポンス本文 = `GET /` ページ = **保存済み marker を描画** → marker チェックが by-design で早期リターン。
4. 委譲先の既存経路（deterministic precheck）は `_detect_xss_variant("/comment")` = "generic"（xss_s パスでない）→ `_validate_reflected_runtime_xss` → `GET /comment` → **405** → dialog 不可 → browser_evidence 不在 → SGK-2026-0461 確認フロー不起動 → Confirmed 0（fail-closed として正しい）。

位置づけ: これは**検出側（smart_xss）ロジック**の課題であり、SGK-2026-0462 の計画 NOT in scope（「検出側 smart_xss/injection ロジックの変更」「SGK-2026-0461 の確認フロー（B）変更禁止」）に該当するため、別タスクとして起票する。確定バー5ファイル・SGK-2026-0461 の B 実装・save-endpoint 発見ロジック（サイドカー）はいずれも無改変。

## 完了契約（Fixed completion criteria）

- CB-1: 練習台5008 フル走行（Caido 8081・Juice Shop 起動下）で保存型XSSが variant=stored・dialog_observed=True の browser_evidence を生成し、SGK-2026-0461 確認フローを経て **formal confirmed=1**、consistency=consistent、混入0。
- CB-2: 確定バー5ファイル無改変（`git diff --quiet HEAD` で exit 0）。判定・閾値の緩和なし（カーブフィッティング禁止）。SGK-2026-0461 の確認フロー（B）変更禁止。
- CB-3: 製品非依存 token0（テストにも DVWA/juice 等のパス片 NG・汎用 `/app/...`）。DVWA 既知安全保留不変（5候補・reason code）。新規/変更ユニット緑。

## 実装方針（確定済み）

**方針1の精密版を採用（2026-08-30 実装完了・DeepSeek）**: `_attempt_stored_revisit_validation` の marker POST（smart_xss.py:807-813 相当）を **`allow_redirects=False`** で送る。

- 追従せず「POST 応答自体が marker を反射するか」だけを見る＝本来の意図どおりの判定になる。
- 3xx を返す保存sink では marker 非反射 → revisit スイープへ進む → 反射 URL 発見 → 実 payload 保存 → `_validate_stored_runtime_xss` で dialog 観測へ到達できる。
- 挙動変化は「3xx を返す保存sink」に限定（200 で反射する sink は従来どおり早期リターン・200 非反射・GET 系も従来どおり）＝追加的で安全。
- fire POST（実 payload 再保存）は現状維持（追従可・その後 reflection_url をブラウザで開くため）。
- 実装: `src/core/agents/swarm/injection/smart_xss.py`（+8/-2・コメント含む）・回帰テスト3件追加（`tests/core/agents/swarm/injection/test_smart_xss_stored_revisit.py` T4/T5/T6）。
- 代替案（3xx スキップ）は不採用（1方針のみ・最小）。

## 検証結果（2026-08-30・DeepSeek 実施分）

- 単体: `test_smart_xss_stored_revisit.py` 8 passed（既存5 + 新規3）。smart_xss 関連 33 passed・injection 全体 632 passed・統合 5 passed。
- DVWA gate: `status: fail` / `reason_codes: ["candidate_above_maximum"]` / candidate_count=5（既知安全保留・不変）。consistency=consistent。
- バー5: `git diff --quiet HEAD -- <バー5>` → **BAR_UNCHANGED**。
- token0: `check_vdp_product_independence.py` → `verdict: pass` / `total_token_hits: 0`。
- 実走行（CB-1）: **Claude 独立再検証で最終確認**（環境: 練習台5008・Caido8081 稼働確認済み 200/200）。

## Claude 独立確認（2026-08-30・単独再現で真因裏取り）

計画書の真因（303追従→marker早期リターン）を額面で信用せず、生きた練習台5008へ単独HTTP再現で裏取りした（`aiohttp` 直叩き）:
- [A] `POST /comment` を **allow_redirects=True（smart_client 既定・network_client.py:317 の request が kwargs 未指定で aiohttp 既定 True）** で送信 → status=200・final_url=`/`・**marker_in_body=True**。→ `_attempt_stored_revisit_validation`（smart_xss.py:817）の marker-in-POST-response チェックが誤発火し早期リターン False（＝反射経路へ委譲）を確認。
- [B] `allow_redirects=False` → 303・**marker_in_body=False**（POST応答自体は反射しない＝正しく判定できる）。
- [C] `GET /` は保存 marker を描画（発火面は健全）。 [D] `GET /comment`=405（反射委譲先が失敗）。
- 結論: **真因確定**。推奨修正は方針1の精密版＝marker POST（smart_xss.py:807-813）を `allow_redirects=False` で送る（POST応答自体の反射のみを見る本来の意図に一致・3xx保存sinkでスイープへ進める）。挙動変化は「3xxを返す保存sink」に限定＝追加的・安全。実装は DeepSeek・Claude が独立検証（本計画 L60 を更新）。

## NOT in scope

- 確定バー5ファイル・SGK-2026-0461 の確認フロー（B）・save-endpoint 発見ロジック（サイドカー）の変更。
- browser_evidence 以外の evidence type の昇格。発火判定・確定基準の緩和。

## ガードレール

- カーブフィッティング禁止・判定緩め禁止・製品非依存 token0・DVWA 既知安全保留と既存ゲートテストでの回帰確認必須。
- 破壊的操作前に対象確認。commit は検証後・push はユーザー。Caido=127.0.0.1:8081。
- コーディングは DeepSeek、Claude が独立検証（単体・実走行 confirmed=1・DVWA gate・バー無改変・token0）。

## Claude CB-1 実走行検証（2026-08-31）

DeepSeek の 0463 実装を独立検証（バー無改変・修正=marker POST に allow_redirects=False・単体8 passed・token0）した上で、練習台5008 フル走行を実施:
- run session_20260831_094944: **Confirmed 0 / Candidate 66**（全件 real_http・browser_execution_missing）・consistent。dialog 未観測のまま。

**単独・直列の末端再現で真因を確定（アプリ側のテスト設計要因・SHIGOKU欠陥ではない）**:
実装済みロジック相当（修正後 allow_redirects=False の marker POST → GET / スイープ → payload 保存 → `PlaywrightValidator.validate_xss`）を **直列**で live 5008 に対して再現 →
1) marker POST=303・本文に marker なし（修正動作）✓
2) GET / スイープで marker 発見 → reflection_url=/ ✓
3) payload POST → GET / に payload 描画 ✓
4) **`PlaywrightValidator.validate_xss('/')` → dialog_executed=True** ✓

→ **0463 修正は正しく、保存型XSSの検出＋ブラウザ確認は末端まで機能する**（dialog 実発火）。フル走行で Confirmed 0 なのは、練習台 `practice_stored_xss.py` が **最新1件のみ保持（`_comments[:] = [c]`）** のため、フルパイプラインの**並行実行**下で fire POST（payload 保存）とブラウザ再訪の間に別タスクの POST が単一コメントを上書きし、ブラウザが payload を描画しないまま観測に至る**競合（race）**。これは**テスト用練習台の過剰簡略化**による人工的競合であり、実在のゲストブック（各コメントを保持）では発生しない。SHIGOKU コード側の欠陥ではない。

**（暫定・後に訂正）残作業**: 練習台を retain-all へ修正し再走行 → 下記のとおり retain-all でも Confirmed 0 のままで、真因は競合ではなかった。

## 真因の訂正（2026-08-31・retain-all 再走行＋smart_client 直検証で確定）

retain-all 練習台（直近200件保持）で再走行（session/report haddix_report_20260831_103022）→ **Confirmed 0 / Candidate 108**・全件 browser_execution_missing・consistent。第2段階スイープは 612 回走った（練習台v2ログ）が、走行ログに `Dialog detected` 0件・`Stored reflection observed` 0件・playwright_validator 活動0 → `_attempt_stored_revisit_validation` はスイープ後 **:834（reflection_url 見つからず）で False** 終了しブラウザ段へ未到達。→ **「並行上書き競合」説は誤り**（retain-all で解消したはずが不変）。

**確定した真因（smart_client 直検証）**: スイープの GET（smart_xss.py:825 `self.smart_client.request("GET", cand, ...)`）が **`use_cache` 既定 True（network_client.py:328・TTL 300s）**。フルパイプラインでは事前クロール/検出で GET `/` が既にキャッシュ済み → marker POST 後のスイープ GET が**古いキャッシュ本文（marker なし）**を返す → marker 未発見 → reflection_url 空 → :834 で False。
- 実証: 実ハンターの smart_client で「GET /（キャッシュ充填）→ POST marker → GET /」= `use_cache` 既定 → **marker_found=False**／`use_cache=False` → **marker_found=True**。
- 単独再現（前セクション）が成功していたのは **フレッシュ接続でキャッシュ未充填**だったため。実パイプラインの状態を再現できていなかった。

**位置づけ**: これは**検出側 smart_xss の実バグ**（書込直後の再訪検証はキャッシュを使ってはならない）。確定バー・0461・0462・save-endpoint 発見・retain-all 練習台のいずれとも独立。

**修正（最小・加算）**: `_attempt_stored_revisit_validation` のスイープ GET（smart_xss.py:825）に **`use_cache=False`** を付す（書込直後の反射確認は常に実取得）。marker POST / fire POST（:808/812/842/846）は POST でキャッシュ対象外だが、防御的に確認する。挙動変化は保存型再訪スイープに限定・追加のみ。判定/閾値/fail-closed 不変。

**実装（2026-09-01・ユーザー指示 B により Claude が直接実施・最小1点）**: `smart_xss.py` の保存型再訪スイープ GET に `use_cache=False` を追加（+6/-1・コメント含む）。

## CB-1 達成（2026-09-01・Claude 実走行検証）— 目標完了

キャッシュ修正後、クリーン練習台5008（retain-all・Caido8081・Juice Shop起動下）でフル走行（`SHIGOKU_RECON_ACTIVE_POST_ENABLED=true`）:
- report `haddix_report_20260901_005408.md` / session `session_20260901_005406.json`: **Confirmed: 1 / Candidate: 189**・**consistency=consistent**。
- 確定 finding: variant=stored・**dialog_observed=True**・**hybrid_final_state=confirmed**（凍結バー：機械フロア payout_grade + poc_judge + 封印再現の3条件AND を正当通過）。レポート影響文「XSS payload executed in a real browser: dialog observed via parameter 'comment' with payload `<img src=x onerror=alert(1)>` (variant=stored)」。
- 走行ログに `Dialog detected! alert` 複数（前回まで0件）→ キャッシュ修正が実パイプラインで発火経路を復旧。
- **修正効果の単独実証**: キャッシュ充填（＝壊れていた条件）で実 `_attempt_stored_revisit_validation` → 修正前 False / 修正後 **fired=True・dialog_observed=True・variant=stored**。

### 完了契約の判定
- **CB-1: 達成** — formal confirmed=1（variant=stored・dialog_observed・hybrid_final_state=confirmed）・consistent・SGK-2026-0461 確認フロー通過。
- **CB-2: 達成** — 確定バー5ファイル `git diff --quiet HEAD` = BAR_UNCHANGED。判定・閾値の緩和なし（キャッシュ回避のみ）。
- **CB-3: 達成** — 製品非依存 verdict=pass/token0。DVWA 既知安全保留不変（status=fail/candidate_above_maximum・5候補）。stored_revisit 単体 8 passed。

deferred（非阻害）: Candidate=189 のノイズ（同一 comment/name パラメータXSSの重複多数）。CB-1 を妨げない reporting/dedup の課題として別途検討。SGK-2026-0461 の当初 CB1（保存型 formal confirmed=1）も本走行で実証達成。
