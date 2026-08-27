---
task_id: SGK-2026-0459
doc_type: plan
status: active
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-22_sgk-2026-0458_stored-xss-firing-path.md
- docs/shigoku/plans/done/2026-08-22_sgk-2026-0457_stored-xss-confirmation.md
- docs/shigoku/plans/2026-08-28_sgk-2026-0460_cross-target-state-isolation.md
created_at: '2026-08-22'
updated_at: '2026-08-28'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- discovery
- xss
- stored
- recon
- browser
---

# SGK-2026-0459 計画書 — 能動的な保存 sink 発見（保存型 XSS を実際に確定まで到達）

## 目的（Objective）

保存型 XSS を **実際に confirmed=1件以上** まで到達させる。SGK-2026-0457（確定ゲートの stored 分岐）と SGK-2026-0458（検出側の stored 発火経路・`reflection_url` 動的算出）はいずれも完成・検証済みだが、実走行で保存 sink（例: レビュー保存 API）が **XSS の stored 経路へ渡らず**、完成済みの stored 経路が発火機会を得られなかった。本タスクは上流の **能動的な保存 sink 発見**（入力操作で書き込み API・項目・再訪表示URLを炙り出す）と **挙動ベースの dispatch 結線** を製品非依存に実装し、0458/0457 の完成経路へ受け渡して confirmed=1 を実証する。SHIGOKU の本質価値である「製品非依存に保存 sink を能動発見できる能力」を伸ばすことが主眼であり、単一製品への過学習も能力の過小化も採らない。

## 背景・真因（SGK-2026-0458 実走行＋実コード引用で再特定・2026-08-22）

> 注記: 当初の 0458 報告では真因を「受け身の偵察なので投稿しない」と記していたが、実コード確認の結果これは不正確だった。以下が引用で確定した実際の欠落である。

- **crawler は既に能動的**: `src/tools/custom/playwright_recon.py` は `_exercise_forms`（`<form>` にダミー値を入れて `requestSubmit`）・`_exercise_post_login_actions`（`[data-testid]`/`[aria-label]`/`input[type=submit]`/`[role=menuitem]`/`nav a` を click）・`_exercise_clickables` を既に実行し、XHR/Fetch を `on_request`/`on_response` で傍受して `endpoints`/`methods_by_url` に収集する。よって「投稿しない」ではない。
- **真の欠落（三点）**:
  1. **多段 SPA 操作の未対応**: Juice Shop のレビュー投稿は `<form action>` ではなく Angular のダイアログで、商品を開く→ダイアログ表示→textarea 入力→送信、という多段操作を要する。現状の `_exercise_forms` は `<form>` 限定、`_exercise_post_login_actions` は単発 click で、この多段経路に到達しないため保存 API が XHR に現れない（実走行: 発見 URL 105 件・api/rest 7 件に保存 API 0 件）。
  2. **マーカー追跡不可**: 現状のダミー値は固定 `'test'` 等で、どの投稿がどの再訪反射かを一意に照合できない。stored 判定には一意マーカーの往復照合が必須。
  3. **dispatch 分類のギャップ**: 仮に保存 EP を捕捉しても `classify_target_url`（`src/core/agents/swarm/injection/manager_internal/target_classifier.py`）は URL/path/param のみで判定し、`/api/…`→"api"・`/rest/products/N/reviews`→"unknown" となり **決して "xss" に回らない**。さらに unknown 分岐は `build_unknown_hypotheses`（`manager_internal/unknown_hypotheses.py`）で `/reviews` が "view"⊂"reviews" の部分一致により **lfi 仮説**へ化け、かつ unknown 分岐は既定 `unknown_classification_only=True`（`manager.py:3965-3967`）で攻撃を実行しない。0458 の stored 経路は `method=="POST"` かつ `revisit_candidates` あり かつ `reflection_url` 無し で発火するが、発見メタからこの起動ゲートへ渡す配線が存在しない。
  4. **起動ゲートの verb 不適合（フェーズ0新発見）**: 0458 の起動ゲート（`smart_xss.py:1237-1241`）は `method=="POST"` 固定。だが Juice Shop のレビュー作成は **PUT `/rest/products/{id}/reviews`**（フロントの ProductReviewService `create()`＝`http.put`）であり、投稿の verb が POST でないためゲートは起動しない。加えてゲートは param ループ内にあり **項目名（candidate_params）が最低1つ**無いと評価されない（`/reviews` は query 無し・form 無しで空）。
- **書き込みガードの穴（安全境界の再定義が必要）**: `sealed_run_get_only`（`src/core/config/settings.py` / `src/core/infra/network_client.py:441-469`）は **`AsyncNetworkClient` 内だけ**で強制される。能動投稿の実体はブラウザ操作（Caido 8081 直行、`page.route` 未設定）であり、この経路は guard を通らない。0458 の検証 POST 自体は `smart_client`（AsyncNetworkClient）経由なので GET-only 時は正しくブロックされるが、**発見側のブラウザ操作と将来のブラウザ保存操作は素通し**。したがって本タスクで browser 経路にも GET-only 強制を新設する必要がある。
- 完成済みで本タスクでは判定として壊さない: 0457 確定ゲート（`sealed_reproduction_checker.py`）、0458 検出側 stored 経路（`smart_xss.py` の `_derive_revisit_candidates`／`reflection_url` 算出／マーカー→巡回→ブラウザ発火）。本タスクは **発見側（recon/discovery）・dispatch 結線・安全境界** が主。

## フェーズ0（診断・実装前の必須ゲート）

1. **発見サブシステムの所有箇所を引用特定**: `src/tools/custom/playwright_recon.py`（能動 exercise の本体：`_exercise_forms`/`_exercise_post_login_actions`/`_exercise_clickables`／XHR 傍受）、`src/core/agents/swarm/discovery/manager.py`（`run_playwright_recon` 呼び出し・結果集約）、injection manager への受け渡し（`manager.py` の `url_results` → `_same_origin_revisit_candidates` → XSS params）。lessons: 一ファイルの挙動を仕様と断定しない。
2. **「なぜ現状の exercise で保存 API が出ないか」を実走行ログで一次証拠確定**: 0458 正本 `session_20260822_102243.json` を再点検し、click/submit の痕跡・到達ページ・捕捉 EP を実測して、欠落が「多段操作未到達」であることを裏付けてから実装に入る（推測で実装しない）。
3. **実走行前提の実測**: レビュー投稿が認証必須か（未認証で保存 sink が現れるか）を先に実測・記録し、認証がスコープ内か別タスクかを確定する。
4. **0458 起動ゲート適合の引用照合**: 能動発見の出力（保存 EP・項目・再訪候補）が 0458 の起動ゲート（`method=="POST"` ＋ `revisit_candidates` ＋ `reflection_url` 無し）と引数形まで適合するかを照合。不適合なら 0458 側の追加改修要否を先に判定し、C4（判定バー無改変）と矛盾しない scope を確定する。
5. **安全境界の設計担保（両経路）**: browser 経路の GET-only 強制（Playwright `page.route` で非 GET/HEAD を `abort`、または get_only 時は能動 exercise を無効化）を設計し、network_client 経路と合わせ二重で担保。能動投稿は許可ホスト（127.0.0.1・localhost 練習台）限定・良性一意マーカー・件数上限・冪等寄り。機微データ書換・破壊操作・大量書込み禁止。
6. **製品非依存・挙動ベースの発見契約を固定**: 「(a) テキスト系入力を持つ操作を実行 → (b) 発生した非 GET リクエストを URL・メソッド・項目として捕捉 → (c) レスポンス/後続 GET に **同一マーカー文字列** の反射を探索」。特定 selector/route/製品名/ホスト名の焼き込み禁止。
→ フェーズ0を提出・レビュー承認後に実装。

### フェーズ0 実施結果（2026-08-26・DeepSeek 診断＋Claude 独立検証・実装なし）

DeepSeek が診断レポート（A–G）を提出し、Claude が実コード・整合済み session を直読して独立検証した。過去に不正確報告があったため主要主張を file:line で突き合わせた結果、**今回は概ね正確**と判定。

- **確認できた（Claude 実物照合）**:
  - 起動ゲートは `method=="POST"` 固定（`smart_xss.py:1237-1241`）。Juice Shop は `_detect_xss_variant`→"generic" で POST に昇格しない（`smart_xss.py:239-247, 1055`）。
  - `/reviews` は `build_unknown_hypotheses` で "view"⊂"reviews" により lfi 仮説化（`unknown_hypotheses.py`・`'view' in 'reviews'==True` を再現）。unknown 分岐は既定 `classification_only=True`（`manager.py:3965-3967`）で攻撃せず。
  - 再訪在庫 `current_context["url_results"]` は空初期化（`manager.py:2846`）＝注入側が自ら攻撃した URL しか入らず、発見側の保存/表示 URL は入らない（`_same_origin_revisit_candidates`:4241 は構造比較のみで製品非依存だが供給元が誤り）。`resolved_method` 既定 GET（`manager.py:2968-2971`）。
  - crawler は既に能動（`_exercise_forms` は `<form>` 限定・固定値 'test'、`_exercise_post_login_actions` の keyword に "review"/"product" 無し、`methods_by_url` 単一上書き、common_paths に商品詳細パス無し＝多段未到達）。
  - 整合済み session `session_20260822_102243.json` 実測: `"method"` は GET 248・空 132・**書き込み系 0 件**、レビュー保存 API（`/rest/products/N/reviews`・`/api/ProductReviews`）**0 件**。attempted=0/confirmed=0。
- **妥当だが Claude 未完全確認（結論不変）**: 投稿の verb が **PUT**（Juice Shop の既知挙動と一致。verb が POST でない事実だけで「ゲート不適合」の結論は成立）。DeepSeek の「PATCH 試験通信あり」の細部は Claude の集計では未確認（結論に非影響の軽微ズレ）。
- **認証前提**: 未認証でもレビューの保存・表示が成立（DeepSeek 実測）。→ 認証付き sink の一般化は本タスク **スコープ外**（別タスクで追跡）。
- **副作用の開示（正直な記録）**: フェーズ0 の良性プローブで **ローカル練習台（localhost:3000）に良性レビュー 1 件が残存**（マーカー `sgk0459-auth-probe-8f3a2c`）。指示で許可した範囲（ローカル練習台・良性・最小）内だが状態を1つ変えた事実として記録。所有者認証必須のため未認証では削除不可・無害・追跡可能。これは「ブラウザ経路に GET-only 強制が無い」穴を実証しており、実装で最優先に塞ぐ。

## 前半（到達・書き込み）の製品非依存手順と中間ゲート

本タスクの難所は「入力画面まで届いて操作し、印を書き込む」前半である（表示を探す後半は 0458 で完成済み）。前半を **決め打ち（特定製品・部品名・ルートの焼き込み）を一切使わず、振る舞いと位置関係だけ** で実現する。人間が「どこを押せば書き込めるか探る」動きをそのまま挙動ベース化する。

**一般手順（4手・全て振る舞いベース）**:
1. **可視な入力面の棚卸し**: 現ページの入力できる面（`textarea`／テキスト系 `input`／`[contenteditable]`）を列挙。無ければ手2へ。
2. **隠れた入力面を“出す”探索**: クリック可能要素（`a`/`button`/`[role=button]`/一覧・カード様要素）を1つ操作し、**操作前後の入力面集合を差分比較**して「新たに入力面/ダイアログが出現したか」を検知（＝到達の合図）。出なければ戻して別要素。**回数・深さ(1〜2段)・制限時間の上限**を課し、少ないクリックで出た面を優先。
3. **一意マーカー投入と送信**: 各入力面に **面ごとに異なる** 一意マーカー `sgk<hex>` を投入し、その入力面と **構造的に紐づく送信手段**（同一 form/ダイアログ内の送信ボタン、または Enter）で送信。送信ボタンは名前でなく **包含・近接（位置関係）** で選ぶ。
4. **書き込み通信の捕捉**: 送信で発生した **非 GET リクエスト** を記録し、本文に投入マーカーが含まれれば、それが「保存 EP＋項目名」の正体（検問Aの証拠）。以後は 0458 の後半（印の往復探索）へ受け渡す。

**未到達は未発見の規律（偽の成功を作らない）**: 手2で入力面が出ない／手4で書き込み通信が観測できない場合は **「未発見」** として記録し、`dialog_observed` や stored finding を **一切付けない**。届かないことを成功に見せかけない。

## 中間ゲート（段階証明・原因不明の全滅を防ぐ）

前半（難所）の直後に **検問A** を置き、鎖の各段を実データで一つずつ証明してから次へ進む。前半そのものは「作業」、検問は「その作業ができたかの合否確認」であり別物。

- **検問A（到達・書き込みの証明）**: 実走行で「一意マーカー入りの非 GET 書き込みが最低1回発生し、保存 EP と項目名を捕捉した」ことを session の記録で確認。**通れば「届く問題」は解決と断定**。通らなければ発火の作り込みに進まず前半だけを直す。
- **検問B（表示の証明）**: 同一マーカーが同一オリジンの別ページに表示（反射）されたことを確認（0458 の後半・完成済み経路）。
- **検問C（発火・確定）**: マーカーを本物のペイロードに替え、ブラウザ実 dialog 発火 → 0457 で confirmed=1（＝C1c）。

## 完了契約（Fixed completion criteria）

段階分割: C1 を C1a/C1b/C1c に分解し、各段に検証可能な価値と正本を紐付ける（失敗点の集中を避ける）。C1a〜C1c は上記 検問A〜C に1対1で対応する。

- **C1a（能動発見・検問A）**: 上記4手（可視入力面の棚卸し→隠れた面を差分検知で“出す”→面ごとに一意マーカー投入→送信で発生した非 GET 書き込みと項目名を捕捉）で保存 sink（書き込み EP・項目・再訪表示URL 候補）を製品非依存に捕捉できる。捕捉は一意マーカー `sgk<hex>` で往復照合可能。**未到達は未発見として記録し偽の成功を作らない**。
- **C1b（dispatch 結線）**: 捕捉した保存 sink が、path 名に依存せず **挙動ベース** で XSS の stored 候補として 0458 経路へ渡る。フェーズ0 で判明した3つの不適合を解消する: (i) 起動ゲートの verb 条件を `method=="POST"` から **非 GET（POST/PUT/PATCH）** へ拡張（追加のみ・判定本体不変。検証本体はマーカー方式で verb 非依存）、(ii) 発見側が **項目名（input 名）** を供給し candidate_params を満たす、(iii) `revisit_candidates` の供給元を注入側 `url_results`（自己履歴）から **発見側の保存EPと同一オリジンの捕捉URL一式** へ是正。実走行で非 GET 保存 sink の XSS タスク node が生成されることを session 直読で確認。
- **C1c（stored 発火・確定）**: Juice Shop の保存型 XSS が、Caido(8081) 経由の実走行で能動発見された保存 sink から `variant="stored"`・`dialog_observed=true` の finding として生成され、0457 の reproduction stored 分岐を通って **confirmed=1件以上**。正本 session/report を残し `verify_report_session_consistency` = `consistent`/`rerun_required=false`。
- **C2（製品非依存・過学習排除）**: 保存 sink 発見と結線は製品非依存（`check_vdp_product_independence.py` verdict=pass・token0・特定 sink/route/製品名/selector の焼き込み禁止）。加えて **2つ目の stub/別練習台** での発見テストが pass し、単一製品特化でないことを構造的に担保。発火しない候補・マーカー未反映候補に `dialog_observed` を付けない（偽陽性なし）。
- **C3（退行なし）**: 既存の発見・検出（反射型/DOM 型 XSS、他 vuln の recon/dispatch）に退行なし。能動発見はフラグ/上限でオプトインし既定挙動を不変に保つ（既存テスト緑・recon 件数・既存 finding 不変）。
- **C4（判定バー無改変）**: `payout_grade.py`/`poc_judge.md`/`task_queue.py`/`finding_validator.py` の判定ルール本体、`sealed_reproduction_checker.py` の 0457 実装、`smart_xss.py` の 0458 検出側 stored 経路を判定として壊さない。本タスクは発見側・dispatch 結線・安全境界が主。**許容される最小改修**: 0458 起動ゲートの verb 条件を `method=="POST"`→**非 GET（POST/PUT/PATCH）** へ広げる追加変更は、検証本体（マーカー往復→反射探索→実 dialog 発火）を一切変えず起動条件を広げるだけであり「判定を壊す」に当たらない（既存の反射型/DOM 型・GET 既定挙動は不変。既存テスト緑で担保）。確定バー本体（5ファイル）は無改変を維持。
- **C5（テスト）**: 新規/変更ユニット全 pass。HEAD 既知失敗以外の新規失敗なし。
- **C6（安全境界・両経路）**: 能動的入力の安全境界を満たす。**network_client 経路と browser 経路の両方で GET-only 強制**（GET-only 時は非 GET をブロック／能動 exercise 無効化）。良性・最小・一意マーカー・許可ホスト（127.0.0.1・localhost 練習台）限定・件数上限、機微データ書換/破壊なし、秘密の生値を成果物に残さない。

## 必須テスト（Required tests）

- **T1（能動発見・C1a）**: 4手の能動発見（可視入力面の棚卸し → クリック前後の差分で隠れた入力面/ダイアログの出現を検知 → 面ごとに一意マーカー投入 → 送信で発生した非 GET 書き込みと項目名を捕捉）が製品非依存の任意 stub ターゲットで機能する（ユニット・stub・特定ルート/selector 非依存）。**到達不可時は「未発見」を返し finding を作らない**回帰を含む。
- **T-reach（検問A・到達の実証・C1a）**: 実走行（Caido 8081・Juice Shop）で「一意マーカー入りの非 GET 書き込みが発生し、保存 EP＋項目名を捕捉」できることを、発火・確定より前に単独で確認する中間ゲート。ここが通らない限り C1b/C1c へ進まない。
- **T2（結線＋偽陽性回帰・C1b/C2/D2）**: 捕捉した保存 sink が挙動ベースで 0458 起動ゲートに適合する形で渡り、発火時のみ `variant="stored"`・`dialog_observed=true` を生成する。**複数マーカー混在時に他マーカーの反射を自マーカーと誤紐付けしない**回帰を含む（同一文字列一致でのみ紐付け）。
- **T3（安全境界・両経路・C6）**: GET-only 時に **network_client 経路と browser 経路の両方**で非 GET がブロック/無効化されること、良性マーカーのみ・許可ホスト限定・件数上限を満たすことをユニットで固定。
- **T4（e2e・C1c）**: Juice Shop の保存型 XSS が能動発見 → `variant="stored"`・`dialog_observed=true` → 0457 経路で confirmed=1・整合 consistent（Caido 8081・実走行）。反映遅延（モデレーション等）時は「保留（未確定）」で記録し偽陰性と区別する扱いを含む。
- **T5（一般化・C2）**: 2つ目の stub/別ローカル練習台で能動発見が機能し、Juice Shop 特化でないことを確認（製品非依存の構造担保）。

## NOT in scope

- SGK-2026-0457 の reproduction gate・SGK-2026-0458 の検出側 stored 経路（完成済み・判定として不変）。確定バーの変更。
- 反射型/DOM 型 XSS の再設計（0454/0455/0456 で完了）。
- 本番/外部ターゲットへの能動書き込み scope 拡大（許可リスト＝ローカル練習台のみ。本番拡大の gate は別タスクへ）。
- 破壊的/機微データ書換の書き込み。死にコード `_check_dom_xss` の掃除（別件）。

## 実装計画（承認後・実装は DeepSeek / 独立検証は Claude）

- **実装対象（配置の是正）**: 能動 exercise は既存の `src/tools/custom/playwright_recon.py` に存在するため、そこを **拡張**する（ゼロ新規ではなく既存 `_exercise_forms`/`_exercise_clickables`/`_exercise_post_login_actions` の延長）。追加する挙動は前半4手: (a) **操作前後の入力面集合の差分検知**で隠れた入力面/ダイアログの出現を判定（多段到達）、(b) 面ごとに **一意マーカー投入**、(c) 送信に紐づく **非 GET リクエストと項目名の捕捉**、(d) 上限（クリック数・深さ1〜2段・制限時間）と **未到達＝未発見**。読む側（同一マーカー再訪反射探索）は 0458 を流用。`discovery/manager.py` は呼び出しと結果受け渡しに限定し二重実装を避ける（局所変更原則・CLAUDE.md §16）。**焼き込み禁止**: 製品名・特定 selector・特定ルートを一切コードに入れず、判断は入力面種別・DOM 差分・包含/近接（位置関係）・マーカー往復のみ。
- **dispatch 結線**: `classify_target_url` の path ベース判定を広げるのではなく、発見メタ（捕捉した保存 EP・項目・再訪候補）から 0458 の `revisit_candidates`/起動ゲートへ挙動ベースで直接渡す配線を追加（追加のみ・path 名/製品名非依存）。具体3点: (i) 起動ゲート verb を非 GET（POST/PUT/PATCH）へ拡張（`smart_xss.py:1237-1241`・追加のみ）、(ii) 発見側が保存 EP の **項目名**を供給し candidate_params を満たす、(iii) `revisit_candidates` を発見側の保存EP同一オリジン捕捉URLへ供給（供給元の是正。`_same_origin_revisit_candidates`/`_derive_revisit_candidates` の構造比較は不変で流用可）。非 GET 保存 EP を検出した場合のみ unknown 既定 `classification_only=True` を発見メタ駆動で迂回、または stored 専用 dispatch キーを追加。
- **安全境界**: browser 経路の GET-only 強制（`page.route("**/*", ...)` で非 GET/HEAD を `abort`、能動投稿モード OFF 時。設定位置は `crawl` の context/page 生成直後）と許可ホスト（127.0.0.1・localhost 練習台）/件数上限/一意マーカー `sgk<hex>` を追加。PlaywrightValidator 側も get_only フラグを注入（既定対象外）。
- **独立検証（Claude・DeepSeek 報告は額面で信用しない）**: フェーズ0引用確認 → T1–T5 ユニット → **検問A（T-reach）を実走行で先に通す**（一意マーカー入り非 GET 書き込み＋保存 EP/項目名の捕捉を session で確認。通らなければ前半のみ差し戻し、発火・確定へ進まない）→ 実走行（Caido 8081・`SHIGOKU_T3_HYBRID_ENABLED=1`・GET_ONLY 無し）で能動発見 → session 直読で **具体キー**（`variant="stored"` 件数・`dialog_observed`・マーカー一致・非 GET の XSS タスク node・保存 EP の出現・`revisit_candidates` 痕跡）を確認 → confirmed=1 → 整合 consistent → 製品非依存 pass/token0＋2つ目の練習台(T5) → バー diff0 → ledger 遷移。DeepSeek 報告は実 session/report と ledger を直接確認して裏取りする。

## ガードレール

- **過学習は絶対禁止（意味がない）**: 特定製品・特定 selector・特定ルートの焼き込みで数字だけ通す実装は不可。前半の到達・書き込みは入力面種別・DOM 差分・包含/近接・マーカー往復という **振る舞いのみ**で成立させる。歯止め＝`check_vdp_product_independence.py` token0＋**2つ目の練習台(T5)** での到達で構造的に担保。カーブフィッティング禁止・確定基準を下げない・**能力の過小化をしない**。書き込みは良性・最小・一意マーカー・許可ホスト（ローカル練習台）限定・件数上限。機微データ抽出/書換・破壊操作禁止。秘密の生値を成果物に残さない。
- **能動書き込み能力の不変条件（能力レベル）**: 許可リスト（ローカル練習台）＋ GET-only 両経路強制＋件数上限＋良性一意マーカー。本番 scope 拡大は別タスクの gate。
- Caido = 127.0.0.1:8081（8080 は SearXNG）。Juice Shop = http://localhost:3000。
- commit は検証後、push はユーザー。
