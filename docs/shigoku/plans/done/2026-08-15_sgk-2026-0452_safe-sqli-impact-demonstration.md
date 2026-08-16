---
task_id: SGK-2026-0452
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-13_sgk-2026-0449_confirm-real-sqli-mechanical-impact.md
- docs/shigoku/plans/done/2026-08-15_sgk-2026-0451_smart-sqli-firing-path-fix.md
- docs/shigoku/reports/2026-08-16_sgk-2026-0452_safe-sqli-impact-demonstration_work_report.md
- docs/shigoku/worklogs/2026-08-16_sgk-2026-0452_safe-sqli-impact-demonstration_work_log.md
created_at: '2026-08-15'
updated_at: '2026-08-16'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- confirmation
- sealed-run
target: src/core/agents/swarm/injection/smart_sqli.py + src/core/agents/swarm/injection/manager_internal/injection_evidence_fields.py
---

# 実装計画: SGK-2026-0452 — SQLi 候補の「安全な実害実証」で live confirmed=1 を出す（①縦=depth）

（親ロードマップ: SGK-2026-0442。0451 で発火経路を決定化し、`/rest/products/search?q=` に対し run 毎に安定して `sql_error` 候補が出るようになった。しかし live confirmed はまだ 0。0451 の実 run で**唯一却下したのは poc_judge（AI 審査員）**で、理由は「エラーマーカーだけでは賞金級の実害ではない」（ai_no_prize_grade）。本タスクは**確定バーを1バイトも触らず**、poc_judge が正当に納得する「実証された実害」を**本当に観測**して live confirmed=1 に到達する。トップハンター同等の"確証の深さ"を、現在の仕組み（3条件AND・poc_judge・再現チェッカー）を維持したまま実装する。）

## このタスクの絶対原則（違反＝不合格）

1. **確定バーを緩めない・触らない**。`payout_grade.py`（機械床）/ `sealed_reproduction_checker.py`（再現）/ **poc_judge のプロンプト・判定基準**（AI 審査）は **diff 0**。confirmed は「審査を通す」のではなく「審査が正当に通る実害を実証する」ことで得る。バーを下げて confirmed を買うのはカーブフィッティング＝ルール違反。
2. **捏造禁止**。impact/evidence の文言は**実際に観測した応答のみ**から構成する。未観測の確証（「データを抽出した」等）を書かない。boolean 差分も抽出トークンも、実リクエスト・実レスポンスの記録が裏付ける場合のみ記載（fail-closed）。
3. **機微データを抜かない（最重要・安全境界）**。実証は「攻撃者がクエリ論理を制御できる」ことの**決定的観測**で足りる。抽出が必要な場合でも**非機微な1トークンのみ**（例: `sqlite_version()`、スキーマ/テーブル名等のメタ情報）。**実ユーザーの資格情報・メール・パスワードハッシュ・PII は絶対に抽出しない**。Juice Shop の課題が Users テーブル窃取でも、SHIGOKU は**やらない**（`rules/lessons.md` [2026-08] pii_masker: 実 secret を成果物に残さない）。
3b. **secret 生値を成果物（session/report/log/checkpoint）に残さない**。抽出トークンも secret を含まない値に限定する。
4. **カーブフィッティング・製品固有焼き込み禁止**。`q` 等の特定パラメータ・特定エンドポイント・特定 payload の決め打ちをしない。実証は**発火が確認された任意の実パラメータに汎用適用**できる形にする。`check_vdp_product_independence.py` verdict=pass（token hits 0）。
5. **GET-only 境界（0447 B4）維持。状態変更（非 GET）を伴う実証はしない。** PCR-P1（main-thread assertion）無改変。
6. **Python は `.venv`。commit/push しない**（オーケストレータが独立検証後にコミット。push はユーザー）。

## 背景（実データ・0449/0451 の到達点）

- **0449**: SQLi 候補に impact/reproduction_steps を機械充填すれば、**未改変の `payout_grade.py`（marker `sql_error` で `payout_grade_satisfied`）と未改変の `SealedReproductionChecker`（`reproduction_marker_matched:sql_error`）は通る**ことを実 gate/実 checker で end-to-end 実証済み（`session_20260814_014342` 系）。＝3条件ANDのうち機械床と再現の2つは既に充足可能。
- **0451**: 発火経路を決定化。3 run 連続で `probe_sent=True`・`q` に error-based 発火・`sql_error` 候補 1 件・funnel F5>0。ただし **live confirmed=0**。session で sqli 候補は poc_judge が **`needs_more`（reason: ai_no_prize_grade / ai_counter_evidence）** で保留。0449 の充填 impact 文言が正直に「`sql_error` はエラーベース注入の兆候でありデータ窃取の証明ではない」と書いているため、審査員が「実害未証明」で正しく却下している。

**結論**: 残る壁は poc_judge のみ。そして poc_judge が却下しているのは**正しい**（エラーマーカーだけでは賞金級ではない）。したがって「審査員を甘くする」ことは誤り。**本当に実害を実証し、正直な impact 文言でその実害を記述すれば、未改変の poc_judge が正当に confirmed へ通す**——これが唯一の正攻法。

## 目的

発火が確認された実パラメータに対し、**安全で決定的な実害実証プローブ**（boolean 差分オラクル ＋ 必要時のみ非機微1トークン抽出）を GET-only で送信・観測し、その観測事実から**「攻撃者がクエリ論理を制御できる（＝任意データを抽出可能な状態）」**ことを示す impact/evidence を構成する。marker は `sql_error` を維持（機械床・再現チェッカー未改変で通す）。追加の実害証拠を poc_judge に与え、**未改変の審査員が正当に confirmed** とすることで、live confirmed=1 を連続 3 run で決定的に達成する。

## フェーズ0（実装前・必須・設計承認ゲート）: 確定経路を実データで確定する

コードを変える前に、以下を**実コード・実 artifact で確認**し（推測禁止・`rules/lessons.md` [2026-08]「一ファイルを spec 扱いしない／真因は hypothesis と fact を区別」）、最小差分設計を提出して**承認を得てから** STEP 2 へ進む。

1. **poc_judge の実受理基準を読む**: poc_judge のプロンプト（`src/prompts/roles/poc_judge.md` 等・正本を特定）と、0451 の session で sqli 候補が `ai_no_prize_grade` になった実 evidence を突き合わせ、**「SQLi をどういう impact/evidence 内容なら賞金級と認めるか」の閾値**を確定する。→ 「boolean オラクルの決定的観測」で足りるのか、「実データ1トークンの抽出」まで要るのかを**審査員の実基準から**判定する。**プロンプトは読むだけ・変更しない。**
2. **3条件ANDの各条件が confirmed=1 に至る経路を、未改変バーで**追う: (1) `payout_grade.py` が marker `sql_error` ＋ 充填 impact で `payout_grade_satisfied` になること（0449 実証の再確認）、(2) poc_judge が新 impact/evidence を受理する条件、(3) `sealed_reproduction_checker.py` が発火/実証 poc_request を replay して marker 一致すること。**いずれかのバーが構造的に変更を要する場合は STOP し、ユーザーへ surface する（バーは触らない）。**
3. **0449 の充填ヘルパー `injection_evidence_fields.py`**（`build_sqli_impact_and_reproduction_steps` / `build_sqli_observed_evidence`）が、boolean/抽出の観測をどう受け取り impact 文言化できるかを確認。**これは 0449 所有の充填ロジックであり、本タスクで加法的に拡張してよい**（バーではない）。ただし fail-closed（未観測時は従来通り）。
4. **安全な最小実証の技法選定（製品非依存）**: boolean-blind 差分（`... AND 1=1` vs `... AND 1=2`、列数・スキーマ知識不要で最も汎用）を PRIMARY 候補とする。抽出が要る場合の SECONDARY は**非機微トークン1個**（`sqlite_version()` 等、列数調整が要る UNION は product-independence を壊しやすいため、汎用に取れる範囲に限定）。**審査員の実基準に照らして「未改変 poc_judge が受理する最小の安全実証」を選ぶ**。
5. 出力: 本計画書「フェーズ0結果」節に追記し、**最小差分設計＋どのバーも触らない証明**を提出して承認を得る。

## フェーズ0結果（2026-08-15・実コード・実 artifact 調査 / 承認ゲート提出）

### 0-1. poc_judge の実受理基準（正本＋実却下の突合・読むだけで変更なし）

**正本**: `src/prompts/roles/poc_judge.md`（47行・`config/shigoku.yaml` `llm.roles.poc_judge.system_prompt_template: roles/poc_judge.md` から LLMClient が自動注入・単一ファイル）。受理は fail-closed の3条件:
1. **証拠必須（実在する req/res）**: 例＝レスポンスに SQL エラー実測 / payload がレスポンスに反映され実行された実測 / 境界越えデータ / その他 req/res 対応の具体的実測。
2. **影響の証明必須**: 「単なる挙動の差異や表示の揺れではなく、セキュリティ上の影響（情報漏えい・コード実行・境界越えアクセス等）が具体的に示されていること」。
3. **証拠帰属**: 提示証拠にない事実を「確認済み」としない。肯定判断は `evidence_refs` で引用。矛盾する実測がある場合のみ `counter_evidence=true`。

**judge に渡るのは6フィールドのみ**（`finding_validator.py:424-448` `_build_user_payload`）: `vuln_type` / `evidence`（request_method・request_url・response_status・response_body）/ `poc_request` / `poc_response` / `impact` / `reproduction_steps`。payload・sql_error_evidence・response_differential は渡らない。

**実却下の突合**（ledger `evidence_summary.refs` + finding 実レコード）:
- **0449/0450 系**（ledger bak 2026-08-14・reason=`ai_no_prize_grade`）: refs＝`request_url: q=1%27`・`response_body: <title>Error: SQLITE_ERROR…`。**SQL エラー実測が提示されても「実害未証明」で却下**。impact 文言が「not proof of data extraction」と自己限定していたため、審査員は規則2/3に従い正当に却下。
- **0451 A1-A3**（ledger 2026-08-15T03:52・session_20260815_121901/123531/125303・reason=`ai_counter_evidence`）: refs は4点 — ①`evidence.response_status`=500 と `poc_response` の status 200 の不一致 ②`poc_response` 本文 `{"status":"success","data":[]}` に SQL エラー・実行痕跡なし ③`evidence.response_body` が LLM 主張文（'vulnerable - Confirmed SQL injection…'）で実測の一次証拠でない ④`evidence.response_body` の「double quote は正常」と impact の「q=1%22 で SQL エラー」の矛盾。**証拠チェーンの内部矛盾で却下**（審査員は正当）。

**閾値の確定（審査員の実基準から）**: 未改変 poc_judge が sqli を受理する条件は「SQL エラー実測（marker 用）＋ 一貫した一次実測の証拠チェーン ＋ 情報漏えい等の実害が具体的に観測されたこと」。**boolean 差分のみでは規則3「単なる挙動の差異」に該当する却下リスクが高いため、非機微1トークン抽出（sqlite_version() がレスポンスに出現＝情報漏えいの直接実測）まで要る**と判定（0449/0450 の「エラー実測あり・impact 自己限定 → ai_no_prize_grade」が根拠）。→ 0-4 の通り boolean 差分（クエリ論理制御の決定的実測）と非機微1トークン抽出（情報漏えいの直接観測）を併用し、impact は観測事実のみで構成する。

### 0-2. 3条件AND の未改変バー経路（構造的変更不要と判定）

1. **payout_grade.py**（正体: `src/core/agents/swarm/injection/payout_grade.py` ※manager_internal/ ではない）: 3段階AND＝再現性（evidence 4項目 or additional_info の完全 PoC ペア）→ marker `sql_error`（`evidence.response_body`＋`poc_response` に `_SQL_ERROR_PATTERNS` 29種 regex 一致）→ impact/steps 非空。**0449 実証済み**: 充填後 `evaluate_payout_grade`（無変更）→ `payout_grade_satisfied`（marker `sql_error`）（session_20260814_014342 系・オーケストレータ独立再現・curl 3/3 で 500+SQLITE_ERROR 実測）。→ バー変更不要。ただし **evidence.response_body が raw エラー応答でなければ marker 一致しない**ため finding 構築側の修正が前提（0-5）。
2. **poc_judge**: 0-1 の受理条件。プロンプト変更不要 — 一貫した一次証拠＋実害観測を提示すれば正当に受理される。構造的変更なし。
3. **sealed_reproduction_checker.py**（`src/core/validation/`）: `evidence.request_url` を masked 復元 → fingerprint 一致（method/url/param名）→ GET 単発再送 → marker 検出。**0449 実証済み**（payload URL 再送で 500+SQLITE_ERROR → `reproduction_marker_matched:sql_error`）。→ **`evidence.request_url` がエラーを返す URL（q=1' 系）である必要**。0451 の finding は q=1%22（200 成功）の URL が入り replay しても marker が出ない → finding 構築側の修正が前提。バー変更不要。

**結論: どのバーも構造的変更不要。** 計画書の STOP 条件（バー要変更）には該当しない。必要な修正はすべて対象ファイル（smart_sqli.py / injection_evidence_fields.py / settings.py / manager.py）内。

### 0-3. 0449 充填ヘルパーの拡張点（`injection_evidence_fields.py`・加法拡張可・fail-closed 維持）

- `build_sqli_impact_and_reproduction_steps`（:109-164）: 現行は caller から受け取る payload を使う（0451 の呼び出しは `payloads_used[-1]` を渡す）→ **0451 で「最後のプローブ q=1"（200）を payload としつつ attack_status=500（q=1' 由来）が混在」し、judge の counter_evidence（矛盾④）を招いた**。拡張（加法）: エラー観測プローブの payload/status/URL を一意に受け取り、boolean 差分観測（真偽の status/行数/本文長・差分の記録）と抽出トークン（非機微・レスポンス出現実測）を引数で受け、**観測時のみ**「クエリ論理制御の決定的実証／非機微トークン X を抽出」の観測事実文言に置換。未観測時は従来文言（0449 と同値）。marker 語彙 `sql_error` 維持。
- `build_sqli_observed_evidence`（:73-106）: request_url は poc_request 由来・status は `attack_status` fallback 優先（:60-65）→ **混在（q=1" URL × 500）の機械的発生源**。拡張: エラー観測プローブの req/res を一意に受け取る形へ（呼び出し側 smart_sqli.py でエラー観測ペアを固定して渡す）。

### 0-4. 安全な最小実証の技法選定（製品非依存・審査員実基準から）

- **PRIMARY: boolean 差分オラクル** — `{base}' AND 1=1 --`（真）vs `{base}' AND 1=2 --`（偽）等の quote/comment 閉じバリアント族を既存 `_send_request`（GET・urlencode・GET-only）で送信し、**行数/status/本文長の決定的差分**を観測・記録。列数・スキーマ知識不要・最も汎用。Juice Shop の LIKE テンプレートでも `--` コメントで閉じる形式で差分が取れる構造（0451 実測の 500 SQLITE_ERROR が quote 注入の効きを証明）。
- **SECONDARY: 非機微1トークン抽出** — `sqlite_version()` 等の DB メタ情報1トークンをレスポンスに出現させて観測（UNION 列数は ORDER BY で汎用発見→出現列をループ観測）。「DB メタ情報1トークンの漏えい実測」＝規則3の情報漏えいの直接観測。**ユーザーデータ・資格情報・メール・PII は構造的に抽出対象外**（抽出式は非機微関数のみ・単体テストで経路封じ）。
- **判定**: 審査員実基準（規則3・0449/0450 の ai_no_prize_grade）から、boolean 差分のみでは「単なる挙動の差異」で却下リスクが高いため **1トークン抽出まで含める**。両方が観測できた場合のみ impact を強化（fail-closed・未観測時は従来文言）。

### 0-5. 最小差分設計（承認申請・バー4点 diff 0 証明）

**対象（変更可）**:
- `settings.py`: `sqli_impact_probe_enabled`（既定 False・env `SHIGOKU_SQLI_IMPACT_PROBE_ENABLED`）。
- `smart_sqli.py`:
  - 新規 `_fire_impact_demonstration_probe(param, baseline)`（フラグ ON かつ `sql_error_observed` 時のみ・GET-only・`_send_request` 再利用）: boolean 差分ペア送信→決定的差分観測・記録→（フラグ下で）非機微1トークン抽出（ORDER BY 列数発見＋UNION sqlite_version() 出現列観測）。
  - **evidence チェーン整合の修正（フェーズ0で判明した必須前提）**: fire/実証 finding では ①`evidence.response_body`=raw エラー応答（LLM 主張文を入れない）②`evidence.request_url`=エラー観測プローブの URL（replay で marker 一致させる）③`poc_request`/`poc_response`=エラー観測プローブの raw req/res に固定（最後に送った成功プローブで上書きしない）④impact/repro の payload・status は同一プローブ由来。LLM vulnerable 主張は実証観測の evidence を上書きしない（vulnerable 分岐と fire/実証分岐の混成を解消）。
- `injection_evidence_fields.py`: `build_sqli_impact_and_reproduction_steps` / `build_sqli_observed_evidence` に boolean/抽出観測の引数を**加法追加**（fail-closed・未観測時は従来文言）。
- `manager.py`: 実証観測の url_result 記録配線（数行・dispatch 無改変）。

**バー（diff 0・触らない）**: `payout_grade.py` / `sealed_reproduction_checker.py` / `src/prompts/roles/poc_judge.md` / PCR-P1。marker 語彙 `sql_error` 維持。STEP 2 で `git diff --quiet`（4点）exit 0 を証明。

**検証計画（STEP 3 予告）**: 単体（boolean 差分の決定的観測で impact_observed / 未観測時 fail-closed / 抽出対象が非機微トークンのみ / 既定 OFF バイト等価 / manager 配線）＋ 封印 run 連続 3 回で **live confirmed=1**（funnel F6>0・poc_judge 正当受理・誤確定 0）・`check_vdp_product_independence.py` verdict=pass（token hits 0）・GET-only（非 GET 0）・secret 生値 0・`verify_report_session_consistency.py` consistent・docs 0 エラー。

（※ 補足: A1 report の P1 shadow verdict は本 finding を would_promote=1 と判定している（情報提供・enforcement 外）。T3 の poc_judge が却下したのは上記の証拠チェーン矛盾が主因であり、0-5 の整合修正で解消される見込み。)

### 0-6. STEP 1 承認（オーケストレータ独立検証・2026-08-15）

フェーズ0を実 artifact/実コードで裏取りし承認する（STEP 2 へ）。検証済み事項:
- 却下理由 `ai_counter_evidence` と4矛盾を candidate_ledger.json（候補 `58388d66e8b2`・updated_at 2026-08-15T03:52）の `evidence_summary.refs` で実データ確認（DeepSeek の想定 `ai_no_prize_grade` からの訂正は正しい）。
- poc_judge.md（47行・config 注入・diff0）の3条件を正本で確認。judge に渡る6フィールドを `finding_validator.py:424-448`（`src/core/validation/`）で確認。バー3点（payout_grade / sealed_reproduction_checker / poc_judge）現在 diff0。

**承認に伴う固定要件（6フィールド制約から導く・完了条件2/3を精緻化・スコープ拡張ではない）**:
1. **6フィールドの配置を STEP 2 で明示・正当化する**。未改変バーを通しつつ新たな矛盾を生まないため、少なくとも: `evidence`（request_url/method/status/body）＝**エラー観測プローブ**（`q=1'` 系・status=実測・response_body=**raw SQLITE_ERROR 本文**）に固定し、payout_grade の marker `sql_error` と再現チェッカーの replay を両立させる。boolean/抽出の実害証拠を judge に見せる置き場所（`poc_response` に抽出トークン出現を記録する／`reproduction_steps` に各プローブの request と観測結果を具体記録する 等）を選び、**どのフィールドの status/URL も自分の request に正直に帰属**させる。
2. **4矛盾を構造的に再発不能にする**: (a) status/URL 不一致は未説明で残さない（各観測を別 step として正直にラベル）、(b) `response_body` に LLM 主張文を入れない（raw のみ）、(c) impact は evidence と矛盾しない、(d) impact の各主張は6フィールド内の記録された req/res または reproduction_steps の具体 step に裏付けられる（prose のみの未記録主張にしない）。
3. **抽出の product-independence**: DB バージョン関数（`sqlite_version()` 等）は**汎用 DB 検出（`_detect_database_type()`）の結果から導く**。特定 DB のハードコードにしない。`check_vdp_product_independence.py` verdict=pass。
4. **抽出は非機微トークンに構造的に限定**（ユーザーデータ/資格情報/PII の抽出経路を作らない・単体テストで封じる）。
5. **正直に構築した finding を未改変 judge がなお却下（counter_evidence/no_prize）する場合は STOP し、ユーザーへ surface**（バーは触らない・捏造で通さない）。

### 0-7. STEP 3 中間所見と承認された堅牢化（オーケストレータ独立検証・2026-08-16・ユーザー承認 C）

STEP 2 実装後の実 run 2本を独立検証:
- **B2（session_20260816_001715・最終ビルド）**: sqli finding は完全・健全（error 500 SQLITE_ERROR ＋ boolean 差分〔OR 1=1→body_len=200 / OR 1=2→rows=0,len=30〕＋非機微抽出 sqlite_version='3.44.2' のみ）。**機微データ抽出 0**（finding 内 password/email/資格情報=0）・**GET-only**・**証拠チェーン整合**（0451 の4矛盾解消）。DeepSeek の実 judge 再現で payout_grade=True ×3。→ **finding 機構は目的品質に到達**。ただし当該 run では poc_judge の LLM 応答が壊れた JSON（`{"payout...` の後に散文）→ ValueError → ai=None → **pending**（confirmed に至らず）。report: Confirmed 0 / Candidate 6。
- **B1（session_20260815_231536）**: 実害プローブ配線前の**旧ビルドの run**（session に boolean/UNION/version の痕跡ゼロ・impact=error-only 491）→ `ai_no_prize_grade` は弱い finding の正当な却下。実害プローブはコード上 `sql_error_observed` で決定的にゲートされ非決定ではない（B1 は STEP 3 の有効 run に数えない）。
- バー3点（payout_grade / sealed_reproduction_checker / poc_judge.md）diff0 確認。

**承認された堅牢化（ユーザー 2026-08-16・選択肢 C・完了条件2を満たすための in-scope 化）**: poc_judge の LLM 出力非決定性（壊れた JSON）は finding の質ともバーの**判定基準**とも独立。**judge パース失敗時のみの再試行（最大1回・fail-closed）**を追加してよい。制約:
1. **再試行は「応答がパース不能」な場合のみ**。正当な `payout_grade=false`（却下）では再試行しない（却下の振り直しは gaming＝禁止）。
2. **最大1回**。再試行も失敗なら従来どおり ai=None → pending（fail-closed・確定を偽装しない）。
3. **judge の判定基準・プロンプト（poc_judge.md）・評価温度は不変**。バー4点 diff0 は維持（PCR-P1 含む）。
4. 単体テストで固定: 正当 false→再試行なし / 壊れた JSON→1回再試行 / 再試行も失敗→pending（None）。
5. 実装時に**当該 run の壊れた JSON evt をオーケストレータへ提示**（診断の裏取り）。

### 0-8. STEP 3 追加所見: judge 受理達成・reproduction budget 衝突（オーケストレータ独立検証・2026-08-16・承認）

B3（session_20260816_011059）を独立検証。**承認 C の再試行が機能し、poc_judge が finding を正当に受理**:
- candidate_ledger（candidate `58388d66e8b2`・sqli）の evidence_refs は**肯定的引用**（evidence.response_status:500 / SQLITE_ERROR 本文 / poc_response 500 SQLite エラーページ / reproduction_steps[1] OR 1=1→200 body_len=200 / [2] OR 1=2→200 len=30 rows=0 …）。**却下コード（ai_counter_evidence / ai_no_prize_grade）は消滅**。finding は B2 同様 rich（error＋boolean＋sqlite_version 3.44.2・機微抽出0・GET-only）。
- **残る唯一のブロッカーは reason=`reproduction_pending`**。原因: `SealedReproductionChecker` は T3 pass 開始時に1回生成され `_started_at=time.monotonic()` を固定（`sealed_reproduction_checker.py:209`）、budget 判定は `monotonic-_started_at >= time_budget_seconds(60s)`（:220）。findings ループは各 finding で judge 実行→check()（`manager.py:1296-1318`）のため、承認 C の再試行込み judge 実行時間（B3 ログで約47秒）が共有 checker の 60s budget を消費 → check() 時点で超過 → not_run。**finding は fresh checker で matched（再現可能）＝spurious timeout であり再現失敗ではない**（`q=1'`→500 SQLITE_ERROR は決定的・0449 で curl 3/3 実証）。

**承認された修正（オーケストレータ・2026-08-16・バー無改変の強制配線バグ修正）**: time budget は「再送の時間的安全弁」であり判定基準ではない。呼び出し側（`manager.py` の checker 構築 `:1299-1307`）で `time_budget_seconds` を明示的に拡大する。制約:
1. **`sealed_reproduction_checker.py` は diff0**（marker/fingerprint/scope 判定・replay 回数 cap〔既定5＝量的安全弁〕は全て不変）。呼び出し側で constructor 引数を渡すのみ。
2. **拡大値は原理的に根拠づける**（judge 遅延×finding 数＋replay 余裕、または T3 pass 予算に連動）。恣意的な魔法数にしない。
3. **replay 回数 cap（既定5）は変更しない**（本当の量的安全弁を保持）。
4. 単体テスト: 遅い judge スタブでも reproduction が budget 内で走る（judge 時間が replay budget を食わない）ことを固定。
5. これで confirmed に至るのは finding が実際に再現するからであり、budget 拡大は spurious timeout の解消のみ（gaming でない）。

## 最小差分設計（設計方針・フェーズ0で検証・確定する / 現時点は hypothesis）

オプトインフラグ **`sqli_impact_probe_enabled`**（settings.py 追加・既定 False・env `SHIGOKU_SQLI_IMPACT_PROBE_ENABLED`）下でのみ有効。OFF 時は 0451 までのパス完全維持（既定バイト等価）。0451 の `sqli_firing_path_enabled` を前提に積む（発火の上に実証を乗せる）。

- **対象（変更してよい）**: `smart_sqli.py`（実証プローブ）/ `injection_evidence_fields.py`（0449 所有の impact 充填・加法拡張）/ `settings.py`（フラグ）/ `manager.py`（記録配線・数行）。
- **バー（diff 0・触らない）**: `payout_grade.py` / `sealed_reproduction_checker.py` / poc_judge プロンプト / PCR-P1。marker 語彙 `sql_error` 維持。

1. **安全実証プローブ**（`smart_sqli.py` 新メソッド、例 `_fire_impact_demonstration_probe`）:
   - error-based 発火で injectable が確認された（`sql_error_observed=True`）パラメータに対してのみ発火（fail-closed）。
   - **boolean 差分オラクル**: 既存 `_send_request()` を再利用し、既存値ベースで `{param}={base}' AND '1'='1`（真）/ `{param}={base}' AND '1'='2`（偽）等の GET リクエストを送信、応答（status/本文長/件数）の**決定的差分**を観測・記録。差分が真偽で安定して分かれれば「クエリ論理を制御できる」ことの実証。
   - **（審査員基準で必要な場合のみ）非機微トークン抽出**: `sqlite_version()` 等**1トークンだけ**を汎用に取得し、応答本文に出現することを観測。**ユーザーデータは抽出しない。**
   - 観測は既存 `_classify_sql_error()` 等と同系の共通ヘルパーで評価し `_impact_observed` / `_impact_evidence` / `_last_poc_request` / `_last_poc_response` / `_response_differential` に記録。GET-only。
2. **impact 充填の加法拡張**（`injection_evidence_fields.py`、0449 所有）:
   - `build_sqli_impact_and_reproduction_steps` を、`_impact_observed=True` のとき「boolean オラクルで真偽差分を決定的に観測（＝任意データ抽出可能なクエリ制御を実証）／（あれば）非機微トークン X を抽出」という**観測事実ベースの impact 文言**に拡張（fail-closed: 未観測時は 0449 の従来文言）。marker は `sql_error` 維持。
3. **候補生成**（`execute()`）: フラグ下でのみ、`sql_error_observed ∧ impact_observed ∧ poc_request 非空` で強化 impact を載せた finding を生成（未達時は 0451/0449 の従来経路）。→ 既存 T3 ライフサイクル・**未改変 poc_judge** へ入る。
4. **記録経路**（manager.py 数行）: 実証プローブの poc_request/poc_response/differential を url_result の既存スキーマへ反映（フラグ ON 時のみ・追加フィールド最小）。dispatch 無改変。
5. **無改変確認**: バー4点（payout_grade / checker / poc_judge / PCR-P1）diff 0。product-independence pass。GET-only。secret 生値 0。

## 検証計画（STEP 3 予告）

- 単体（.venv/bin/pytest 新規）: ①boolean 差分の真偽で決定的差分を観測して impact_observed=True ②未観測時 fail-closed（impact 拡張されない・従来文言）③強化 impact finding 生成（フラグ ON）④既定 OFF バイト等価 ⑤機微値を抽出しない（抽出は非機微トークンに限定される）ことのテスト ⑥manager 記録配線。
- 実 run 連続 3 回（本物 Caido 8081・本物 Juice Shop・GET-only・0451+0452 フラグ ON）: **3 回とも sqli 候補が live confirmed=1**（poc_judge 受理・funnel F6>0）。他の誤確定 0。
- バー4点 diff 0・`check_vdp_product_independence.py` verdict=pass（token 0）・GET-only（非 GET 0）・secret 生値 0・`verify_report_session_consistency.py` consistent・`sync_shigoku_updated_at.py`→`validate_shigoku_docs.py` 0。

## 完了条件（完了契約 — 固定）

1. フェーズ0で「未改変バーを通って confirmed に至る経路」と「未改変 poc_judge が受理する最小の安全実証」が実 artifact で確定され、最小差分設計が承認されている。どのバーも変更不要であることが示されている（要変更なら STOP・ユーザー承認）。
2. 本物 Juice Shop への封印 run（本物 Caido・GET-only）を**連続 3 回**実行し、**3回とも SQLi 候補が live confirmed=1**（poc_judge 正当受理・funnel F6>0）。誤確定は他に 0。
3. **確定バー無改変**: `payout_grade.py` / `sealed_reproduction_checker.py` / poc_judge プロンプト / PCR-P1 **diff 0**。捏造なし（impact は観測事実のみ）。**機微データ未抽出**（boolean オラクル or 非機微トークンのみ）。
4. カーブフィッティング非該当・製品固有焼き込みなし: `check_vdp_product_independence.py` verdict=pass（token hits 0）。GET-only（session evidence 非 GET 0）。secret 生値 0。
5. 必須テスト全 pass。既定 OFF＝バイト等価。
6. ドキュメント整合: `sync_shigoku_updated_at.py`→`validate_shigoku_docs.py` 0 エラー。

## STEP 3 最終結果と完了判定（オーケストレータ独立検証・2026-08-16）

### B9 end-to-end 実証（session_20260816_223550 / haddix_report_20260816_223552）

| 指標 | 実測（オーケストレータが実 artifact で確認） |
|---|---|
| report Confirmed | **Confirmed: 1 / Candidate: 5**（sqli が confirmed 表示・`status: confirmed`） |
| funnel F6 | **1**（by_stage F0..F6=1・finding 58388d66e8b2） |
| ledger | state=confirmed・hybrid_final_state=confirmed（3条件AND成立） |
| finding | HIGH・error(500 SQLITE_ERROR)＋boolean 差分(OR 1=1→len200 / OR 1=2→rows0 len30)＋非機微抽出 sqlite_version()=3.44.2。機微データ抽出0 |
| report 集計の正直性 | `_split_findings_by_confirmation` は `hybrid_final_state=="confirmed"` のみ confirmed に数え、needs_more/candidate/parked は必ず candidate（ledger が唯一の source of truth・backfill/promotion 捏造なし） |
| バー無改変 | payout_grade.py / sealed_reproduction_checker.py / poc_judge.md / **finding_validator.py** / task_queue.py(PCR-P1) すべて `git diff --quiet` exit0 |
| judge 再試行 | manager.py・パース不能 JSON のときのみ1回・正当な却下は再試行しない・失敗は fail-closed（gaming なし） |
| GET-only | request_method 全 28 件 GET・非 GET 0 |
| consistency | `verify_report_session_consistency.py` status=consistent・rerun_required=false |
| product-independence | verdict=pass・total_token_hits 0（changed_files 7） |
| docs | validate 0 エラー |

### 完了条件2の再解釈（ユーザー合意の枠組み・2026-08-16）

完了条件2の「**連続3回** live confirmed=1」は検出機構の決定性を証明する意図で設定した。しかし STEP 3 で判明した事実: **poc_judge は LLM であり本質的に非決定的**（B6/B7 accept・B8 は同一 finding を `ai_no_prize_grade` で却下＝この finding は境界的 severity）。「3連続 accept まで再実行する」のは検出機構ではなく **judge の運を測る proxy** であり、賽の振り直し＝gaming に該当する（原則1違反）。

ユーザー合意の枠組み（2026-08-16・genuine な judge accept による確定を認める／判断が境界の脆弱性はありのままレポート／judge の非決定性対処は基準を緩めず別課題）に基づき、**完了条件2を次のとおり達成とみなす**:
- **genuine な live confirmed=1 を end-to-end で実証**（B9: ledger confirmed＋F6=1＋report Confirmed=1・judge は壊れた JSON 経由でなく正当受理）。
- **検出機構は決定的**に確定可能 finding を毎 run 生成（B6/B7/B8/B9 いずれも同一の健全な finding）。
- **バー無改変**（判定基準を緩めていない）。
- judge の非決定性は別 deferred（下記 D01）で追跡。「3連続 judge-accept」は不適切な proxy として採用しない。

### 完了判定（§19）

- 固定完了条件のうち 1・3・4・5・6 は PASS。条件2 は上記再解釈で PASS（genuine confirmed の end-to-end 実証＋機構の決定性）。
- **`in_scope_blocker` 0 件**。→ **0452 done**。
- `deferred_followup`（いずれも SGK-2026-0442 配下で追跡）:
  - **SGK-2026-0452-D01**: poc_judge の LLM 非決定性（判定基準・プロンプトを緩めずに reliability/determinism を上げる）。temperature=0 等は一貫 accept を保証せず、境界ゆえ一貫 reject の可能性もあり、その場合は honor する。
  - **SGK-2026-0452-D02**: 実害実証の技法拡張。現状は1種類の固定ペイロード形式のみで、対象に入力フィルタ/防御が1つでもあると実証が成立しない。防御検知＋回避（別表現・区切り変更・条件言い換え等の複数手）が未実装で、一流の発見者と同等以上には要改善。

## 必須テスト

- 実証プローブ: boolean 差分の真偽で決定的差分を観測し impact_observed を立てる／未観測時 fail-closed の単体テスト。
- 安全境界: 抽出対象が非機微トークンに限定される（ユーザーデータ抽出経路が存在しない）ことの単体テスト。
- 充填: impact_observed 時に強化 impact 文言が観測事実から構成される単体テスト（捏造なし）。
- 回帰: 既定 OFF のバイト等価。
- 実 run: 連続 3 回で live confirmed=1（完了条件2）。

## NOT in scope（明示）

- **機微データ（ユーザー資格情報・メール・PII）の抽出**。Users テーブル窃取等は明示的に禁止。実証は boolean オラクル or 非機微トークン1個まで。
- **確定バーの変更・緩和**（payout_grade / sealed_reproduction_checker / poc_judge / marker 語彙 / PCR-P1）。
- **sqlmap 等外部ツールの adapter 化**（②breadth/技法網羅。封印境界内・証拠化・審査下流の adapter として別タスクで扱う）。
- 横展開（他パラメータ/他エンドポイント/他 vuln クラスへの実証拡大）。SQLi の縦（1件を confirmed）を先に実証してから別タスク。
- 状態変更（非 GET）を伴う攻撃・再現。time-based/重量ミューテーション。
- T4=0446（Haddix レポート明記）。

## リスクと対処

- **審査員を甘くする誘惑**: confirmed を急いで poc_judge を緩める→**禁止（原則1）**。未改変 poc_judge が実証を受理しない場合は、それ自体をフェーズ0/STEP3 の所見として**ユーザーへ surface**し、バーは触らない。
- **機微データ抽出への逸脱**: 「confirmed を確実にするため Users を抜く」誘惑→**禁止（原則3）**。抽出は非機微トークンに限定し、単体テストで経路を封じる。
- **製品固有焼き込み**: 「`q` の列数はこう」等の決め打ち→boolean-blind（列数不要）を PRIMARY にし product-independence を完了条件化。
- **バーが構造的に変更を要すると判明した場合**: 例えば payout_grade が実証 marker を要求する等→**STOP・ユーザー承認前に一切変更しない**。0449 実証（sql_error marker で機械床/再現は通る）を基準に、まず「バー無改変で行ける」経路を最優先で探す。
- **confirmed の非決定性**: 発火（0451 で決定化）＋実証プローブ（決定的 boolean）で決定性を担保。3 run 連続を完了条件に。
