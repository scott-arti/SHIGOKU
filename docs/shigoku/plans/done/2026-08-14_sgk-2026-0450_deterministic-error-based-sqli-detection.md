---
task_id: SGK-2026-0450
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-13_sgk-2026-0449_confirm-real-sqli-mechanical-impact.md
- docs/shigoku/plans/2026-08-15_sgk-2026-0451_smart-sqli-firing-path-fix.md
- docs/shigoku/reports/2026-08-15_sgk-2026-0450_ai-hunter-toolcalling-dedup_work_report.md
- docs/shigoku/worklogs/2026-08-15_sgk-2026-0450_ai-hunter-toolcalling-dedup_work_log.md
created_at: '2026-08-14'
updated_at: '2026-08-15'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- reliability
target: src/core/agents/swarm/base_manager.py,src/core/agents/swarm/thought_loop.py,src/core/agents/swarm/injection/smart_sqli.py
---

# 実装計画: SGK-2026-0450 — AI ハンターの信頼化（tool-calling 移行 ＋ 重複排除ガード ＋ LLM 設定）

（親ロードマップ: SGK-2026-0442。0449 で「候補さえ出れば確定できる」機構は実証済み。本タスクは"候補を毎回確実に出す＝検出を信頼できるものにする"。**能力を削らずに信頼性を上げる**のが絶対条件。）

## このタスクの絶対原則（違反＝不合格。過去の失敗を踏まえた最優先事項）

1. **能力を縮小して信頼性を買わない**。検出を固定少数ペイロードに狭める等は禁止（過去の2ペイロード方式は破棄済み）。本タスクは"柔軟な AI ハンターを信頼できる形にする"ものであり、攻撃の幅を狭めてはならない。
2. **カーブフィッティング禁止**。標的（Juice Shop）固有の分岐・ペイロード・エンドポイント・焼き込み答えを入れない。`check_vdp_product_independence.py` exit 0。
3. **確定バー・再現チェッカー・0449 充填ヘルパーは無改変**：`payout_grade.py` / `sealed_reproduction_checker.py` / `injection_evidence_fields.py` は import 変更のみ可、ロジック変更禁止（diff 0）。
4. **GET-only 境界（0447 B4）維持。PCR-P1 の main-thread assertion 無改変。secret 生値を残さない。**
5. **Python は `.venv`。commit/push しない**（オーケストレータが検証後にコミット）。

## 背景（SGK-2026-0450 step-1 根本原因調査の結論・実データ）

0449 の実 run では「同じコードで発火したり不発だったり」という**検出の非決定性**で confirmed=0 だった。step-1 で実ログ（`/tmp/opencode/sgk0449/run_step3.log` 他）と実 API 計測から原因を3つ特定した:

1. **LLM 判定が遅かった**（pro の thinking=high が実測 5〜14s/呼、ばらつき大。target は ~0.5s で無関係）。→ **【対処済み】** 全ロールを flash に統一（判断系4ロールは flash 既定の推論、ハンター/マネージャは thinking 無効で 1〜2s）。commit `8040cf2`。
2. **自由テキスト ReAct の脆いパース**：LLM の手を自由テキストで書かせ `ast.parse()`→regex で解釈（`base_manager.py:452-477`）。LLM が散文（`Thought: … await Observation`）や空引数（`run_sqli_hunter({})`）を返すとその手が無駄になり、脆弱エンドポイントへ発火ペイロードが送られないまま予算切れ。
3. **マネージャに重複排除ガードが無い**（`base_manager.py` の think loop、grep で該当ゼロ）。LLM が同じ手（同一エンドポイントへの `run_sqli_hunter({})`）を繰り返しても止まらず、脆弱でない `/account/security` に5回 ThoughtLoop を回して予算を浪費。

結果、脆弱な場所に発火ペイロードが予算内に届くかが運任せ＝非決定的。**足りないのは「AI の推論を確実に実行に移す仕組み」と「無駄な繰り返しを止める仕組み」。**

## 目的

AI ハンターの推論を**確実に実行へ移し**、**無駄な繰り返しを止める**ことで、対象に脆弱性が実在する限り**run 毎に安定して検出**できるようにする。0449 の充填機構と合わさり、検出が信頼できるものになる。

## スコープ（step-1 で confirmed の2点のみ実装。1つ目は対処済み）

### A) tool-calling 移行（根本原因2の対処）
- 自由テキスト ReAct ＋ ast/regex パースを、**ネイティブの tool/function-calling**（型付き JSON スキーマでツール宣言 → モデルが検証済みの構造化ツール呼び出しを返す）に置き換える。
- **実測確認済み**：deepseek/litellm は tool-calling をサポート（`litellm.supports_function_calling("deepseek/deepseek-v4-flash")=True`、flash で実ツール呼び出しが 1.4s で構造化 JSON を返す）。
- これにより「散文で返って手が無駄になる」「AST パース失敗」が構造的に無くなる。

### B) 重複排除／前進ガード（根本原因3の対処）
- マネージャの think loop に、**「同一の的×同一の手」を検出して繰り返させない／前進させる**ガードを追加する。
- 予算を脆弱でないエンドポイントの繰り返しで浪費しないようにする。**判定は手続き（機械的）**で行い、AI の勝手な繰り返しに委ねない。

## フェーズ0（実装前・必須・DeepSeek が実施）: 移行範囲と配線点を実データで確定

コードを変える前に:
- 自由テキスト ReAct を使う**全呼び出し箇所**を洗い出す（`base_manager.py` の think loop・`thought_loop.py`・各 specialist の decide/act）。tool-calling へ移す**最小の中核経路**（InjectionManager ＋ SmartSQLiHunter）を特定する。
- ツール群のスキーマ（ツール名・型付き引数）を、**既存のツール（run_sqli_hunter / sqli_scan / cors_scan 等）から機械的に**起こせるか確認する。
- 重複排除ガードを入れる箇所（think loop のどこで「同一の的×同一の手」を判定するか）を特定する。
- 封印 run を1回実行し、flash 化後にハンターが速く安定して回るか（step-1 の遅さ・繰り返しが解消したか）を funnel/ログで確認する。
- 出力: この計画書「フェーズ0結果」節に追記し、A/B の**最小差分設計**を提出して**承認を得てから** STEP 2 に進む（設計承認ゲート）。

## フェーズ0結果（2026-08-15・実データ確定・STEP 2 承認ゲート）

### 0-1. 自由テキスト ReAct の全呼び出し箇所マップ（実コード行番号付き）

| # | 場所 | 構造 | パース方式 |
|---|---|---|---|
| M1 | `base_manager.py` `dispatch()` L173-394（think loop `while turn < max_turns` L273） | マネージャ Phase 2。`LLMClient(role=swarm_manager/planner).agenerate(history)` L295 → `_parse_llm_output` → `_execute_tool` | 自由テキスト `Action: name(args)` を **ast.parse**（L452-474、true/false/null 置換）→ 失敗時 **regex fallback**（L479-505）。`Final Answer:` 検出 L514 |
| M2 | `base_manager.py` `_parse_llm_output` L422-521 | Action 行の解釈（上記） | ast.parse→regex |
| M3 | `base_manager.py` `_execute_tool` L523-624 | `available_tools` dict（name→func、`register_tool` L160-165）→ guard enforcement L528-565 → コンテキスト注入（url/cookies/auth_headers L591-606）→ `inspect.signature` 引数フィルタ L609-618 | ディスパッチ表は dict 直接参照（分岐なし）。無効ツールは `ValueError`（fail-closed L525） |
| M4 | `thought_loop.py` `ThoughtLoop.run_loop()` L43-110 | decide→act→ThoughtStep→should_stop。抽象 `decide` L113 / `act` L120 | 自由テキスト規約（実装側で解釈） |
| S1 | `smart_sqli.py` `SmartSQLiHunter.decide()` L532-618 | `LLMClient(role=sqli_specialist).agenerate` L560。「Observation:」「Final Answer:」不正検出→再帰リトライ L574-600 | **regex**（L607-609: THOUGHT/ACTION/INPUT）。空応答→finish 強制 L568 |
| S2 | `smart_sqli.py` `act()` L620+ | `finish`/`request` 文字列分岐。`request` で payload 送信・`used_payloads` 記録 L631-633 | action 文字列 match |
| S3 | `smart_xss.py` decide L1017 / `smart_lfi.py` L323 / `smart_cmd_ssrf.py` L884 / `actor_critic_fuzzer.py` L204 | 同型（ThoughtLoop 継承、各 decide が regex で THOUGHT/ACTION/INPUT） | regex（S1 と同パターン） |

**tool-calling へ移す最小の中核経路 = M1/M2/M3（InjectionManager の Phase 2 think loop）+ S1/S2（SmartSQLiHunter）のみ。** S3 他 specialist・Logic/Auth/Discovery マネージャは対象外（横展開は別タスク）。

### 0-2. tool-calling 設計（A・最小差分）

- **スキーマ生成は機械的に可能**: 全ハンターツールが共通シグネチャ `run_sqli_hunter(url: str, params: Dict=None, quick_mode: bool=False, **_kwargs)`（manager.py L4013 等）。`inspect.signature` + 型アノテーションから JSON schema（`properties: url/params/quick_mode`）を一括生成できる。意味は現行と同一（配線置換のみ）。
- **実行経路**: `LLMClient.agenerate/generate` は既に `tools`/`tool_choice`/`message.tool_calls` ループを持つ（llm.py L307/L400-429、L491/L582-611）が、**ツール実行はダミー文字列**（L418/L600 `f"Result from {function_name}"`）。→ `tool_executor` コールバック引数を追加（既定 None → 現行ダミー挙動を維持＝他呼び出し元・既定 run はバイト等価）。非 None 時は tool_calls の `function.name/arguments`（構造化 JSON）から実実行し `role: tool` で履歴へ戻す。
- **ast/regex 除去範囲**: tool-calling 経路が有効なとき、M2 の `_parse_llm_output`（ast.parse L452-477・regex L479-505）と S1 の regex（L607-609）を経由しない（tool_calls が無い最終応答のみ content 観察）。既存の `Action:` 文字列パースは非 tool-calling 経路として温存（既定 OFF の後方互換）。
- **fail-closed 維持**: 無効引数・未知ツールは従来どおり `ValueError`/シグネチャフィルタでスキップ（`_execute_tool` の既存動作をそのまま利用）。
- **能力を狭めない**: SmartSQLiHunter のツールは `request(payload: str)` / `finish(summary: str)` の2つにスキーマ化。payload は自由文字列のまま（ペイロード幅・適応ループ不変）。専用スキーマ生成は specialist 側に `_build_specialist_tool_schema()` を additive 追加。

### 0-3. 重複排除／前進ガード設計（B・機械的判定）

- **挿入点**: `base_manager.py` think loop の「2. Parse & Act」直後・`_execute_tool` 実行前（L343-350 の間）。ツール実行前に `(action, normalized_url, param_fingerprint)` の履歴集合 `self._executed_actions: set` を検査。
- **正規化**: URL は scheme/host/port 検証 + クエリソート（既存 origin 正規化ルール準拠・lessons 適用）。params は `frozenset(sorted(params.items()))`（`_auth` 等の注入メタは除外）。
- **判定**: 同一キーが存在 → 実行せず観察 `"Observation: action already executed for this target; choose a different move"` を返し**前進を促す**（AI の任意繰り返しに委ねない）。予算は脆弱でない的の繰り返しで消費されない。
- **能力を狭めない**: params 違い（例: 異なるパラメータ集合・payload）は**別手として許可**（同一 URL でも params が異なれば再実行可）。空引数 `run_sqli_hunter({})` の同一 URL 再実行のみ抑止。
- **既定挙動**: 計画書どおり `task_params` オプトイン（既定 OFF・バイト等価）。封印 run 時に ON する。

### 0-4. flash 化封印 run の観測（実データ: session_20260815_015847・本物 Caido 8081・GET-only・diagnostics ON）

- **速さ**: LiteLLM completion 呼び出し 162 回。呼び出し間隔 median 2s / p90 14s（並行・バッチ・リトライ混在のため個別レイテンシは推定値。step-1 の pro 5-14s/呼 は概ね解消）。
- **根本原因2（空引数 Action）は flash 化後も再現**: `Action: run_sqli_hunter({})`（01:47:29）・`Action: sqli_scan({})`（01:48:12）等の空引数呼び出しが発生。URL はコンテキスト注入で補完されるが **params 無し**（= 手の情報量が落ちる）。→ tool-calling 移行の必要性を実データで確認。
- **根本原因3（同一的の繰り返し）は flash 化後も再現**: 脆弱でない `/account/security` への `run_sqli_hunter` が **4 回**（01:48:44 / 01:48:47 / 01:50:23 / 01:53:03、うち 01:50:23 は 30 超の偽パラメータ付き、01:53:03 はパスワード変更フォーム params）。→ 重複排除ガードの必要性を実データで確認。
- **対象への到達**: SmartSQLiHunter は `/rest/products/search?q=` に ThoughtLoop を複数回起動（01:47:29 / 01:48:12 / 01:58:35。後者は sqli 分類で正しく起動）。ただし本 run の funnel は F5:0（0449 と同型: phase2_skipped_early_return 3 / task_suppressed_ownership 2）で **sql_error 候補は未生成**。検出決定性は STEP 2 実装後の STEP 3 で検証する。
- **GET-only**: session evidence の `request_method` は **GET のみ 24 件・非 GET 0**。OPTIONS 17 件がネットワーク境界でブロック（`Sealed-run GET-only enforcement`）。0447 B4 維持を実測確認。
- **その他**: `verify_report_session_consistency.py` → **consistent**。`data/vuln_roi_db.json` のみ run 副作用（報告のみ・commit 対象外）。config/shigoku.yaml は byte-exact 復元（sha256 一致）。

### 0-5. 無改変確認（bar/checker/impact-helper）

- `git diff HEAD` で `payout_grade.py` / `sealed_reproduction_checker.py` / `injection_evidence_fields.py` は **diff 0**（作業ツリークリーン・本タスクで未変更）。
- PCR-P1（main-thread assertion）無改変・secret 生値 0。

## STEP 2/3 結果・再スコープ（2026-08-15・ユーザー承認済み・§19 契約変更）

### STEP 2 実装（A+B・実装済み・独立検証 PASS）
- 差分: `base_manager.py` +243 / `smart_sqli.py` +111 / `settings.py` +4 / `llm.py` +28（合計 +371/-15）。新規テスト3本 20 件。
- A) tool-calling: `llm.py` に `tool_loop: bool=True`（既定 True＝既存呼び出しはバイト等価。False で tool_calls 生応答返却・キャッシュスキップ）。`base_manager._build_tool_schemas()`（`inspect.signature` から機械生成）・`_handle_tool_calls`（fail-closed・`role: tool` 履歴）。`smart_sqli._build_specialist_tool_schema()`（`request(payload: str)`/`finish` — payload 自由文字列＝能力不変）。`settings.tool_calling_enabled=False`（既定 OFF・env オプトイン）。
- B) 重複排除: `_normalize_target_url`/`_action_fingerprint`/ガードを think loop の `_execute_tool` 前に追加。`settings.dedup_guard_enabled=False`（既定 OFF）。params 違いは別手として許可（適応幅不変）。
- **独立検証（Claude・実データ）**: 保護3ファイル `payout_grade.py`/`sealed_reproduction_checker.py`/`injection_evidence_fields.py` **diff 0**。新規20 passed・injection 回帰 567 passed。`check_vdp_product_independence.py` **verdict=pass・token hits 0**。既定 OFF＝byte-equal。PCR-P1 無改変。

### STEP 3 実 run（連続3回・本物 Caido 8081・GET-only・オプトイン ON）
- session_20260815_083119 / 084844 / 090008。tool-calling で**空引数 Action は消滅・繰り返しは低減**（根本原因2/3 は解消を実データで確認）。
- **ただし完了条件3（F5>0）は未達**: 3 run とも `finding_funnel_v1 F5=0`、SQLi finding 0。**独立検証で `probe_sent=True` が全 sqli url_result（各18件）で 0**＝SmartSQLiHunter が発火 payload（`q` にシングルクォート）を**一度も送っていない**。`q` に届いた実リクエストは CORS 検査の空 `q=`（`Origin: evil.com`）のみ。DeepSeek が「`q=',` 送信」と読んだのは session 内 Python repr のクロージング誤認で、実 payload ではない。GET-only 維持・consistency consistent。

### 第4の根本原因（step-1 が拾えなかった新事実）
- 検出が非決定的なのは、A+B が対処した根本原因2/3（空引数・繰り返し）だけでなく、**SmartSQLiHunter の発火経路が実 HTTP プローブを出していない（probe_sent=0）**という、より上流の欠陥があるため。A+B ではここは直らない。

### 再スコープ（ユーザー承認・2026-08-15）
- 完了条件3（F5>0×3run）を本タスクから **SGK-2026-0451 へ carve-out**。0451 の完了契約が F5>0×3（発火経路の汎用修正）。**能力ギャップは破棄せず 0451 が所有**する。
- 0450 は **A+B（根本原因2/3 の解消＝landed improvement）の範囲で done**。§19 に基づきユーザー明示承認を得て契約を変更。silent-done（未達のまま条件3を残して done）は §19 違反として却下した。

## 修正方針（フェーズ0承認後）

### A) tool-calling
- ツールを型付きスキーマで宣言し、`litellm` の tools/tool_choice でモデルに渡す。応答の `message.tool_calls`（構造化）から名前と引数を取得して実行する。ast/regex パースは中核経路から除去。
- 既存ツールの意味は変えない（配線の置き換えのみ）。ツールが無効な引数の場合は fail-closed（従来どおりスキップ）。
- 適応ループ（結果を観測 → 次の手）は維持・強化する。**ハンターの適応幅を狭めない。**

### B) 重複排除ガード
- think loop に「(action, 正規化した対象) の集合」を持ち、同一手の再実行を抑止／前進させる（機械的判定）。
- 予算配分が脆弱でない的の繰り返しに食われないようにする。

## 完了条件（完了契約 — 固定）

1. フェーズ0の移行範囲・配線点・重複箇所が実データで確定し、A/B の最小差分設計が承認されている。
2. 中核経路（InjectionManager ＋ SmartSQLiHunter）が tool-calling で動作し、think loop に重複排除ガードが入る。**`payout_grade.py` / `sealed_reproduction_checker.py` / `injection_evidence_fields.py` は無改変**（diff 0）。PCR-P1 無改変。
3. ~~本物 Juice Shop への封印 run（本物 Caido・GET-only）を**連続 3 回**実行し、**3回とも SmartSQLiHunter が脆弱エンドポイント `/rest/products/search?q=` に発火ペイロードを送信し `sql_error` 候補を生成**~~ → **【再スコープ・SGK-2026-0451 へ carve-out】** STEP 3 で未達（probe_sent=0＝発火経路が実プローブを出さない第4根本原因）と判明。ユーザー承認のうえ本条件を 0451 の完了契約へ移管。誤検出・誤確定 0 は本 run でも維持。
4. 検出は狭めていない（tool-calling は幅を狭めず、適応ループを維持）ことをレビューで確認。カーブフィッティング非該当。
5. 必須テスト全 pass。`check_vdp_product_independence.py` exit 0。secret 生値 0。GET-only（session evidence に非 GET 状態変更 0）。
6. ドキュメント整合: `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` 0 エラー。

> 注（正直な範囲設定）: 本タスクの完了条件は**「検出の信頼化」**であり、**confirmed=1 を保証しない**。error-based SQLi は「エラーが出た」だけでは AI 審査員（poc_judge）が正しく賞金級と認めない（実害未証明）。**live confirmed には別途「実害の安全な実証（データ抽出）」能力が必要**で、これは後続タスクとして追跡する（`deferred_followup`）。ここで審査員を甘くする・impact を捏造することは禁止（原則1-3）。

## 必須テスト

- tool-calling: 中核経路がツールスキーマでモデルを呼び、`tool_calls` から名前・引数を取り出して実行する単体テスト（無効引数は fail-closed）。ast/regex パースに依存しないことを示す。
- 重複排除ガード: 同一 (action, target) の再実行が抑止／前進する単体テスト。
- 回帰: 既定 run のバイト等価性（tool-calling / ガードは中核経路に限定。既定挙動を変える場合はオプトイン）。
- 実 run: 連続3回で検出決定性（完了条件3）。

## NOT in scope（明示）

- **実害の実証（データ抽出）能力** — live confirmed に必要だが本タスクの範囲外。別タスクで追跡（審査員は触らない）。
- 確定バー・marker 語彙・再現チェッカー・0449 充填ヘルパーの変更。AI 審査員（poc_judge）の判定基準の緩和。
- 検出の幅を狭める最適化（能力縮小の禁止）。固定少数ペイロードへの回帰。
- SQLi 以外の specialist への tool-calling 一括移行（中核経路を先行。他は横展開を別途）。
- 状態変更（非 GET）を伴う攻撃・再現。特定製品向けの分岐・焼き込み。
- T4=0446（Haddix レポート明記）。

## リスクと対処

- **能力縮小への逆戻り**: tool-calling 化のついでに payload を絞る誘惑。→ 完了条件4で「幅を狭めていない」をレビュー必須化。適応ループ維持を明記。
- **大規模リファクタの回帰**: 中核経路に限定＋既定バイト等価性テストで隔離。全 specialist 一括移行はしない。
- **confirmed=1 の過大約束**: 本タスクは検出信頼化まで。live confirmed は実害実証（別タスク）が要る、と完了条件に明記済み。
