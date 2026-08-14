---
task_id: SGK-2026-0450
doc_type: plan
status: active
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-13_sgk-2026-0449_confirm-real-sqli-mechanical-impact.md
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
3. 本物 Juice Shop への封印 run（本物 Caido・GET-only）を**連続 3 回**実行し、**3回とも SmartSQLiHunter が脆弱エンドポイント `/rest/products/search?q=` に発火ペイロードを送信し `sql_error` 候補を生成**（＝検出が決定的になった）。誤検出・誤確定は 0 のまま。
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
