---
task_id: SGK-2026-0450
doc_type: plan
status: active
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-13_sgk-2026-0449_confirm-real-sqli-mechanical-impact.md
created_at: '2026-08-14'
updated_at: '2026-08-14'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- confirmation
target: src/core/agents/swarm/injection/smart_sqli.py
---

# 実装計画: SGK-2026-0450 — エラーベース SQLi 検出を決定的にして「本物の確定1件」を実 run で出す

（親ロードマップ: SGK-2026-0442。0449 で「充填すれば確定する」機構は完成・実証済み。残る唯一の壁＝検出の非決定性を潰し、実 run で確実に confirmed=1 を出す。）

## 背景（なぜこのタスクが必要か）

- 0449 で、SQLi 候補に impact/Evidence を機械充填すれば **payout_grade PASS ＋ 再現チェッカー matched ＝ confirmed** になることを end-to-end で実証した（実 gate・実 checker 無変更、本物 Caido 経由 GET リプレイ 3/3 で `sql_error` 再発火）。
- **しかし 0449 STEP 3 の実 run では confirmed=0**。理由は再現チェッカーでも impact 欠落でもなく、**エラーベース SQLi の検出が非決定的**なこと:
  - `SmartSQLiHunter` の LLM 駆動 Phase-2（ThoughtLoop）が `Phase 2 timed out after 90s` を5回起こし、`sql_error_observed=True` の候補が **1件も生成されなかった**（session_20260814_014342 で `sql_error_observed=True` 0件を実測）。
  - 一方 0448 STEP 3 の run では同じ経路が発火して候補が生成された（session_20260813_232923）。**検出は run 毎に出たり出なかったりする**。
- ターゲット挙動そのものは決定的（`/rest/products/search?q='...` は 3/3 で HTTP 500 + `SQLITE_ERROR: incomplete input`）。**足りないのは「その決定的な挙動を、LLM の気まぐれに依存せず必ず候補化する検出経路」**。

## 目的

エラーベース SQLi の検出を、**LLM Phase-2 の予算・タイミングに依存しない決定的な経路**で行い、対象に SQL エラーが実在する限り run 毎に必ず候補（`sql_error_observed=True`）を生成する。これにより 0449 の充填機構と組み合わさって、**実 run で安定して confirmed=1** が出る状態にする。

## スコープの切り分け（confirmed vs hypothesis — フェーズ0で確定）

- **[confirmed]** 0449 の充填機構は正しく、候補さえ出れば confirmed に至る（0449 で実証）。
- **[confirmed]** ターゲットは決定的に SQL エラーを返す（3/3 実測）。
- **[hypothesis — フェーズ0で要確定]** confirmed=0 の直接原因は LLM Phase-2 の非決定性（90s タイムアウト）であり、決定的なエラーベース・プローブを加えれば候補が安定生成される。
- **[hypothesis — フェーズ0で要確定]** `SmartSQLiHunter` 内にすでに決定的プローブの下地（`_classify_sql_error` 等）があり、それを LLM 経路と独立に必ず走らせるだけで足りる（大改修不要）。

## フェーズ0（実装前・必須）: 非決定性の原因を run 実データで特定

コードを変える前に、封印 run（本物 Caido・GET-only・diagnostics ON）を実行し、次を確認する。

- `SmartSQLiHunter` が discovered parameters（例 `q`）に対し、決定的なエラーベース payload を **LLM 予算と独立に**送っているか、それとも検出が ThoughtLoop 内でのみ起きるか。
- `Phase 2 timed out after 90s` が候補生成を妨げている箇所（どの段で打ち切られ、決定的プローブが走らないか）。
- 既存の決定的経路（`_classify_sql_error` / `_sql_error_observed` を立てる箇所）が、どの条件で呼ばれるか。
- 出力: この計画書「フェーズ0結果」節に追記し、決定的プローブを「どこに・どう最小差分で足すか」を確定してから STEP 2 の設計承認を得る。

## 修正方針（フェーズ0で hypothesis が confirmed の場合のみ）

### 決定的エラーベース SQLi プローブ
- discovered parameters に対し、**汎用的な**エラー誘発 payload（例: 未閉じクォート `'`）を **GET で**送り、応答本文を既存の `_classify_sql_error` で判定して `sql_error_observed` を立てる経路を、**LLM Phase-2 の予算・タイムアウトと独立に**必ず走らせる。
- payload は**製品非依存の一般的な SQL 構文破壊**に限定（Juice Shop 固有の文字列・エンドポイント・答えを焼き込まない＝カーブフィッティング禁止）。
- 生成される Finding は 0449 の充填経路（`injection_evidence_fields.build_sqli_*`）にそのまま乗る（impact/Evidence が埋まり payout_grade PASS → 再現チェッカーが独立再送で matched）。
- **確定バー（payout_grade.py）・再現チェッカー（sealed_reproduction_checker.py）・0449 の充填ヘルパーは無変更**。本タスクは「候補を安定生成する」ことだけに集中する。
- GET-only 境界維持。状態変更を伴うプローブは送らない。

## 完了条件（完了契約 — 固定）

1. フェーズ0で非決定性の原因が run 実データで特定され、決定的プローブの最小差分設計が承認されている。
2. 決定的エラーベース SQLi プローブが入り、**`payout_grade.py`・`sealed_reproduction_checker.py`・`injection_evidence_fields.py` は無改変**（diff 0 で証明）。PCR-P1 無変更。
3. 本物 Juice Shop への封印 run（本物 Caido・GET-only）を**連続 3 回**実行し、**3回とも confirmed ≥ 1**（当該 SQLi が 3条件 AND を独立に満たし confirmed）。誤確定は 0 のまま。＝検出が決定的になったことを実 run で証明。
4. confirmed finding の impact/Evidence が**捏造でない**（観測事実のみ）ことをレビューで確認。
5. 必須テスト全 pass。`check_vdp_product_independence.py` exit 0（製品トークン 0）。secret 生値 0。GET-only（session evidence に非 GET 状態変更 0）。
6. ドキュメント整合: `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` 0 エラー。

## 必須テスト

- 決定的プローブの単体テスト: discovered param に対し LLM 経路を通さずエラー誘発 payload が GET 送信され、SQL エラー応答で `sql_error_observed=True` の Finding が生成される（fail-closed: SQL エラーが無ければ候補を作らない）。
- 製品非依存テスト: payload に製品固有トークンが無いこと（汎用構文破壊のみ）。
- 回帰: 既定 run のバイト等価性（決定的プローブは既存挙動に付加。既定挙動を変える場合はオプトイン）。

## NOT in scope（明示）

- 確定バー（3条件 AND）・marker 語彙・再現チェッカー・0449 充填ヘルパーの変更。
- SQLi 以外のカテゴリの検出決定化（本タスクはエラーベース SQLi に集中）。
- boolean/time-based blind SQLi の決定化（エラーベースの1件確定を優先）。
- 状態変更（非 GET）を伴うプローブ。
- 特定製品（Juice Shop）向けの分岐・payload・焼き込み答え（カーブフィッティング禁止）。
- T4=0446（Haddix レポート明記）。

## リスクと対処

- **カーブフィッティング圧**: 「confirmed を出す」ために Juice Shop 固有の payload/エンドポイントを焼き込む誘惑。→ payload は汎用構文破壊のみ・製品非依存テストで必須化。確定は再現チェッカーの独立再送が earned する（無変更）。
- **過検出（誤確定）**: 決定的プローブが増えると false positive が増える懸念。→ 候補生成は `sql_error` marker 実観測時のみ。確定は 3条件 AND（再現 matched 必須）で守られ、バーは無変更。誤確定 0 を run で確認。
- **既定 run への回帰**: 新プローブが既存挙動を変える。→ オプトイン化＋バイト等価性テストで隔離。
