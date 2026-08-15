---
task_id: SGK-2026-0451
doc_type: plan
status: active
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-14_sgk-2026-0450_deterministic-error-based-sqli-detection.md
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
