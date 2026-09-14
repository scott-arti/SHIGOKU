---
task_id: SGK-2026-0490
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0490_jwt-key-confusion-confirmation.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0490_jwt-key-confusion-confirmation_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- jwt
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0490 作業ログ（JWT RS256→HS256 キー混同・実 Juice Shop・◎）

## 1. 偵察（事実優先・実測）
- 既存 jwt_alg_none(◎・マーカー jwt_forgery_accepted)の拡張として RS256→HS256 キー混同を選定。
- 実測: Juice Shop は JWT alg=RS256・公開鍵 /encryptionkeys/jwt.pub を認証なし入手可。公開鍵 PEM を
  HMAC 秘密に HS256 署名した偽造トークンを /rest/user/whoami に送ると forged identity 反映=受理、
  誤り秘密=拒否、無し=空の3者差分を確認（PyJWT 2.x は本攻撃を防ぐため手動 HMAC で署名）。非破壊。
- 確定意味論は alg=none と同型→マーカー jwt_forgery_accepted 共有・封印再現 _check_jwt_forgery_replay も
  手法非依存で流用可（sealed_reproduction 改修不要）と判断。

## 2. 台帳・計画・承認
- SGK-2026-0490 採番（registry.yaml・DOC-0560）。JWT 拡張の選択＝ビルド承認（凍結1=payout_grade 追加）。

## 3. 実装（Claude 直接）
- smart_jwt_forgery（新規）: 正規トークン payload の識別子クレームに一意マーカーを差込み、公開鍵秘密/
  誤り秘密/無しの3者を observe へ送り①のみ反映でキー混同確定。手動 HMAC 署名・_client seam・
  forged_token+forged_identity+jwt_alg=hs256+jwt_key_confusion+unauth_baseline_absent+jwt_forgery_evidence
  +3者差分poc。正規トークンは payload 導出のみで finding 非包含。製品固有ハードコードなし。
- payout_grade: `_MARKER_CATEGORIES["jwt_rs256_hs256"]="jwt_forgery_accepted"`（共有）+jwt_rs256_hs256 発火
  分岐（jwt_alg=hs256+key_confusion+baseline absent+forged 反映・全て揃いで発火・fail-closed・alg=none 不変）。
- sealed_reproduction: 改修なし（jwt_forgery_accepted dispatch+_check_jwt_forgery_replay 流用）。

## 4. 独立検証（Claude・実出力）
- smoke: 発火 positive／key_confusion 偽・baseline 非absent・alg 不一致 の fail-closed／alg=none 非回帰 確認。
- 実 Juice Shop E2E: execute→3者差分（公開鍵秘密反映/誤り秘密非反映/無し空）→payout_grade=True/
  jwt_forgery_accepted→封印再現 matched→CONFIRMED。正規トークンが finding に無いことをアサート。
- 実 poc_judge: **初回から 5/5**（3者差分＝署名検証した上で攻撃者制御トークンを受理と評価）。
- 新規19テスト緑。非回帰: 失敗3件は HEAD でも失敗する既存（phase_b×2・t3_hybrid budget・0488/0489 で
  stash 確認済み）＝0490 起因の回帰ゼロ（1287 passed）。凍結3 exit 0・sealed も不変。製品 token0・
  whitespace0・秘密値非露出（正規トークン非包含）。

## 5. 完了
- 完了条件1〜5 充足（条件3 実 poc_judge 5/5）。in_scope_blocker 0 → done。
- 能力マップ: JWT 行に **RS256→HS256 キー混同 ◎** を追記（alg=none と2偽造手法）。高度化 中(L2) 据置。
- 教訓: (1) 確定意味論が同じなら**マーカー共有＋既存封印再現の流用**で凍結改変を最小化できる
  （payout_grade 1ファイルのみ・sealed 不変）。(2) キー混同は「誤り秘密で拒否」の第3の差分が署名未検証との
  区別に必須。(3) 攻撃で作る偽造トークンは公開鍵署名＝秘密非包含で安全、正規トークンは finding 非包含。
  [[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・[[no-capability-minimization]]。
- 観測(別件): kid injection・weak-secret ブルート・他対象・統合は高度化フェーズで deferred。
