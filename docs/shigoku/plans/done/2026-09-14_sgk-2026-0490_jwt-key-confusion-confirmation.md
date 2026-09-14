---
task_id: SGK-2026-0490
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0490_jwt-key-confusion-confirmation_work_report.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0490_jwt-key-confusion-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0489_race-condition-confirmation.md
tags:
- shigoku
- detection
- jwt
- confirmation-bar
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0490 計画 — JWT RS256→HS256 キー混同を実対象で本物確定（◎・JWT拡張）

## 背景・事実（偵察で実測）

既存 JWT は `jwt_alg_none`（無署名偽造の受理）が ◎（SGK-2026-0476・マーカー
`jwt_forgery_accepted`）。JWT の拡張として **RS256→HS256 キー混同**（サーバの RS256 公開鍵を
HMAC 秘密鍵として HS256 署名した偽造トークンが受理される）を ◎ 化する。確定の意味論は alg=none と
同型（unauth ベースライン差分＋forged_identity 反映）で、**偽造手法が違うだけ**。よって既存マーカー
`jwt_forgery_accepted` を再利用し、封印再現 `_check_jwt_forgery_replay`（forged_token 再送・手法非依存）
も**そのまま流用**できる。

実対象（実測・非破壊）：**Juice Shop**。
- JWT は alg=RS256、公開鍵は `/encryptionkeys/jwt.pub`（RSA PUBLIC KEY PEM）で認証なし入手可。
- 偽造 HS256（公開鍵 PEM を HMAC 秘密に署名・PyJWT 2.x はこの攻撃を防ぐため手動 HMAC で署名）を
  `/rest/user/whoami` に送ると **forged identity（data.email）が反映＝受理**。誤り秘密の HS256 は反映
  されず（拒否）、トークン無しでも反映されない。**3者差分**（公開鍵秘密＝受理／誤り秘密＝拒否／
  無し＝空）が「公開鍵を HMAC 秘密として検証している本物のキー混同」（署名無視ではない）を証明。
- 非破壊（読み取り GET のみ・偽造は自分の識別子を差し替えるだけ）。

## 確定バーの欠落点（事実）

- `_MARKER_CATEGORIES` に `jwt_rs256_hs256` が無く、`jwt_forgery_accepted` の発火分岐は
  `jwt_alg=="none"` 必須で HS256 キー混同では発火しない。

## 対象（完了契約）

Juice Shop の RS256→HS256 キー混同を実対象で **機械フロア＋実再現＋実 poc_judge の完全3ゲート**で
◎ に到達。確定は**3者差分＋一意マーカー**（公開鍵秘密の偽造＝受理・反映／誤り秘密＝拒否／無し＝空）。

## 実装方針（新設・最小差分）

1. **新エンジン `smart_jwt_forgery.py`（非凍結・新規）**: `SmartJWTForgeryHunter`。task 由来の
   正規トークン（auth）＋公開鍵（`jwt_public_key` PEM か `jwt_pubkey_url`）＋observe エンドポイントで
   駆動。正規トークンの payload の識別子クレーム（既定候補 data.email/email/username/sub…）に一意
   マーカーを差し込み、①公開鍵 PEM を HMAC 秘密に HS256 署名（手動 HMAC）②誤り秘密で HS256 署名
   ③トークン無し の3者を observe へ送信し、①のみマーカー反映＝キー混同確定。`self._client` 注入 seam。
   `forged_token`（①）＋`forged_identity`＋`unauth_baseline_absent`＋`jwt_alg="hs256"`＋
   `jwt_key_confusion`＋構造化 `jwt_forgery_evidence`（3者本文）＋3者差分 poc を付与。正規トークン
   （ユーザーの秘密）は finding に一切含めない（payload 導出のみ）。製品固有ハードコードなし。
2. **確定バー `payout_grade.py`（凍結・承認）**: `_MARKER_CATEGORIES["jwt_rs256_hs256"]=
   "jwt_forgery_accepted"`。`_match_firing_marker` に `jwt_rs256_hs256` 分岐（jwt_alg=="hs256"＋
   jwt_key_confusion 真＋unauth_baseline_absent 真＋forged_identity 非空かつ反映）を**全て揃った
   ときだけ**発火（fail-closed・既存 alg=none 分岐は不変で非回帰）。
3. **再現チェッカー `sealed_reproduction_checker.py`**: **改修不要**。`jwt_forgery_accepted` の dispatch
   と `_check_jwt_forgery_replay`（forged_token を Authorization/Cookie で再送し forged_identity 再出現で
   matched）は手法非依存で流用（forged_token＋forged_identity は additional_info に付与済み）。

## 完了条件

1. 実 Juice Shop で実 `SmartJWTForgeryHunter.execute` が3者差分で自走検出→
   payout_grade=True/jwt_forgery_accepted。
2. 実 `SealedReproductionChecker` が forged_token を再送し forged_identity 再出現→matched→CONFIRMED。
3. 本物の poc_judge（実 LLM）で承認（3者差分＝公開鍵秘密で受理/誤り秘密で拒否/無しで空を poc に提示）。
4. 製品非依存 fixture の新規テスト緑（発火／fail-closed 各否定側＝alg 不一致・key_confusion 偽・
   baseline 非 absent・非反映／engine 3者差分・誤り秘密で反映なら不確定／正規トークン非露出）。
5. 凍結3 exit 0（sealed_reproduction は今回不変）。製品トークン 0・秘密値非露出・回帰ゼロ。

## NOT in scope

- kid injection（別サブクラス・別タスク）。JWT 秘密ブルート（weak secret）。
- Juice Shop 以外への一般化（実対象1件で ◎ 到達・幅優先）。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§18/§19、`rules/lessons.md`（mask-and-restore・一ファイルの挙動を仕様と
しない）、`rules/codingrules.md`（bare except 禁止・秘密非露出・境界のみ noqa）、メモリ
[[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]。
