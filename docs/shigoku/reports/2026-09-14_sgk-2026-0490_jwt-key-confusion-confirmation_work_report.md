---
task_id: SGK-2026-0490
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0490_jwt-key-confusion-confirmation.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0490_jwt-key-confusion-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0489_race-condition-confirmation.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- jwt
- confirmation-bar
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0490 作業完了報告 — JWT RS256→HS256 キー混同を実対象で本物確定（◎・JWT拡張）

## 何をしたか / なぜ

既存 JWT は `jwt_alg_none`（無署名偽造の受理）が ◎（SGK-2026-0476）。その JWT 拡張として
**RS256→HS256 キー混同**（サーバの RSA 公開鍵を HMAC 秘密鍵として HS256 署名した偽造トークンの
受理）を ◎ 化した。確定の意味論は alg=none と同型（unauth ベースライン差分＋forged_identity 反映）で
**偽造手法が違うだけ**のため、既存マーカー `jwt_forgery_accepted` を共有し、封印再現
`_check_jwt_forgery_replay`（forged_token 再送・手法非依存）も**そのまま流用**（sealed_reproduction は
改修不要）。

実対象（実測・非破壊）：**Juice Shop**。JWT は alg=RS256、公開鍵は `/encryptionkeys/jwt.pub` で認証なし
入手可。公開鍵 PEM を HMAC 秘密に HS256 署名した偽造トークンを `/rest/user/whoami` に送ると forged
identity（data.email）が反映＝受理。誤り秘密の HS256 は拒否、トークン無しは空。この **3者差分**が
「公開鍵を HMAC 秘密として検証している本物のキー混同」（署名未検証ではない）を証明。攻撃者は任意の
identity/role（管理者を含む）を偽造できる＝完全な認証バイパス。

## 実装（新設・非凍結1＋承認済み凍結1）

- **smart_jwt_forgery.py（非凍結・新規エンジン）**: `SmartJWTForgeryHunter`。task 由来の正規トークン
  （auth）＋公開鍵（`jwt_public_key` PEM か `jwt_pubkey_url`）＋observe で駆動。正規トークンの payload の
  識別子クレーム（既定候補 data.email/email/username/sub…・実在するものだけ）に一意マーカーを差し込み、
  ①公開鍵 PEM を HMAC 秘密に HS256 署名（**手動 HMAC**＝PyJWT 2.x は本攻撃を防ぐため）②誤り秘密で HS256
  署名 ③トークン無し の3者を observe へ送信し、①のみ反映かつ②③非反映＝キー混同確定。`self._client` 注入
  seam。`jwt_alg="hs256"`＋`jwt_key_confusion`＋`unauth_baseline_absent`＋`forged_identity`＋
  `forged_identity_reflected`＋`forged_token`（封印再現用）＋構造化 `jwt_forgery_evidence`（3者本文）＋
  3者差分 poc を付与。**正規トークン（ユーザーの秘密）は payload 導出のみで finding に一切含めない**。
  製品固有ハードコードなし。
- **payout_grade.py（凍結・承認）**: `_MARKER_CATEGORIES["jwt_rs256_hs256"]="jwt_forgery_accepted"`
  （alg=none と共有）。`_match_firing_marker` に `jwt_rs256_hs256` 分岐（jwt_alg=="hs256"＋
  jwt_key_confusion 真＋unauth_baseline_absent 真＋forged_identity 非空かつ反映）を**全て揃ったときだけ**
  発火（fail-closed・既存 alg=none 分岐は不変で非回帰）。
- **sealed_reproduction_checker.py**: **改修なし**。`jwt_forgery_accepted` の dispatch と
  `_check_jwt_forgery_replay`（forged_token を Authorization/Cookie で再送し forged_identity 再出現で
  matched）を手法非依存で流用。

## 秘密情報の扱い（監査）

- 正規トークン（ログインで得た自分のテストアカウントの JWT・ユーザーの秘密扱い）は **payload 構造の
  導出にのみ使用し finding には一切含めない**（E2E で `legit not in json.dumps(finding)` をアサート）。
- forged_token は攻撃成果物（公開鍵＝公開情報で署名・秘密を含まない）で finding/poc に含めてよい。
  公開鍵は誰でも入手可能な公開情報。

## 結果（独立検証・Claude が実測）

- **実 Juice Shop** で実 `SmartJWTForgeryHunter.execute` が3者差分で自走検出（claim data.email・公開鍵
  秘密→反映／誤り秘密→非反映／無し→空・HTTP 200）→`payout_grade=True/jwt_forgery_accepted`→**実
  `SealedReproductionChecker` が forged_token を再送し forged_identity を再観測→matched→CONFIRMED**。
- **本物の poc_judge（実 LLM）で 5/5 承認**（is_real=True・has_actual_impact=True・counter=False・
  初回から）。審査理由は「3者差分＝無トークンで identity 無し／攻撃者 JWT で一意 identity が 200 反映／
  誤り秘密で拒否＝サーバは署名検証した上で攻撃者制御トークンを受理」。**完全3ゲート達成＝◎**。
- テスト: 新規19テスト緑（payout_grade 発火/alg=none とのマーカー共有/fail-closed 各否定側＝alg 不一致・
  key_confusion 偽・baseline 非 absent・identity 空・非反映・impact 欠落／engine 3者差分・正規トークン
  非露出・3者 poc・forged_token 付与・署名未検証なら不確定・pubkey 無しで不確定／sealed_reproduction
  共有パス matched・mismatched・not_run）。非回帰: 失敗3件は本変更前でも失敗する既存（phase_b×2・
  t3_hybrid budget・SGK-2026-0488/0489 で stash 確認済み）＝**0490 起因の回帰ゼロ**（1287 passed）。
- 凍結3（poc_judge.md / task_queue.py / finding_validator.py）exit 0。**sealed_reproduction_checker.py も
  今回不変**（既存 jwt パス流用のため payout_grade のみ変更）。製品非依存 token 0（追加コード・新規テストは
  target.example のみ。Juice Shop/3000/encryptionkeys は scratchpad E2E のみ）。trailing whitespace 0。

## 確度の結論（正直な格付け）

- **RS256→HS256 キー混同（完全な認証バイパス）＝実害あり（CRITICAL）**で、実 poc_judge も通り
  **◎（完全3ゲート）**。curve-fit なし（新分岐は fail-closed・3者差分で署名未検証と区別・エンジンは
  製品固有ハードコードなし・既存 alg=none/sealed は不変）。**JWT 全体の高度化は 中(L2)**（alg=none＋
  RS256→HS256 の2偽造手法・Juice Shop 中心。kid injection/weak-secret は別途）。

## 完了条件の充足

計画の完了条件 1〜5 をすべて充足（条件3 の実 poc_judge を 5/5 で達成）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§18/§19、`rules/lessons.md`（mask-and-restore・一ファイルの挙動を仕様と
しない）、`rules/codingrules.md`（bare except 禁止・秘密非露出・境界のみ noqa）、メモリ
[[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]。

## 非阻害の観測（deferred / 別件）

- kid injection・JWT weak-secret ブルート・Juice Shop 以外の JWT 対象・パイプライン統合は本タスク
  対象外（`deferred_followup`・高度化フェーズ）。
