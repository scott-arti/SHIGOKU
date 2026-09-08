---
task_id: SGK-2026-0476
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/reports/2026-09-09_sgk-2026-0476_jwt-alg-none-forgery-confirmation_work_report.md
- docs/shigoku/worklogs/2026-09-09_sgk-2026-0476_jwt-alg-none-forgery-confirmation_work_log.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/plans/done/2026-09-07_sgk-2026-0471_open-redirect-confirmation.md
- docs/shigoku/plans/done/2026-09-09_sgk-2026-0475_cors-credentialed-reflection-confirmation.md
tags:
- shigoku
- detection
- auth
- jwt
- confirmation-bar
created_at: '2026-09-09'
updated_at: '2026-09-09'
---

# SGK-2026-0476 計画 — JWT alg=none 偽造受理を「本物確定（◎）」まで到達させる

## 目的（何を・なぜ）

検出能力マップ [[sgk-2026-0465]] で認証/JWT は「△〜○ 突破試行は可・決め手の証拠は今後」。
**実対象 Juice Shop で本物の認証バイパス（JWT alg=none 偽造受理）を確定（◎）** できる状態へ引き上げる。

## 事実（実測・実コードで確定・2026-09-09）

- **実 Juice Shop は alg=none 偽造トークンを受理する**（GET のみで実測確定・攻撃者ホスト表現は fabricated ID）:
  - トークン無しで `GET /rest/user/whoami` → `{"user":{}}`（未認証）。
  - **無署名（alg=none）の偽造トークン**（でっち上げの identity・署名なし）を Authorization/Cookie に付けて
    同 GET → `{"user":{"id":1,"email":"<fabricated>"}}`＝サーバが署名検証せず偽造 identity を受理。
    攻撃リクエストは GET のみ（偽造はローカル計算）。JWT は本来 RS256（`admin@juice-sh.op`/`admin123` で取得した
    トークンで確認・値はマスク）。
- 確定バー: `payout_grade._MARKER_CATEGORIES` に auth/jwt が**無い** → unknown_category で自動却下
  （オープンリダイレクト SGK-2026-0471 / CORS SGK-2026-0475 と同型でマーカー新設が要る）。
- エンジン `AuthNinja`（`auth_ninja.py`）: `_check_none_alg` は現状**常に False を返すスタブ**
  （コメントに「本来はサーバに送って検証が必要」と明記）＝サーバ側受理の確証が未実装。`_check_weak_secret` は
  HS256 辞書（RS256 の Juice Shop には非該当）。生成 Finding は impact/reproduction_steps 無し・token を task.params で要求。
- 機械フロア step3 は impact＋reproduction_steps 必須・status>0。AI 審査 poc_judge は種別非依存（改変不要）。

## 対象（このタスクで触るファイル）

- **B（非凍結）** `src/core/agents/swarm/auth/auth_ninja.py`（必要なら小さな JWT ヘルパー）
  - **サーバ側受理の実確証を実装**: 認証 identity を反映するエンドポイント（whoami 系）に対し、
    (1) トークン無しの baseline GET を送り identity 不在を観測、
    (2) **エンジンが fabricate した identity**（実トークンの複製ではない・攻撃者選択の値）を載せた
        **alg=none 無署名トークン**を Authorization/Cookie に付けて GET、
    (3) 応答本文に fabricated identity が反映（かつ baseline では不在）＝**差分成立**のときだけ vulnerable とする。
        サーバが 401/拒否/identity 非反映なら vulnerable=False（fail-closed）。
  - 発火 Finding に impact / reproduction_steps を設定し、`additional_info` に
    `forged_identity`（fabricated 値）・`auth_endpoint`・`forged_token`（偽造トークン・再現用）・
    `unauth_baseline_absent=True`・`jwt_alg="none"` を残す。evidence.response_body に反映本文の抜粋、
    evidence.response_status に実 status。
  - 既存 weak-secret 経路は非回帰で維持。トークン/秘密は値をログに出さない（マスク）。
- **A①（凍結・ユーザー明示承認済み・2026-09-09）** `src/core/agents/swarm/injection/payout_grade.py`
  - `_MARKER_CATEGORIES` に JWT alg=none 種別（`jwt_alg_none`。VulnType.JWT_ALG_NONE.value=="jwt_alg_none"）→
    `"jwt_forgery_accepted"` を追加。
  - `_match_firing_marker` に分岐: **`jwt_alg="none"`（無署名/未検証）かつ forged_identity が応答に反映
    （additional_info/evidence.response_body）かつ unauth_baseline_absent が真**のときだけ
    `"jwt_forgery_accepted"` を返す。署名検証済み/受理されない/差分なしは None（fail-closed）。既存マーカー相乗り禁止。
- **A②（凍結・承認済み）** `src/core/validation/sealed_reproduction_checker.py`
  - `"jwt_forgery_accepted"` を再現対象に追加。専用 `_check_jwt_forgery_replay`: 元 Finding の
    `forged_token` を Authorization/Cookie に付けて `auth_endpoint`（無ければ target）へ封印 GET 再送し、
    応答本文に `forged_identity` が再出現すれば `matched`、非出現なら `mismatched`、送信不能/client None は `not_run`。
    forged_token/forged_identity が欠落なら `not_run`（fail-closed）。既存 `_send_get`（他種別本文経路）は byte-identical。

## 確定バー（凍結・本タスクでは無改変）

- `poc_judge.md` / `task_queue.py` / `finding_validator.py` は無改変（`git diff --quiet HEAD` exit 0）。

## 完了条件（完了契約）

1. B: alg=none 偽造を認証エンドポイントに送り、baseline 不在→偽造で fabricated identity 反映の差分成立時のみ
   vulnerable Finding（impact/reproduction_steps 非空・forged_identity/forged_token/auth_endpoint/jwt_alg=none 保持）。
   サーバ拒否/非反映/差分なしでは vulnerable=False（fail-closed）。
2. A①: `evaluate_payout_grade({vuln_type:'jwt_alg_none', ...偽造受理証拠...})` が
   `payout_grade=True / marker=jwt_forgery_accepted`。署名検証・非受理・差分なしは False（fail-closed）。
3. A②: forged_token を付けた封印再送で forged_identity 再出現→matched、非出現→mismatched、
   送信不能/client None/欠落→not_run。
4. `finding_validator.validate_finding` に AI 賞金級＋再現 matched で `CONFIRMED / hybrid_confirmed`。
5. 凍結: 改変は `payout_grade.py` と `sealed_reproduction_checker.py` のみ。`poc_judge.md` /
   `task_queue.py` / `finding_validator.py` は `git diff --quiet HEAD` exit 0。
6. 製品非依存 token 0（denylist）。テストの fabricated identity は example 系（例: forge@evil.example）。
   juice/dvwa/localhost:3000 等を入れない。
7. **実対象での ◎ 実証**: 認可対象 **Juice Shop** の identity 反映エンドポイントに対し、alg=none 偽造→受理→
   フル判定経路が `CONFIRMED`（fabricated identity 反映・baseline 不在・GET-only・トークンはマスク）。
8. **fail-closed 否定側**: 署名を正しく検証して alg=none を拒否する制御対象では vulnerable=False /
   `payout_grade=False`（偽 ◎ を出さない）ことをテストで担保。

## 必須テスト

- `payout_grade` 単体: (a) alg=none＋forged 反映＋baseline 不在→True/marker=jwt_forgery_accepted、
  (b) 署名検証済み(alg=RS256/HS256)→False、(c) forged 非反映→False、(d) baseline に既出（差分なし）→False。
- `sealed_reproduction_checker` 単体: (a) forged_token 再送で forged_identity 再出現→matched、(b) 非出現→mismatched、
  (c) client None/forged 欠落→not_run、(d) 既存マーカー（external_redirect/cors/本文系）の非回帰。
- engine 単体: (a) 受理サーバ（stub）で差分成立→vulnerable＋証拠、(b) 署名検証サーバ（stub・401）→False。
- 統合: `validate_finding` が JWT 偽造本物証拠＋AI賞金級＋再現matched で CONFIRMED。
- injection + validation + auth スイート非回帰。
- 変更後 `python3 scripts/sync_shigoku_updated_at.py` → `python3 scripts/validate_shigoku_docs.py` が 0 エラー。

## NOT in scope

- 確定バーの敷居低下・見かけだけ通す curve-fitting。
- `poc_judge.md` / `task_queue.py` / `finding_validator.py` の改変。
- weak-secret/RS256→HS256/kid injection/OAuth 等の他 JWT 種別（本タスクは alg=none に限定）。
- 破壊的テスト（GET-only 維持。baseline/attack はいずれも GET）。

## リスク

- 凍結2ファイルへの変更＝確定バーの語彙拡張。**能力追加であり敷居低下ではない**ことを、署名検証済み/非受理/
  差分なしの fail-closed テスト（条件2/3/8 の否定側）で担保する。
- 偽造 identity は必ずエンジン fabricate（実トークンの複製禁止）＝「盗んだ有効セッションの再生」ではなく
  「無署名偽造の受理」を証明する。差分（baseline 不在）で担保。
- 秘密（実トークン/秘密鍵）は値をログ・証拠・レポートに出さない（マスク）。偽造トークンは fabricated ID のみ。

## 実装・検証の分担

- 実装は DeepSeek/opencode に**テキストで**指示（ドキュメント化しない）。opencode は fixer サブエージェントの
  makora フォールバック対策として repo opencode.json に一時 agent→deepseek 上書きを入れて起動し完了後復元
  （[[opencode-fixer-subagent-makora-fallback]]）。
- 完了報告は額面通り信用せず、Claude が独立検証（テスト実出力・diff・凍結残り3無改変・実 Juice Shop E2E・
  署名検証サーバでの正しい非確定）。
