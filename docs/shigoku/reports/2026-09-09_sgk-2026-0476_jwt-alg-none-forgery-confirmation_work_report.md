---
task_id: SGK-2026-0476
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-09_sgk-2026-0476_jwt-alg-none-forgery-confirmation.md
- docs/shigoku/worklogs/2026-09-09_sgk-2026-0476_jwt-alg-none-forgery-confirmation_work_log.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
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

# SGK-2026-0476 作業完了報告 — JWT alg=none 偽造受理を本物確定（◎）まで到達

## 何をしたか / なぜ

検出能力マップ [[sgk-2026-0465]] で認証/JWT は「△〜○」。実対象 Juice Shop で本物の認証バイパス
（**JWT alg=none 無署名偽造トークンの受理**）を確定（◎）できる状態へ引き上げた。実測で Juice Shop は
無署名偽造トークンの偽造 identity を GET のみで受理する（トークン無し＝`{"user":{}}` との差分で確定）ことを
確認。確定バーに auth/jwt マーカーが無く（オープンリダイレクト/CORS 同型）、AuthNinja の alg=none チェックは
常に False のスタブ（サーバ側受理の確証が未実装）だった。

## 実装（非凍結1＋凍結2・凍結はユーザー明示承認済み）

- **B（`auth_ninja.py`・非凍結）**: alg=none サーバ側受理の実確証を実装。identity 反映エンドポイントに対し
  (1) トークン無し baseline GET、(2) **エンジンが fabricate した identity**（実トークンの複製ではない攻撃者選択値・
  example 系）を載せた**無署名（alg=none・署名空）トークン**を Authorization/Cookie に付けた GET を送り、
  (3) baseline 不在→forged で identity 反映の**差分成立時のみ** vulnerable。401/拒否/非反映/差分なし/エンドポイント
  不在/送信不能は False（fail-closed）。redirect 非受理。発火 Finding に impact/reproduction_steps/additional_info
  （forged_identity/forged_token/auth_endpoint/unauth_baseline_absent/jwt_alg=none）/実 status/本文抜粋。既存
  weak-secret 経路は非回帰。トークン/秘密値はログに出さない。
- **A①（`payout_grade.py`・凍結・承認済み）**: `_MARKER_CATEGORIES` に `jwt_alg_none`→`jwt_forgery_accepted`。
  `_match_firing_marker` 分岐は **jwt_alg=="none" ＋ unauth_baseline_absent 真 ＋ forged_identity 非空かつ応答反映**の
  ときだけ発火。署名検証済み/非受理/差分なしは None（fail-closed）。
- **A②（`sealed_reproduction_checker.py`・凍結・承認済み）**: `jwt_forgery_accepted` を専用 `_check_jwt_forgery_replay`
  で再現。forged_token を Authorization/Cookie に付けた封印 GET 再送で forged_identity 再出現→matched、非出現→
  mismatched、client None/欠落/送信不能→not_run。`_send_get`（他種別本文経路）は byte-identical。

## 結果（独立検証・Claude が実施）

- **実 Juice Shop で ◎ を実証**: 実 AuthNinja→fabricated identity（forge-*@evil.example）の alg=none 無署名トークンを
  identity エンドポイントへ送付→baseline 不在・forged で反映の差分→`payout_grade=True/jwt_forgery_accepted`→
  実 `SealedReproductionChecker` の forged_token 再送で forged_identity 再出現 `matched`→**`CONFIRMED/hybrid_confirmed`**。
- **fail-closed 否定側**: 署名を検証して alg=none を拒否する制御サーバでは finding 0 件＝正しく非確定（偽 ◎ なし）。
- テスト: 新規4ファイル36テスト全緑（独立実行）。`tests/core/agents/swarm/injection/ tests/core/validation/
  tests/core/agents/swarm/auth/` = **1039 passed / 2 failed**。2 failed は `test_phase_b_readiness.py`（別環境の成果物
  存在チェック）で本変更と無関係。
- 凍結: 改変は承認済み `payout_grade.py` / `sealed_reproduction_checker.py` のみ。`poc_judge.md` /
  `task_queue.py` / `finding_validator.py` は `git diff --quiet HEAD` exit 0（無改変）を独立確認。
- 製品非依存 token 0（denylist 照合で変更コード・テストにヒット 0）。秘密（実トークン/鍵）は非ログ・偽造は fabricated ID のみ。
- 敷居は下げていない（署名検証済み/非受理/差分なしの fail-closed をテストと制御サーバ実測で担保）。

## 完了条件の充足

計画の完了条件 1〜8 すべて PASS。`in_scope_blocker=0`。実対象 ◎ は Juice Shop で達成（条件7）、署名検証サーバで
正しく非確定（条件8）。

## 実装フローの注記（インフラ）

opencode デタッチ起動＋repo `opencode.json` の一時 agent→deepseek 上書き（fixer→makora フォールバック対策・
[[opencode-fixer-subagent-makora-fallback]]）で genuine deepseek 完走、完了後に `opencode.json` を復元（無改変確認）。

## 能力マップ更新

認証/JWT を △〜○ → **◎**（実 Juice Shop で JWT alg=none 偽造受理を確定・署名検証サーバでは正しく非確定）に更新。
