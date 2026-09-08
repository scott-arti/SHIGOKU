---
task_id: SGK-2026-0475
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-09_sgk-2026-0475_cors-credentialed-reflection-confirmation.md
- docs/shigoku/worklogs/2026-09-09_sgk-2026-0475_cors-credentialed-reflection-confirmation_work_log.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/plans/done/2026-09-07_sgk-2026-0471_open-redirect-confirmation.md
tags:
- shigoku
- detection
- cors
- confirmation-bar
created_at: '2026-09-09'
updated_at: '2026-09-09'
---

# SGK-2026-0475 作業完了報告 — CORS 誤設定の本物確定（◎）能力を構築（認証付きオリジン反映）

## 何をしたか / なぜ

検出能力マップ [[sgk-2026-0465]] で CORS は「△ 機微データ漏えいまで示さないと確定に上げない」。
**本物の高影響 CORS（攻撃者オリジン反映＋ACAC:true＋認証付き機微データ越境読み取り）を確定(◎)できる能力**を構築した。

**重要（実測・ユーザー承認）**: 認可対象 Juice Shop の CORS は全エンドポイント `Access-Control-Allow-Origin: *`
（オリジン反映なし・ACAC なし）＝公開データのみの低影響で、本物の高影響 CORS バグは実在しない。
CLAUDE.md 既知セーフホールドでも「CORS は公開データのみ＝confirmed に上げない」。よって `*` を ◎ にするのは
curve-fitting で禁止。◎ 実証は**認可済み制御対象**（反映＋ACAC:true＋認証付き機微データ）で行い、
**Juice Shop の `*` は fail-closed で正しく非確定（偽 ◎ を出さない）ことを実証**した。

## 実装（非凍結2＋凍結2・凍結はユーザー明示承認済み）

- **B（`smart_cors.py` / `cors_tester.py`・非凍結）**: `origin_reflection_with_credentials`（acao==test_origin
  かつ acac==true）かつ**認証コンテキスト付き**のときだけ、越境応答本文の抜粋（最小32字・fail-closed）を
  `additional_info.credentialed_body_excerpt` と `evidence.response_body` に残す。`evidence.response_status` を
  実観測値に。`*`/null/反映なし/認証なしでは抜粋を残さない。
- **A①（`payout_grade.py`・凍結・承認済み）**: `_MARKER_CATEGORIES` に `cors`/`cors_misconfiguration`→
  `cors_credentialed_reflection` を追加。`_match_firing_marker` の cors 分岐は **acao がテストオリジンに
  ホスト一致で反映（`*`/null/空/対象自身のオリジンは不可）＋ acac==true ＋ credentialed_body_excerpt 非空**の
  ときだけ発火。1つでも欠ければ None（fail-closed）。ホスト一致は urlparse hostname。
- **A②（`sealed_reproduction_checker.py`・凍結・承認済み）**: `cors_credentialed_reflection` を
  `_HEADER_OBSERVABLE_MARKERS` に追加。専用 `_check_cors_replay` が元 Finding の test_origin を Origin ヘッダに
  付けて（認証ヘッダも併せて）封印 GET 再送し、ACAO 反映＋ACAC true で matched・非反映/非true で mismatched・
  送信不能/client None で not_run。A① の `_acao_reflects_test_origin` を import 共有。`_send_get`（他種別本文経路）は
  byte-identical。

## 結果（独立検証・Claude が実施）

- **制御対象で ◎ を実証**: 反映＋ACAC:true＋認証付き機微本文を返す認可済み制御サーバに対し、実 SmartCORSHunter→
  acao 反映(https://evil.com)＋acac=true＋excerpt(99字)→`payout_grade=True/cors_credentialed_reflection`→
  実 `SealedReproductionChecker` の Origin 付き再送で ACAO 反映＋ACAC true `matched`→**`CONFIRMED/hybrid_confirmed`**。
- **実 Juice Shop の正しい非確定**: 実 `/rest/user/whoami` 等に対し 15 件全て acao=`*`・acac 空・excerpt 空→
  `payout_grade=False/no_firing_marker`→CONFIRMED に到達しない（偽 ◎ なし・fail-closed）。
- テスト: 新規4ファイル48テスト全緑（独立実行）。`tests/core/agents/swarm/injection/ tests/core/validation/`
  = **944 passed / 2 failed**。2 failed は `test_phase_b_readiness.py`（別環境の成果物存在チェック）で本変更と無関係。
- 凍結: 改変は承認済み `payout_grade.py` / `sealed_reproduction_checker.py` のみ。`poc_judge.md` /
  `task_queue.py` / `finding_validator.py` は `git diff --quiet HEAD` exit 0（無改変）を独立確認。
- 製品非依存 token 0（denylist 照合で変更コード・テストにヒット 0）。
- 敷居は下げていない（`*`/null/認証なし/本文なしの fail-closed をテストと Juice Shop 実測で担保）。

## 完了条件の充足

計画の完了条件 1〜8 すべて PASS。`in_scope_blocker=0`。◎ は制御対象で達成（条件7）、Juice Shop は正しく非確定（条件8）。

## 実装フローの注記（インフラ）

opencode デタッチ起動。1回目は主 run 稼働中にサブエージェントが `error=Aborted` で早期終了（対象ファイル無変更）。
repo `opencode.json` の一時 agent→deepseek 上書き（[[opencode-fixer-subagent-makora-fallback]]）を維持したまま再起動し完走、
完了後に `opencode.json` を元へ復元（無改変を確認）。

## 能力マップ更新

CORS を △ → **○（本物確定能力あり・制御対象で ◎ 実証・実 Juice Shop は `*` のため正しく非確定）** に更新。
実 Juice Shop に本物の CORS バグが無いため「実対象 ◎」ではないが、確定経路は整備済みで偽 ◎ を出さない。
