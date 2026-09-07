---
task_id: SGK-2026-0471
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-07_sgk-2026-0471_open-redirect-confirmation.md
- docs/shigoku/worklogs/2026-09-07_sgk-2026-0471_open-redirect-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-07_sgk-2026-0472_open-redirect-allowlist-enum-and-chains.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
created_at: '2026-09-07'
updated_at: '2026-09-07'
tags:
- shigoku
- detection
- open-redirect
- confirmation-bar
---

# SGK-2026-0471 作業完了報告 — オープンリダイレクトを本物確定（◎）まで到達

## 何をしたか / なぜ

検出能力マップ [[sgk-2026-0465]] でオープンリダイレクトは「○（対応エンジンあり）」。
IDOR/SQLi/保存型XSS と同様に、**実対象で本物と確定（◎）** できる状態へ引き上げた。

## 事実（実物観測で確定）

- 既存 `OpenRedirectSpecialist` の検出自体は機能（実ブラウザで攻撃者ホスト遷移を捉え Finding 生成）。
- ◎ に届かない原因は 2 つ（両方実測）:
  - A（確定バー・凍結）: `payout_grade` の `_MARKER_CATEGORIES` に `open_redirect` が無く `unknown_category` で自動却下。
  - B（非凍結エンジン）: Finding の `impact=''` / `reproduction_steps=[]` で、A 修正後も `missing_impact` 却下。
- 実製品（Juice Shop `/redirect?to=`）は飛び先の**許可リスト部分文字列チェック**で守られ、素朴ペイロードは 406。
  手動実測で「攻撃者ホストを基点にアプリ正規値を部分文字列として付す」形なら攻撃者ホストへ 302 することを確認。

## 実装（3 ファイル・凍結2つはユーザー明示承認のうえ改変）

- **B（`open_redirect.py`・非凍結）**: 発火時に `impact` と `reproduction_steps` を設定。攻撃者ホストを
  `additional_info.injected_host` に安定記録。**B'**: 許可リスト回避ペイロードを追加（攻撃者ホスト基点＋
  runtime 観測した正規値を path/query/fragment に部分文字列で付す・製品名ハードコードなし）。
- **A①（`payout_grade.py`・凍結）**: `_MARKER_CATEGORIES` に `open_redirect: external_redirect` を追加。
  `_match_firing_marker` に専用分岐（3xx かつ注入攻撃者ホストが Location にホスト一致で出現かつ外部のときのみ発火・
  偽陽性は None）。他種別へ相乗りしない新マーカー。
- **A②（`sealed_reproduction_checker.py`・凍結）**: `external_redirect` をヘッダ観測マーカーとして追加。
  封印 GET 再送の Location ヘッダで攻撃者ホスト再出現（外部）を確認して matched。A① と同一ヘルパーを import 共有。
- **誤検知修正（`open_redirect.py`）**: 「本文への反射のみ」および「リクエストURLの部分文字列一致」での誤確定を廃し、
  確定根拠を「リダイレクト/リクエストの**ホスト**が攻撃者ホストと一致」に限定（Playwright ハンドラ・フォールバック双方）。
  これにより実対象のエラーページ反射（406）で誤発火せず、後続の本物 bypass ペイロードに到達する。

## 結果（独立検証・Claude が実施）

- **実 Juice Shop E2E で ◎ を実証**: 実エンジン→bypass ペイロード→302 Location=攻撃者ホスト→
  `payout_grade=True/external_redirect`→実 `SealedReproductionChecker` が GET 再送し `matched`→
  **`CONFIRMED / hybrid_confirmed`**。自作脆弱サーバでの E2E ◎ も維持。
- テスト: 新規テスト群（payout_grade/sealed_reproduction/engine evidence/hybrid 統合/allowlist bypass/誤検知回帰）
  すべて緑。`tests/core/agents/swarm/injection/ tests/core/validation/` = **862 passed / 2 failed**。
  2 failed は `test_phase_b_readiness.py`（別環境の成果物存在チェック）で、変更を退避した HEAD でも同一失敗＝本変更と無関係。
- 凍結: 承認した 2 ファイル（`payout_grade.py`/`sealed_reproduction_checker.py`）のみ改変。
  残り 3（`poc_judge.md`/`task_queue.py`/`finding_validator.py`）は `git diff --quiet HEAD` exit 0（無改変）。
- 製品非依存 token 0（denylist 0 hit・テストは example.org/example.com/evil.com のみ）。
- 偽陽性は fail-closed（外部でない/3xx でない/自己ホスト/ホスト非一致 → 不成立）をテストで担保。敷居は下げていない。

## 完了条件の充足

計画の完了条件 1〜7 すべて PASS。`in_scope_blocker=0`。実対象 ◎ は Juice Shop で達成（条件7・拡張版）。

## deferred_tasks

```yaml
deferred_tasks:
  - title: オープンリダイレクト検出の賢さ強化（許可リスト値の能動獲得・多段連鎖）
    reason: 本タスクは runtime 観測済みの正規値を再利用する範囲に限定。正規値未観測ケースや多段連鎖は将来対応。
    blocking: false
    tracking_task_id: SGK-2026-0472
```
