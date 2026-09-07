---
task_id: SGK-2026-0471
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-07_sgk-2026-0471_open-redirect-confirmation.md
- docs/shigoku/reports/2026-09-07_sgk-2026-0471_open-redirect-confirmation_work_report.md
created_at: '2026-09-07'
updated_at: '2026-09-07'
tags:
- shigoku
- detection
- open-redirect
---

# SGK-2026-0471 作業ログ

## 1. 事実確認（仮説より先に実物）
- open_redirect の実装・確定経路を精読。確定は 3 条件 AND（機械フロア＋AI 賞金級＋再現一致）。
- 自作最小脆弱サーバに既存エンジンを当て、証拠の形と停止点を実測 → `unknown_category` で止まると確定。
- 機械フロアは status>0 で 302 有効・再現チェッカーは本文のみ照合（Location ヘッダを捨てる）・poc_judge は種別非依存、を実コードで確認。

## 2. 台帳・計画
- SGK-2026-0471 採番・登録、計画書（完了契約）作成。凍結2ファイル改変はユーザー明示承認。

## 3. 実装（opencode / 本物 deepseek-v4-flash・Claude 独立検証）
- B（証拠充実）＋A①（payout_grade 種別追加）＋A②（sealed_reproduction Location 照合）。
- 実 Juice Shop E2E で ◎ 未達 → 実測で 2 段の真因を特定・修正:
  1. 素朴ペイロードが許可リストで 406、確定バーは正しく却下。エンジンにバイパスペイロード（B'）を追加。
  2. `_verify_with_playwright` の `verify_host in request.url`（部分文字列）が、最初のリクエストURLのクエリに
     攻撃者ホスト名を含むだけで誤発火 → ホスト一致判定に修正（フォールバックの Location 判定も同様に修正）。

## 4. 独立検証（Claude）
- 実 Juice Shop E2E: bypass→302 攻撃者ホスト→payout_grade=True/external_redirect→再現 matched→CONFIRMED。
- injection+validation 862 passed / 2 failed（phase_b 環境依存・HEAD で同一・無関係）。
- 凍結残り3無改変・denylist 0・偽陽性 fail-closed をテストで確認。

## 5. deferred
- 許可リスト値の能動獲得・多段連鎖は SGK-2026-0472 で追跡（非阻害）。
