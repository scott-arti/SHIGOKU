---
task_id: SGK-2026-0371
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0295
related_docs:
- docs/shigoku/reports/2026-06-23_SGK-2026-0295_work_report.md
- docs/shigoku/reports/2026-06-23_SGK-2026-0296_work_report.md
- docs/shigoku/reports/2026-07-21_sgk-2026-0371_work_report.md
- docs/shigoku/worklogs/2026-07-21_sgk-2026-0371_work_log.md
title: AuthProbe relative redirect handling follow-up
created_at: '2026-07-21'
updated_at: '2026-07-28'
tags:
- shigoku
target: src/core/preflight/auth_probe.py, tests/unit/preflight/test_auth_probe.py
---

# 実装計画書：AuthProbe relative redirect handling follow-up

## 1. 達成したいゴール（ユーザー視点）
- [x] `docker compose run --rm shigoku ... --target http://localhost:4280/` の preflight で、`Location: login.php` のような相対リダイレクトを誤って `TARGET_CONNECTION_FAILURE` と判定しないこと。
- [x] 認証済み Cookie が無効だった場合でも、実際の状態に沿って `AUTH_LOGIN_PAGE` などの認証系 reason code へ進めること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/preflight/auth_probe.py`: 修正。manual redirect follow の `Location` 解決を標準ライブラリで統一する。
  - `tests/unit/preflight/test_auth_probe.py`: 既存回帰テストを red/green 検証に使う。
- **データの流れ / 依存関係:**
  - target URL -> `AuthProbe._request_with_redirects()` -> follow-up GET -> `AuthProbe._classify_deterministic()` -> `AUTH_LOGIN_PAGE` / `AUTHENTICATED` / other reason code

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `target` (URL), response `Location` header (absolute / root-relative / relative)
- **出力/結果 (Output):** follow-up redirect URL が正しく解決され、認証画面なら `LOGIN_PAGE`、認証済み画面なら `AUTHENTICATED` と判定される
- **制約・ルール:**
  - 変更は `AuthProbe` の redirect 解決に限定し、他の preflight 分類ロジックは広げない
  - 既存の失敗テストを先に再現し、修正後に targeted test と broader preflight test で確認する
  - Cookie や session 値は新規ログやドキュメントに書かない

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `AuthProbe._request_with_redirects()` の `Location` 解決を調査し、相対 `login.php` が `ClientError` へ落ちる経路を確認する
- [x] ステップ2: `urljoin()` を使う最小修正を入れ、`tests/unit/preflight/test_auth_probe.py` の既存回帰テストで green を確認する
- [x] ステップ3: `tests/unit/preflight -q` を実行して関連 preflight 群へ回帰がないことを確認する

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] 既存の `docs/shigoku` 台帳には `task_268_missing_file` が残っており、今回の docs validation を clean では通せない - 別タスクの台帳不整合を解消後に再検証する

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0371-D01
    title: "継続監視: pre-existing registry inconsistency cleanup"
    reason: "今回の修正とは別件の docs registry 不整合が残っている"
    impact: medium
    tracking_task_id: SGK-2026-0371
    recommended_next_action: "missing file を解消して `validate_shigoku_docs.py` を再実行する"
```
