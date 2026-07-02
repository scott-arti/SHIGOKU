---
task_id: SGK-2026-0338
doc_type: plan
status: done
parent_task_id: SGK-2026-0001
related_docs:
  - docs/shigoku/manuals/2026-07-02_sgk-2026-0337_detailed-command-reference.md
  - docs/shigoku/manuals/USER_MANUAL.md
  - docs/shigoku/specs/TECHNICAL_SPEC_JA.md
  - docs/shigoku/specs/ARCHITECTURE.md
  - docs/shigoku/manuals/2026-07-02_sgk-2026-0338_operator-user-manual.md
  - docs/shigoku/specs/2026-07-02_sgk-2026-0338_internal-architecture-and-dataflow-spec.md
  - docs/shigoku/reports/2026-07-02_sgk-2026-0338_work_report.md
  - docs/shigoku/worklogs/2026-07-02_sgk-2026-0338_work_log.md
title: SHIGOKU ユーザーマニュアル・内部仕様書整備
created_at: '2026-07-02'
updated_at: '2026-07-02'
tags:
  - shigoku
target: docs/shigoku/manuals and docs/shigoku/specs
---

# 実装計画書：SHIGOKU ユーザーマニュアル・内部仕様書整備

## 1. ゴール
- 初期設定、Docker 利用、モード、出力ファイル、ユースケース別コマンドを含む運用者向けユーザーマニュアルを作成する。
- SHIGOKU の実行経路、データフロー、セッション・レポート契約、内部モジュール責務をまとめた仕様書を作成する。
- 既存の旧マニュアル・旧仕様から現行版へ迷わず辿れる導線を追加する。

## 2. 対象ファイル
- `docs/shigoku/manuals/2026-07-02_sgk-2026-0338_operator-user-manual.md`: 新規ユーザーマニュアル。
- `docs/shigoku/specs/2026-07-02_sgk-2026-0338_internal-architecture-and-dataflow-spec.md`: 新規内部仕様書。
- `docs/shigoku/README.md`: ドキュメント Hub から新規正本へリンク。
- `docs/shigoku/manuals/QUICK_START.md`: 次のステップへ新規正本リンクを追加。
- `docs/shigoku/manuals/USER_MANUAL.md`: 旧マニュアルから現行版へ誘導。
- `docs/shigoku/specs/TECHNICAL_SPEC_JA.md`: 旧仕様から現行版へ誘導。

## 3. 実装手順
- [x] 既存資料と実装入口を確認する。
- [x] タスク台帳へ `SGK-2026-0338` を登録し、計画書を作成する。
- [x] 新規マニュアルと仕様書を追加し、既存導線を更新する。
- [x] 作業報告書・作業ログを追加し、タスクを `done` に移動する。
- [x] `sync_shigoku_updated_at.py` と `validate_shigoku_docs.py` で検証する。

## 4. 検証方針
- SHIGOKU ドキュメントの front matter、リンク、台帳整合性を `python3 scripts/validate_shigoku_docs.py` で確認済み。
- 今回はコード挙動を変更しないため、ユニットテストは対象外とする。

## 5. リスク
- 一部既存資料には古いポート番号・パスワード・CLI 引数が残っているため、今回の新規正本では `docker-compose.yml` と `src/main.py` を優先して記載する。
- 外部ツールやレポート形式は増減し得るため、詳細な全オプションは `SGK-2026-0337` のコマンドリファレンスを正本としてリンクする。
