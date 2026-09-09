---
task_id: SGK-2026-0478
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-09_sgk-2026-0478_command-injection-inband-confirmation.md
- docs/shigoku/worklogs/2026-09-09_sgk-2026-0478_command-injection-inband-confirmation_work_log.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/plans/done/2026-09-09_sgk-2026-0477_xss-browser-execution-confirmation.md
tags:
- shigoku
- detection
- command-injection
- confirmation-bar
created_at: '2026-09-09'
updated_at: '2026-09-10'
---

# SGK-2026-0478 作業完了報告 — コマンドインジェクション（in-band）を本物確定（◎）まで到達（実DVWA）

## 何をしたか / なぜ

検出能力マップ [[sgk-2026-0465]] で SSRF/コマンド系は「△」。**実対象 DVWA で本物の OS コマンドインジェクション
（in-band・出力が応答に返る）を確定（◎）** できる状態へ引き上げた。Juice Shop 以外の**2例目の実対象**での ◎。

## 事実（実測・実コードで確定）

- 実 DVWA `/vulnerabilities/exec/` は **POST 専用**。`ip=127.0.0.1;id` で応答本文に `uid=33(www-data)` が in-band 返却
  （GET クエリでは不発・認証=セッション＋`security=low` クッキー）。
- 確定バーは command_execution 対応済み（本文 `_CMD_INDICATORS` `uid=` 等で発火）。だが (1) エンジン Finding に
  impact/reproduction_steps 無し、(2) **再現チェッカーが GET-only 再送**で POST 本文の注入を再現できない＝◎に届かない壁。

## 実装（非凍結1＋凍結1・凍結はユーザー明示承認済み）

- **B（`smart_cmd_ssrf.py`・非凍結）**: in-band POST 確定時のみ impact/reproduction_steps と構造化再送記述子
  `command_replay`（method=POST・url・body_params・readonly_command・content_type）を付与。注入コマンドは
  **読み取り専用許可リスト**（id/whoami/uname/pwd/hostname/groups）から `_extract_readonly_command` で抽出。
  delivery に request_headers/body_params を記録（再送に必要）。GET-based/ブラインド/指標なしは従来どおり
  impact/repro/command_replay を付けない（byte-identical・fail-closed）。
- **A（`sealed_reproduction_checker.py`・凍結・承認済み）**: `command_execution` 専用の
  `_check_command_execution_replay` を GET-only ガードより前に分岐。**検証済み command_replay（読み取り専用
  コマンド限定）**のときだけ、封印スコープ再検証＋request fingerprint 一致の上で**元 method(POST)＋body_params を
  再送**し、本文 `_CMD_INDICATORS` 再出現で matched。記述子なし/許可外コマンドは従来 GET-only 経路へ
  byte-identical にフォールバック。GET-only 緩和は**この非破壊コマンド POST 再送に限る**。

## 結果（独立検証・Claude が実施）

- **実 DVWA で ◎ を実証**: 実注入（POST `ip=127.0.0.1;id`）→本文 `uid=33(www-data)`→
  `payout_grade=True/command_execution`→**実 `SealedReproductionChecker` が DVWA へ `;id` を再 POST し `uid=` 再観測**
  （reproduction_marker_matched:command_execution）→**`CONFIRMED/hybrid_confirmed`**。
- **fail-closed 否定側**: 本文に `_CMD_INDICATORS` が無い（ping 出力のみ）→`payout_grade=False/missing_impact`＝非確定。
- テスト: 新規3ファイル26テスト全緑（独立実行・checker replay/非回帰・engine artifacts・hybrid CONFIRMED）。
  `tests/core/agents/swarm/injection/ tests/core/validation/` = **1008 passed / 2 failed**。2 failed は
  `test_phase_b_readiness.py`（別環境の成果物存在チェック）で本変更と無関係。既存 GET-based command_execution・
  他マーカーは非回帰。
- 凍結: 改変は承認済み `sealed_reproduction_checker.py` のみ。`payout_grade.py` / `poc_judge.md` /
  `task_queue.py` / `finding_validator.py` は `git diff --quiet HEAD` exit 0（無改変）を独立確認。
- 製品非依存 token 0（denylist 照合で変更コード・テストにヒット 0）。注入/再送は読み取り専用コマンド限定（非破壊）。

## 完了条件の充足

計画の完了条件 1〜8 すべて PASS。`in_scope_blocker=0`。実対象 ◎ は DVWA で達成（条件7）、指標なしは
正しく非確定（条件8）。

## 実装フローの注記（インフラ）

opencode デタッチ起動＋repo `opencode.json` 一時 agent→deepseek 上書き（fixer→makora フォールバック対策・
[[opencode-fixer-subagent-makora-fallback]]）で genuine deepseek 完走、完了後 `opencode.json` 復元（無改変確認）。
末尾のサブエージェント cancel(Aborted) は主ループ完了後の oracle diff review の打ち切りで無害。

## 能力マップ更新

SSRF / コマンド系の行を更新: **コマンドインジェクションは実 DVWA で in-band 確定（◎）**。
SSRF は引き続き △（OOB 経路整備が前提・Juice Shop は到達性未確証）。
