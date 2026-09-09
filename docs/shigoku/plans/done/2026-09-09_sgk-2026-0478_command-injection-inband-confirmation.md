---
task_id: SGK-2026-0478
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/reports/2026-09-09_sgk-2026-0478_command-injection-inband-confirmation_work_report.md
- docs/shigoku/worklogs/2026-09-09_sgk-2026-0478_command-injection-inband-confirmation_work_log.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/plans/done/2026-09-08_sgk-2026-0474_lfi-path-based-confirmation.md
- docs/shigoku/plans/done/2026-09-09_sgk-2026-0477_xss-browser-execution-confirmation.md
tags:
- shigoku
- detection
- command-injection
- confirmation-bar
created_at: '2026-09-09'
updated_at: '2026-09-10'
---

# SGK-2026-0478 計画 — コマンドインジェクション（in-band）を「本物確定（◎）」まで到達させる

## 目的（何を・なぜ）

検出能力マップ [[sgk-2026-0465]] で SSRF/コマンド系は「△」。**実対象 DVWA で本物の OS コマンドインジェクション
（in-band・出力が応答に返る）を確定（◎）** できる状態へ引き上げる。

## 事実（実測・実コードで確定・2026-09-09）

- **実 DVWA に in-band コマンドインジェクションが実在**（実測・認証付き・非破壊コマンドのみ）:
  `/vulnerabilities/exec/` は **POST 専用**（`ip` フィールド）。`ip=127.0.0.1;id` で
  応答本文に `uid=33(www-data) gid=33(...)` が返る（GET クエリでは注入不発＝POST 必須）。認証は
  セッションクッキー＋`security=low` クッキー。
- 確定バーは command_execution 対応済み: `_MARKER_CATEGORIES["cmd_ssrf"/"os_command_injection"/"rce"]=
  "command_execution"`。`_match_firing_marker` の分岐は本文に `_CMD_INDICATORS`（`uid=`/`gid=`/`root:` 等）出現、
  または `additional_info.command_execution_evidence` で発火。→ in-band 出力で発火する（本文に `uid=`）。
- エンジン `smart_cmd_ssrf` はフォーム解析＋auth＋POST 対応（form method POST 検出で method=POST）。
  だが**発火 Finding に impact/reproduction_steps が未設定**（機械フロア step3 で missing_impact 停止）。
- **再現チェッカーは GET-only 再送**（check() は `assert_read_only_probe("GET", ...)`・command_execution は
  GET 再送本文の `_CMD_INDICATORS` 照合）。DVWA は POST 注入のため **GET 再送では再現できない**＝◎に届かない壁。

## 対象（このタスクで触るファイル）

- **B（非凍結）** `src/core/agents/swarm/injection/smart_cmd_ssrf.py`
  - 認証付き POST フォーム（セッション＋level クッキーは `_auth` 経由）へ**読み取り専用コマンド注入**
    （`;id` / `|id` / `;whoami` 等）を届け、応答本文の `_CMD_INDICATORS`（`uid=` 等）in-band 出力を確認する経路を確実化。
  - 発火 Finding に impact（任意 OS コマンド実行＝サーバ完全掌握の起点）と reproduction_steps を設定。
  - 再現のため `additional_info` に**構造化された再送記述子** `command_replay`
    （`method`（POST 等）・`url`・`body_params`（注入を含むフォーム値）・`readonly_command`（使用した非破壊コマンド名）・
    `content_type`）を残す。注入は必ずエンジンの**非破壊コマンド許可リスト**（id/whoami/uname/pwd/hostname/groups）内。
- **A（凍結・ユーザー明示承認済み・2026-09-09）** `src/core/validation/sealed_reproduction_checker.py`
  - `command_execution` 専用の再現パス `_check_command_execution_replay`（cors/jwt と同じ位置・流儀）を追加。
    元 Finding の `command_replay` 記述子があり、その `readonly_command` が**読み取り専用許可リスト**に含まれるときだけ、
    **元 method（POST）＋ body_params を再送**し、応答本文に `_CMD_INDICATORS` 再出現で matched。
    記述子なし/許可外コマンドは従来の GET 再送＋本文照合にフォールバック（GET-based in-band の非回帰）。
    送信不能/client None は not_run（fail-closed）。**GET-only ガードは command_execution の非破壊 POST 再送に
    限って緩め、他マーカーは byte-identical**（read-only 原則は「非破壊コマンドの再実行」に限定して維持）。

## 確定バー（凍結・本タスクでは無改変）

- `payout_grade.py`（command_execution を既に本文 `_CMD_INDICATORS` で発火）・`poc_judge.md` / `task_queue.py` /
  `finding_validator.py` は無改変（`git diff --quiet HEAD` exit 0）。

## 完了条件（完了契約）

1. B: 認証付き POST の in-band コマンド注入で、発火 Finding が本文 `uid=`（`_CMD_INDICATORS`）・impact 非空・
   reproduction_steps 非空・`command_replay` 記述子（非破壊コマンド）を持つ。in-band 指標が出ない場合は vulnerable=False。
2. A①（無改変確認）: `evaluate_payout_grade({vuln_type:'os_command_injection', ...本文 uid=...})` が
   `payout_grade=True / marker=command_execution`。
3. A②（凍結改変）: `command_replay`（読み取り専用コマンド）で POST 再送し `_CMD_INDICATORS` 再出現→matched、
   非再出現→mismatched、送信不能/client None/許可外コマンド→not_run もしくは GET フォールバック（fail-closed）。
   既存の GET-based command_execution（本文照合）は非回帰。他マーカーの GET-only は不変。
4. `finding_validator.validate_finding` に in-band コマンド実行本物証拠＋AI賞金級＋再現 matched で `CONFIRMED`。
5. 凍結: 改変は `sealed_reproduction_checker.py` のみ。`payout_grade.py` / `poc_judge.md` /
   `task_queue.py` / `finding_validator.py` は `git diff --quiet HEAD` exit 0。
6. 製品非依存 token 0（denylist。dvwa/localhost:4280 等を入れない）。テスト fixture は target.example・汎用コマンド。
7. **実対象での ◎ 実証**: 認可対象 **DVWA** の `/vulnerabilities/exec/`（POST）に非破壊コマンド注入→本文 `uid=`→
   `payout_grade=True/command_execution`→再現 POST 再送で `uid=` 再出現 matched→`CONFIRMED`（証拠は合言葉マスク）。
8. **fail-closed 否定側**: in-band 指標が出ないパラメータ→非確定。許可外/破壊的コマンドは再送しない。
   他マーカー（sql_error/reflected_payload/file_content_leak/cors/external_redirect/jwt/authz_diff）の GET-only・
   判定・戻り値は byte-identical（非回帰）。

## 必須テスト

- `sealed_reproduction_checker` 単体: (a) command_replay（id）で POST 再送→`uid=` 再出現→matched、(b) 非再出現→mismatched、
  (c) 許可外コマンド/記述子なし→GET フォールバック or not_run、(d) client None→not_run、
  (e) 既存 GET-based command_execution・他マーカーの非回帰（byte-identical 経路）。
- engine 単体: (a) POST in-band で `uid=`＋impact/repro＋command_replay、(b) 指標なし→False、(c) 非破壊コマンド限定。
- 統合: `validate_finding` が in-band コマンド実行本物証拠＋AI賞金級＋再現matched で CONFIRMED。
- injection + validation スイート非回帰。
- 変更後 `python3 scripts/sync_shigoku_updated_at.py` → `python3 scripts/validate_shigoku_docs.py` が 0 エラー。

## NOT in scope

- 確定バーの敷居低下・curve-fitting。`payout_grade.py`/`poc_judge.md`/`task_queue.py`/`finding_validator.py` の改変。
- 破壊的コマンド（rm 等）の注入/再送。許可リストは非破壊の読み取り専用コマンドに限定。
- ブラインド/OOB コマンド系・SSRF（別途）。コマンドインジェクション以外の種別。

## リスク

- 凍結 `sealed_reproduction_checker.py` で GET-only ガードを command_execution の**非破壊 POST 再送**に限って緩める。
  **能力追加であり敷居低下ではない**ことを、許可外コマンド非再送・他マーカー byte-identical・指標なし fail-closed の
  テストで担保する。再送コマンドはエンジンの非破壊許可リスト内のみ（id/whoami/uname/pwd/hostname/groups）。

## 実装・検証の分担

- 実装は DeepSeek/opencode に**テキストで**指示（ドキュメント化しない）。opencode は fixer サブエージェントの
  makora フォールバック対策として repo opencode.json に一時 agent→deepseek 上書きを入れて起動し完了後復元
  （[[opencode-fixer-subagent-makora-fallback]]）。
- 完了報告は額面通り信用せず、Claude が独立検証（テスト実出力・diff・凍結残り4無改変・実 DVWA E2E・
  in-band 非出力での非確定・他マーカー非回帰）。
