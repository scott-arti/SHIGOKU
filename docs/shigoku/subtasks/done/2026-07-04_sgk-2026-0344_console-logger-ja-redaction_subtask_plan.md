---
task_id: SGK-2026-0344
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0342
related_docs:
- docs/shigoku/reports/2026-06-22_sgk-2026-0290_cli-japanese-localization_work_report.md
- docs/shigoku/reports/2026-07-03_sgk-2026-0342_cli-localization-parallelism-quick-fix_work_report.md
title: console logger 日本語化と秘密情報redaction計画
created_at: '2026-07-04'
updated_at: '2026-07-21'
tags:
- shigoku
target: src/recon/tool_runner.py, src/recon/pipeline.py, src/core/logger.py, logging
  console handlers, secret redaction boundary
---

# 実装計画書：console logger 日本語化と秘密情報redaction計画

## 1. 達成したいゴール（ユーザー視点）
- [ ] `shigoku` CLI / `vulntest` 実行中に端末へ表示される標準 logger 由来の INFO/WARNING が、日本語で読めること。
- [ ] 例: `Executing: ...`, `httpx found ...`, `whatweb not found, skipping`, `[Step 3] Live Check completed...` が、CLI上では日本語メッセージとして表示されること。
- [ ] `Cookie: PHPSESSID=...`, `Authorization: Bearer ...`, API key, JWT などの秘密情報が、コンソールログ・ファイルログのどちらにも生値で出ないこと。
- [ ] 内部解析に必要な logger 名、ログレベル、時刻、パス、件数、ステップ番号は保持されること。
- [ ] 既存の `src/cli/messages.py` による対話表示日本語化と矛盾せず、対象スコープを「CLIで見えるログ表示」まで拡張すること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/recon/tool_runner.py`: 外部コマンド実行ログの主発生源。`Executing: ...` と失敗/timeoutログをredaction対象にする。
  - `src/recon/pipeline.py`: recon進行ログの主発生源。httpx/whatweb/Step完了/保存ログをCLI日本語化対象にする。
  - `src/core/logger.py`: `shigoku.*` logger の console/file handler 境界。redaction filter/formatter の適用候補。
  - CLI logging bootstrap (`src/main.py` または CLI entrypoint の logging setup): `src.recon.*` のような標準 logger が端末へ出る経路を特定し、console formatter/filter を適用する。
  - `src/core/security/pii_masker.py`: 既存の Bearer/JWT/API key マスク機能。HTTP Header/Cookie向けredactionを再利用または補強する。
  - `src/core/notifications/body_builder.py`: 既存の一方向redactionパターン候補。Cookie/Authorization/API key/JWT の通知向けredactionを、ログ向け共通helperへ切り出せるか確認する。
  - `src/cli/messages.py`: CLI表示用の日本語メッセージカタログ。event key 方式を採る場合の追加先。
  - `src/core/adapters/external/external_tool_logger.py`: 新外部ツールadapter経路のログ境界。今回は旧recon経路を主対象にし、既存adapter loggerへ影響する場合のみredaction helperの利用可否を確認する。
  - `tests/unit/...`: redaction/filter/localization の回帰テスト追加先。
- **データの流れ / 依存関係:**
  - `ReconPipeline` が認証ヘッダーを構築 -> `ToolRunner.run()` に `cmd: list[str]` として渡す -> logger が `LogRecord` を生成 -> handler/formatter/filter がredactionとCLI向け日本語化を適用 -> console/fileへ出力する。
  - redactionは表示直前の共通境界で必ず行い、callsite単位の対策漏れを防ぐ。
  - 日本語化はコンソール表示を主対象とし、必要に応じてファイルログは検索性維持のため event key / logger名 / 原文テンプレートを保持する。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - `logging.LogRecord.msg` / `logging.LogRecord.args`
  - `cmd: list[str]` に含まれる `-H Cookie: ...`, `Authorization: Bearer ...`
  - `src.recon.pipeline` の進行ログ、保存先パス、件数
- **出力/結果 (Output):**
  - コンソール例: `実行中: /path/httpx_wrapper.py ... -H Cookie: [REDACTED_COOKIE] (timeout=600s)`
  - コンソール例: `httpx: live subdomain を 1 件検出しました`
  - コンソール例: `whatweb が見つからないためスキップします`
  - コンソール例: `[Step 3] Live Check 完了: live=1, dead=0`
  - ファイルログにも秘密情報の生値は残さない。
- **制約・ルール:**
  - redactionは最下流の書き込み境界に置く。`ToolRunner` だけの局所対応で終わらせない。
  - ログ保存境界では復元不能な一方向redactionを使う。`PIIMasker` は双方向token mapを保持するため、AI送信前マスク用途として扱い、ログ向けhelperとは役割を分ける。
  - 既存の `src/core/notifications/body_builder.py` の `redact()` / `REDACT_PATTERNS` と `PIIMasker` を確認し、共通化できる一方向パターンはログ向けhelperへ寄せる。Cookie/PHPSESSID/Header文字列は専用パターンで補強する。
  - `Cookie`, `Set-Cookie`, `Authorization`, `Proxy-Authorization`, `X-Api-Key`, `api_key`, `token`, `password`, `secret` はキー名ベースで値を伏せる。
  - `-H "Cookie: ..."` のような CLI 引数内ヘッダーも伏せる。
  - `LogRecord.msg` / `LogRecord.args` / dict / list / tuple / stderr抜粋 / コマンドlistを再帰的にredactする。
  - redaction後もコマンド名、出力パス、対象ファイル、timeout、件数は読めるように残す。
  - セッションJSONやレポートschemaは変更しない。ログ表示とログ保存の境界に限定する。
  - 正規表現だけで全ログを翻訳しきる実装は避ける。短期は高頻度ログの明示マッピング、長期は event key / message catalog 方式に寄せる。
  - console日本語化は handler別formatterで行う。file log はredaction済みの原文テンプレート、logger名、level、event key、数値、pathを保持し、検索性を壊さない。
  - `src/cli/messages.py` にlogger用メッセージを追加する場合は、同ファイル冒頭の「Internal logger messages は含めない」方針コメントを更新し、対象がCLI-visible logger表示であることを明記する。
  - 並列処理ログの調査とは分離し、本タスクでは「見えるログの日本語化と秘密情報redaction」を主目的にする。

## 3.5 CTOレビュー指摘への最適修正案
- [ ] **logging適用境界の明確化:** `src.recon.*` の標準loggerがroot handlerへ流れる経路と、`shigoku.*` の `QueueListener` 経路を分けて整理する。実装対象は「console/fileへ書き込む handler/formatter 境界」とし、callsite単位の局所redactionだけで完了扱いにしない。
- [ ] **一方向redaction helperの導入:** `PIIMasker` は双方向復元用途として温存し、ログ用には `redact_log_value()` / `redact_log_record_fields()` のような復元不能helperを置く。既存 `JapaneseBodyBuilder.redact()` のパターンは重複実装せず、共通化または参照元として扱う。
- [ ] **漏洩経路の追加捕捉:** `ToolRunner.run()` の `Executing:` だけでなく、`src.recon.pipeline` の `Katana auth headers configured: %s`、`Command failed ... Stderr: %s`、timeout/errorログ、`ExternalToolLogger` の command/raw_output 影響範囲を確認する。
- [ ] **handler別の責務分離:** console formatter はredaction後に高頻度ログを日本語化する。file formatter はredaction後の原文、logger名、level、event key、パス、件数を残す。`Filter` で `LogRecord` を破壊的に書き換える場合は、handler間で意図しない共有副作用がないことをテストする。
- [ ] **messages.py方針更新:** event key方式で `src/cli/messages.py` を使う場合、冒頭コメントとキー命名規約に `logger.recon.*` などのCLI-visible loggerメッセージを追加する。使わない場合はformatter内の限定マッピングに閉じ、messages.pyを変更しない。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: logging設定の入口を特定する。
  - `src/main.py`, CLI entrypoint, `src/core/logger.py` を確認し、`src.recon.*` の標準 logger が端末へ出る handler を特定する。
  - root logger / `src.recon.*` / `shigoku.*` / `external_tool.*` の handler, formatter, propagate 設定を表にする。
  - `logging.basicConfig()` が複数ある場合は、実行時に有効な設定だけを対象にする。
- [ ] ステップ2: redaction helper の責務と再利用元を確定する。
  - `src/core/security/pii_masker.py` は双方向マスク用途として扱い、ログ向けには復元不能な一方向helperを新設する方針にする。
  - `src/core/notifications/body_builder.py` の Cookie/Authorization/API key/JWT redactionパターンを確認し、共通helperへ切り出すか、ログ向けhelperに同等仕様を移す。
  - redaction対象を `str`, `list`, `tuple`, `dict`, `LogRecord.msg`, `LogRecord.args`, stderr抜粋、command list に固定し、ファイルパス・件数・timeout・ツール名は保持する。
- [ ] ステップ3: redaction境界のテストを先に追加する。
  - サンプル文字列 `-H Cookie: PHPSESSID=16de...; security=low` が `[REDACTED_COOKIE]` になること。
  - `Authorization: Bearer abc...`, JWT, `X-Api-Key` が生値を残さないこと。
  - `cmd: list[str]`, dict/listのネスト、`LogRecord.args` のどれでも漏れないこと。
  - `ToolRunner.run()` の `Executing:`, `Command failed ... Stderr:`, timeout/errorログで Cookie/Bearer/JWT/API key が漏れないことを検証する。
  - `src.recon.pipeline` の `Katana auth headers configured: %s` 相当ログで auth header list が伏せられることを検証する。
- [ ] ステップ4: 共通redaction helperとログ境界を実装する。
  - ログ向けの一方向redaction helperを追加し、必要なら `JapaneseBodyBuilder` 側も同じhelperを使うようにしてredaction仕様の重複を減らす。
  - console handler と file handler の両方に formatter/filter として適用する。
  - handler別に出力を変える必要があるため、console日本語化はformatter側で行い、file logはredaction済み原文とevent keyを保持する。
  - callsiteでは `cmd_str = " ".join(cmd)` の生値を直接logし続けない、またはformatter側で必ず伏せる。二重防御として `ToolRunner` に安全なコマンド表示helperを置く。
- [ ] ステップ5: 高頻度ログへ event key / message catalog 方針を適用する。
  - `src.recon.tool_runner` と `src.recon.pipeline` の高頻度ログを優先する。
  - `Executing`, `httpx found`, `whatweb not found`, `[Step 3] Live Check completed`, auth header注入ログを event key 化するか、formatterの限定マッピング対象にする。
  - `src/cli/messages.py` を使う場合は、冒頭コメントとキー命名規約を更新し、`logger.recon.*` のようなキーを追加する。
  - 短期対応でcallsite文言を日本語化する場合も、file log の検索性を壊さないよう logger名/level/数値/パス/event keyを残す。
- [ ] ステップ6: CLIコンソール向け日本語化を実装する。
  - console formatterで redaction 後の代表ログを日本語文へ変換する。
  - 未知ログは翻訳せず、redaction済み原文として表示する。
  - file formatterでは日本語化より検索性を優先し、redaction済み原文テンプレートとevent keyを保持する。
- [ ] ステップ7: スコープ外経路の影響を確認する。
  - `ExternalToolLogger` の INFO/DEBUG/ERROR に command/raw_output/error_message が含まれるため、今回のhelperを適用する必要があるか確認する。
  - 旧recon経路以外のadapter loggerを本タスクで直さない場合は、work_report の `deferred_tasks` に既存SGKタスクID付きで残す。
  - `logs/debug`, `HuntingLogger`, 通知本文などの既存redaction済み経路は、今回の変更で挙動を壊していないことだけ確認する。
- [ ] ステップ8: 実行時の見え方を確認する。
  - モックまたは最小reconで `ToolRunner.run()` を通し、端末相当の stream に日本語ログが出ることを確認する。
  - サンプルCookie値が console/file/log artifact に存在しないことを確認する。
  - `rg "16de57|PHPSESSID=16de|Bearer <raw>|abc123def456ghi789"` を対象ログ・テスト出力へ実行し、生値が残らないことを確認する。
- [ ] ステップ9: ドキュメントと台帳を閉じる。
  - 実装後に work_report / work_log を作成し、必要なら本subtask_planを `done/` へ移動する。
  - `python3 scripts/sync_shigoku_updated_at.py --repo-root .` の後に `python3 scripts/validate_shigoku_docs.py --repo-root .` を実行する。

## 5. テスト計画
- [ ] Unit: redaction helper/filter が Cookie/Bearer/JWT/API key を伏せ、パスや件数を保持する。
- [ ] Unit: `LogRecord.msg` と `LogRecord.args` の双方に秘密情報があるケースを検証する。
- [ ] Unit: `dict` / `list` / `tuple` のネスト、stderr抜粋、command list 内の `-H Cookie: ...` が再帰的に伏せられる。
- [ ] Unit: `ToolRunner.run()` の `Executing:` 相当ログにCookie生値が残らない。
- [ ] Unit: `ToolRunner.run()` の失敗/timeout/errorログにstderr由来の秘密情報が残らない。
- [ ] Unit: `src.recon.pipeline` の `Katana auth headers configured: %s` 相当ログにCookie/Bearer生値が残らない。
- [ ] Unit: `src.recon.pipeline` の代表ログがコンソールformatterで日本語になる。
- [ ] Unit: file formatter はredaction済み原文、logger名、level、event key、数値、pathを保持する。
- [ ] Unit: 未知ログは翻訳されず、redaction済み原文で表示される。
- [ ] Regression: 既存 `tests/test_pii_masker.py` または関連テストが壊れない。
- [ ] Regression: `src/core/notifications/body_builder.py` の通知本文redactionが、共通helper化後も壊れない。
- [ ] Smoke: DVWA相当のCookieを含む疑似コマンドで、端末出力・ファイルログを `rg "16de57|PHPSESSID=16de|Bearer <raw>"` して漏れがないこと。

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] 正規表現ベースの日本語化だけで全ログを扱うと壊れやすい - 高頻度ログは event key 化し、未知ログは原文をredaction済みで出す。
- [ ] [重要度:高] Cookieがツール引数・HTTPヘッダー・辞書・stderrの複数経路から出る - 最下流filterに加えて、`ToolRunner` のコマンド表示helperでも二重に伏せる。
- [ ] [重要度:中] 過剰redactionで診断情報が消える - キー名と値だけ伏せ、ファイルパス・status・件数は保持するテストを置く。
- [ ] [重要度:中] `ExternalToolLogger` は command/raw_output/error_message を持つ - 本タスクで旧recon経路に限定する場合も、影響確認結果を work_report に残す。
- [ ] [重要度:中] `src/cli/messages.py` は現状 Internal logger messages を対象外としている - message catalog を使う場合はコメントとキー規約を同時更新する。
- [ ] [重要度:中] pytest環境が壊れている場合に検証が止まる - 先に `.venv/bin/python -m pytest` の利用可否を確認し、不可なら環境復旧を別タスク化する。

## 7. 完了条件
- [ ] ユーザー提示サンプル相当のログがCLI上で日本語表示される。
- [ ] `PHPSESSID`, Bearer token, API key, JWT の生値が console/file log に残らない。
- [ ] `LogRecord.msg` / `args` / dict / list / tuple / stderr抜粋 / command list に含まれる秘密情報が一方向redactionされる。
- [ ] console は代表ログを日本語表示し、未知ログはredaction済み原文で表示する。
- [ ] file log はredaction済み原文、logger名、level、event key、数値、pathを保持する。
- [ ] `src.recon.tool_runner` と `src.recon.pipeline` の代表ログに対するテストが追加され、成功する。
- [ ] 既存の `src/cli/messages.py` 日本語化と矛盾しない。
- [ ] work_report / work_log / task registry / docs validation が完了している。
