---
task_id: SGK-2026-0290
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0266
related_docs:
- docs/shigoku/plans/2026-06-05_sgk-2026-0266_cli-entrypoint-split-plan_plan.md
- docs/shigoku/plans/2026-06-21_sgk-2026-0289_commonization-technical-debt-roadmap_plan.md
title: CLI日本語化設計計画
created_at: '2026-06-22'
updated_at: '2026-07-02'
tags:
- shigoku
target: src/main.py, src/cli/, src/core/logger.py, user-facing CLI output
---

# 実装計画書：CLI日本語化設計計画

## 1. 達成したいゴール（ユーザー視点）
- [x] ユーザー向けCLI表示を日本語で利用できること。
- [x] `--translate-logs` のような後翻訳ではなく、CLI本体の help、対話メッセージ、主要進行表示を正規の日本語文面で出せること。
- [x] 内部ログ、開発者向けデバッグログ、外部ツール生出力は分離し、ユーザー向け表示だけを日本語化対象にできること。
- [x] 将来的に `ja/en` 切替や message catalog 化へ拡張しやすい構造にすること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/main.py`: argparse `description/help`、標準出力メッセージ、対話ガイド文の整理。
  - `src/cli/cli.py`: interactive CLI の案内、エラー、終了メッセージの整理。
  - `src/cli/commands.py`: `/help`, `/mode`, `/model`, `/sessions`, scanner command 出力などユーザー向け文面の整理。
  - `src/core/logger.py`: `status()`、tree/table/panel のタイトルなどユーザー向け表示に限定した文言整理。
  - `src/cli/messages.py` または `src/core/i18n/`（新規候補）: 文言定数または翻訳辞書の集約先。
- **データの流れ / 依存関係:**
  - CLI引数/コマンド入力 -> formatter/message resolver -> Rich/print 出力。
  - 内部 logger メッセージとユーザー向け console 出力を分離し、翻訳対象を明示する。
  - 初期段階では日本語を正本とし、将来の英語切替は message key ベースで追加できるようにする。
  - message resolver または `messages.py` をユーザー向け文面の唯一の正本とし、`src/main.py`、`src/cli/commands.py`、`src/core/logger.py` へ文言直書きを残さない。
  - 翻訳責務は CLI presentation 層に限定し、scanner / report / session のドメインロジックへ翻訳分岐を持ち込まない。
  - ユーザー向け文面は「説明本文」と「次の操作ヒント」を分離し、パス、`task_id`、`exit code`、対象URLなどの識別子は英数字のまま保持する。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** argparse help文、interactive command 文面、Rich status/title、標準出力の hint/error/success 文。
- **出力/結果 (Output):** 日本語CLI表示、必要なら言語設定フラグ、既存CLI挙動とexit codeの互換維持。
- **制約・ルール:**
  - 対象は「ユーザー向け表示」に限定する。Python logger の内部英語ログや外部ツールの標準出力はこのタスクで全面翻訳しない。
  - `--translate-logs` は別責務として扱い、CLI日本語化の完了条件に含めない。
  - 既存のCLIオプション名、JSON出力、report/session schema、exit codeは変えない。
  - help文字列、interactive help、主要成功/失敗メッセージ、resume/HITL/deferred系のオペレーター向け案内は対象候補に含める。
  - 内部 logger の event key / log level / raw message は互換維持し、既存の grep、アラート、runbook 前提を壊さない。
  - 文面参照は message key ベースで行い、初期実装が `ja` のみでも key 命名規約を先に固定する。

### 3.1 スコープ外の明示
- [x] 通知文面の日本語化は本タスクに含めない。必要なら別タスクで `src/core/notifications/` 側を扱う。
- [x] `--translate-logs` の後翻訳改善は本タスクに含めない。
- [x] logger / 外部ツール / session / report の生出力全面翻訳は本タスクに含めない。
- [x] 完全な多言語切替 (`ja/en`) や message catalog の本格導入は後続タスクで扱う。

## 3.2 完了条件（Definition of Done）
- [x] `python -m src.main --help` の主要説明文と主要オプション help が日本語で読める。
- [x] interactive CLI の `/help`, `/mode`, `/sessions`, `/resume` など主要案内が日本語で読める。
- [x] 主要な標準出力メッセージ（成功、失敗、注意、次の操作ヒント）が日本語化されている。
- [x] JSON出力モードではキー構造を壊さず、機械処理互換を維持する。
- [x] 少なくとも文面生成または help出力の focused test が追加されるか、既存テストが更新される。
- [x] `--translate-logs` を使わなくてもCLI日本語化が成立している。
- [x] 内部 logger の英語ログ、event key、log level が変わらず、運用上の grep / アラート前提を壊していない。
- [x] `--help`、interactive `/help`、主要エラーパス、deferred/HITL/resume案内で日本語化対象が確認できる。
- [x] 80-100桁程度の端末幅でも主要 status / panel / table タイトルが過度に崩れない。
- [x] 主要フローで初見ユーザーが次の操作を判断できる案内文を維持している。

### 3.3 Phase 進行の GO / NO-GO 条件
- [x] Phase 1 (`src/main.py` の `--help` と主要案内) から Phase 2 へ進む GO 条件: message resolver 経由への集約方針が成立し、`--help` の日本語化、JSON非汚染、内部 logger 互換、主要識別子保持の4点が確認できていること。
- [x] Phase 1 の NO-GO 条件: `src/main.py` の日本語化だけで domain logic への翻訳分岐、CLI option/exit code 変更、JSON出力汚染、内部 logger 改変のいずれかが必要になった場合は、その時点で実装を停止し、計画書を再レビューすること。
- [x] Phase 2 (interactive CLI) から Phase 3 (`src/core/logger.py` の human-facing 補助表示) へ進む GO 条件: interactive `/help` と主要エラーパスが presentation 層のみの変更で日本語化でき、文面直書きの再増殖がなく、focused test で回帰切り分け可能な状態になっていること。
- [x] Phase 2 の NO-GO 条件: interactive 表示の日本語化のために command dispatch、scanner 実行、report/session 生成などの業務ロジック改変が必要になった場合は、logger 周辺へ横展開せず停止し、責務境界の設計を見直すこと。

### 3.4 代表ユーザーフロー受け入れ例
- [x] 代表フロー例: 初見ユーザーが `python -m src.main --help` を実行したとき、主要説明文を日本語で読めて、必須オプションの意味を理解でき、次に取る操作として「対話CLIへ入る」「対象URLを指定して実行する」の少なくともどちらかを help 文面だけで判断できること。
- [x] 上記代表フローでは、コマンド名、オプション名、`exit code`、ファイルパス、`task_id` のような機械的識別子は英数字のまま保ち、説明文だけを日本語化して理解コストを下げること。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: CLIのユーザー向け文面を棚卸しし、`argparse help`、`print/console`、`rich_logger.status/show_tree`、interactive command 出力に分類する。あわせて `argparse` / interactive command / logger helper の3系統で出力経路一覧を残す。
- [x] ステップ2: 対象外を明確化する。内部 logger、外部ツール原文、デバッグトレース、JSONキーは原則そのままにし、翻訳対象外確認のチェックリストを作る。
- [x] ステップ3: 文面を message resolver 経由に寄せる。最初は `messages_ja` の固定実装でもよいが、message key 命名規約を固定し、直書き文面の残存箇所を棚卸し表でゼロ確認する。
- [x] ステップ4: Phase 1 として `src/main.py` の `--help`、deferred/HITL/resume/report まわりのユーザー向け出力を優先して日本語化する。説明本文と次操作ヒントを分離し、識別子は英数字のまま残す。
- [x] ステップ5: Phase 2 として `src/cli/cli.py` と `src/cli/commands.py` の interactive 表示を日本語化する。presentation 層だけで閉じることを確認し、ドメインロジック側へ翻訳分岐を入れない。
- [x] ステップ6: Phase 3 として `src/core/logger.py` の human-facing 補助表示を整理し、内部ログ互換と terminal width での表示崩れを確認する。
- [x] ステップ7: 主要CLIパスの focused test を追加する。全文一致だけでなく、message key・主要フレーズ・JSON非汚染を確認する粒度で `--help`、interactive `/help`、主要エラーパス、通常モード表示を検証する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [x] [重要度:高] `src/main.py` と `src/cli/commands.py` に文面直書きが多く、単純置換だと漏れやすい - 先に棚卸し表を作り、message集約先を用意する。
- [x] [重要度:中] 一部のメッセージはオペレーター向けだが JSON や report 操作と混在している - human-readable path と machine-readable path を分けて扱う。
- [x] [重要度:中] Rich装飾つき英語文面をそのまま訳すと表示幅や可読性が崩れる - 日本語前提で短く再設計する。
- [x] [重要度:低] 将来の英語再対応が面倒になる - 初期でも message key を意識して構造化しておく。

## 5.2 視点別レビュー懸念点と具体的な計画書への修正案

### 5.2.1 SRE / インフラエンジニア視点
| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
| --- | --- | --- | --- |
| 日本語化対象と内部ログの境界が曖昧なまま進むと、障害解析に必要な英語ログまで変更され、既存の grep / アラート / runbook が使いにくくなる。 | 高 | 大 | `## 3. 具体的な仕様と制約条件` に「内部 logger の event key / level / raw message は互換維持し、翻訳対象は human-facing console 出力に限定する」を追記し、`## 4` に翻訳対象外の確認ステップを追加する。 |
| Rich の status / panel / table タイトルを日本語化した結果、狭い端末幅や CI ログで折り返しが増え、進行状況が読み取りづらくなる。 | 中 | 中 | `## 3.2 完了条件` に「80-100桁程度の端末幅で主要ステータスが過度に崩れないこと」を追加し、`## 4` に narrow terminal での表示確認を入れる。 |
| エラーや注意文を日本語化しても、運用上必要な識別子や再実行ヒントが抜けると、夜間対応時の復旧速度が落ちる。 | 中 | 大 | `## 2. 全体像とアーキテクチャ` に「ユーザー向け文面は説明本文と操作ヒントを分離し、パス・task_id・exit code・対象URLなどの識別子は英数字のまま保持する」を追記する。 |

### 5.2.2 ソフトウェアアーキテクト視点
| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
| --- | --- | --- | --- |
| `src/main.py`、`src/cli/commands.py`、`src/core/logger.py` が個別に日本語文面を持ち続けると、初回実装後も文言差分と修正漏れが再発する。 | 高 | 大 | `## 2. 全体像とアーキテクチャ` に message resolver または `messages.py` を唯一の正本にする方針を明記し、`## 4` のステップ3に「直書き文面の残存箇所を棚卸し表でゼロ確認する」を追加する。 |
| 今回は日本語固定でも、文言キー設計がないまま始めると将来の `ja/en` 切替や通知系再利用で再分解が必要になる。 | 中 | 中 | `## 3. 具体的な仕様と制約条件` に「文面は message key ベースで参照し、初期実装は `ja` のみ提供しても key 命名規約を先に固定する」を追記する。 |
| help 文面、対話CLI文面、logger装飾タイトルの責務が混ざると、i18n 導入が presentation 層ではなく業務ロジックへ侵食する。 | 中 | 大 | `## 2` に「翻訳責務は CLI presentation 層に限定し、scanner / report / session のドメインロジックへ翻訳分岐を入れない」を追記し、`## 4` に import 境界確認のステップを足す。 |

### 5.2.3 デバッガー視点
| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
| --- | --- | --- | --- |
| 日本語化後に不具合が出ても「翻訳辞書ミス」「出力経路ミス」「既存分岐の取りこぼし」のどれかが切り分けられないと、修正が遅くなる。 | 高 | 大 | `## 4. 実装ステップ` に「argparse / interactive command / logger helper の3系統で出力経路を分類し、変更箇所一覧を残す」を明記し、`## 5` に切り分け順序を記録する。 |
| テストが `--help` だけに寄ると、`/resume`、HITL、deferred、例外時メッセージなどの回帰が実装後に漏れる。 | 高 | 大 | `## 3.2 完了条件` に対象シナリオ一覧を追記し、少なくとも `--help`、interactive `/help`、主要エラーパス、JSONモード併用時の非破壊確認を含めると固定する。 |
| 文面比較を完全一致だけで行うと、装飾差分や改行差分に引きずられ、本当に壊れた経路を見失いやすい。 | 中 | 中 | `## 4` に「focused test は全文一致だけでなく、message key・主要フレーズ・JSON非汚染を確認する粒度で追加する」を追記し、過剰に brittle な snapshot を避ける方針を入れる。 |

### 5.2.4 CTO視点
| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
| --- | --- | --- | --- |
| CLI日本語化、通知日本語化、`--translate-logs`、将来の多言語化が同時に語られているため、今期スコープが再び肥大化する。 | 高 | 大 | `## 3. 具体的な仕様と制約条件` に「今期は CLI本体の user-facing 出力のみ」「通知文面・ログ後翻訳・完全多言語化は別タスク」を箇条書きで明示し、スコープ外項目を独立小節として追記する。 |
| 成功条件が「日本語で読める」に寄りすぎると、導入後に利用率向上や問い合わせ減少へつながる品質基準が曖昧なままになる。 | 中 | 中 | `## 3.2 完了条件` に「主要フローの初見理解性を損なわない」「次の操作が分かる案内文を維持する」など、ユーザー価値ベースの受け入れ条件を追加する。 |
| 初回で大きく置き換えすぎると、CLI分割や共通化ロードマップとの競合でレビュー・統合コストが上がる。 | 中 | 大 | `## 4` に段階導入方針を追加し、Phase 1 を `src/main.py --help` と共通 message 集約、Phase 2 を interactive CLI、Phase 3 を logger 周辺の human-facing 補助表示として分ける。 |

### 5.3 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0290-D01
    title: "継続監視: CLI多言語化の本格対応"
    reason: "初期スコープでは日本語正本の提供を優先し、ja/en切替や message catalog 化は後続で進める"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "日本語化完了後に言語切替方式と未対応メッセージの棚卸しを行い、追跡サブタスクを起票する"
```
