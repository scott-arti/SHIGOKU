---
task_id: SGK-2026-0301
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0298
related_docs:
- docs/shigoku/plans/2026-06-24_sgk-2026-0298_internal-behavior-visibility-governance_plan.md
- docs/shigoku/plans/2026-06-08_sgk-2026-0268_haddix-report-payout-readiness-output-improvements_plan.md
title: '内部挙動可視化 S3: Haddixレポート日本語併記出力'
created_at: '2026-06-24'
updated_at: '2026-06-30'
tags:
- shigoku
target: haddix_formatter Japanese/English paired report
---

# 実装計画書：内部挙動可視化 S3: Haddixレポート日本語併記出力

## 1. 達成したいゴール（ユーザー視点）
- [ ] SHIGOKUのHaddixレポートに、日本語で理解しやすい説明と、企業にそのまま提出できる英語レポートを併記できること。
- [ ] 英語提出セクションは既存Haddix品質と互換性を保ち、日本語セクションによってBug Bounty提出本文が汚染されないこと。
- [ ] report/session consistency gateを守り、翻訳・併記対象が正しいsession由来であることを確認できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/reporting/haddix_formatter.py`: 修正候補。既存英語Haddixを正本として維持する。
  - `src/reporting/haddix_ja_en_formatter.py`: 新規候補。正規化済み findings / execution_notes を受け取り、日本語サマリー + 英語提出本文を組み立てる。
  - `src/main.py`: 修正候補。ja-en 出力の生成正本として既存の report 生成経路を再利用する。
  - `scripts/shigoku_ops_cli.py`: 修正候補。必要な場合のみ report/session/validate の補助導線を追加する。
  - `src/reporting/report_session_consistency.py`: 互換確認対象。命名、`Generated`、`Source Session` の既存 reader 前提を維持または明示更新する。
  - `src/reporting/initial_release_gate.py`: 互換確認対象。新format導入時の gate 影響有無を確認する。
  - `tests/unit/reporting/test_haddix_ja_en_formatter.py`: 新規。日本語/英語の分離、見出し、提出セクション保持を固定する。
- **データの流れ / 依存関係:**
  - `HaddixFormatter.format_markdown()` -> English submission section
  - existing session extraction / heuristic / dedup path -> normalized findings + execution notes
  - normalized findings/session metadata -> Japanese summary section
  - combined formatter -> `haddix_report_<timestamp>.md` 互換の ja-en report

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - resolved report/session pair
  - existing Haddix markdown or formatter inputs
  - findings summary, severity, PoC, impact, remediation, execution notes
- **出力/結果 (Output):**
  - `# SHIGOKU 脆弱性レポート（日本語サマリー）`
  - `# Submission Report (English / Ready to Submit)`
  - 日本語側: 概要、重要Finding、再現概要、影響、提出時の注意
  - 英語側: 既存Haddix相当の提出用本文
- **制約・ルール:**
  - 既存 `--format haddix` の出力を変更しない。新formatまたは明示オプションで追加する。
  - 英語提出セクションを提出用の唯一の正本とし、severity / impact / remediation / reproduction の意味論は英語本文と canonical finding fields に従う。
  - 日本語は理解補助であり、企業提出先が英語を求める場合は英語セクションのみを提出可能な構造にする。
  - 初期版の日本語セクションは canonical finding fields と execution notes から定型生成し、自由翻訳レイヤは導入しない。
  - ja-en 出力でも初期版は `haddix_report_<timestamp>.md`、`**Generated:**`、`**Source Session:**` の互換性を維持する。
  - `shigoku-ops` は report/session/validate の補助導線に限定し、独自レンダリングの正本を持たない。
  - 出力は一時ファイルに生成し、ja/en 両セクションと整合確認完了後にのみ最終パスへ反映する。
  - report pathが指定された場合はconsistency checkerを先に通す。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: 英語提出セクションを提出用の唯一の正本、日本語セクションを理解補助とする責務境界を固定し、ファイル命名・ヘッダー・`Source Session`・`Generated` の互換要件を明文化する。
- [ ] ステップ2: `haddix_report_<timestamp>.md`、`**Generated:**`、`**Source Session:**`、セクション境界、英語/日本語見出しのgolden fixtureを先に追加し、既存読取側との互換テストを作成する。
- [ ] ステップ3: session から findings / execution_notes / scenario_coverage を抽出する既存経路を再利用し、新formatterには正規化済み入力のみを渡す構成に固定する。
- [ ] ステップ4: 既存Haddix formatterの英語本文を再利用する `haddix_ja_en` formatter を追加し、日本語セクションは canonical finding fields と execution notes から定型生成する。初期版では自由翻訳レイヤを導入しない。
- [ ] ステップ5: `--format haddix` は不変のまま維持し、opt-in の新formatまたは明示オプションで ja-en 出力を追加する。`shigoku-ops` は report/session/validate の補助導線に限定し、独自レンダリングは持たせない。
- [ ] ステップ6: 出力は一時ファイルに生成し、ja/en 両セクションと検証が完了した場合のみ最終パスへ反映する。source session 欠落、consistency checker NG、unsupported format では既存生成物を汚さず明確な失敗を返す。
- [ ] ステップ7: formatter unit tests、CLI tests、既存 Haddix regression tests を `.venv/bin/pytest` で対象実行し、Unicode/Markdown混在、findings空、heuristic昇格、partial findings fallback、軽微破損session復旧、負系exit codeを確認する。
- [ ] ステップ8: 実在 `haddix_report_*.md` がある場合は `python3 scripts/verify_report_session_consistency.py --report <absolute-report-path>` も実行し、必要に応じて gate 系の関連確認を追加してから完了判定する。

## 5. 懸念点と対策

### 5.1 SRE / インフラエンジニア観点
- 懸念点: `haddix_report_ja_en_*.md` のような新命名を採用すると、既存の report/session consistency checker や gate 系ツールが `haddix_report_<timestamp>.md` 前提で読めなくなる。
  - 発生確率: 高
  - 影響度: 大
  - 対策: 初期版は出力ファイル名を `haddix_report_<timestamp>.md` のまま維持し、ja-en 種別は本文ヘッダーまたは明示formatで表現する。別命名を採用する場合は reader 側の全互換更新を実装ステップへ含める。
- 懸念点: `src/main.py` と `scripts/shigoku_ops_cli.py` の両方に生成責務が分散すると、運用経路ごとに異なるレポートが生成される。
  - 発生確率: 高
  - 影響度: 大
  - 対策: レポート生成の正本は `src/main.py --report --format ...` に統一し、`shigoku-ops` は report/session/validate の補助オペレーションのみに限定することを計画書へ明記する。
- 懸念点: ja-en 合成途中で失敗した場合に中途半端なレポートが残り、後続の整合チェックや運用判断を誤らせる。
  - 発生確率: 中
  - 影響度: 大
  - 対策: 一時ファイル生成と原子的反映を前提にし、失敗時は既存レポートを上書きせず、終了コードとエラーメッセージを固定する負系テストを追加する。

### 5.2 ソフトウェアアーキテクト観点
- 懸念点: `optional translation layer` が曖昧なままだと、初期版から翻訳機構・要約機構・整形機構が混在し、責務分離が崩れる。
  - 発生確率: 高
  - 影響度: 大
  - 対策: 初期版の日本語セクションは canonical finding fields と execution notes からの定型生成に限定し、自由翻訳レイヤは将来拡張として明示的にスコープ外とする。
- 懸念点: 新formatter側で findings 抽出や正規化を再実装すると、既存 Haddix 経路と出力差分や重複バグが発生しやすい。
  - 発生確率: 中
  - 影響度: 大
  - 対策: session からの抽出・heuristic補完・dedup の正本は既存経路を再利用し、新formatterは正規化済み入力を受けて表示だけを担当する構成へ変更する。
- 懸念点: 影響範囲の reader / parser / gate を計画段階で列挙していないため、実装後に互換性破壊が見落とされる。
  - 発生確率: 高
  - 影響度: 中
  - 対策: 互換対象として `src/main.py`、`src/reporting/report_session_consistency.py`、`src/reporting/initial_release_gate.py`、`scripts/shigoku_ops_cli.py`、既存テスト群を計画の確認対象へ追加する。

### 5.3 デバッガー観点
- 懸念点: 現行ステップは見出し固定中心で、実データ分岐や fallback 経路の検証が不足している。
  - 発生確率: 高
  - 影響度: 大
  - 対策: findings空、heuristic昇格、partial findings fallback、軽微破損session復旧、Unicode/Markdown混在、finding 0件のgoldenケースを追加し、各分岐を計画済みの検証対象にする。
- 懸念点: 日本語サマリーが英語正本にない意味や推論を混ぜると、提出内容との差分原因を後から追跡しづらい。
  - 発生確率: 中
  - 影響度: 大
  - 対策: 日本語側は canonical fields に存在する情報だけで組み立て、各 finding に元の title / severity / target_url または stable key を対応づける方針を計画へ明記する。
- 懸念点: 失敗系の仕様が弱いと、missing source session や consistency checker NG 時に silent failure が起こる。
  - 発生確率: 中
  - 影響度: 中
  - 対策: unsupported format、source session欠落、report/session 不整合、読取側が新出力を解釈できない場合の CLI exit code と期待エラー文言を負系テストとして先に定義する。

### 5.4 CTO 観点
- 懸念点: レポート本体実装と `shigoku-ops` 拡張を同時に進めると、初期リリースのスコープが不要に広がる。
  - 発生確率: 中
  - 影響度: 大
  - 対策: Phase A を本体の ja-en formatter と `--format` 追加、Phase B を必要に応じた ops 補助導線と位置づけ、既定値変更は行わない段階導入を計画へ組み込む。
- 懸念点: 英語提出本文と日本語補助本文のどちらが正本か曖昧だと、品質判断・レビュー責任・将来の自動ゲート条件がぶれる。
  - 発生確率: 高
  - 影響度: 大
  - 対策: 英語提出セクションを提出用の唯一の正本と定義し、severity / impact / remediation / reproduction の意味論は英語側と canonical finding に従うとゴールおよび制約へ明記する。
- 懸念点: リリース条件とロールバック条件がないと、問題発生時に新formatを安全に外せない。
  - 発生確率: 中
  - 影響度: 大
  - 対策: 対象unit test、既存 Haddix regression、実artifact整合チェック完了までは opt-in の新formatとし、障害時は新format選択肢のみを外せば復旧できる構成を前提条件として計画に追加する。

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] 自動翻訳が技術的意味を変える。 - 初期版は翻訳AI依存を最小化し、定型文 + finding fieldsから生成する。
- [ ] [重要度:中] 日本語セクションが提出物に混入する。 - `English / Ready to Submit` セクションを明確な境界にする。
- [ ] [重要度:中] 既存parserが見出し追加に影響される。 - 新formatに分離し、既存Haddixは不変にする。

### 6.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0301-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
