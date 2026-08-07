---
task_id: SGK-2026-0406
doc_type: manual
status: active
parent_task_id: SGK-2026-0406
related_docs:
  - docs/shigoku/plans/done/2026-07-29_sgk-2026-0406_workspace-storage-and-manual-guide_plan.md
  - src/core/project/project_manager.py
created_at: '2026-07-29'
updated_at: '2026-08-07'
---

# ワークスペース保存構造とマニュアル案内

SHIGOKU を実行したときにできるファイルの場所と、目的に合うマニュアルの選び方をまとめた案内です。

## まず知っておく場所

通常の実行結果は、次の場所に保存されます。

```text
workspace/projects/<対象名>/
```

`<対象名>` は、たとえば `localhost:4280` のような対象URLから作られる名前です。保存先の標準構造は `src/core/project/project_manager.py` が管理しています。

| 項目 | 何が入るか | 残す理由 |
| --- | --- | --- |
| `findings/` | 検出結果のJSON | ダッシュボードや後続処理で使うため |
| `hunting_log/` | AIによる調査履歴 | 調査の振り返りに使うため |
| `reports/` | 利用者向けレポートと証拠データ | 結果を確認・提出するため |
| `scans/raw/` | ツールから得た加工前の結果 | 根拠を確認するため |
| `scans/filtered/` | 整理後のスキャン結果 | 次の処理に渡すため |
| `screenshots/` | 画面の証拠画像 | 画面上の挙動を残すため |
| `sessions/` | 実行状態のJSON | 実行再開とレポートの照合に使うため |
| `tagged_urls/` | URLの分類結果 | 次に調べるURLを選ぶため |
| `meta.yaml` | 対象URLなどのプロジェクト設定 | プロジェクト一覧の表示に使うため |
| `recon_state.json` | 偵察処理の途中状態 | 偵察を途中から再開するため |

## `workspace/` 直下のフォルダー

| フォルダー | 役割 | 扱い |
| --- | --- | --- |
| `projects/` | 対象ごとの正式な実行結果 | 必ず残す |
| `bugbounty/` | 対象範囲や禁止事項などのルール | 必ず残す |
| `runtime/` | 実行中の内部データや再送待ちデータ | 必ず残す |
| `snapshots/` | 前回結果との比較用データ | 必ず残す |
| `assets/` | 単語リストなど | 互換用として残す |
| `data/` | 脆弱性の優先度計算に使う古いデータ | 互換用として残す |
| `logs/` | 実行ログ | 履歴・互換用 |
| `recon/` | 旧形式の偵察結果 | 履歴・互換用 |
| `tagged_urls/` | 旧形式のURL分類結果 | 履歴・互換用。通常は対象別フォルダーを使う |
| `tmp/` | 一時的な集計結果 | 履歴・互換用 |
| `projects_old/` | 旧形式のプロジェクト保存先 | 通常実行では不要。削除前に必要な履歴がないか確認する |
| `target_site/` | 以前取得した対象サイトのHTML | 通常実行では不要 |
| `workspace/` | 過去の保存先不具合で二重に作られたデータ | 通常実行では不要。過去記録が必要な場合だけ残す |

## `workspace/` 直下のファイル

| ファイル | 役割 | 扱い |
| --- | --- | --- |
| `.task_overflow.db` | 実行待ちタスクの退避用データベース | 残す |
| `session_state.json` | 古い再開機能のセッション状態 | 互換用として残す |
| `cookies.txt` | 手動ログイン時のCookie | 必要なら再作成できる。中身を共有しない |
| `subdomains.txt` | 手動調査用のサブドメイン一覧 | 必要なら再作成できる |
| `targets.txt` | 手動スキャン用の対象一覧 | 必要なら再作成できる |

2026-07-29 の整理では、上記以外の直下ファイルと明らかに未使用のフォルダーをゴミ箱へ移しました。`projects_old/`、`target_site/`、旧 `vulnerabilities/` は root 所有のため残っています。

## マニュアルの選び方

| 読みたいこと | まず読む文書 | 補足 |
| --- | --- | --- |
| 初めて起動する | [QUICK_START.md](QUICK_START.md) | インストールと最初の実行向け |
| 日常的な使い方を知る | [MANUAL_JA.md](MANUAL_JA.md) | 機能の全体像を知るための日本語マニュアル |
| 設定や環境変数を調べる | [REFERENCE.md](REFERENCE.md) | 設定項目とCLIオプションの一覧 |
| 外部ツールの運用をする | [external_tools_operations.md](external_tools_operations.md) | 監視、並行実行、外部ツール連携向け |
| 手動調査の進め方を考える | [MyMethod.md](MyMethod.md) | 調査者の手順メモ。自動処理の仕様書ではない |
| 過去の設計判断を確認する | [QA.md](QA.md) | 2025年時点の構成Q&A。現行仕様との違いに注意 |
| 以前の運用手順・障害対応を調べる | [manual_legacy/](manual_legacy/) | 過去資料。現在の標準手順としては使わない |

## `manual_legacy/` の分類

`manual_legacy/` は古い文書を残す場所です。現在の基本操作ではなく、過去の経緯や特定の運用作業を確認するときにだけ使います。

| 種類 | 文書 |
| --- | --- |
| 過去の利用者向け手順・コマンド一覧 | `2026-07-02_sgk-2026-0338_operator-user-manual.md`、`2026-07-02_sgk-2026-0337_detailed-command-reference.md` |
| 障害対応・劣化時の運用 | `2026-05-26_*runbook.md`、`2026-06-03_*runbook.md`、`2026-06-03_degrade-drill-evidence_template.md` |
| 特定フェーズ・機能の運用 | `2026-06-30_phase9_operator_runbook.md`、`2026-07-17_sgk-2026-0287_pruning-operator-runbook.md`、`dashboard.md` |
| バグバウンティ向け運用 | `2026-07-02_sgk-2026-0335_bugbounty-bundle-operator-runbook.md` |
| 過去の運用計画 | `cli_first_ops_plan.md` |

迷った場合は、まず `QUICK_START.md`、次にこの文書、必要に応じて `REFERENCE.md` を確認してください。
