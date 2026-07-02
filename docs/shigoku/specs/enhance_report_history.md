---
name: enhance-report-history-and-timezone
description: Enhances the report history to include all project history across all
  reports, supports grouping by target, and adds execution time display.
task_id: SGK-2026-0117
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# Enhance Report History & Timezone

## 1. 概要 (Overview)

- **Historyの完全性確保**: 個別の過去レポートを開いたときも、最新の全履歴情報にアクセスできるようにします。
- **実行時刻の表示**: `latest.html` 上部に実行時刻（JST）を表示します。
- **Historyのグルーピング**: 複数のターゲット（プロジェクト）の履歴を混在させず、ターゲットごとにCollapse（折りたたみ）可能なUIで表示します。

## 2. 変更範囲 (Scope of Changes)

- `src/reports/html_generator.py`: 全プロジェクトの履歴収集ロジック追加、データ構造変更。
- `src/reports/templates/dashboard.html`: 時刻表示エリア追加、Historyタブの折りたたみUI実装。

## 3. 詳細な挙動 (Detailed Behavior)

### A. History収集ロジックの変更 (`html_generator.py`)

1.  現在のプロジェクトだけでなく、`workspace/projects/` ディレクトリ配下の全プロジェクトをスキャンします。
2.  各プロジェクトごとに `session_*.json` を収集します。
3.  データ構造を以下のように変更してテンプレートに渡します。
    ```json
    {
      "Target A (example.com)": [
        {"timestamp": "2026-02-02 10:00", "filename": "../../Target A/reports/report_01.html", ...},
        ...
      ],
      "Target B (test.com)": [...]
    }
    ```
    _注意_: リンクパスは相対パスで解決する必要があります。`latest.html` は `workspace/projects/TargetA/sessions/` にあると仮定すると、他プロジェクトへのリンクは `../../TargetB/sessions/report.html` となります。
    ただし、現状の実装では `latest.html` は `project_dir/sessions/` に出力されているはず。

### B. 過去レポートのHistory更新

- 前回実装した「Backfill（欠損自動生成）」に加え、既存のHTMLがある場合も「全履歴データ」だけを更新するのは困難（HTMLパースが必要）。
- **方針変更**: ユーザーは「どの履歴を見てもHistoryにはすべての履歴が出るようにしたい」と望んでいる。
- これを実現するため、**Backfill時に渡すHistoryデータを「全プロジェクトの全履歴」にする** ことで、これから生成される（またはBackfillされる）レポートは要件を満たす。
- 既存のレポートについても、レポート生成コマンド実行時に**強制的に再生成するオプション**を用意するか、あるいはBackfillロジックで「HTMLがあってもHistoryが古いなら更新」するロジックを入れる。
  - パフォーマンスを考慮し、今回は **「HTMLが存在しない場合のみ生成（Backfill）」** のままとしつつ、「全プロジェクト履歴」を渡すように変更する。これにより、一度でも `python -m src.main --report` を実行すれば（Backfillが走れば）Historyは充実する。既存ファイルが更新されない件については、ユーザーに「一度 `rm workspace/projects/*/sessions/*.html` して再生成してください」と案内するか、あるいはコード内で上書きフラグを立てる。今回は**安全のため上書きはせず、Backfill強化のみ**とする。

### C. UI変更 (`dashboard.html`)

1.  **Header**: タイトル横またはその下に `Generated at: YYYY-MM-DD HH:MM (JST)` を表示。
2.  **History Tab**: リスト表示をアコーディオン形式に変更。
    - プロジェクト名をクリックすると展開/折りたたみ。
    - デフォルトでは「現在のプロジェクト」のみ展開する。

## 4. 制約 (Constraints)

- 相対パス計算: `os.path.relpath` を使用して、閲覧中のHTMLからターゲットHTMLへの正しいリンクを生成する。
- 実行速度: プロジェクト数が増えるとスキャンに時間がかかるため、`session_*.json` の探索は浅く行う（再帰しない）。
