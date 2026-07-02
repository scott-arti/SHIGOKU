---
task_id: SGK-2026-0076
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-01-30'
updated_at: '2026-07-02'
---

# Specification: Project Integration & Dashboard Enhancements

**Target**: Roadmap Phase 4.1, 4.2

## 1. Overview

SHIGOKUの実行結果管理を「セッション単位」から「プロジェクト単位」へ移行し、HTMLレポートを「プロジェクトポータル」として機能させる。
これにより、ユーザーは過去の実行履歴を一元的に閲覧でき、データがターゲットごとに整理されるようになる。

## 2. Changes

### 2.1 Project Based Storage (`src/core/project/project_manager.py`)

- **Action**: `ProjectManager` クラスの拡張。
- **Details**:
  - `save_session(session_data, filename)` メソッドの追加: `workspace/projects/{name}/sessions/` へ保存。
  - `list_sessions()` メソッドの追加: 保存されたセッション一覧（日時、ID）を返す。
  - `get_reports_dir()` プロパティの追加。

### 2.2 Main Execution Flow (`src/main.py`, `src/core/conductor/interactive_bridge.py`)

- **Action**: プロジェクト初期化の強制。
- **Details**:
  - `main.py` および `interactive_bridge.py` で、`target` が指定された時点で `ProjectManager(target)` を初期化。
  - `MasterConductor` に `project_manager` インスタンスを渡す。
  - `--resume` 時、プロジェクトディレクトリ内の `latest.json` から読み込むように変更（後方互換性維持）。

### 2.3 Master Conductor Integration (`src/core/engine/master_conductor.py`)

- **Action**: 保存ロジックの変更。
- **Details**:
  - `save_session` 内で `self.project_manager.save_session` を呼び出すように変更。
  - 従来の `workspace/session_state.json` もバックアップとして維持するが、ログにはプロジェクトパスを表示。

### 2.4 Dashboard Enhancement (`src/reports/`)

- **Action**: レポート生成ロジックとテンプレートの改修。
- **Details**:
  - `HTMLReportGenerator`:
    - `ProjectManager` から履歴データを取得。
    - テンプレート変数として注入。
  - `dashboard.html`:
    - **[Bug Fix]** `[object Object]` 表示問題の修正（`JSON.stringify` 適用）。
    - **[New UI]** 左サイドバーに「History」タブを追加。過去レポートへのリンク一覧を表示。

## 3. Data Structure

```text
workspace/projects/
  └── example.com/
        ├── sessions/
        │     ├── session_20260130_100000.json
        │     └── latest.json
        ├── reports/
        │     └── report_20260130_100000.html
        ├── findings/
        └── meta.yaml
```

## 4. Verification

### 4.1 Automated Tests (New)

- `tests/core/test_project_manager.py`:
  - `save_session` が正しいパスにファイルを生成すること。
  - `list_sessions` がソートされたリストを返すこと。
- `tests/reports/test_html_generator.py`:
  - 生成されたHTMLに履歴データが含まれていること。
  - `[object Object]` がJSコードに含まれていないこと。

### 4.2 Manual Verification

1. `docker compose run --rm shigoku python3 -m src.main --target example.com --dry-run` を実行。
2. `workspace/projects/example.com/sessions/` が作成されることを確認。
3. `docker compose run --rm shigoku python3 -m src.main --report --format html` を実行。
4. 生成されたレポートを開き、Historyタブが表示されていること確認。
5. OutputにJSONが綺麗に表示されていることを確認。
