---
task_id: SGK-2026-0009
doc_type: manual
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# SHIGOKU Dashboard 機能マニュアル

SHIGOKUには2種類のダッシュボード/レポート機能が存在します。

## 1. Static Execution Report (静的レポート)

セッションごとの実行ログ、戦略ツリー、詳細結果を記録した単一のHTMLファイルです。ログファイルの共有やアーカイブに適しています。

### 生成方法

既存のセッションファイル（`session_state.json`）から生成します。

```bash
# 最新のセッションからレポートを生成
python -m src.main --target <URL> --report --format html

# 特定のファイルを指定して生成 (CLIからは直接指定できないため、pythonコード利用または上記コマンド)
# 基本的には --report 実行時に自動的に html_generator が呼ばれます。
```

### 構成

- **ファイル場所**: `src/reports/templates/dashboard.html` (テンプレート)
- **生成ロジック**: `src/reports/html_generator.py`
- **特徴**:
  - サーバー不要（ローカルファイルとして開ける）
  - セッションデータをBase64でHTML内に埋め込むため、完全なポータビリティがある

---

## 2. Live Web Dashboard (Webダッシュボード)

プロジェクト全体の管理、脆弱性Findingの集約、ハンティングログの閲覧が可能なWebアプリケーションです。

### アーキテクチャ

- **Backend**: FastAPI (`src/dashboard/api`)
- **Frontend**: React + Vite (`src/dashboard/frontend`)

### 起動方法

現時点では統合ランチャーがないため、バックエンドとフロントエンドを個別に起動する必要があります。

#### Backend (Terminal 1)

```bash
python -m src.dashboard.api.main
# http://localhost:8000 でAPIが起動
```

#### Frontend (Terminal 2)

```bash
cd src/dashboard/frontend
PROJECT_ROOT=$(pwd)/../../.. npm install  # 初回のみ(依存解決が必要な場合)
npm run dev
# http://localhost:5173 でUIが起動
```

### 機能

- **Projects**: 登録済みプロジェクトの一覧とステータス
- **Findings**: 検出された脆弱性のリスト（フィルタリング可能）
- **Score**: プロジェクトごとの脆弱性スコア（0-10）
- **Hunting Log**: 実行された攻撃/偵察のタイムライン

## 今後の推奨アクション

Webダッシュボードを簡単に起動するための `python -m src.main --dashboard` コマンドの実装を推奨します。
