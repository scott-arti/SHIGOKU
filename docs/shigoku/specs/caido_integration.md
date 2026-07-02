---
task_id: SGK-2026-0027
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# Caido Integration & Tagging Filter 実装計画

## 目的

`caido_importer.py` を実装し、Caido のログを取り込み、PII マスクを適用し、新しい `TaggingFilter` に渡す。`TaggingFilter` は URL を分類し、軽量なコンテキスト（認証ヘッダー、Body のスニペット）を抽出して、`MasterConductor` が専門エージェントに効率的にタスクを振り分けられるようにする。

## アーキテクチャ: ハイブリッドアプローチ

1.  **`caido_importer.py`**:
    - Caido からエクスポートされた JSON ログを取り込む。
    - `src.core.security.pii_masker` を使用して PII をマスクする。
    - データを標準化する（Method, URL, Headers, Body, Status）。
2.  **`tagging_filter.py`**:
    - Request/Response を解析してタグを付与する。
    - **コンテキスト抽出**: エージェントが認証できるように `Authorization`, `Cookie`, `X-CSRF-Token` ヘッダーを抽出する。
    - **証拠 (Evidence) 抽出**: 一時的な状態（Heisenbugs）に対処するため、関連する Body の一部（例: エラーメッセージ）を "evidence" として抽出する。
    - **一意性**: 一意なキー = `Method` + `正規化済み URL`（詳細は下記）。
3.  **中間処理 (`MasterConductor` 将来のコンテキスト)**:
    - ドメイン + タグで URL をグループ化する。
    - バッチ化されたタスクを専門エージェントにディスパッチする（例：「これら 5 つの URL で IDOR をチェックせよ」）。
4.  **専門エージェント (将来のコンテキスト)**:
    - URL リスト + 認証コンテキスト + 証拠を受け取る。
    - **プロキシ設定**: エージェントのトラフィックをキャプチャするために、Caido を指す `HTTP_PROXY` / `HTTPS_PROXY` （例: `127.00.1:8080`）を利用する。
    - **信頼設定**: SSL エラーを回避するために Caido CA 証明書をロードする。

## 詳細仕様

### 1. `src/tools/custom/caido_importer.py`

- **CLI 入力**:
  - `argparse` ベースで `-i / --input` オプションを使用。
  - 例: `python caido_importer.py -i /path/to/caido_export.json`
  - パスが指定されない場合、プロンプトで入力を待機する。
- **処理**:
  - JSON をロードする。
  - `raw` リクエスト/レスポンスフィールドを Base64 デコードする。
  - URL, Headers, Body に `PIIMasker` を適用する。
  - **静的ファイル除外**: 以下の拡張子を持つ URL はスキップする。
    - `.css`, `.js`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.svg`, `.ico`, `.woff`, `.woff2`, `.ttf`, `.eot`, `.map`
  - Caido エクスポートに重複エントリがある場合は処理する（`TaggingFilter` 側でもロジックの重複排除は行うが）。
- **エラーハンドリング**:
  | エラー種別 | 挙動 |
  | :--- | :--- |
  | ファイルが存在しない | エラーメッセージを出力し、再入力を促す |
  | JSON パース失敗 | エラー詳細を出力し、再入力を促す |
  | ファイルが空 | 「コンテンツがありません」と出力し、再入力を促す |
  | Base64 デコード失敗 | 該当エントリをスキップし、警告ログを出力 |
  | エンコーディングエラー (非 UTF-8) | エラーメッセージを出力し、再入力を促す |
- **出力構造 (辞書リスト)**:
  ```python
  {
      "id": "caido-id",
      "method": "POST",
      "url": "https://example.com/api/v1/login",
      "headers": {"Authorization": "...", "Cookie": "..."},
      "body": "...",
      "response": {"status": 200, "body": "..."}
  }
  ```

### 2. `src/core/intel/tagging_filter.py`

- **重複排除 (Deduplication)**:
  - 一意キー = `Method` + `正規化済み URL`
  - **URL 正規化ルール**:
    1.  クエリパラメータをキー名でソートする（例: `?b=2&a=1` → `?a=1&b=2`）。
    2.  パラメータの値は保持するが、同一パラメータ名の複数値は値ソート後に結合。
    3.  フラグメント (`#...`) は除去する。
    4.  ポート 80 (HTTP) / 443 (HTTPS) は URL から省略する。
- **静的ファイル除外**: Importer で除外されなかった場合のフォールバックとして、ここでも同じ拡張子を除外する。
- **タグ付けルール** (7-8 個のコアタグ):
  | タグ | 条件 | 対象エージェント |
  | :--- | :--- | :--- |
  | `auth` | Path/Body に `login`, `password`, `token` が含まれる | AuthSwarm |
  | `admin` | Path に `admin`, `dashboard` が含まれ、かつ 200 OK | GeneralAgent |
  | `id_param` | Query/Body に `id=`, `user_id=` が含まれる | InjectionSwarm |
  | `redirect_param` | Query に `url=`, `next=` が含まれる | LogicSwarm |
  | `file_param` | Query に `file=`, `path=` が含まれる | InjectionSwarm |
  | `upload` | Path に `upload`, `import` が含まれる | LogicSwarm |
  | `debug_info` | Response にエラーメッセージ/スタックトレースが含まれる | SecretSwarm |
- **未分類の処理**:
  - どのタグにも一致しない URL は、手動レビュー用に `uncategorized.jsonl` に保存する。
- **データ抽出**:
  - `auth_context`: `Authorization`, `Cookie`, `X-*` ヘッダー。
  - `evidence`: `debug_info` が検出された場合、Body の最初の 200 文字。
- **出力ファイル命名規則**:
  - 形式: `YYYYMMDD_<project>_tagged_<tag>.jsonl`
  - 例:
    - `20260117_example_com_tagged_auth.jsonl`
    - `20260117_example_com_tagged_id_param.jsonl`
    - `20260117_example_com_uncategorized.jsonl`
  - 保存先: プロジェクトの `workspace/projects/<project>/scans/raw/caido` ディレクトリ。

### 3. テストと検証

- **単体テスト**:
  - `tests/tools/test_caido_importer.py`: Base64 デコード、PII マスク、JSON パース、静的ファイル除外を検証。
  - `tests/core/intel/test_tagging_filter.py`: タグの正規表現マッチング、コンテキスト抽出、重複排除、URL 正規化を検証。
- **手動検証**:
  - サンプルログに対して `caido_importer` を実行する。
  - 出力を `tagging_filter` にパイプする。
  - `uncategorized.jsonl` とタグ付けされた出力を検査する。
