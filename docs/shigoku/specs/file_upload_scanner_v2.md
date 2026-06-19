---
task_id: SGK-2026-0119
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# File Upload Vulnerability Scanner v2 Specification (Revised: Context-Aware Path Prediction)

Ver.1において高度なRCE確認まで完遂することは困難であると判断し、スコープを「**WebShellのアップロード成功可否の判定**」および「**Katanaやアプリケーションコンテキストを活用した、保存先パス（Path）の候補推測（Suggestion）**」にフォーカスする。

## 1. 目的と出力

- 目的:
  - 対象エンドポイント（フォーム等）が、拡張子偽装やMIMEタイプ偽装等の手法によって、実行可能ファイル（`.php`等）を受け入れるか検証する。
  - アップロードに成功した場合、ユーザーや後続の攻撃フェーズのために「どこに保存された可能性が高いか」をコンテキストから推測・提示する。
- 出力 (Finding):
  - **種類**: `FILE_UPLOAD`
  - **タイトル**: "Unrestricted File Upload Detected (Potential WebShell)"
  - **証拠 (Evidence)**: アップロード成功を示すレスポンス情報（ステータスコード、メッセージ等）。
  - **推測パスリスト (Suggested Paths)**: コンテキストから導き出された保存先URLの候補と、その推測理由（Reason）。

## 2. アーキテクチャ構成

巨大な実行クラスを避け、責務を分割する。

### 2.1 FileUploadTester (Main Orchestrator)

ファイルアップロード検証作業を統括する。

- `PayloadManager` からペイロード（画像や偽装PHPファイルなど）を取得。
- 対象URLに対してアップロードを実行。
- レスポンスから「アップロード自体が成功したか」を判定。
- 成功した場合、`PathPredictor` を呼び出して候補パスを生成。

### 2.2 PathPredictor (New Component: 保存先推測モジュール)

KatanaのReconデータとターゲットのURLコンテキストを利用し、アップロードされたファイルの「保存先URLの候補」を推測・スコアリングする。
以下の3つのTier（層）から候補を合成する。

#### Tier 1: Katana Context (構造的推論)

Katanaが見つけてきた実在のURL群を利用し、実際に使われているディレクトリを抽出する。

1. `MasterConductor` などの共有状態、またはファイル（例: `tagged_urls/`）から、Katanaが収集したURLリストを取得。
2. 拡張子が画像・ドキュメント（`.jpg`, `.png`, `.pdf` 等）で終わるURLをフィルタリング。
3. フィルタリングされたURLの親ディレクトリ部分を抽出。（例: `/assets/img/logo.png` -> `/assets/img/`）
4. ノイズディレクトリ（`/css/`, `/js/`, `/vendor/` 等）を除外。

#### Tier 2: Endpoint Context (機能的推論)

アップロード処理を行うURL自体の構造をヒントにする。

1. ターゲットURLからエンドポイント名（`upload.php`等）を除外した親ディレクトリ。（例: `/api/v1/users/upload` -> `/api/v1/users/`）
2. ターゲットURLの親ディレクトリに対して、一般的なアップロードサブディレクトリ名を付加。（例: `/upload/` -> `/upload/uploads/`）

#### Tier 3: Fallback Dictionary (一般的な辞書)

アプリに依存しない、頻出の保存先ディレクトリ。

- `/uploads/`, `/files/`, `/images/`, `/media/`, `/assets/` などを固定で追加。

#### 合成

上記のTierから得られた「ディレクトリ候補リスト」に対して、本スキャンでアップロードした「ファイル名（例: `shell.php`）」を結合し、候補（Suggested Path）リストを作成する。

## 3. スコアリングと優先度付け (Scoring & Ranking)

合成された `Suggested Paths` に対してランキングを行うため、以下の基準でスコアリング（点数化）を行い、降順でソートする。

1. **基本Tierスコア**:
   - `Tier 1` (Katana由来の実在パス): +50点
   - `Tier 2` (EndpointURLからの推測): +30点
   - `Tier 3` (一般的なFallback辞書): +10点
2. **パス類似度ボーナス**:
   - 対象のアップロードエンドポイントURLと候補のパス間で、共通するディレクトリ階層が深いほど加点する。
   - （例: エンドポイントが `http://target/users/profile/upload` の場合、Katanaで見つかった `http://target/users/profile/images/` はより高スコアになる）

## 4. 実行フロー

1. **アップロード試行**:
   - `PayloadManager` で生成した検証用ファイル（WebShell候補）を送信する。
2. **アップロード成否の判定**:
   - ステータスコード（例: 200, 201）やレスポンスボディの特徴（"uploaded", "success"など）から、単純に「拒否されなかったか」を判断する。サーバーエラー（500系）や明示的な検証エラー（"Invalid file type"等）が返らなければ「アップロード成功（脆弱性あり）」とみなす。
3. **パス推測 (Path Prediction)**:
   - アップロード成功と判定された場合、`PathPredictor` を起動する。
   - Reconデータ（Katanaのクローリング結果）とターゲットURLから、 `Suggested Paths`（推測パスリスト）を生成し、スコアリングしてソートする。
4. **Finding生成**:
   - 成功の証拠とスコア順に並んだ `Suggested Paths` を含む `Finding` オブジェクトを構築し、結果として返す。
   - （Ver.1では、推測されたパスへ実際にアクセスしてRCEを確認する処理は**行わない**）

## 5. データ構造とレポート出力フォーマット

### 内部データ構造

```python
@dataclass
class SuggestedPath:
    url: str      # 生成されたURL候補 (例: "http://target/uploads/shell.php")
    tier: int     # 生成元がどのTierか (1: Katana, 2: Endpoint, 3: Fallback)
    reason: str   # 推測理由 (例: "Found static image directory in Katana logs")
    score: int    # 算出されたスコア

@dataclass
class UploadFinding:
    url: str                        # アップロード機能のURL
    method: str                     # 成功した手法 (e.g., "MIME Type Bypass")
    evidence: str                   # 成功を示すレスポンス情報
    suggested_paths: list[SuggestedPath] # スコア順の保存先候補のリスト
```

### レポート出力フォーマット（Finding文字列例）

```text
[FILE_UPLOAD] Unrestricted File Upload Detected (Potential WebShell)
URL: http://localhost:4280/vulnerabilities/upload/
Severity: High
Method: MIME Type Bypass (image/jpeg)
Evidence: Server responded with HTTP 200 indicating success.

--- Suggested Paths (Where is the shell?) ---
1. http://localhost:4280/vulnerabilities/upload/uploads/shell.php
   Reason: [Tier 2] Derived from endpoint URL.
2. http://localhost:4280/assets/img/shell.php
   Reason: [Tier 1] Static directory found in Katana crawl data.
3. http://localhost:4280/uploads/shell.php
   Reason: [Tier 3] Common fallback directory.
```
