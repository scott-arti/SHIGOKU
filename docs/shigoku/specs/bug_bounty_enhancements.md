---
task_id: SGK-2026-0106
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Specification: Bug Bounty Optimization

## 概要 (Overview)

SHIGOKUエンジンのバグバウンティ特化運用に向けた機能強化および安全対策の実装仕様を定義する。
主な変更点は、スコープに基づく危険な攻撃（Post Exploitation）の自動停止、不要機能の削除、およびバウンティで高評価を得やすい3つの新しいSpecialist（Takeover, WebCache, SourceMap）の追加である。

## 変更範囲 (Scope of Changes)

- **Core / Engine**: `src/core/domain/scope/`, `src/core/engine/master_conductor.py`, `src/core/engine/swarm_dispatcher.py`
- **Agents (Swarm)**: `src/core/agents/swarm/`
  - `secret/manager.py` (CloudMisconfig 本実装, SourceMap 追加)
  - `scanner/` または `discovery/` (Takeover 追加, WebCache 追加)
  - `scanner/llm_specialists.py` (CryptoAnalyzer 削除)
- **Recon**: `src/recon/tool_runner.py`, `src/recon/pipeline.py` (Mock整理)

## 詳細仕様 (Detailed Specifications)

### 1. Scope-based Post Exploitation Control

- **挙動**: `--mode bugbounty` 実行時、初期セットアップで読み込まれる Scope 情報（YAMLまたはユーザー入力）を AI に解釈させ、`allow_post_exploit` フラグ（boolean）を生成する。
  - 明示的にRCE後調査や内部ネットワークスキャンが許可されていない限り、Bug Bounty モードではデフォルトを `False` とする。
- **適用**: `MasterConductor` がタスクをディスパッチする際、または `SwarmManager` 内で、Post Exploit系のタスク（`secret_looter`, `internal_recon`, `pivot_scan` など）の実行前にこのフラグをチェックし、`False` の場合は実行をスキップ（ログに理由を出力して完了扱い）する。

### 2. High-Value Specialists Implementation

#### A. Subdomain Takeover Specialist

- **目的**: サブドメインの乗っ取り可能性を検証する。
- **Input**: Recon Pipeline で収集された `dead_subs.txt` などのNot Found応答を返すサブドメインリスト。
- **ロジック**:
  1.  既存の `src/tools/custom/subjack.py` ラッパーを呼び出し、リストを検証。
  2.  さらに精度を高めるため、`Nucliei` ツールの `takeover` テンプレート群を指定して実行。
- **Output**: 乗っ取り可能なドメインと利用されているプロバイダ情報（GitHub Pages, S3等）。

#### B. Web Cache Deception Specialist

- **目的**: キャッシュサーバの設定不備を突き、他のユーザーの機密情報を取得可能か検証する。
- **Input**: 認証が必要な動的コンテンツページのURL（例: `/api/profile`, `/settings`）。
- **ロジック**:
  1.  認証状態（Cookieあり）でターゲットURLにダミーの静的拡張子を付与（例: `/api/profile/dummy.css`, `/settings;dummy.js`）してアクセス。
  2.  直後に、**非認証状態（Cookieなし）**で全く同じURLにアクセス。
  3.  レスポンスボディに認証時のユーザー情報（メールアドレス等）が含まれており、かつレスポンスヘッダにキャッシュヒットの痕跡（`X-Cache: HIT`, `Age: *` 等）があれば「Vulnerable」と判定。
- **Output**: 脆弱なURLと、情報漏洩を証明するレスポンスの抜粋。

#### C. Source Map & JS Secrets Specialist

- **目的**: JavaScript のソースマップを復元し、隠された情報を抽出する。
- **Input**: Recon または Crawl フェーズで発見された JavaScript ファイル (`*.js`) のURLリスト。
- **ロジック**:
  1.  各 `.js` URL の末尾に `.map` を付与してリクエストを実行。
  2.  有効なソースマップ（一般的にJSON形式で `sourcesContent` を含む）が取得できた場合、その内容を展開・解析。
  3.  展開されたソースコード内から、正規表現を用いて APIキー（AWS, Stripe, Maps等）や、未公開のエンドポイントURLを抽出する。
- **Output**: 発見された機密情報、および元のソースファイル構造。

#### D. Cloud MisconfigChecker (既存TODOの解消)

- **目的**: 公開設定されたクラウドストレージを検出する。
- **ロジック**: サブドメイン探索やHTMLソースから抽出したS3バケットURL等に対して、匿名アクセス（List, Read）を試行し、アクセス権限の不備を判定する。

### 3. 不要モックの削除・整理

- **削除**: `LLMCryptoAnalyzer` を完全に削除。ディレクトリ階層からも取り除く。
- **整理**: Recon パイプライン内の `DEV_MODE` 判定によるハードコードされたモック出力（`example.com` など）を分離。`pytest` でのモックとしてパッチを当てる等の方式に変更し、プロダクションコードから固定文字列の出力を無くす。

## 制約 (Constraints)

- `shigoku-architecture` のルールに従い、「Core/Shared Module の改修」→「Dependent Modules (Specialist) の実装」→「Entry Points の更新」の順に実装を進めること。
- すべての機能は EthicsGuard によるネットワーク保護の下で実行されること。
- ドキュメントとシステム出力に関する言語は、英語での内部推論を除き、日本語に統一すること。
