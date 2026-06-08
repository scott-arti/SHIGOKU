---
task_id: SGK-2026-0167
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# XSS Specialist (Stored & Reflected) Feature Specification

## 概要

LLMの推論能力を活用し、対象アプリケーションのコンテキスト（入力値がHTMLのどこに、どのようなエスケープ処理を施されて反射しているか）を動的に解析して最適なペイロードを生成する、知的な XSS (Cross-Site Scripting) Specialist エージェントを実装します。

単純にペイロードリストを投げる静的なスキャナとは異なり、以下のインテリジェントな動きを実現します。

1. **コンテキスト分析**: 安全なマーカー（例: `shigoku_xss_probe`）を送信し、レスポンスHTML内のどの部分（属性値、JS変数内、タグ外など）に反射しているか、エスケープ（`<` が `&lt;` に変換される等）が行われているかを解析します。
2. **ペイロード推論**: LLMが解析結果をもとに文脈・WAFを突破可能なペイロードを選択・生成します。
3. **発火検証**: すでにプロジェクト内に存在する `XSSVerifier` (`PlaywrightValidator` 経由) を活用し、実際にヘッドレスブラウザ上で `alert()` 等のダイアログが発火したかどうかの確実なエビデンスを収集します。

## 変更範囲

- `docs/specs/xss_specialist.md` (本ファイル)
- `src/core/agents/swarm/injection/smart_xss.py` (新規作成)
  - `SmartXSSHunter` エージェントの実装
  - コンテキスト解析ロジック、PlaywrightVerifier連携、各種ツール登録
- `src/core/agents/swarm/injection/manager.py` (修正)
  - `InjectionManagerAgent` の初期化に `SmartXSSHunter` を追加 (`self.specialists["xss"]`)
  - パラメータ分析ツール(`analyze_parameters`) の検知ロジックに XSS 向けのキーワード（例えば `q`, `search`, `name`, `msg` など）や処理を追加
  - LLM呼び出しツール `run_xss_hunter` の追加
- `src/core/attack/xss_tester.py` (修正)
  - 現在プレースホルダー（コメントアウト）になっている通信部分を、非破壊的マーカーテスト機能として実際に動くように調整するか、エージェント側の内部ツールとして統合します。

## 挙動 (Input / Output)

### 1. Reflected XSS テストフロー

- **Input**: 対象URL、テスト対象のパラメータリスト、セッション（Cookie等の認証情報）
- **Process**:
  1. `SmartXSSHunter` が安全なマーカーを入力してGETリクエスト送信。
  2. レスポンスHTML内でのマーカーを探索し、周辺のコンテキスト文字列を取得してLLMに分析依頼。
  3. LLMが「ここでは `<script>` は使えないが `onfocus` 属性なら挿入可能」と推論し、エッジケースを考慮したペイロードを決定。
  4. 生成されたペイロード付きURLを `XSSVerifier` に渡し、ブラウザ上でレンダリング。
  5. アラート検知などが行われたら脆弱性判定。
- **Output**: 脆弱性詳細とPoC（Payload）、エビデンスを含む `Finding` オブジェクトのリスト。

### 2. Stored XSS テストフロー

- **Input**: 対象となる入力フォーム(URLとパラメータ/ボディ)、および、結果が反映される表示画面(URL)
- **Process**:
  1. マーカーを含むデータをPOST送信（例：プロフィールの名前更新、掲示板への書き込み）。
  2. 表示ページ（プロフィール画面や掲示板一覧）をGETし、マーカーの反射状態を確認。
  3. コンテキスト解析および推論したペイロードを同様にPOST送信。
  4. 再度表示ページに `XSSVerifier` でアクセスして発火検証。
- **Output**: 脆弱性とPoCを含む `Finding` オブジェクトのリスト。

## 制約・セキュリティガイドライン (Constraints)

1. **EthicsGuardの遵守**:
   - バックエンドとの通信時やヘッドレスブラウザによる検証時は、必ず `ethics_guard.check_scope(url)` を適用すること。
2. **データの破壊回避 (Safe Stored Testing)**:
   - Stored XSSのテストにおいて、過剰な書き込みを行ってシステムを破壊しないこと。
   - レートリミット（`AdaptiveRateLimiter`）を必ず遵守すること。
3. **PII保護**:
   - ログ出力時に `PIIMasker` を使い、取得したHTML内の機密情報やセッショントークンが直接ログにダンプされないように注意すること。
4. **ガードレールの競合解決 (AggressiveLimiter Override)**:
   - SHIGOKUにはPOST/PUT/DELETEなどを破壊的操作とみなして一時停止させる `AggressiveLimiter` があるが、XSSテストにおいては「通常のフォーム機能へのペイロード送信」が主目的であるため、過剰なブロック対象となる。
   - `SwarmDispatcher`（または Limiter の判定ロジック）を改修し、タグが `xss_candidate` または担当 Swarm が `injection` の場合は、メソッドが POST であっても明示的に `is_aggressive = False` として Limiter をバイパス（例外化）させる仕組みを導入する。
   - 同時に、他人のデータを変更しうる IDOR などの `LogicSwarm` においてはLimiterのプロンプトで人間が承認した場合、`user_approved=True` フラグを渡し、エージェント側の `safe_mode` スキップを解除するように連携を修正する。
