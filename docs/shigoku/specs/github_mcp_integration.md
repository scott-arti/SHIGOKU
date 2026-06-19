---
task_id: SGK-2026-0128
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# GitHub MCP Integration (GitHub Dorks)

## 概要

Recon（情報収集）の初期段階において、ターゲット企業のドメイン名やキーワードを用いてGitHub上を検索し、パブリックリポジトリに誤ってコミットされたAPIキー、シークレット、内部コードなどの情報漏洩をAIが自動で調査する機能（GitHub Dorks）を追加します。
本機能は、Antigravity標準で利用可能な `github-mcp-server` をSHIGOKUの既存の `MCPClient` 経由で呼び出すことで実現します。

## 変更範囲

1. **`src/config.py`**
   - 認証に必要なトークンを管理するため、`github_token`（環境変数 `SHIGOKU_GITHUB_TOKEN` または `GITHUB_PERSONAL_ACCESS_TOKEN`）の設定項目を追加します。
2. **`src/core/agents/swarm/discovery/github_recon.py` (新規作成)**
   - `github-mcp-server` を立ち上げ、Dorksクエリ（例: `"{domain}" (password OR secret OR token OR key)`）で `search_code` や `search_repositories` を実行する特化型Workerエージェント（`GitHubRecon`）を実装します。
   - 解析結果から機密漏洩の疑いがあるものを抽出し、`Finding`（Severity: HighまたはCritical）として記録します。
3. **`src/core/agents/swarm/discovery/manager.py`**
   - `DiscoveryManagerAgent` に `run_github_dorks` ツールを初期ツールとして登録し、`GitHubRecon` Workerへ処理を委譲するように拡張します。
4. **`src/mcp/mcp_client.py` (オプション微修正)**
   - MCPサーバープロセス（`npx`）起動時に、親プロセスの環境変数（特に `GITHUB_PERSONAL_ACCESS_TOKEN`）を適切に引き継ぐか確認し、必要があれば修正します。

## 挙動 (Input/Output)

- **Input**: ターゲットのドメイン名や組織名（例: `example.com`）。
- **Output**:
  - GitHub上から発見された、ターゲットに関連するソースコードやシークレット情報。
  - 重大な漏洩が確認された場合は、`MasterConductor` 経由で通知（`Finding`）が生成されます。

## 制約

- **認証の必須性**: 動作には有効なGitHubトークンが必要です。設定されていない場合はエラーで停止せず、安全に（Gracefulに）スキップして他のReconプロセスを継続します。
- **レートリミット**: GitHub APIのレートリミットに配慮し、大量のページネーション取得は避け、関連度の高い上位の検索結果に限定して解析を行います。必要に応じて `AdaptiveRateLimiter` を適用します。
- **EthicsGuard (Safety Protocols)**: GitHubはサードパーティの公開プラットフォームであるため、Activeな攻撃インジェクションは行いません。パッシブなOSINT（公開情報収集）として分類され、ターゲットシステムそのものへのリクエストには該当しないため、通常通り実行可能です。

## テスト/検証計画

1. **Pytest**: `mcp_client` のモックを使用し、`GitHubRecon` が正しいDorksクエリを生成し、結果をパースできるかを検証する単体テストを追加します（`tests/core/agents/test_github_recon.py`）。
2. **E2E**: `python -m src.main --target example.com --mode bugbounty --dry-run` を実行し、GitHub Recon タスクがキューに積まれ、スキップまたは実行されることを確認します。
