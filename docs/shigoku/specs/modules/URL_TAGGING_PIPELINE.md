---
task_id: SGK-2026-0044
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# URL Tagging Pipeline (URL タグ付けパイプライン)

SHIGOKU の Phase 6 で実装された、高度な URL 発見と分類を行うパイプラインです。
ハイブリッドな手法（Active Crawling + Passive Archive）で URL を収集し、ルールベースでタグ付けを行って攻撃対象を絞り込みます。

## 概要

| コンポーネント                     | 役割                                                                                |
| ---------------------------------- | ----------------------------------------------------------------------------------- |
| **Hybrid URL Discovery** (Step 3b) | Katana (Active) + GAU (Passive) + Httpx (Live Check) を組み合わせた URL 収集        |
| **SubdomainEnricher**              | GAU で発見された「未知のサブドメイン」を自動検出し、WAF/Port/Tech 情報を Enrich     |
| **TaggingFilter**                  | ルールベース (`config/tagging_rules.yaml`) で URL を分類 (Auth, Admin, Upload etc.) |
| **SubdomainContext**               | 各エントリに親サブドメインのコンテキスト (WAF/Port) を付与し、MC の意思決定を支援   |

## データフロー

```mermaid
graph TD
    subgraph "Step 3b: Hybrid URL Discovery"
        LiveSubs[Live Subdomains] --> Katana[Katana (Active Crawler)]
        LiveSubs --> GAU[GAU (Passive Archiver)]

        Katana -->|Found URLs| Entries[Entry List]

        GAU -->|All URLs| ScopeFilter{Scope Filter}
        ScopeFilter -->|In Scope| GAU_URLs[GAU URLs]

        GAU_URLs --> SubEnrich{Subdomain Enricher}
        SubEnrich -->|New Subdomain| WAF_Port[WAF/Port Scan]
        WAF_Port --> Context[Subdomain Context]

        GAU_URLs --> Httpx[Httpx (Live Check)]
        Httpx -->|Live Entry + Context| Entries
    end

    Entries --> TagFilter{TaggingFilter}
    TagFilter -->|Match Rule| TaggedJSON[tagged_urls/*.jsonl]
    TagFilter -->|No Match| Untagged[untagged_urls.txt]

    TaggedJSON --> MC[Master Conductor]
    Untagged --> Archive[File Archive]
```

## 1. Hybrid URL Discovery (Step 3b)

アクティブとパッシブの両方のアプローチを統合し、網羅性と鮮度を両立させます。

### 1.1 Katana (Active)

- **役割**: 現在アクセス可能な URL を動的にクロール
- **設定**:
  - `mode="standard"`: Standard モード (depth 3)
  - Proxy: Caido (`http://127.0.0.1:8080`) 経由
  - Output: JSONL 形式

### 1.2 GAU (Passive)

- **役割**: 過去の URL アーカイブ（Wayback Machine, AlienVault, CommonCrawl）から収集
- **フィルタリング**:
  - **Dead Subdomains**: Step 2 で Dead と判定されたサブドメインを除外
  - **Scope**: URL のホストがターゲットドメインに属するか `urlparse` で厳密にチェック
- **URL サンプリング**: Httpx の処理負荷軽減のため、デフォルトで **50件** に制限 (E2E テスト用設定、本番は緩和可能)

### 1.3 Httpx (Validation)

- **役割**: GAU で収集した URL の生存確認
- **コンテキスト付与**: 各エントリに `subdomain_context` (WAF/Port/Tech) を付与

## 2. SubdomainEnricher

GAU は、Recon の初期段階（Step 1）で見つからなかった「**野良サブドメイン**」を発見することがあります。
SubdomainEnricher はこれらを逃さずキャッチし、詳細なコンテキストを追加します。

1. **抽出**: GAU URL リストからホストを抽出
2. **差分検知**: `live_subs` (Step 1 結果) と比較し、新規サブドメインを特定
3. **Enrich**:
   - **WAF Detection**: `wafw00f` を実行
   - **Port Scan**: `naabu` (Phase 1) を実行
4. **Context Injection**:
   - URL エントリの `subdomain_context` フィールドに情報を格納
   - 例: `{"subdomain_context": {"waf": "Cloudflare", "ports": ["443"], "source": "gau"}}`

## 3. TaggingFilter

収集されたすべての URL をルールベースで分類します。

- **設定ファイル**: `config/tagging_rules.yaml`
- **分類ルール (抜粋)**:
  - `auth`: ログイン、サインアップ関連 (path, body)
  - `admin`: 管理画面関連 (path, status 2xx)
  - `upload`: ファイルアップロード機能
  - `id_param`: `id=`, `user_id=` などの ID パラメータ
  - `file_param`: `file=`, `path=` などのファイル操作パラメータ
  - `redirect_param`: `url=`, `next=` などのリダイレクトパラメータ
  - `debug_info`: エラーメッセージ、スタックトレース

## 4. 出力ファイル

`workspace/{target}/tagged_urls/` ディレクトリに出力されます。

- `YYYYMMDD_{target}_tagged_auth.jsonl`
- `YYYYMMDD_{target}_tagged_admin.jsonl`
- `_untagged.txt` (タグなし URL リスト)
