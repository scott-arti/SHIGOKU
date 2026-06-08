---
task_id: SGK-2026-0007
doc_type: manual
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# 📘 SHIGOKU ユーザーマニュアル

**SHIGOKU** を「最強の相棒」として使いこなすための包括的なガイドです。
基本操作から高度な戦略的オーケストレーションまでをカバーします。

---

## 目次 (Table of Contents)

1. [CLI リファレンス](#1-cli-リファレンス)
2. [運用モード詳解](#2-運用モード詳解)
   - [Recon Mode (偵察)](#2-1-recon-mode-偵察)
   - [Hybrid Hunt Mode (ハイブリッド)](#2-2-hybrid-hunt-mode-ハイブリッドハント)
   - [Sentinel Mode (監視)](#2-3-sentinel-mode-センチネル)
   - [Demo Mode (デモ)](#2-4-demo-mode-デモ)
3. [スコープ定義ガイド](#3-スコープ定義ガイド)
4. [RAG ナレッジエンジニアリング](#4-rag-ナレッジエンジニアリング)
5. [ROI 最適化戦略](#5-roi-最適化戦略)
6. [レポート管理](#6-レポート管理)
7. [ベストプラクティス](#7-ベストプラクティス)

---

## 1. CLI リファレンス

### 基本構文

```bash
python -m src.main [OPTIONS]
```

### オプション一覧

| オプション       | 引数       | 説明                                 |
| :--------------- | :--------- | :----------------------------------- |
| `--recon`        | URL        | 偵察モード：サイトマップ構築         |
| `--log`          | FILE       | ハイブリッドハント：プロキシログ解析 |
| `--watch`        | OWNER/REPO | センチネル：GitHub リポジトリ監視    |
| `--scope`        | FILE       | スコープ定義 YAML ファイル           |
| `--demo`         | (なし)     | デモモード実行                       |
| `--full-refresh` | (なし)     | RAG インデックスの完全再構築         |
| `--vault`        | PATH       | Obsidian Vault のパス                |
| `--help`         | (なし)     | ヘルプ表示                           |

### 使用例

```bash
# 偵察モード
python -m src.main --recon https://api.target.com

# ハイブリッドハント（スコープ付き）
python -m src.main --log traffic.har --scope scopes/target.yaml

# GitHub監視
python -m src.main --watch facebook/react

# RAGを別のVaultで初期化
python -m src.main --vault ~/Obsidian/Security --demo
```

---

## 2. 運用モード詳解

SHIGOKU は 4 つの運用モードを提供します。それぞれバグバウンティワークフローの異なるフェーズに対応しています。

### 2-1. Recon Mode (偵察)

**目的**: ターゲットの全貌を把握し、攻撃対象領域（Attack Surface）をマップ化

```bash
python -m src.main --recon <TARGET_URL> [--scope <SCOPE_FILE>]
```

#### 実行される処理

```
1. EthicsGuard 初期化
   └─ スコープファイルがあれば読み込み

2. Cartographer サイトマップ生成
   ├─ 再帰クロール (max_depth まで)
   ├─ リンク抽出
   └─ フォーム検出

3. Fingerprinter 技術識別
   ├─ HTTPヘッダー解析
   └─ HTML解析

4. Knowledge Graph 保存
   ├─ Domain ノード作成
   ├─ Page ノード作成
   ├─ Technology ノード作成
   └─ リレーション設定
```

#### 出力

- **コンソール**: 発見されたページ数、技術スタック
- **Neo4j**: グラフデータベースに資産情報を保存
- **ログ**: 詳細なクロールログ

#### 設定オプション

| 項目           | 環境変数                 | デフォルト |
| :------------- | :----------------------- | :--------- |
| 最大深度       | `CARTOGRAPHER_MAX_DEPTH` | 2          |
| タイムアウト   | `CARTOGRAPHER_TIMEOUT`   | 10 秒      |
| リクエスト間隔 | (設定ファイル)           | 0.5 秒     |

---

### 2-2. Hybrid Hunt Mode (ハイブリッドハント)

**目的**: 手動調査と自動攻撃を組み合わせた高精度な脆弱性検証

```bash
python -m src.main --log <PROXY_LOG_FILE> [--scope <SCOPE_FILE>]
```

#### 前提条件

プロキシツール（Burp Suite、Caido、OWASP ZAP 等）を使用してターゲットを手動でブラウジングし、トラフィックログをエクスポートしておく必要があります。

**対応フォーマット**:

- HAR (HTTP Archive) - Chrome DevTools, Burp
- Caido JSON
- Burp XML (将来対応予定)

#### 実行される処理

```
1. ProxyLogAnalyzer ログ解析
   ├─ ログファイル読み込み (HAR/Caido)
   ├─ ノイズ除去 (静的ファイル、CDN等)
   └─ Smell (匂い) 検出
       ├─ IDOR_CANDIDATE
       ├─ JWT_PRESENT
       ├─ HIDDEN_PARAM
       ├─ ADMIN_ENDPOINT
       └─ etc.

2. Attack Plan 生成
   └─ 候補を優先度順にソート

3. エージェント派遣
   ├─ AuthNinja (JWT/OAuth/MFA)
   ├─ BizLogicHunter (IDOR/権限昇格)
   └─ (対応エージェントに自動振り分け)

4. Finding 生成
   └─ 成功した攻撃から Finding オブジェクト作成

5. AutoReporter レポート生成
   └─ reports/ にMarkdownファイル保存
```

#### Smell (匂い) タイプ

| Smell            | 説明                   | 推奨エージェント  |
| :--------------- | :--------------------- | :---------------- |
| `IDOR_CANDIDATE` | 連番 ID、UUID          | BizLogicHunter    |
| `JWT_PRESENT`    | JWT トークン検出       | AuthNinja (JWT)   |
| `OAUTH_FLOW`     | OAuth 関連リクエスト   | AuthNinja (OAuth) |
| `MFA_ENDPOINT`   | MFA 関連エンドポイント | AuthNinja (MFA)   |
| `HIDDEN_PARAM`   | 権限パラメータ         | BizLogicHunter    |
| `ADMIN_ENDPOINT` | 管理画面               | BizLogicHunter    |

---

### 2-3. Sentinel Mode (センチネル)

**目的**: GitHub リポジトリのリアルタイム監視とシークレット漏洩検出

```bash
python -m src.main --watch <OWNER/REPO>
```

#### 実行される処理

```
1. CommitWatcher 初期化
   └─ GitHub API 接続

2. 継続的ポーリング
   ├─ 新規コミット取得
   ├─ Diff 解析
   └─ シークレットパターンマッチング
       ├─ AWS Keys
       ├─ GCP/Azure Keys
       ├─ API Tokens (Stripe, Twilio等)
       ├─ Private Keys
       └─ etc.

3. Finding 生成 (検出時)
   └─ AutoReporter でレポート作成
```

#### 検出されるシークレット

| カテゴリ   | パターン例                        |
| :--------- | :-------------------------------- |
| **AWS**    | `AKIA[0-9A-Z]{16}`                |
| **GitHub** | `ghp_[a-zA-Z0-9]{36}`             |
| **Stripe** | `sk_live_[0-9a-zA-Z]{24}`         |
| **秘密鍵** | `-----BEGIN RSA PRIVATE KEY-----` |

---

### 2-4. Demo Mode (デモ)

**目的**: システム全体の動作確認

```bash
python -m src.main --demo
```

シミュレートされた脆弱性を使用して、RAG 初期化からレポート生成までの全パイプラインをテストします。

---

## 3. スコープ定義ガイド

### 基本構造

`scopes/target.yaml`:

```yaml
# プログラム情報
program:
  name: "Target Bug Bounty"
  platform: "hackerone" # hackerone / bugcrowd / other

# 許可リスト (IN SCOPE)
in_scope:
  domains:
    - "api.target.com"
    - "*.staging.target.com"
  ips:
    - "192.168.1.0/24"

# 禁止リスト (OUT OF SCOPE)
out_of_scope:
  domains:
    - "auth.target.com" # 認証サーバーは除外
    - "*.internal.target.com"
  paths:
    - "/logout"
    - "/api/*/delete"

# レート制限
rate_limit:
  requests_per_minute: 60
  cooldown_seconds: 10
```

### ワイルドカード記法

| パターン          | マッチ                               | 非マッチ          |
| :---------------- | :----------------------------------- | :---------------- |
| `example.com`     | `example.com`                        | `www.example.com` |
| `*.example.com`   | `api.example.com`, `www.example.com` | `example.com`     |
| `*.*.example.com` | `a.b.example.com`                    | `api.example.com` |

### ポート指定

```yaml
in_scope:
  domains:
    - "example.com:8080" # ポート8080のみ
    - "api.example.com" # デフォルトポート (80/443)
```

---

## 4. RAG ナレッジエンジニアリング

### Obsidian 連携

SHIGOKU は Obsidian Vault からナレッジを取得し、攻撃に活用します。

#### 設定

```bash
# 環境変数で設定
export OBSIDIAN_VAULT_PATH=~/Obsidian/Security

# またはCLIで指定
python -m src.main --vault ~/Obsidian/Security --demo
```

### メモの書き方ガイド

AI が効率的に検索できるメモの構造：

````markdown
---
title: JWT Algorithm None Attack
tags: [jwt, authentication, critical]
category: auth_bypass
---

# JWT Algorithm None Attack

## 概要

JWT の署名アルゴリズムを `none` に変更し、署名検証をバイパスする攻撃。

## 条件 (Prerequisite)

- サーバーがアルゴリズムを検証していない
- JWT ライブラリが `alg: none` を許可

## 攻撃手順 (Steps)

1. JWT を Base64 デコード
2. ヘッダーの `alg` を `none` に変更
3. 署名部分を削除または空文字に
4. 再エンコードしてリクエスト

## ペイロード例 (Payload)

```json
{ "alg": "none", "typ": "JWT" }
```
````

## 参考リンク

- https://portswigger.net/web-security/jwt/algorithm-confusion

````

### タグの活用

```yaml
tags:
  - jwt        # 認証技術
  - idor       # 脆弱性タイプ
  - critical   # 重要度
  - wordpress  # CMS
````

RAG クエリ時にタグでフィルタリングできます。

---

## 5. ROI 最適化戦略

### 時間対効果の最大化

#### 戦略 1: 深度より幅を優先（初期）

```yaml
# 最初は浅く広く
in_scope:
  domains:
    - "*.target.com"
```

```bash
# max_depth=2 で広くスキャン
CARTOGRAPHER_MAX_DEPTH=2 python -m src.main --recon https://target.com
```

#### 戦略 2: 高 ROI 領域の深掘り

API エンドポイントや管理画面を発見したら、その領域を集中攻撃：

```yaml
# APIに絞る
in_scope:
  domains:
    - "api.target.com"
out_of_scope:
  domains:
    - "www.target.com" # フロントエンドは除外
    - "static.target.com" # 静的ファイルは除外
```

#### 戦略 3: 認証済みスキャン

プロキシログは認証済み状態でブラウジングして取得：

1. ブラウザにプロキシ設定 (Burp/Caido)
2. ターゲットにログイン
3. 全機能を手動で操作
4. HAR/JSON をエクスポート
5. `--log` で解析

### 優先度付け

| 優先度   | ターゲット    | 理由                   |
| :------- | :------------ | :--------------------- |
| **最高** | APIs, GraphQL | ビジネスロジックが集中 |
| **高**   | 管理画面      | 権限昇格の可能性       |
| **中**   | ログイン/登録 | 認証バイパス候補       |
| **低**   | 静的ページ    | XSS 以外の発見は稀     |

---

## 6. レポート管理

### レポート出力先

```
reports/
├── 2024-01-15_jwt_algorithm_none_bypass.md
├── 2024-01-15_idor_user_profile_api.md
└── 2024-01-16_exposed_admin_panel.md
```

### レポート構造

```markdown
# [脆弱性タイトル]

## Summary

[概要]

## Severity

- Rating: Critical
- CVSS: 9.8
- CWE: CWE-327

## Description

[詳細説明]

## Steps to Reproduce

1. [手順 1]
2. [手順 2]

## Proof of Concept

[リクエスト/レスポンス]

## Impact

[影響]

## Remediation

[修正案]
```

### レポート編集

自動生成されたレポートは手動で編集可能です。提出前に以下を確認：

- [ ] タイトルが明確か
- [ ] 再現手順が具体的か
- [ ] 影響範囲が明記されているか
- [ ] スクリーンショット/動画を追加

---

## 7. ベストプラクティス

### Do (推奨)

1. **スコープファイルを必ず作成**: 事故防止の最重要ステップ
2. **手動調査を先に**: 質の高いプロキシログがハントの質を決める
3. **RAG を育てる**: 成功パターンを Obsidian に記録し、継続的に学習
4. **定期的に偵察**: 新規エンドポイントの追加を検知

### Don't (非推奨)

1. **スコープなしでの実行**: `EthicsGuard` は全ブロックモードになる
2. **深度 5 以上の一括クロール**: 時間・リソースの無駄、BAN のリスク
3. **レポートの無編集提出**: 自動生成は「たたき台」と考える
4. **複数ターゲットの同時実行**: 混乱・誤爆の原因
