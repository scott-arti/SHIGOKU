---
task_id: SGK-2026-0338
doc_type: manual
status: active
parent_task_id: SGK-2026-0001
related_docs:
  - docs/shigoku/plans/done/2026-07-02_sgk-2026-0338_user-manual-and-internal-spec_plan.md
  - docs/shigoku/manuals/2026-07-02_sgk-2026-0337_detailed-command-reference.md
  - docs/shigoku/manuals/QUICK_START.md
  - docs/shigoku/manuals/USER_MANUAL.md
  - docs/shigoku/specs/2026-07-02_sgk-2026-0338_internal-architecture-and-dataflow-spec.md
title: SHIGOKU ユーザーマニュアル 2026-07 運用版
created_at: '2026-07-02'
updated_at: '2026-07-02'
tags:
  - shigoku
  - manual
  - operator
target: SHIGOKU operator workflow
---

# SHIGOKU ユーザーマニュアル 2026-07 運用版

この文書は、SHIGOKU を運用するユーザーが最初に読む現行版マニュアルです。詳細な全コマンド一覧は [`2026-07-02_sgk-2026-0337_detailed-command-reference.md`](2026-07-02_sgk-2026-0337_detailed-command-reference.md) を正本とし、このマニュアルでは「いつ、どのコマンドを、どの引数で使うか」をユースケース別に説明します。

## 1. 利用前提と安全ルール

SHIGOKU はバグバウンティ、許可済み脆弱性検証、CTF、検証環境向けの自動化フレームワークです。必ず自分が明示的に許可された対象にだけ使ってください。

- 本番 bug bounty では、プログラムの scope、rate limit、禁止行為、認証情報の扱いを先に確認します。
- `--cross-test-approved` はクロスアカウント検証が明示許可されている場合だけ使います。
- `--mode vulntest` や強い fuzzing は、自分の検証環境または明示許可された環境で使います。
- Cookie、Bearer token、API key はログやセッションに残り得るため、共有前に redaction 済みか確認します。

## 2. 初期設定

### 2.1 必要なもの

- Python 3.10 以上。
- Docker と Docker Compose v2。
- Git。
- 任意: OpenAI/LiteLLM 互換 API key、Caido token、GitHub token。
- 任意: 外部ツール検証用の wordlist ディレクトリ。

### 2.2 リポジトリと Python 環境

```bash
cd /path/to/Shigoku
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e .
```

`uv` を使う運用では、ロックファイルに合わせて同期します。

```bash
uv sync --frozen
```

### 2.3 環境変数と LLM 設定

LLM 設定の正本は `config/shigoku.yaml` の `llm:` セクションです。API key の生値は YAML に書かず、`api_key_env` で環境変数名を参照します。

```bash
export OPENAI_API_KEY="..."
export LITELLM_API_KEY="..."
export SHIGOKU_NEO4J_PASSWORD="..."
```

新規コードや運用では role ベースの設定を使います。内部的には `LLMClient(role="<role名>")` が role に紐づく provider/profile/system prompt を読みます。

### 2.4 初回確認

```bash
.venv/bin/python -m src.main --help
.venv/bin/shigoku-ops --help
```

`src.main` はスキャン・解析の実行入口、`shigoku-ops` は report/session/validate/gate などの運用確認入口です。

## 3. Docker での利用

### 3.1 サービス構成

`docker-compose.yml` は次のサービスを起動します。

| サービス | 役割 | 主なポート |
|---|---|---|
| `shigoku` | SHIGOKU 実行コンテナ | `network_mode: host` |
| `neo4j` | ナレッジグラフ | `7474`, `7687` |
| `chromadb` | RAG 用ベクトル DB | `8003 -> 8000` |

`shigoku` コンテナはリポジトリを `/app`、workspace を `/workspace` にマウントします。`/home/bbb/Documents/tools/wordlists:/wordlists:ro` はローカル環境依存のため、自分の環境に合わせて変更してください。

### 3.2 起動と確認

```bash
docker compose build shigoku
docker compose up -d neo4j chromadb
docker compose ps
```

接続確認:

```bash
curl http://localhost:8003/api/v1/heartbeat
```

Neo4j Browser は `http://localhost:7474` で開きます。認証情報は `docker-compose.yml` の `NEO4J_AUTH` と `SHIGOKU_NEO4J_PASSWORD` を確認してください。

### 3.3 Docker からコマンドを実行する

```bash
docker compose run --rm shigoku python3 -m src.main --help
docker compose run --rm shigoku python3 scripts/shigoku_ops_cli.py --help
```

例:

```bash
docker compose run --rm shigoku \
  python3 -m src.main \
  --mode bugbounty \
  --target https://example.com \
  --recon https://example.com \
  --format haddix-ja-en
```

## 4. モードとプロファイル

### 4.1 `--mode`

| mode | 想定用途 | 特徴 |
|---|---|---|
| `bugbounty` | 公開 bug bounty / 許可済み本番 | 安全寄り、scope と evidence 品質を重視 |
| `vulntest` | 自前検証環境 / 明示許可環境 | 検証深度を上げやすい |
| `ctf` | CTF / lab | 速度と探索を優先 |

### 4.2 `--profile`

| profile | 想定用途 |
|---|---|
| `bbpt` | Bug bounty penetration testing 寄りの標準運用 |
| `ctf` | CTF/lab 用の軽量・探索寄り運用 |

### 4.3 重要な制御オプション

| オプション | 用途 |
|---|---|
| `--dry-run` | 実行計画や対象確認だけ行い、危険な実行を避ける |
| `--debug` | 詳細ログを出す |
| `--skip-initial-recon` | 初期 recon をスキップする |
| `--recon-start-step` / `--recon-end-step` | recon の一部ステップだけ実行する |
| `--recon-resume` | `recon_state.json` から再開する |
| `--fast-iterate` | Step 6-8 へ寄せた高速反復モード |
| `--sessions-file` | 複数アカウント・セッション設定を読み込む |
| `--cross-test-approved` | クロスアカウント検証が許可済みであることを明示する |

## 5. 出力されるファイル

SHIGOKU の実行結果は主に `workspace/projects/<target>/` に保存されます。`<target>` は URL などから安全なプロジェクト名へ変換されます。

```text
workspace/projects/<target>/
├── meta.yaml
├── scans/
│   ├── raw/
│   └── filtered/
├── findings/
├── screenshots/
├── reports/
├── sessions/
│   ├── session_YYYYMMDD_HHMMSS.json
│   └── latest.json
└── hunting_log/
```

| パス | 内容 |
|---|---|
| `meta.yaml` | プロジェクトの対象、scope、作成日時など |
| `scans/raw/` | 外部ツールや recon の未加工出力 |
| `scans/filtered/` | 分類・整形済み出力 |
| `findings/*.json` | finding 単位の保存結果 |
| `screenshots/` | headless/browser 系の証跡画像 |
| `sessions/session_*.json` | 実行状態、タスク、coverage、finding 抽出元 |
| `sessions/latest.json` | 最新セッションへの固定名コピー |
| `reports/` | Markdown/JSON/HTML/PDF/Haddix などのユーザー向け成果物 |
| `hunting_log/` | 調査ログや補助メモ |

## 6. ユーザーが見るレポート

### 6.1 主要レポート

| レポート | 用途 |
|---|---|
| `haddix_report_*.md` | バグバウンティ提出やレビュー向けの主報告書 |
| `haddix_ja_en_*.md` | 日本語・英語併記の報告書 |
| `run_narrative.md` | 実行が何を行い、何をスキップし、どこで止まったかの時系列説明 |
| `target_profile.md` | 対象の技術・URL・面の概要 |
| `attack_paths.md` / `attack_paths.json` | finding や仮説を攻撃パスとして整理した成果物 |
| `session_*.json` | raw な実行証跡。レポート検証時の一次情報 |

### 6.2 レポート検証

レポートを読む前に、レポートと元セッションが一致しているか確認します。

```bash
python3 scripts/shigoku_ops_cli.py report consistency \
  --report /absolute/path/to/workspace/projects/<target>/reports/haddix_report_*.md
```

初期リリースゲートや品質確認:

```bash
python3 scripts/shigoku_ops_cli.py gate initial-release \
  --report /absolute/path/to/haddix_report_*.md
```

セッション内 finding の確認:

```bash
python3 scripts/shigoku_ops_cli.py session findings \
  --session /absolute/path/to/workspace/projects/<target>/sessions/latest.json
```

## 7. ユースケース別コマンド

### 7.1 まずヘルプと環境だけ確認したい

```bash
.venv/bin/python -m src.main --help
.venv/bin/shigoku-ops --help
```

`src.main` の全オプションは詳細コマンドリファレンスを参照します。

### 7.2 公開 bug bounty の初回 recon を走らせたい

```bash
.venv/bin/python -m src.main \
  --mode bugbounty \
  --profile bbpt \
  --target https://example.com \
  --recon https://example.com \
  --format haddix-ja-en
```

最初は `--dry-run` を付けて scope と実行計画だけ確認するのが安全です。

```bash
.venv/bin/python -m src.main \
  --mode bugbounty \
  --target https://example.com \
  --recon https://example.com \
  --dry-run
```

### 7.3 認証付き対象を検証したい

Cookie だけで足りる場合:

```bash
.venv/bin/python -m src.main \
  --mode bugbounty \
  --target https://app.example.com \
  --cookie "session=REDACTED; other=REDACTED" \
  --crawl \
  --crawl-depth standard \
  --analyze
```

Bearer token を使う場合:

```bash
.venv/bin/python -m src.main \
  --mode bugbounty \
  --target https://api.example.com \
  --bearer-token "REDACTED" \
  --analyze
```

複数アカウント検証は、プログラムで明示許可されている場合だけ実行します。

```bash
.venv/bin/python -m src.main \
  --target https://app.example.com \
  --sessions-file ./sessions.example.yaml \
  --cross-test-approved
```

### 7.4 recon の途中から再開したい

```bash
.venv/bin/python -m src.main \
  --target https://example.com \
  --recon https://example.com \
  --recon-resume
```

特定ステップだけ実行する場合:

```bash
.venv/bin/python -m src.main \
  --target https://example.com \
  --recon https://example.com \
  --recon-start-step 6 \
  --recon-end-step 8
```

高速反復:

```bash
.venv/bin/python -m src.main \
  --target https://example.com \
  --fast-iterate
```

### 7.5 Proxy / Caido ログを使ったハイブリッド解析

HAR やプロキシログを入力して解析します。

```bash
.venv/bin/python -m src.main \
  --log ./traffic.har \
  --target https://example.com \
  --mode bugbounty \
  --analyze
```

Caido 連携を使う場合は、`CAIDO_API_URL` と `CAIDO_API_TOKEN` を環境変数または設定で渡します。

### 7.6 Docker だけで一通り動かしたい

```bash
docker compose up -d neo4j chromadb
docker compose run --rm shigoku \
  python3 -m src.main \
  --mode bugbounty \
  --target https://example.com \
  --recon https://example.com
```

レポート確認も Docker 経由で行えます。

```bash
docker compose run --rm shigoku \
  python3 scripts/shigoku_ops_cli.py report consistency \
  --report /workspace/projects/example.com/reports/haddix_report_YYYYMMDD_HHMMSS.md
```

### 7.7 RAG に資料を入れて検索したい

```bash
.venv/bin/python -m src.main \
  --rag-ingest ./docs/security-notes \
  --rag-collection shigoku-notes
```

```bash
.venv/bin/python -m src.main \
  --rag-query "この対象で優先すべきIDOR観点は？" \
  --rag-collection shigoku-notes
```

### 7.8 レポートの品質を確認したい

```bash
REPORT=/absolute/path/to/workspace/projects/example.com/reports/haddix_report_YYYYMMDD_HHMMSS.md

python3 scripts/shigoku_ops_cli.py report consistency --report "$REPORT"
python3 scripts/shigoku_ops_cli.py gate initial-release --report "$REPORT"
```

整合性チェックが失敗した場合、そのレポートだけで結論を出さず、解決された `session_*.json` を確認します。

### 7.9 Attack Path と Target Profile を見たい

```bash
SESSION=/absolute/path/to/workspace/projects/example.com/sessions/latest.json

python3 scripts/shigoku_ops_cli.py report target-profile --session "$SESSION"
python3 scripts/shigoku_ops_cli.py report attack-paths --session "$SESSION"
python3 scripts/shigoku_ops_cli.py report narrative --session "$SESSION"
```

### 7.10 CTF / lab で軽く回したい

```bash
.venv/bin/python -m src.main \
  --mode ctf \
  --profile ctf \
  --target http://localhost:3000 \
  --crawl \
  --crawl-depth quick \
  --analyze
```

### 7.11 自前検証環境で fuzzing を有効にしたい

```bash
.venv/bin/python -m src.main \
  --mode vulntest \
  --target http://localhost:3000 \
  --fuzz \
  --openapi ./openapi.yaml \
  --format markdown
```

## 8. よくあるトラブル

### 8.1 ChromaDB に繋がらない

`docker-compose.yml` ではホスト側 `8003` へ公開されています。古い資料の `8001` と混同しないでください。

```bash
docker compose ps chromadb
curl http://localhost:8003/api/v1/heartbeat
```

### 8.2 レポートとセッションが一致しない

必ず consistency checker の結果を優先します。

```bash
python3 scripts/shigoku_ops_cli.py report consistency --report "$REPORT"
```

失敗時は、古い report と新しい session を混ぜて読んでいる、または source session が失われている可能性があります。

### 8.3 Docker の wordlist mount で失敗する

`docker-compose.yml` の `/home/bbb/Documents/tools/wordlists:/wordlists:ro` はローカルパス依存です。存在しない環境では自分の wordlist パスへ変更するか、その volume を一時的に外します。

### 8.4 どのコマンドを正本にすべきか迷う

- 実行: `.venv/bin/python -m src.main ...`
- 運用確認: `.venv/bin/shigoku-ops ...` または `python3 scripts/shigoku_ops_cli.py ...`
- 詳細な全引数: [`2026-07-02_sgk-2026-0337_detailed-command-reference.md`](2026-07-02_sgk-2026-0337_detailed-command-reference.md)

## 9. 次に読む文書

- 詳細コマンド: [`2026-07-02_sgk-2026-0337_detailed-command-reference.md`](2026-07-02_sgk-2026-0337_detailed-command-reference.md)
- 内部仕様: [`../specs/2026-07-02_sgk-2026-0338_internal-architecture-and-dataflow-spec.md`](../specs/2026-07-02_sgk-2026-0338_internal-architecture-and-dataflow-spec.md)
- クイックスタート: [`QUICK_START.md`](QUICK_START.md)
