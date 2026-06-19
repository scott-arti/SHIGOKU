---
task_id: SGK-2026-0002
doc_type: roadmap
doc_usage: reference_roadmap
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# 将来の機能拡張 (Future Functions)

このドキュメントは、今回の実装範囲外だが将来的に検討すべき機能をまとめたものです。

---

## 1. 並列実行（Parallel Execution）

**概要**: Swarm 内の Specialist を並列で実行し、処理速度を向上させる。

**現状**: マルチディスパッチ（直列）を採用。リソース消費・制御の複雑さから今回は見送り。

**将来の実装案**:

```python
# asyncio.Semaphoreで並列数を制御
async def dispatch_parallel(self, task: Task) -> SwarmResult:
    semaphore = asyncio.Semaphore(3)  # 同時3つまで

    async def run_with_limit(specialist):
        async with semaphore:
            return await specialist.execute_async(task.params)

    results = await asyncio.gather(
        *[run_with_limit(s) for s in specialists]
    )
    return SwarmResult(findings=flatten(results))
```

**検討事項**:

- ターゲットへの負荷（レート制限対策）
- LLM API 呼び出しの並列化（コスト・レート制限）
- エラーハンドリングの複雑化

---

## 2. KnowledgeGraph 連携

**概要**: Neo4j に保存された資産間の関係性を活用し、攻撃候補の推論を行う。

**現状**: Cartographer/Fingerprinting で保存はしているが、Attack Phase での活用が限定的。

**将来の活用案**:

```python
# MC側でSwarmにタスクを渡す前に攻撃候補を推論
candidates = kg.query("""
    MATCH (p:Page)-[:RUNS_ON]->(t:Technology)
    WHERE t.name = 'WordPress' AND t.version < '5.0'
    RETURN p.url as target, t.version
""")

for candidate in candidates:
    task = Task(agent_type="scanner_swarm", params={"target": candidate["target"]})
```

**実装ステップ**:

1. `get_attack_candidates()` メソッドの拡充
2. MC 初期化時に KnowledgeGraph を接続
3. Recon 完了後に推論結果をタスク生成に活用

---

## 3. リアルタイム Swarm 間共有（Event Bus）

**概要**: Swarm 内の Agent が発見した情報を、他の Swarm にリアルタイムで共有する。

**現状**: MC が Swarm 完了後に結果を受け取り、次のタスクを生成する形式。

**将来の実装案**:

```python
class SwarmBus:
    def publish(self, event_type: str, data: dict):
        for swarm in self.swarms:
            if event_type in swarm.subscribed_events:
                swarm.handle_event(event_type, data)

# DiscoverySwarm内
if self._is_login_page(url):
    self.bus.publish("login_page_found", {"url": url})

# AuthSwarm (subscribed_events = ["login_page_found"])
def handle_event(self, event_type, data):
    self.add_task(AuthTask(target=data["url"]))
```

**検討事項**:

- イベントの粒度（細かすぎるとノイズ、粗すぎると見逃し）
- 優先度管理（進行中タスクとの競合）

---

## 4. 学習ループの強化

**概要**: 成功したペイロードやバイパス手法を自動で Recipe 化し、次回の攻撃に活用。

**現状**: `LearningRepository`に成功パターンを保存する仕組みはあるが、Recipe への自動変換は未実装。

**将来の実装案**:

```python
# 成功時にRecipeを自動生成
if result.success and result.novel_technique:
    recipe = self._generate_recipe_from_result(result)
    self.recipe_loader.save_recipe(recipe)
```

---

## 5. Swarm Manager 高度化（判断ロジック）

**概要**: Swarm Manager が単なる直列実行ではなく、結果に基づいて動的に判断を行う。

**現状**: 直列で Specialist を実行し、結果を蓄積して返すのみ。

**将来の実装案**:

### 戦略選択

```python
class AuthManager:
    def dispatch(self, task):
        # 1. JWT がありそうか判断
        jwt_result = self.jwt_inspector.execute(task.params)

        # 2. JWT脆弱性あり → 他はスキップして即報告
        if jwt_result.has_critical_finding:
            return SwarmResult(findings=jwt_result.findings, early_exit=True)

        # 3. JWTなし → OAuthを試す
        oauth_result = self.oauth_dancer.execute(task.params)
        ...
```

### 動的調整

- 失敗率が高ければ撤退
- 成功があれば関連 Specialist をエスカレート
- タイムアウト前に切り上げて部分結果を返す

### リソース監視

- 各 Specialist の実行時間を計測
- Swarm 全体のタイムアウト前に残り時間を考慮して判断

---

## 6. Intelligence モジュール活用

**概要**: `src/core/intelligence/` の高度な分析・学習機能を Swarm Manager 判断に統合。

**現状**: 未統合。個別モジュールとして存在。

**対象モジュール**:

| モジュール            | 用途                  | 統合先            |
| --------------------- | --------------------- | ----------------- |
| `adaptive_fuzzer.py`  | 動的ペイロード調整    | InjectionSwarm    |
| `feedback_loop.py`    | 成功/失敗パターン学習 | 全 Swarm Manager  |
| `risk_predictor.py`   | 脆弱性確率予測        | MC (タスク優先度) |
| `self_reflection.py`  | 攻撃結果の自己評価    | Swarm Manager     |
| `priority_booster.py` | 優先度動的変更        | MC                |

---

## 7. セッション再認証フロー

**概要**: 長時間実行中にセッションが切れた場合の自動再認証。

**現状**: 未実装。AuthSwarm は情報収集のみで、POST 攻撃を伴う Swarm は少ない。

**将来の必要性**: LogicSwarm が POST リクエストを多用する場合、401 エラー時に再認証が必要。

**トリガー条件**:

- HTTP レスポンス 401 Unauthorized
- セッション有効期限切れメッセージ検出

---

## 8. Agentic RAG (Feedback Loop)

**概要**: RAG 検索結果の信頼性を評価し、不十分な場合にクエリを改善して再検索するループ。

**現状**: 未実装。単純なクエリのみ利用。

**将来の実装案**:

1. Swarm が RAG にクエリ
2. LLM が結果の有用性（Confidence Score）を評価
3. Score < 0.7 の場合、クエリをリライトして再検索（最大 n 回）
4. それでもダメなら、LLM 自身の知識ベースで代替（フォールバック）

```python
# 将来的なコードイメージ
for attempt in range(max_retries):
    results = rag.query(current_query)
    score = evaluate_usefulness(results, task_context)
    if score >= threshold:
        return results
    current_query = rewrite_query(current_query, feedback="too generic")
# fallback
return llm.generate_from_knowledge(task_context)
```

---

## 9. ロガー統合

**概要**: 既存の個別ロガー（`audit_logger.py`, `debug_logger.py`, `hunting_logger.py`）を中央集約ロガー（`src/core/logger.py`）へ統合。

**現状**: 中央集約ロガーを新規作成。既存ロガーは未統合。

**将来の作業**:

1. 各モジュールで使用されている既存ロガー呼び出しを特定
2. `from src.core.logger import logger` に置き換え
3. 既存ロガーファイルを廃止（または後方互換ラッパーに変換）

---

## 10. Dead サブドメインパス再利用

**概要**: Dead (NXDOMAIN/解決不可) サブドメインで発見されたパスを、Live サブドメインに適用して追加の攻撃面を発見。

**背景**: Dead サブドメインの URL パス (`/admin`, `/api/v2/users` など) は、同一組織の Live サブドメインでも存在する可能性が高い。

**将来の実装案**:

1. Recon 時に Dead サブドメインのパスを `dead_paths.txt` として保存
2. Live サブドメインに対して Dead パスを適用 (path bruteforce)
3. 200/403 レスポンスのパスをタグ付けして Swarm へ渡す

```python
# 将来的なコードイメージ
dead_paths = load_dead_paths()  # ["/admin", "/api/internal", ...]
for live_sub in live_subdomains:
    for path in dead_paths:
        url = f"https://{live_sub}{path}"
        resp = httpx.get(url)
        if resp.status_code in [200, 403]:
            tagged_urls.append((url, infer_tags(path, resp)))
```

**優先度**: 低（次期バージョン）

---

## 11. Phase 4B: 追加ツール統合

**概要**: Phase 4A で統合した主要ツール以外の Specialist ツール統合。

**Phase 4A (完了)**: sqlmap, tplmap, race_the_web, nuclei, naabu, jwt_tool, forbidden_bypasser, git_dumper, secret_finder

**Phase 4B (追加予定)**:

| Swarm          | ツール                      | 用途                          |
| -------------- | --------------------------- | ----------------------------- |
| InjectionSwarm | `nosql_exploit.py`          | NoSQL Injection               |
| InjectionSwarm | `xxeinjector.py`            | XXE                           |
| InjectionSwarm | `commix.py`                 | Command Injection             |
| AuthSwarm      | `hydra.py`                  | Brute Force                   |
| ScannerSwarm   | `nmap.py`                   | Port Scan / Service Detection |
| ScannerSwarm   | `nikto.py`                  | Web Server Scanner            |
| SecretSwarm    | `s3scanner.py`              | S3 Bucket Enumeration         |
| SecretSwarm    | `cloud_metadata_scanner.py` | Cloud Metadata Exposure       |

**優先度**: 中（Phase 4A 安定後）

- [ ] **Arjun Integration**: パラメータ探索エンジンの強化。Fuzz Faster U Fool - v2.1.0-dev

HTTP OPTIONS:
-H Header `"Name: Value"`, separated by colon. Multiple -H flags are accepted.
-X HTTP method to use
-b Cookie data `"NAME1=VALUE1; NAME2=VALUE2"` for copy as curl functionality.
-cc Client cert for authentication. Client key needs to be defined as well for this to work
-ck Client key for authentication. Client certificate needs to be defined as well for this to work
-d POST data
-http2 Use HTTP2 protocol (default: false)
-ignore-body Do not fetch the response content. (default: false)
-r Follow redirects (default: false)
-raw Do not encode URI (default: false)
-recursion Scan recursively. Only FUZZ keyword is supported, and URL (-u) has to end in it. (default: false)
-recursion-depth Maximum recursion depth. (default: 0)
-recursion-strategy Recursion strategy: "default" for a redirect based, and "greedy" to recurse on all matches (default: default)
-replay-proxy Replay matched requests using this proxy.
-sni Target TLS SNI, does not support FUZZ keyword
-spoof-ip Spoof IP address via headers (default: false)
-timeout HTTP request timeout in seconds. (default: 10)
-u Target URL
-ua-rotate Rotate User-Agent header (default: false)
-x Proxy URL (SOCKS5 or HTTP). For example: http://127.0.0.1:8080 or socks5://127.0.0.1:8080

GENERAL OPTIONS:
-V Show version information. (default: false)
-ac Automatically calibrate filtering options (default: false)
-acc Custom auto-calibration string. Can be used multiple times. Implies -ac
-ach Per host autocalibration (default: false)
-ack Autocalibration keyword (default: FUZZ)
-acs Custom auto-calibration strategies. Can be used multiple times. Implies -ac
-ai Enable AI features (default: false)
-ai-endpoint AI API Endpoint
-ai-key AI API Key
-ai-model AI Model (default: gpt-3.5-turbo)
-ai-provider AI Provider (openai, ollama) (default: openai)
-c Colorize output. (default: false)
-config Load configuration from a file
-json JSON output, printing newline-delimited JSON records (default: false)
-maxtime Maximum running time in seconds for entire process. (default: 0)
-maxtime-job Maximum running time in seconds per job. (default: 0)
-noninteractive Disable the interactive console functionality (default: false)
-p Seconds of `delay` between requests, or a range of random delay. For example "0.1" or "0.1-2.0"
-rate Rate of requests per second (default: 0)
-runner-type Runner type: simple (default) or fast
-s Do not print additional information (silent mode) (default: false)
-sa Stop on all error cases. Implies -sf and -se. (default: false)
-scraperfile Custom scraper file path
-scrapers Active scraper groups (default: all)
-se Stop on spurious errors (default: false)
-search Search for a FFUFHASH payload from ffuf history
-sf Stop when > 95% of responses return 403 Forbidden (default: false)
-t Number of concurrent threads. (default: 40)
-v Verbose output, printing full URL and redirect location (if any) with the results. (default: false)

MATCHER OPTIONS:
-mc Match HTTP status codes, or "all" for everything. (default: 200-299,301,302,307,401,403,405,500)
-ml Match amount of lines in response
-mmode Matcher set operator. Either of: and, or (default: or)
-mr Match regexp
-ms Match HTTP response size
-mt Match how many milliseconds to the first response byte, either greater or less than. EG: >100 or <100
-mw Match amount of words in response

FILTER OPTIONS:
-fc Filter HTTP status codes from response. Comma separated list of codes and ranges
-fl Filter by amount of lines in response. Comma separated list of line counts and ranges
-fmode Filter set operator. Either of: and, or (default: or)
-fr Filter regexp
-fs Filter HTTP response size. Comma separated list of sizes and ranges
-ft Filter by number of milliseconds to the first response byte, either greater or less than. EG: >100 or <100
-fw Filter by amount of words in response. Comma separated list of word counts and ranges

INPUT OPTIONS:
-D DirSearch wordlist compatibility mode. Used in conjunction with -e flag. (default: false)
-e Comma separated list of extensions. Extends FUZZ keyword.
-enc Encoders for keywords, eg. 'FUZZ:urlencode b64encode'
-ic Ignore wordlist comments (default: false)
-input-cmd Command producing the input. --input-num is required when using this input method. Overrides -w.
-input-num Number of inputs to test. Used in conjunction with --input-cmd. (default: 100)
-input-shell Shell to be used for running command
-mode Multi-wordlist operation mode. Available modes: clusterbomb, pitchfork, sniper (default: clusterbomb)
-request File containing the raw http request
-request-proto Protocol to use along with raw request (default: https)
-w Wordlist file path and (optional) keyword separated by colon. eg. '/path/to/wordlist:KEYWORD'

OUTPUT OPTIONS:
-audit-log Write audit log containing all requests, responses and config
-debug-log Write all of the internal logging to the specified file.
-o Write output to file
-od Directory path to store matched results to.
-of Output file format. Available formats: json, ejson, html, md, csv, ecsv (or, 'all' for all formats) (default: json)
-or Don't create the output file if we don't have results (default: false)

EXAMPLE USAGE:
Fuzz file paths from wordlist.txt, match all responses but filter out those with content-size 42.
Colored, verbose output.
ffuf -w wordlist.txt -u https://example.org/FUZZ -mc all -fs 42 -c -v

Fuzz Host-header, match HTTP 200 responses.
ffuf -w hosts.txt -u https://example.org/ -H "Host: FUZZ" -mc 200

Fuzz POST JSON data. Match all responses not containing text "error".
ffuf -w entries.txt -u https://example.org/ -X POST -H "Content-Type: application/json" \
 -d '{"name": "FUZZ", "anotherkey": "anothervalue"}' -fr "error"

Fuzz multiple locations. Match only responses reflecting the value of "VAL" keyword. Colored.
ffuf -w params.txt:PARAM -w values.txt:VAL -u https://example.org/?PARAM=VAL -mr "VAL" -c

More information and examples: https://github.com/ffuf/ffuf よりも高度なヒューリスティック探索のため、Arjun との連携またはロジック移植を行う。

## 12. OOB検知の強化

- 現状OOBはローカル環境で検知する仕組みになっているが、将来的にはInteractshのような外部サービスを活用する仕組みを検討する。
