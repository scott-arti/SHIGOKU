---
task_id: SGK-2026-0108
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# SmartCmdSSRFHunter Phase 3 仕様書

## 概要

Phase 2 で構築した `SmartCmdSSRFHunter` の基盤（LLM ThoughtLoop + OOB + 破壊コマンドブロック）を **実戦レベル** に引き上げる。
主に以下の3つの課題を解決する。

| #   | 課題              | 現状                              | Phase 3 目標                               |
| --- | ----------------- | --------------------------------- | ------------------------------------------ |
| 1   | 手数不足          | 1ターン=1ペイロード、max_turns=10 | FfufToolで数千件バルク投入 → OOBポーリング |
| 2   | Exa MCP スタブ    | `search_exploit` がモック         | MCPClient経由で実際にExa検索               |
| 3   | Blind SSRF 未対応 | ssrf_probeはレスポンス目視のみ    | InteractSHを用いたOOBコールバック          |

---

## 変更範囲

### 修正ファイル

| ファイル                                            | 変更内容                                                         |
| --------------------------------------------------- | ---------------------------------------------------------------- |
| `src/core/agents/swarm/injection/smart_cmd_ssrf.py` | `cmd_fuzz`, `ssrf_oob` アクション追加 / `search_exploit` 本実装  |
| `src/core/agents/swarm/injection/manager.py`        | 軽微: wordlist パス設定の受け渡し                                |
| `src/tools/oob/interactsh_client.py`                | `generate_payload()` メソッド追加（OOBドメイン埋め込みヘルパー） |

### 新規ファイル

| ファイル                                           | 内容                                                          |
| -------------------------------------------------- | ------------------------------------------------------------- |
| `src/core/agents/swarm/injection/cmd_wordlists.py` | CMD/SSRF ペイロードリスト + OOBドメイン埋め込みユーティリティ |

---

## 挙動 (Input / Output)

### 1. `cmd_fuzz` アクション（バルクファジング）

**目的**: LLMの1ターン消費で数百件のペイロードを一括投入する。

**Process**:

1. LLMが `cmd_fuzz` を選択し、`{"category": "basic|blind_oob|waf_bypass"}` を指示。
2. Hunter が `cmd_wordlists.py` から該当カテゴリのペイロードリストを取得。
3. OOBペイロードの場合、`{{OOB_DOMAIN}}` を実際のInteractSHドメインに置換。
4. 一時ワードリストファイルを `/tmp/` に書き出し。
5. `FfufTool.run()` を同期呼び出し（`url=ターゲットURL&param=FUZZ`, `wordlist=一時ファイル`）。
6. FFUFの出力をパースし、ステータスコードやレスポンスサイズの異常を観測結果として返す。
7. OOBカテゴリの場合、追加で `InteractshOOBClient.poll()` を実行し、コールバック有無を確認。

**Input**: `{"category": "basic|blind_oob|waf_bypass"}`
**Output**: `"SUCCESS: 3/200 payloads triggered anomalous responses. OOB: 1 hit."` 等。

### 2. `ssrf_oob` アクション（Blind SSRF用OOB検知）

**目的**: レスポンスに何も現れないSSRFを、OOBコールバック（DNS/HTTP）で確実に検知する。

**Process**:

1. LLM が `ssrf_oob` を選択し、`{"template": "http://{{OOB_DOMAIN}}/ssrf-test"}` を指示。
2. `{{OOB_DOMAIN}}` をInteractSHドメインに置換。
3. ターゲットパラメータに注入してリクエスト送信。
4. 待機後 `poll()` でDNS/HTTPコールバックを確認。

**Input**: `{"template": "http://{{OOB_DOMAIN}}/ssrf-test"}`
**Output**: `"SUCCESS: Received 1 OOB interactions (HTTP callback on /ssrf-test)!"` 等。

### 3. `search_exploit` アクション（Exa MCP本実装）

**目的**: 特定技術を検知した際に、最新のExploit PoCを動的検索する。

**Process**:

1. LLM が `search_exploit` を選択し、`{"tech": "Apache ActiveMQ 5.15.0"}` を指示。
2. `MCPClient` 経由で Exa MCP サーバーの `search` ツールを呼び出し。
3. 検索結果（タイトル + URL + スニペット）をLLMに返却。
4. LLMがPoCを解析し、次のターンで `cmd_probe` 等のアクションとしてペイロードを生成。

**Input**: `{"tech": "Apache ActiveMQ 5.15.0"}`
**Output**: `"Found 3 results: [1] CVE-2023-46604 RCE PoC (github.com/...) ..."` 等。

---

## 制約

1. **EthicsGuard遵守**: 全リクエストはスコープ内であること。
2. **破壊コマンド禁止**: `cmd_fuzz` で使用するワードリストにも `BLOCKED_COMMANDS` チェックを適用。
3. **Exa API 制限**: 1セッション中の `search_exploit` 呼び出しは最大3回。キャッシュ機構で重複防止。
4. **一時ファイル管理**: `/tmp/shigoku_fuzz_*` は実行後に即時削除。
5. **FFUFの同期実行**: `FfufTool.run()` は `subprocess.run` であるため、`asyncio.to_thread()` でラップして非同期化。

---

## テスト計画

| テスト                       | 検証内容                                                 |
| ---------------------------- | -------------------------------------------------------- |
| `test_cmd_fuzz_basic`        | ワードリスト生成 → FFUF呼び出し → 結果パースの一連フロー |
| `test_cmd_fuzz_oob`          | OOBペイロード埋め込み → poll → ヒット検知                |
| `test_ssrf_oob`              | ssrf_oob アクション→ InteractSH poll → 検知              |
| `test_search_exploit_mcp`    | MCPClient.call_tool のモック → 結果フォーマット          |
| `test_search_exploit_cache`  | 同じ tech で2回呼び出し → 2回目はキャッシュヒット        |
| `test_fuzz_blocked_commands` | ワードリスト内の危険コマンドがフィルタされること         |
