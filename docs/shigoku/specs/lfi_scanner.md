---
task_id: SGK-2026-0134
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# LFI / Path Traversal Scanner v2 (Smart LFI Hunter) Specification

## 1. 概要 (Overview)

SHIGOKUのインジェクション防御網の中核として、AIの推論能力を活用した「Smart LFI Hunter」を実装します。単なるリスト攻撃ではなく、ターゲットのOS、サーバースタック、WAFの挙動、そしてKatana等の偵察データを統合・推論し、最小限のリクエストで最大の結果（任意ファイル読み取り・RCEへの道筋）を導き出します。

## 2. 変更範囲 (Scope of Changes)

### 2.1 Core 攻撃ロジック (`src/core/attack/lfi_tester.py`)

- **動的ペイロード生成エンジン**: 固定のワードリストに頼らず、ターゲットのURL階層の深さに応じて `../` を動的に生成。
- **ヒューリスティックOS判定**: レスポンスヘッダ（`Server`, `X-Powered-By`）や既知のパスパターンから、ターゲットOSを確率的に特定。
- **非同期・並列実行**: `AsyncNetworkClient` を活用し、複数のバイパスパターンを効率的に試行。

### 2.2 SmartLFIHunter Specialist (`src/core/agents/swarm/injection/smart_lfi.py`)

- **ThoughtLoop 搭載**: LLM（デフォルト: DeepSeek/Gemini）による「観察 → 推論 → 攻撃」の思考ループを実装。
- **文脈適応型バイパス**: 403/406等の拒絶レスポンスを解析し、「URLエンコードが必要か」「Nullバイト注入が効くか」をLLMが自律的に判断。
- **攻撃チェインの布石**: LFI成功時に「ログポイズニングが可能か」「既存のアップロード済みファイルが踏み台にできるか」をエビデンスとして記録。

### 2.3 Injection Manager (`src/core/agents/swarm/injection/manager.py`)

- **LFI検知の高度化**: `?page=`, `?file=`, `?path=` に加え、エンコードされたパスや、過去に発見された（`learned_params.txt`）疑わしいパラメータを自動検知対象に追加。
- **SmartLFIHunter への委譲**: 骨組みだけだったLFIチェックを、新設する `SmartLFIHunter` に紐付け。

## 3. 挙動 (Behavior)

### フェーズ1: 観察と最適化 (Core Intelligence)

1. **Probeリクエスト**: 通常のファイル指定を投げ、レスポンスの挙動（200 OK, 404, 500, etc.）を確認。
2. **OS/言語推測**: ヘッダからスタックを特定。「Linux/PHPなら `php://filter` カテゴリを最優先」といったスコアリング。

### フェーズ2: 推論ループ (The Brain)

1. **LLM推論**: 基礎攻撃が弾かれた場合、LLMが「フィルタリングの種類」を予測。
2. **戦略変更**: `..%252f` (Double Encode) や `....//` (Filter bypass) など、最も成功確率の高い変種を生成して実行。

### フェーズ3: 結果の Finding 化と次への布石

1. **証拠収集**: 漏洩したファイルの一部（`/etc/passwd` の root エントリ等）を Evidence として確保。
2. **チェイン準備**: システムパスが判明した場合、Shared Workspace に情報を書き戻し、後続の RCE タスク（ログポイズニング等）にコンテキストを繋ぐ。

## 4. 制約と安全性 (Constraints & Safety)

- **EthicsGuard 準拠**: すべてのリクエストは `EthicsGuard.check_scope()` を通過させる。
- **非破壊**: 対象ファイルの読み取り（Read）に限定し、OSコマンド実行はその後の RCE 専任エージェントに任せる。
- **Rate Limit**: `AdaptiveRateLimiter` を尊重し、WAFによるIP BANを回避する。
