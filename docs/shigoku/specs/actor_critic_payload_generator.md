---
name: llm-actor-critic-fuzzer
description: LLMをCritic/Generatorとして用いたコンテキスト節約型・動的Fuzzingシステム
status: active
task_id: SGK-2026-0102
doc_type: spec
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# LLM Actor-Critic Fuzzing Loop 仕様書

## 1. 概要

世界トップのBug Bountyハンターの手法（大量のFuzzing結果からWAFのルールを推測し、ペイロードを洗練させる）をAIエージェントで再現する。
完全な機械学習（RL）ではなく、**「LLM（Critic / Generator）」と「軽量Pythonツール（Prober）」の三位一体**のループ構造を採用する。
これにより、LLMのコンテキスト肥大化を防ぎつつ、高度な推論と大量の試行を両立する。

## 2. 新アーキテクチャの役割と工夫点

### A. Prober (Pythonツール - 実行と集計)

- **役割**: Generatorが作ったペイロードリスト（例: 50~100個）をターゲットに高速送信する。
- **工夫点（コンテキスト節約・並列化）**:
  - **Fuzzingエンジンの並列化**: `asyncio.gather` 等を用いて非同期でフルスピードでリクエストを送信する。
  - 生のHTMLレスポンスは**絶対にLLMに返さない**。
  - レスポンスの「ステータスコード」「Body長」「特定のパターンの有無」のみを抽出し、**統計・要約データ**としてCriticに渡す。
  - 大量に同じ結果（例: 全て403）が出た場合は、それらをグループ化して1行にまとめる。

### B. Critic (LLM - 評価と推理)

- **役割**: Proberの要約データを見て、「ターゲットの防壁（WAFやフィルタ）の性質」と「反射コンテキスト」を推理する。
- **工夫点（深い推論とコンテキスト静的評価）**:
  - `403` になったペイロードと、`200` だが無害化されたペイロード、`500` になったペイロードを見比べ、「どの文字やキーワードがブロックトリガーになっているか」を論理的に分析する。
  - **ベースライン比較 (Diff Analysis) の厳密化**: 「ペイロードを入れない普通の正常なリクエスト（Baseline）」のレスポンスと、「攻撃時のレスポンス」の差分（Diff）を計算し、「何文字減ったか」「どの単語が消えたか」だけを要約してLLMに報告する仕組みを用いる。
  - **反射コンテキストの静的評価**: 事前に無害なカナリア文字列（例: `shigoku123`）を送信し、「反射した場所の構造（例: HTML属性値の中）」を特定。そのコンテキストに応じた脱出推論（エスケープ手法など）を決定する。

### C. Generator (LLM - 次の手の生成)

- **役割**: Criticの推論に基づき、防壁をすり抜けるための**新しいペイロードのリスト**を生成する。
- **工夫点（変異戦略の指定）**:
  - 単にランダムに作るのではなく、「大文字・小文字を混ぜる」「URLエンコードする」「特定の文字を置換する」などの「変異戦略」を意識して生成する。

### D. PlaywrightValidator (動的バリデーション)

- **役割**: Critic層が有望と判断したペイロードについて、実際のブラウザでJavaScriptが発火（実行）するかを最終確認する。
- **工夫点（動的評価）**:
  - WAFを抜けたペイロードが、実際にブラウザ上で発火するか（例: 別のJSエラーで処理が止まっていないか、CSPで弾かれていないか等）をPlaywrightで検証する。
  - `console.log('SHIGOKU_XSS_SUCCESS')` のようなスクリプトを生成させ、確実に裏側でキャッチできるかをチェックし、その結果をAIフレームワークのループにフィードバックする。

## 3. 実装の工夫とベストプラクティス（Best Approach）

既存の仕組みにより効果的に組み込むための工夫です。

1. **AIの成長サイクルへの組み込み**:
   結果に基づくフィードバックをループで学習させる。
   - **403弾き**: 「タグや文字を変異・難読化する」方向への指示。
   - **200（無害化）**: 「エンコードや別ルート」方向への指示。
   - **Playwright発火失敗**: 「タグの閉じ方・エスケープの修正」方向への指示。
   - **Console.log成功**: エクスプロイト完成。

2. **既存システムとの緩やかな統合 (Fallback Mechanism)**:
   - 既存の `smart_xss.py` 等の「フォールバック（行き詰まったときの必殺技）」としての組み込み。既存のエージェントが「決め打ち」のペイロードで失敗した場合に、このActor-Critic Fuzzing Loopを呼び出す。

## 4. ワークフローフロー図

```mermaid
sequenceDiagram
    participant Main as Existing Agent<br>(smart_xss etc)
    participant Loop as Actor-Critic Loop<br>(Coordinator)
    participant Gen as Generator AI
    participant Prober as Async HTTP Prober
    participant Critic as Critic AI
    participant Playwright as Browser Validator

    Main->>Loop: 発見できず。<br>深掘り検証を依頼
    Loop->>Prober: カナリア文字列を送信(コンテキスト調査)
    Prober-->>Loop: 反射コンテキスト情報
    loop Max N Iterations
        Loop->>Gen: 分析結果(過去の推論 + コンテキスト情報)<br>とターゲット情報を渡す
        Gen->>Loop: 50~100個の変異ペイロードリスト生成
        Loop->>Prober: 非同期(asyncio.gather)でリストを実行
        Prober->>Loop: ベースラインとのDiffを計算し、<br>結果をグループ化して要約
        Loop->>Critic: 要約データを分析依頼
        Critic->>Loop: WAFのフィルタ規則の推測と<br>次の戦略を提示

        opt 有望なペイロードを発見
            Loop->>Playwright: ブラウザでJS発火検証 (console.log)
            Playwright-->>Loop: 検証結果 (Triggered / Failed)
            Loop->>Critic: 動的検証結果をフィードバック
        end

        opt Success Condition Met
            Loop-->>Main: 成功したペイロードを返却
        end
    end
    Loop-->>Main: タイムアウト / 失敗
```
