---
task_id: SGK-2026-0111
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# 仕様書: CPUバウンド処理のオフロード

## 概要

SHIGOKUのイベントループが、巨大なデータのパースや複雑な正規表現マッチングによってブロッキングされる問題を解決します。
計算負荷の高い処理を `asyncio.to_thread` を用いて別スレッドで実行し、ネットワークI/Oの停止を防ぎます。

## 背景

JavaScriptの解析（数十個の正規表現実行）や、大量のURLリストに基づくアプリ機能分析は、ファイルサイズやデータ数に比例してメインスレッドを占有します。これにより、並列スキャンの効率が著しく低下し、タイムアウトや応答遅延の原因となっています。

## 変更対象

1. **src/core/intel/js_analyzer.py**
   - `analyze` メソッド等のオフロード
   - `re.compile` による正規表現の最適化
2. **src/core/intel/app_analyzer.py**
   - `detect_functions`, `classify_app`, `assess_vulnerability` 等のオフロード
   - `re.compile` による正規表現の最適化
3. **src/core/intelligence/error_analyzer.py**
   - `_categorize` 等の正規表現マッチングの最適化
   - `analyze_async` ラッパーの追加
4. **src/core/intelligence/self_reflection.py**
   - `reflect` メソッドのオフロード

## 実装方針

- 既存の同期メソッドはそのまま維持し、`_async` サフィックスを付けた非同期ラッパーを追加する。
- `asyncio.to_thread` を使用して、Python 3.9以降の標準的なスレッドオフロードを実装する。
- 正規表現パターンはクラス初期化時またはビルド時に `re.compile` しておく。

## 制約

- `EthicsGuard` のスコープチェックなど、安全に関わるロジックをバイパスしないこと。
- スレッドセーフでない状態操作（共有インスタンス変数の書き換え）が解析中に発生しないか確認すること。
