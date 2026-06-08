---
task_id: SGK-2026-0168
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Spec: XSS Hunter Workflow & Tool Integration Improvements

## 概要 (Overview)

SHIGOKUのXSS（クロスサイトスクリプティング）をはじめとするInjection系脆弱性検出の精度と効率を劇的に向上させるため、Katanaによるフォーム検出機能の活用、MasterConductorでの的確なルーティング、およびSmartXSSHunterでのPlaywrightベースの解析へとアーキテクチャを刷新します。また、情報収集ツールであるVisual Reconの責務を純化し、分類不能（Uncategorized）なエンドポイントによる無駄なブラウザスキャンを防ぎます。

## 変更範囲 (Scope)

以下のファイルが主な変更の対象となります：

1. `src/tools/custom/katana.py`
2. `src/recon/pipeline.py` (抽出・変換ロジック)
3. `src/core/models/url_context.py`
4. `src/core/intel/tagging_filter.py`
5. `config/tagging_rules.yaml`
6. `src/core/engine/master_conductor.py`
7. `src/core/agents/swarm/discovery/visual_recon.py`
8. `src/core/agents/swarm/injection/smart_xss.py`

## 挙動 (Behavior)

### 1. メタデータ抽出とコンテキストの拡充 (Katana & Tagger)

- **変更内容**: Katanaのクロール時に `-form-extraction` オプションを有効にし、JSONL出力から `forms` オブジェクト（action, method, parameters）を手続き（Pythonコード）的に抽出します。
- **変更内容**: 抽出された詳細なフォーム情報を `RichUrlContext` (モデル)に持たせ、TaggingFilterでフォームが存在することをルールマッチングに利用できるようにします。

### 2. ルーティングの最適化 (MasterConductor & TaggingRules)

- **変更内容**: フォームを持つURLやGETパラメータを持つURLを確実に `xss_candidate` もしくは同等のInjection候補としてタグ付けし、自動的に `Injection Manager` 経由で `SmartXSSHunter` などにアサインされるように `tagging_rules.yaml` を改良します。
- **変更内容**: `uncategorized`（分類不能）と判定されたエンドポイントについては、攻撃対象（アタックサーフェス）がないとみなし、`Injection Manager` へのルーティング対象から除外します。

### 3. Visual Recon の責務の純化

- **変更内容**: `VisualRecon` ツールが無理にフォームを探して `run_xss_hunter` 等の攻撃用エージェントやツールを直接呼び出す（越権行為）ロジック・プロンプト指示を完全に削除します。
- **期待される結果**: `VisualRecon` は本来の「純粋な視覚的情報収集（スクリーンショット取得、静的エラー確認、UI露出の機密情報チェックなど）」のみに特化し、無駄な処理時間を削減します。

### 4. SmartXSSHunter の高度化 (Playwright)

- **変更内容**: `SmartXSSHunter` が対象URLにアクセスして手探りで解析を行うプロセスを廃止し、Katanaから引き継いだメタデータ（action, HTTPメソッド, 対象となる複数の入力パラメータ）を起点として、一撃必殺で精密に最適化されたペイロードを生成するよう改修します。
- **変更内容**: 発火の確認やフォームの送信には、すでにSHIGOKUに存在する `PlaywrightValidator` 等の強力なPlaywright基盤を活用するか、専用のPlaywrightロジックを実装し、モダンなSPAや動的DOM環境でも確実なXSS検証を行えるようにします。

## 制約 (Constraints)

- **EthicsGuardとの整合性**: いかなる変更も `EthicsGuard` プロトコル（対象スコープの制限順守、レートリミット等）の制約下で行われます。
- **実装順序（Order of Operations）**: `shigoku-architecture` ルールに従い、Core（共通データモデル `url_context.py` や抽出ロジック）→ Dependent Modules（MasterConductorルーティング, `tagging_rules.yaml`）→ Entry/Agents（SmartXSSHunter, VisualRecon）の順序で実装を進めます。
