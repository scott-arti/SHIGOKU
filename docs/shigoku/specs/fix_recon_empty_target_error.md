---
task_id: SGK-2026-0124
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# Spec: Recon Pipeline 空ターゲットガードの実装

## 概要

Recon Pipeline において、生存サブドメイン（live_subs）が0件の場合に `naabu` や `httpx` などの外部ツールが空の入力ファイルで実行され、エラー（Exit Code 1）を発生させる問題を修正する。

## 変更範囲

- `src/recon/pipeline.py`
  - `step3b_hybrid_url_discovery`
  - `step4_waf_detection`
  - `step5_port_scan_phase1`

## 挙動

- 対象となるリスト（`live_subs` 等）が空の場合、ログに警告を出力し、空の結果（辞書またはリスト）を即座に返す。
- 外部ツールの実行（`self.runner.run` 等）をスキップする。

## 制約

- 既存のエラーハンドリング（`ToolNotFoundError` 等）との整合性を保つ。
- `ReconState` の更新は適切に行い、後続のステップで不整合が起きないようにする。

## 期待される結果

- ターゲットが解決不能で生存ホストが0件の場合でも、パイプラインがクラッシュしたり、エラーログで埋め尽くされたりせずに正常に（あるいは「結果なし」として）終了する。
