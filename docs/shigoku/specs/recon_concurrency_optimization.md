---
task_id: SGK-2026-0158
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# 仕様書: Recon Pipeline 並列数制御の最適化

## 1. 概要

SHIGOKUのRecon Pipelineおよび個別ツール（naabu, nuclei）の並列実行数を最適化し、リソース消費（特にメモリ）を抑制しつつ、安定したスキャン動作を実現する。

## 2. 背景と目的

- **課題**: SHIGOKU側で並列タスク数を上げると、呼び出される各ツール（naabu/nuclei）も内部で独自のスレッドを生成するため、CPU/メモリへの負荷が指数関数的に増大し、環境によってはフリーズやクラッシュの原因となる。
- **目的**: SHIGOKU側の同時実行数と、ツール側の内部並列数のバランスを「設定ファイル（shigoku.yaml）」で一元管理し、適切に制御する。

## 3. 変更範囲

- `config/shigoku.yaml`: 設定項目の整備（threads / max_concurrent_tasks）
- `src/config.py`: 設定項目の読み込みと提供
- `src/tools/custom/nuclei.py`: Nuclei実行時の並列数指定 (`-c`) の実装
- `src/tools/custom/naabu.py`: Naabu実行時のスレッド数指定の実装
- `src/recon/pipeline.py`: Pipeline全体のセマフォ制御とデフォルト値の最適化
- `src/recon/parallel_tasks.py`: Naabu呼び出し箇所の最適化

## 4. 詳細挙動

### 4.1 設定の優先順位

1. `config/shigoku.yaml` の `scan.threads` を基本の「並列単位」とする。
2. ツール側の内部並列数（Nucleiの-c等）にはこの `threads` 値を直接渡す。
3. SHIGOKU側の同時実行プロセス数 (`max_concurrent_tasks`) は、OSのCPUコア数を目安とするが、設定ファイルで上書き可能にする。

### 4.2 ツール毎のパラメータ指定

- **Nuclei**:
  - `-c` (concurrency) に `settings.scan.threads` を指定。
  - 現在の `rate-limit` はそのまま維持。
- **Naabu**:
  - `-t` (threads) に `settings.scan.threads` を指定。
  - `-rate` は維持するが、スレッド数とのバランスを考慮。

## 5. 制約事項

- `EthicsGuard` のスコープチェックおよびレート制限ロジックを遵守すること。
- 既存の `-rate-limit` 設定と競合しないよう注意し、必要に応じて設定ファイルから取得する。

## 6. 重要事項

- 全てのメッセージ、プラン説明、ドキュメントは日本語で記述する。
- コードコメントも日本語とする。
