---
task_id: SGK-2026-0038
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-06-19'
---

# GAUIntegrator

**現行モジュールパス**

- `src/core/wordlist/gau_integrator.py`

## 概要

GAUIntegrator は GAU の URL 収集結果を統計要約へ変換し、ワードリスト選択や AI 判断に渡す補助モジュールです。

## 現行の主要構成

- `GAUIntegrator`
- `get_gau_integrator()`

## 現行仕様

- `GauAdapter` と external executor を利用して URL を取得する
- URL 一覧そのものではなく、`top_paths` `top_extensions` `top_params` などの軽量サマリーを返す
- recommendation として `api` `graphql` `php` `admin` などを返す

## 主要メソッド

- `fetch_urls()`
- `analyze_patterns()`
- `_generate_recommendations()`
- `get_summary_for_ai()`

## 注意点

- 旧仕様書の詳細な出力例は現行コードに依存するため固定しない
- 主用途は「受動 URL 収集の統計要約」であり、単独の crawling engine ではない
