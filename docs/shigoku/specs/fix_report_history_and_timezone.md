---
name: fix-report-history-and-timezone
description: Fixes broken history links in HTML reports and ensures all timestamps
  are displayed in JST.
task_id: SGK-2026-0125
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Report History & Timezone Fix Spec

## 1. 概要 (Overview)

HTMLレポート (`latest.html`) の "History" タブにおいて、リンク先の過去レポート (`report_*.html`) が存在しないために 404 エラーが発生する問題を解消します。
また、レポート内の時刻表示がシステム時刻（多くの場合UTC）のままとなっているため、これを明示的に日本時間 (JST) に変換して表示するようにします。

## 2. 変更範囲 (Scope of Changes)

- **Target File**: `src/reports/html_generator.py`

## 3. 詳細な挙動 (Detailed Behavior)

### A. History レポートの自動生成 (Auto-generation of Missing Reports)

現状では、`latest.html` は過去の `session_*.json` のファイル名だけを見てリンクを作成していますが、実体の HTML ファイルを作っていません。

**変更後:**

1. レポート生成処理 (`generate_report_from_file`) が走った際、同じディレクトリ内の全ての `session_*.json` をスキャンします。
2. 各セッションファイルに対応する `report_*.html` が存在するか確認します。
3. **存在しない場合、その場で `HTMLReportGenerator` を使用して HTML を生成保存します。**
4. History タブのリンクは、これら生成済みの HTML ファイルを指すようになります。

### B. JST (日本時間) への統一 (Timezone Correction)

Docker コンテナ環境等で UTC となっているタイムスタンプを JST に変換します。

**変更後:**

1. ファイルの更新日時 (`st_mtime`) や JSON 内の `start_time` を取得する際、`datetime` オブジェクトを Timezone Aware な状態にします。
2. 固定で `UTC+9` (Asia/Tokyo) に変換してから文字列化 (`YYYY-MM-DD HH:MM`) します。
3. これにより、いつ実行しても、どこで実行しても、レポート上は「日本時間」で表示されます。

## 4. 影響と制約 (Impact & Constraints)

- **パフォーマンス**: 過去のログが大量（数十件以上）にある場合、初回の `latest.html` 生成時に一括変換が走るため、数秒〜十数秒の時間がかかる可能性があります。
  - _緩和策_: すでに `report_*.html` がある場合はスキップします。
- **依存関係**: 新たな外部ライブラリ (`pytz` 等) は導入せず、標準の `datetime.timezone` を使用します。
