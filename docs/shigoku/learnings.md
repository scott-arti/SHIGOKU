---
task_id: SGK-2026-0001
doc_type: manual
status: active
parent_task_id: SGK-2026-0001
related_docs: []
title: 'Learned Lessons (AI Agent Orientation)'
created_at: '2026-06-10'
updated_at: '2026-06-10'
tags:
- ai-agent
- lessons-learned
---

- 巨大クラスからサービスへメソッドを抽出する際、元実装を理解して書き直すとスコア重み・カテゴリ重み・条件分岐の微細な差異を生み、既存テストを通過しながら出力が変化する。抽出時は元コードを1行単位でコピーし、`self.attr` → `self._attr` の置換だけに留めること。
- クラスの可変属性（`project_manager`, `workspace` など後から `set_project_manager`/`initialize_workspace` で差し替わる属性）を注入して保持する service インスタンスは `@property` でキャッシュ (`if not hasattr`) してはいけない。毎回新規生成するか、注入元属性の identity 変化を検出して再生成すること。
- Python の `lines[start:end]` スライスでファイル行番号からメソッド本体を抽出する場合、end は exclusive である。1-indexed の行番号 N まで含めるには `lines[start-1:N]` とすること。`lines[start-1:N-1]` は最終行を切り落とす（本セッションでは `return` 文欠落によりメソッドが `None` を返した）。
- `self.xxx` → `self._xxx` 文字列置換でメソッドを別クラスへ移す場合、置換表はパターン長降順にソートして適用し、部分一致を避ける。置換後は必ず最終行を含む全行が完全に移行されたことを tail で確認すること。
