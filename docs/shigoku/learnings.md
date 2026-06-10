---
task_id: SGK-2026-0001
doc_type: manual
status: active
parent_task_id: SGK-2026-0001
related_docs: []
title: 'Learned Lessons (AI Agent Orientation)'
created_at: '2026-06-10'
updated_at: '2026-06-11'
tags:
- ai-agent
- lessons-learned
---

- 巨大クラスからサービスへメソッドを抽出する際、元実装を理解して書き直すとスコア重み・カテゴリ重み・条件分岐の微細な差異を生み、既存テストを通過しながら出力が変化する。抽出時は元コードを1行単位でコピーし、`self.attr` → `self._attr` の置換だけに留めること。
- クラスの可変属性（`project_manager`, `workspace` など後から `set_project_manager`/`initialize_workspace` で差し替わる属性）を注入して保持する service インスタンスは `@property` でキャッシュ (`if not hasattr`) してはいけない。毎回新規生成するか、注入元属性の identity 変化を検出して再生成すること。
- Python の `lines[start:end]` スライスでファイル行番号からメソッド本体を抽出する場合、end は exclusive である。1-indexed の行番号 N まで含めるには `lines[start-1:N]` とすること。`lines[start-1:N-1]` は最終行を切り落とす（本セッションでは `return` 文欠落によりメソッドが `None` を返した）。
- `self.xxx` → `self._xxx` 文字列置換でメソッドを別クラスへ移す場合、置換表はパターン長降順にソートして適用し、部分一致を避ける。置換後は必ず最終行を含む全行が完全に移行されたことを tail で確認すること。
- プロジェクト内の `.gitignore` に `workspace/` など runtime ディレクトリ名がエントリされている場合、既存コードがそのパスから import している stub モジュールが gitignore で不可視化され、`ModuleNotFoundError` が pre-existing baseline として潜む。テスト収集前に必ず `git check-ignore -v <missing-path>` で可視性を確認し、source stub は `git add -f` で強制追加すること。
- 抽出したメソッド本体を新モジュールへ移植した後、元クラスの不要 import を削除する際は `grep -c` で出現回数を見るだけでは不十分。import 行自体も出現回数に含まれるため、必ず `rg <symbol> <file> | grep -v '^\d+:\s*(from\|import)'` でコード本体での使用有無を確認してから削除すること。
- Pythonコードのメソッド呼び出し一括置換に `sed 's/self\._method(\([^)]*\))/func(\1, extra=arg)/g'` は使ってはいけない。`[^)]+` はネストした括弧（`.get("k", [])`、`urlparse(x).query`、`len(x)`）を正しく扱えず破損を生む。代わりに Python の `re.sub` で対象メソッド名の完全一致かつ引数末尾の `)` を文脈で特定するか、AST/手動で1件ずつ置換すること。
- URL中のUUIDと数値IDを併せて正規化する場合、UUID置換（`/[0-9a-fA-F-]{36}` → `/{uuid}`）を必ず数値置換（`/\d+` → `/{id}`）より先に実行すること。逆順だとUUIDパス `/123e4567-e89b-...` が `/{id}e4567-e89b-...` に破壊される。またレスポンス本文からIDを抽出する際はUUIDマスク（`UUID_RE.sub('', text)`）後に `\b(\d+)\b` を適用し、UUID末尾の12桁数値断片がID poolに混入するのを防ぐこと。
- クラスメソッドをスタンドアロン関数へ抽出する際、元メソッドが `if not isinstance(self.current_context, dict): self.current_context = {}` のようなガードを先頭に持っていた場合、抽出先の関数には deps dict 経由で `None` が渡る可能性がある。抽出先では `current_context` を初回アクセス前に `isinstance` 検査するか、ガードを wrapper 側に残すこと。
- editツールで `task_queue.add()` や `self._injected_task_ids.add()` を含む guard メソッドの本体を thin wrapper に置換する際、oldString は必ずメソッド終端の `return True` の次行まで含めること。`return True` でマッチを止めると、その下に残った payload 構築コードや2つ目の `task_queue.add()` が次のメソッドとの間に orphaned dead code として残留する。置換後は `grep -n 'def '` で次のメソッド定義が wrapper の直後にあることを確認すること。
- guard/payload builder を service へ抽出するとき、`scenario_probe`、`source_category`、priority 値、`evidence_by_url` のキー名は元コードから1行ずつコピーすること。値を記憶で再構築すると `"scenario_probe_guard"` が `"coverage_backfill_guard"` に、priority 1249 が 1252 に化け、`task.params.get("source_category")` を assert する既存テストが検出できず失敗する。
