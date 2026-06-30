---
task_id: SGK-2026-0319
doc_type: manual
status: active
parent_task_id: SGK-2026-0289
related_docs:
  - rules/lessons.md
  - rules/shigoku-docs.md
  - rules/report-session-consistency.md
  - rules/python-tests.md
  - AGENTS.md
title: SHIGOKU Learnings
created_at: '2026-06-26'
updated_at: '2026-06-30'
---

# SHIGOKU Learnings

## 恒久ルールとして昇格した項目

- `rules/lessons.md`: 再発頻度が高い project-specific な落とし穴を恒久ルールへ昇格した。
- `rules/shigoku-docs.md`: Front Matter 必須項目、`done/` 移動時のリンク更新、`deferred_tasks` の実ID必須を明文化した。
- `rules/report-session-consistency.md`: raw findings の正規抽出方法と consistency verdict fail-closed を明文化した。
- `rules/python-tests.md`: report CLI の artifact 検証と `pytest.raises(match=...)` の実メッセージ基準を明文化した。
- `AGENTS.md`: 非 trivial な変更では `rules/lessons.md` を先に読む運用へ接続した。

## 運用方針

- このファイルは raw learnings の一次保管場所として残す。
- 同じ失敗が繰り返されるか、複数領域で効く learning は `rules/*.md` または `AGENTS.md` へ昇格する。
- 昇格後も、ここには元の事象と判断材料を残してよい。

## Raw Learnings

- **`snip` wrapper (bash tool) tokenizes at semicolons**: `python3 -c "import x; x.y()"` breaks because `snip` treats `;` as a command separator inside `-c`. Use `.venv/bin/python -c` (which `snip` passes through cleanly) or chain commands with `&&` inside the Python string. Never use `;` inside `python3 -c` strings in this environment.
- **`validate_shigoku_docs.py` enforces `status` in Front Matter for ALL doc_types**: even though `rules/shigoku-docs.md` only listed `task_id, doc_type, created_at, updated_at` before, the validator flags `missing_status` on `work_report` and `work_log`. Always include `status` plus the full validator-required front matter set in every SHIGOKU Markdown doc.
- **`MasterConductor.__new__()` bypass in tests**: existing tests (e.g. `test_master_conductor_recipe_contracts.py`) construct `MasterConductor` via `__new__()` without calling `__init__()`. Any lazily-initialized instance attribute added to `MasterConductor` MUST be guarded with `if not hasattr(self, "attr"): self.attr = None` before access. Direct attribute reference inside a method added to the class will raise `AttributeError` on these test paths.
- **Closure state lifetime in `_execute_recipe_task`**: the `_step_executor` closure is invoked once per recipe step. State created inside the closure body (e.g. `ProbeCache()`) is destroyed and recreated on every call. State that must persist across steps within one recipe execution belongs in the outer method scope. State that must persist across recipe tasks belongs at `MasterConductor` instance level with lazy init.
- **`plan`/`subtask_plan` を `done/` に移動した後は、移動先ファイルを参照する全 `related_docs` エントリも一括で新しいパスに更新すること**: `validate_shigoku_docs.py` は `primary_doc` だけでなく `related_docs` 内のパスも検査し、1つでも旧パスが残っていると `REGISTRY_ISSUE` になる。
- **`work_report` の `deferred_tasks` は `tracking_task_id: TBD` では台帳ルール違反**: `SGK-YYYY-NNNN` 形式の実IDが必須。複数の deferred item を1つの bundle plan の子として追跡してよい。
- **Multi-stage guard ordering in reauth strategies: zero-network checks BEFORE network-dependent checks**: placing `if not self.network_client: return ...` above `_detect_unsupported_auth_scheme(...)` caused OIDC/SAML/MFA URL detection to silently skip when `network_client=None`.
- **`main.main()` returns `None` for `--report` path; CLI tests must verify generated file artifacts**: `assert exit_code == 0` after `main()` always fails because the report path returns `None`, not `int`. Check generated report existence and content instead.
- **`msg("some.key")` silently renders `??some.key??` if the key is absent from `src/cli/messages.py`**: the message system has no fallback or error. Always grep for the exact key string before calling `msg()`.
- **Quarantine pending tasks from `task_queue.get_all()`, not `completed_tasks`**: `MasterConductor.task_queue` is the canonical source for tasks awaiting execution. `completed_tasks` contains only already-finished tasks.
- **Circular-import-safe `Recipe` validation**: `recipe_contracts.py` imports `Recipe` from `recipe_loader.py` via `TYPE_CHECKING`, so importing `validate_recipe_schema` back into `recipe_loader.py` at module scope creates a circular dependency. Use a lazy import inside the method body.
- **`pytest.raises(match=...)` matches substring, not word-token**: `"zero steps"` will not match `recipe_validation_failed:zero_steps`. Extract the actual raised message first, then write the regex to match the emitted substring.
- **`src/config.py` の flat config field 削除時は `getattr(app_settings, "field", default)` を grep しろ**: direct field references are only part of the surface. Identify indirect consumers before deleting the field and update them in the same fixer.
- **モジュール削除とその import 先クリーンアップは同一 fixer に束ねるか順序依存を明示せよ**: parallel fixers can fail if deletion lands before downstream import cleanup.
- **Session findings の正規抽出は `src/reporting/finding_extractor.extract_all_findings()` を使え**: `vulnerabilities_found` や `task["vulnerabilities_found"]` だけを見る formatter は実発見を大量に取りこぼす。
- **`shigoku-ops --report` 経由の session 解決後は consistency verdict をチェックせよ**: session パスだけを見て処理を進めると、`status: inconsistent/blocked` でも生成が通ってしまう。
- **Pydantic `@model_validator(mode='after')` で collection 依存の検証をする場合は空コレクションをガードせよ**: `self.default_role in self.roles` のような検証は、`roles={}` のデフォルト構築で失敗し全テストが壊れる。
- **`LLMClient(role="...", model="...")` は role 解決を黙ってスキップする**: role 移行時は `model` パラメータを完全に削除し `LLMClient(role="...")` のみにすること。
- **複数 fixer が同一 `__init__.py` にエクスポート追加する並列実行は禁止**: fixer はファイル全体を read -> write するため、最後の fixer の内容だけが残る。
- **Cross-cutting security boundaries must be enforced at the lowest-level write API**: redact `input_summary`, `error`, and nested `source_refs` inside the canonical recorder so no callsite can bypass the boundary.
- **Recursive content scanning must cover all nested data-bearing fields**: a flat top-level string scan silently passes secrets inside nested dicts and lists. Always test with secrets at depth >= 2.
- **`process_batch()` 内で `_mark_sent()` を呼ぶと通知欠落する**: send success is the point where dedup state can be updated. Keep batch helpers responsible only for candidate preparation.
- **ファサードのキャッシュキーではシークレットの存在有無（bool）ではなく値をハッシュ化して含めよ**: credential value changes must invalidate the cache.
- **SHIGOKU の session metadata は `metadata["context"]` 階層に認証情報が格納される**: resume 時は `metadata.get("context", {})` を先に見てから top-level へフォールバックすること。
- **ドメインモデルの `to_dict()` に掛けた変換（redaction/schema_version inject）は、別モジュールの並列 write 境界には自動伝播しない**: `Task.to_dict()` が secret redaction しても `build_async_session_payload()` が `task.metadata` を生書きすれば disk へ秘匿漏洩する。同一オブジェクトを直列化する全 disk-write 境界は `to_dict()` に統一するか単一 sanitizer helper（`_sanitize_metadata_for_session_payload` 相当）を共有し、境界を done 宣言する前に `rg "task\.metadata"` / `rg "to_dict\(\)"` を grep して直参照を検出すること。
- **完了報告書の「全 write 境界で redaction 済み」は実テストされた経路しか保証しない**: Phase 1 報告は universal `[REDACTED]` を主張したが検証されていたのは `to_dict`/`from_dict` のみ。完了判定レビューでは各 write 境界のコードを読み、その境界単位で変換を assert するテストが存在することを確認すること（テスト件数や報告文面からカバレッジを推論しない）。
- **Task.metadata を永続化する全 write API で同一 sanitize helper を使え**: `Task.to_dict()` に `_redact_secrets` + `schema_version` inject を実装しても、`build_async_session_payload()` が `task.metadata` 生参照で dict を構築すると、disk 上の session JSON だけ redaction/inject 未適用のまま分裂する。`to_dict()` と等価な sanitize helper（`_redact_secrets` import + schema_version inject）を全 write 経路で共通化し、実装後は計画書に列挙された全 serialization 境界で `grep "metadata"` して生参照の残存がないか確認すること。
- **計画書に列挙された全 serialization 境界を grep + 目視で差分確認せよ**: Phase 1 の計画書 section 2 には 6 境界（`Task.to_dict`, `build_async_session_payload`, `serialize_legacy`, `deserialize_legacy`, `restore_task_queue`, `restore_completed_tasks`）が明記されていたが、実装時に 5 境界だけ修正し `build_async_session_payload` の `task.metadata` 生参照を見逃した。全境界で metadata の読み書きが同一 sanitize 経路を通っていることを、コード行単位で grep して差分がないか確認すること。
- **Read ツール末尾の `(End of file - total N lines)` と行頭の `<n>: ` は表示用注記でありファイル内容ではない**: これらを `edit` の `oldString` に含めると "oldString not found" になる。oldString には prefix 後の実際の行内容のみを指定すること。
- **Pydantic `model_config = ConfigDict(extra="ignore")` の Settings では、新規 YAML セクション（例: `parallelism:`）は対応 model field が追加されるまで黙って無視される**: YAML に書いただけでは設定効果ゼロ。設定依存ロジックを書く前に `rg "class <Name>Settings" src/core/config/settings.py` で model 存在を確認すること（SGK-2026-0311 で `parallelism` セクション不在でも default 起動した事例）。
- **`urlparse("example.com")` は `.scheme=""`, `.hostname=None` を返す（path 扱い）**: origin/URL 正規化関数は `parsed.scheme` と `parsed.hostname` の両者を検証し、欠落時に `ValueError` を raise すること。scheme なし / host なし入力の単体テストを必ず含めること。
- **既存テストゼロのモジュールへ挙動変更を加える場合は characterization test を先に書くこと**: admission gate や budget 強制など挙動を変える変更前には現行挙動を固定する baseline test を最初に追加し、実装後も緑を維持すること。これを省くと後方互換性破壊が回帰テストに検出されない（SGK-2026-0311 の T-0.1）。
- **Factory caching removal regression test must exercise real factory, not replace it with pre-made mocks**: when removing object-pool caching from a factory method, `patch.object(factory, return_value=premade_mock)` makes the test blind to pool-reuse regression. Instead call `_original(name)` through an interceptor and mock only the leaf method (e.g. `.dispatch`) on the resulting real instance. Then `assert intercepted[0] is not intercepted[1]` catches same-instance-reuse.
- **Temporary pool-reuse emulation for regression verification requires early return at factory top**: storing in pool only at the bottom without `if name in pool: return pool[name]` before instance creation still creates a new instance every call and does not emulate true reuse. The early-return branch must be placed above the `swarm_class(config)` instantiation line.
- **`validate_shigoku_docs.py` は台帳(`task_ledger.md/.csv`, `task_registry.yaml`)の `status`/`primary_doc` と実ファイル配置の整合を検査しない**: `status: done`+`done/` 配置でも台帳が `active`+旧パスのままだと validator は GREEN になる。完了判定レビューでは `rg "SGK-<id>" docs/shigoku/registry/task_ledger.* task_registry.yaml` で status・path が実体と一致するか手動照合すること（SGK-2026-0311 で発覚）。
- **singleton dispatcher が shared client を inject する pooled manager を per-dispatch instance 化する場合は ContextVar/compatibility shim より優先し、`try/finally close()` 導入前に `SwarmManager.close()`/`Specialist.close()` が shared network/llm client を閉じないことを実コードで確認すること**: shim が `self.current_context` へ書き戻す設計は並列汚染を再導入する。close は per-manager 一時リソース(`_ephemeral_network_clients` 等)のみ解放する前提で追加する（base.py:150-152/244-253 が shared client を close しないことを確認済み）。
- **「`current_context` を隔離する」計画でも `self.history`/`self.total_tools_executed`/`self._phase2_detection_mode` 等 dispatch 冒頭で reset される全 per-dispatch mutable instance state を列挙対象に含めること**: 1属性だけ隔離しても sibling 状態で同時dispatch汚染が残る。棚卸しは `self.current_context` だけでなく dispatch メソッド内の全 `self.<attr> = ...` reset 行を grep 対象にする（SGK-2026-0312 LB-2）。
- **計画書の判定を Not-Ready→Ready に反転させるときは、参照した全 Blocker の `[ ]`→`[x]` 反転と具体解決設計を同一編集パスで反映すること**: 6.2 だけ Ready にして 6.3 を未解決のまま残す内部矛盾が実装をブロックする。編集後に `rg "\- \*\\*判定.*Ready"` と `rg "\- \[ \] \*\\*LB"` で「Ready 判定なのに未解決 Blocker 残存」がないか自己チェックすること（SGK-2026-0313 レビューで発覚）。
- **lane 分類は mutation-safety / statefulness / rate-limit / exclusivity を別 boolean field で持ち、単一 lane enum に圧縮しないこと**: `rate_limited` を lane に畳むと `parallel_safe=false` 過剰直列化を起こす。`CATEGORY_TO_LANE.get(category,"read_only")`（`src/core/engine/parallel_orchestrator.py:39-46`）は unknown を read_only の危険側へ倒すため、shadow は Phase 0 specialist 分類（`load_inventory()["specialist_classification"]`）を権威とし unknown→`sequential_required` へ正す（SGK-2026-0313 6.3.1/6.3.2）。
- **`build_async_session_payload()` の `decision_traces` / `run_ledger_payload` 等の構造化 payload 引数は `copy.deepcopy` のみで `_sanitize` 対象外**（`src/core/engine/master_conductor_session_service.py:141-156`）: redaction が効くのは `Task.metadata` 経由の `_sanitize_metadata_for_session_payload` のみ。新規に構造化 payload を同関数へ通す場合は safe-by-construction（cookie/token/header 実値を field に持たない）で設計し、auto-redaction に依存しないこと（SGK-2026-0313 LB-4）。
- **`concurrency_map.yaml` の specialist `name` フィールドには rationale が混入するケースがある（例: `"DiscoverySwarm specialists (visual_recon, github_recon)"`）**: swarm→specialist マッピングは `name` 一致に依存せず、YAML の `file` フィールドの path prefix（`src/core/agents/swarm/<swarm>/`）から導出すること。`name` による硬直マッチは inventory 更新で黙って破壊される（SGK-2026-0313）。
- **`master_conductor.py` の `build_async_session_payload` 呼び出しには既存 `decision_traces=self.decision_tracer.to_list()` が既に渡っている**: Phase 4 shadow の `_shadow_decisions` list は既存リストと `+` で結合し、置換しないこと。既存 sink がある場合は `grep` で呼び出し元を確認してから値を渡す（SGK-2026-0313）。
- **working-tree に大規模な未整理変更がある repo では `git add .` を禁止し、`git diff --staged --stat` で差分サイズを毎回確認せよ**: 目的の変更が 2 insertions でも、unstaged の 1670+ insertions を含むファイルを誤って stage すると成果物境界が崩れる。安全手順: `git reset HEAD -- <file>`, `git checkout HEAD -- <file>`（必要な場合）、外科的 edit 適用、`git add <file>`、`git diff --staged --stat -- <file>` で想定行数のみであることを確認（SGK-2026-0317 N-001/NF-001）。
- **Phase plan で T-5.x を Deferred する場合は 7.5 Local Deferred 表への D-N 行追加と 7.8 TDD チェックリスト checkbox 更新の両方が必須**: どちらか一方だけではレビューで Not Complete 判定になる（`validate_shigoku_docs.py` は TDD checkbox 状態を検査しないため、手動照合のみが検出手段）。checkbox は `[ ]` → `[ ] **Phase 9 Deferred (D-N)**` に書き換える（SGK-2026-0317 B-002）。
- **`git diff --cached` は staged 成果物だけを検査し、pytest は working tree 全体を実行する**: staged を最小 hunk に絞っても unstaged 側にテスト前提の大規模差分が残ると broad validation 結果が変わる。完了判定では `git diff --cached --numstat -- <file>` と `git diff --numstat -- <file>` を両方確認し、staged 成果物境界と検証実行環境を分けて報告すること（SGK-2026-0317 NF-002）。
- **MC payload 境界の修正は `SwarmResult.to_dict()` だけでは完了しない**: MasterConductor が独自 dict へ変換する経路（`data={...}`）は model serializer を通らないため、replay metadata 追加時は `rg "result\\.to_dict\\(|data\": \\{" src/core/engine/master_conductor.py` で直列化境界を探し、model `to_dict()` と MC payload の両方に同じ field を通すテストを追加すること（SGK-2026-0317 B-001）。
