---
task_id: SGK-2026-0278
doc_type: work_log
status: done
parent_task_id: SGK-2026-0277
related_docs:
  - docs/shigoku/subtasks/2026-06-09_sharedworkspace-stub-id-pool-compat_subtask_plan.md
  - docs/shigoku/reports/2026-06-09_sgk-2026-0278_sharedworkspace-stub-compat_work_report.md
created_at: '2026-06-09'
updated_at: '2026-06-11'
---

# Work Log: SGK-2026-0278

## 2026-06-09

### Baseline confirmation
- `.venv/bin/pytest tests/core/security/test_idor_enhancement_phase1.py -q` で5件失敗を再現確認
  - 全件 `AttributeError: 'SharedWorkspace' object has no attribute 'register_ids'` 系

### Call site analysis
- `grep` で `SharedWorkspace|register_ids|stage_ids_for_approval|approve_staged_ids|get_pending_approval_report|\.root` を全 src/tests 横断検索
- 呼び出し元: `idor.py`, `idor_cross_tester.py`, `master_conductor.py`, `base.py`, `swarm/base.py`, `task_expander.py`, `biz_logic_hunter.py`
- テスト期待: `test_idor_enhancement_phase1.py`, `test_idor_matrix_secret_phase3.py`, `test_shared_workspace_integration.py`

### Implementation
- `SharedWorkspace` を stub から最小互換 API 実装へ置き換え
- 属性追加: `.root` (Path property), `id_pool` (defaultdict of set), `_owner_map` (Dict[Tuple[str,str], str]), `_pending_approval` (Dict)
- メソッド追加: `register_ids`, `get_pool_ids`, `stage_ids_for_approval`, `approve_staged_ids`, `get_pending_approval_report`
- メソッド有効化: `ingest_response` (ID抽出＋URL正規化＋模式振り分け), `save_finding` (JSON保存), `save_intel` (JSONL保存)
- ID抽出: `\b(\d+)\b` 正規表現
- URL正規化: `/\d+` → `/{id}`, `/[0-9a-fA-F-]{36}` → `/{uuid}`, クエリ除去（idor.py 互換）
- ディレクトリ自動作成: `_ensure_directories()` で `findings/`, `intel/` を作成

### Verification
- targeted tests: `.venv/bin/pytest tests/core/security/test_idor_enhancement_phase1.py tests/core/security/test_idor_matrix_secret_phase3.py tests/unit/core/agents/test_shared_workspace_integration.py -q` → **11/11 pass**
- broad tests: `tests/core/security/` + `tests/unit/core/agents/test_shared_workspace_integration.py` → **70/70 pass**
- SHIGOKU docs: `python3 scripts/validate_shigoku_docs.py` → MD_FILES=353, FRONT_MATTER_ISSUES=0, BROKEN_LINKS=0, REGISTRY_ISSUES=0

### Scope guard
- SGK-2026-0277 の InjectionManager / API minimal runner には手を入れていない
- 既存テストの期待に変更なし

## Next Actions
- deferred_tasks: SharedWorkspace 本格永続化と検索API（別タスクで棚卸し、tracking_task_id: SGK-2026-0265）
- `graphify update .` の実行（別途）

### Review fixes (post-implementation)
- FIX-1 (Owner loss): `stage_ids_for_approval` に `owner` パラメータ追加、`_pending_approval.owners` dict 保持、`approve_staged_ids` で `register_ids(..., owner=...)` に伝達。`ingest_response` で stage モード時に role を owner として伝達
- FIX-2 (UUID handling): `_normalize_url_pattern` で UUID 置換を数値置換より先に実行。`_extract_ids_from_text` に `UUID_RE` 追加
- FIX-3 (Determinism): `id_pool` を `defaultdict(set)` → `defaultdict(OrderedDict)`、`get_pool_ids` 戻り値を `sorted()` で決定論的順序に。`exclude_owner` を `_id_belongs_to_owner` に抽出し部分キーマッチで全 pool 横断検索
- FIX-4 (Placeholder): `tracking_task_id` を `SGK-YYYY-NNNN` → `SGK-2026-0265` に修正
- FIX-5 (UUID numeric contamination): `_extract_ids_from_text` で UUID 抽出後に `UUID_RE.sub('', text)` で UUID をマスクしてから数値正規表現を実行。UUID 末尾の12桁数値 `426614174000` が pool に混入するのを防止
- Regression tests: 9 tests added → total 20/20 pass, broad 79/79 pass
