---
task_id: SGK-2026-0278
doc_type: work_report
status: done
parent_task_id: SGK-2026-0277
related_docs:
  - docs/shigoku/subtasks/2026-06-09_sharedworkspace-stub-id-pool-compat_subtask_plan.md
  - docs/shigoku/reports/2026-06-09_sgk-2026-0277_api-probe-runner-extraction_work_report.md
  - docs/shigoku/worklogs/2026-06-09_sgk-2026-0277_api-probe-runner-extraction_work_log.md
  - docs/shigoku/worklogs/2026-06-09_sgk-2026-0278_sharedworkspace-stub-compat_work_log.md
created_at: '2026-06-09'
updated_at: '2026-06-11'
---

# Work Report: SGK-2026-0278 SharedWorkspace stub解消とID pool互換復旧

## 実装内容

### 修正ファイル
- `src/core/workspace/shared_workspace.py`
  - no-op stub から最小互換 API 実装へ置き換え
  - 追加属性: `.root` (Path), `id_pool` (Dict[str, OrderedDict]), `_owner_map`, `_pending_approval`
  - 追加メソッド: `register_ids`, `get_pool_ids`, `stage_ids_for_approval`, `approve_staged_ids`, `get_pending_approval_report`
  - 機能有効化: `ingest_response` (ID抽出＋URL正規化＋stage/register振り分け)
  - 機能有効化: `save_finding` (findings/ ディレクトリへの JSON 保存)
  - 機能有効化: `save_intel` (intel/ ディレクトリへの JSONL 保存)
  - `workspace_root` 配下に `findings/` `intel/` ディレクトリを自動作成

- `tests/core/security/test_idor_enhancement_phase1.py`
  - 既存 5 tests + 新規 7 リグレッションテストを追加

### ID抽出とURL正規化
- `_normalize_url_pattern`: UUID パス置換 (`/[0-9a-fA-F-]{36}` → `/{uuid}`) を **先に** 実行し、その後に 数値パス置換 (`/\d+` → `/{id}`) を実行。クエリ除去
- `_extract_ids_from_text`: UUID (`UUID_RE`) と 数値 (`\b(\d+)\b`) の両方を抽出

### ID pool 操作
- `register_ids`: 重複排除（OrderedDict）、owner map 対応
- `get_pool_ids`: exclude / exclude_owner / limit フィルタ対応。戻り値は `sorted()` により決定論的順序を保証。`exclude_owner` は部分キーマッチで owner 判定
- `stage_ids_for_approval`: 承認待ち状態にIDとownerを保持、poolへは即時投入しない
- `approve_staged_ids`: 承認待ちIDをowner情報と共にpoolへ移行、投入件数を返す
- `get_pending_approval_report`: 承認待ち状態をdictで返却

## 修正履歴（review指摘対応）

1. **Owner loss in approval flow** (`stage_ids_for_approval` / `approve_staged_ids`):
   - `stage_ids_for_approval` に `owner` パラメータ追加、`_pending_approval` 内に `owners` dict を保持
   - `approve_staged_ids` が `register_ids(..., owner=...)` で owner 情報を引き継ぐ
   - `ingest_response` が stage モード時に role を owner として伝達
   - リグレッションテスト: `test_staging_preserves_owner_for_exclude_owner`

2. **UUID handling** (`_normalize_url_pattern` / `_extract_ids_from_text`):
   - UUID パス置換を数値パス置換より先に実行（逆順による URI 破壊を防止）
   - `_extract_ids_from_text` に UUID 抽出 (`UUID_RE`) を追加。UUID 抽出後に `UUID_RE.sub('', text)` でマスクしてから数値正規表現を実行し、UUID 末尾の数値断片混入を防止
   - リグレッションテスト: `test_normalize_url_uuid_before_numeric`, `test_extract_ids_includes_uuids`, `test_ingest_response_stores_uuid_in_pool`, `test_uuid_only_body_no_numeric_suffix_in_pool`, `test_uuid_extraction_masks_numeric_fragments`

3. **Non-deterministic `get_pool_ids`**:
   - `id_pool` を `defaultdict(set)` → `defaultdict(OrderedDict)` に変更
   - 戻り値を `sorted()` で決定論的順序に
   - `exclude_owner` を `_id_belongs_to_owner` に抽出し、部分キーマッチで全 pool 横断検索
   - リグレッションテスト: `test_get_pool_ids_deterministic_order`, `test_get_pool_ids_exclude_owner_partial_key`, `test_get_pool_ids_limit_stable`

## テスト結果

| テスト群 | 結果 | 備考 |
|---------|------|------|
| `test_idor_enhancement_phase1.py` | **14/14 pass** | 既存 5 + 新規回帰 9 |
| `test_idor_matrix_secret_phase3.py` | **3/3 pass** | owner-aware ID pool 回帰確認 |
| `test_shared_workspace_integration.py` | **3/3 pass** | `.root`, `save_finding`, `save_intel` 回帰確認 |
| `tests/core/security/` + `tests/unit/core/agents/test_shared_workspace_integration.py` | **79/79 pass** | 広域回帰確認 |

## 完了条件チェックリスト

- [x] `test_idor_enhancement_phase1.py` の5件失敗が解消
- [x] `test_idor_matrix_secret_phase3.py` の owner-aware ID pool が通過
- [x] `test_shared_workspace_integration.py` の `.root`, `save_finding`, `save_intel` が通過
- [x] `.root` が Path 互換で `master_conductor.py`, `swarm/base.py`, `takeover.py` の参照と互換
- [x] `register_ids`, `stage_ids_for_approval`, `approve_staged_ids`, `get_pending_approval_report` がテスト期待と互換
- [x] ID pool が重複排除され、owner map で exclude_owner フィルタが動作
- [x] ファイル永続化が `workspace_root` 配下に限定
- [x] SGK-2026-0277 の InjectionManager / API minimal runner に手を入れていない
- [x] 既存テストの期待に変更なし
- [x] BugBounty 承認フローで owner 情報が欠落しない（review指摘対応）
- [x] UUID 抽出・正規化が破壊されず動作する（review指摘対応）
- [x] `get_pool_ids` が決定論的順序を返す（review指摘対応）

## リスクと保留事項

### deferred_tasks

```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0278-D01
    title: "継続監視: SharedWorkspace 本格永続化と検索API"
    reason: "本タスクは既存テスト互換の復旧を優先し、仕様書にある全ワークスペース機能の再実装までは扱わない"
    impact: medium
    tracking_task_id: SGK-2026-0265
    recommended_next_action: "SharedWorkspace の findings/intel/artifacts/context 永続化仕様を別タスクで棚卸しする"
```
