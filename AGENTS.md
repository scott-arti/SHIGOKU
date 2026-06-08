# AGENTS Instructions

You are a careful coding agent. Follow this workflow strictly:

## 1) First understand scope
- Restate objective briefly.
- Do not edit before locating exact files/symbols.
- If repo has AGENTS.md or CONTRIBUTING rules, follow them.

## 2) Plan before edit
- Create a short step plan (3-6 steps).
- Keep exactly one step in progress.
- Update status as you finish each step.

## 3) Safe exploration
- Search broadly, then narrow.
- Read only needed files.
- Do not assume; verify with code references.

## 4) Surgical edits
- Minimal diff only; no unrelated refactors.
- One concern per patch when possible.
- Preserve existing style and naming.
- Never revert unrelated local changes.

## 5) Validate changes
- Run targeted checks first (file-level or specific tests).
- Then run broader checks if needed.
- Report failures honestly; do not claim success without evidence.

## 6) Reporting
- Output: What changed / Why / Validation run / Risks / Next step.
- Include file paths and key lines.
- If blocked, state exact blocker and proposed options.

## 7) Guardrails
- No destructive git commands unless explicitly requested.
- No commits/branch changes unless asked.
- Ask before network/elevated/destructive actions.

## 8) Mandatory Report/Session Consistency Gate
- This section is mandatory for any user request that includes a report path (for example `haddix_report_*.md`).
- Before recommending re-run, before comparing with any older run, and before summarizing results, run:
  - `python3 scripts/verify_report_session_consistency.py --report <absolute-report-path>`
- Never mix timestamps from different reports in one conclusion.
- The provided report path is the primary source of truth for that turn.
- If consistency check fails or session cannot be resolved, do not guess. Explicitly say it is blocked by missing/invalid artifacts.
- Any re-run recommendation must include the checker verdict and reason codes.

### Report/Session Terminology
- `report`: a generated Markdown artifact such as `haddix_report_*.md`; summaries are derived from a session and formatter logic.
- `session`: the raw execution artifact such as `session_*.json`; this is the closest record of what the run actually produced.
- `primary source of truth`: the report path explicitly provided by the user for the current turn, together with the session resolved from the consistency checker.
- `backfill`: report-time or gate-time enrichment derived from scenario coverage or heuristics rather than directly from raw findings; do not present backfill as raw evidence unless clearly labeled.

## 9) Python / Test Execution Convention
- Prefer `.venv/bin/python` and `.venv/bin/pytest` for project code, imports, and tests.
- Use host `python3` only for lightweight repository scripts that do not depend on project-only binary wheels or local venv state.
- Run targeted checks first, then broader related checks only if the targeted checks pass or if broader verification is needed for confidence.
- Do not claim a fix or success without the exact validation command and its observed result.

## 10) Reporting / Gate Completion Criteria
- For report-formatting or report-summary changes:
  - Validate with targeted unit tests first.
  - If a real `haddix_report_*.md` is available, also run the consistency checker against that real report.
- For gate or quality-policy changes:
  - Validate with targeted gate-related tests first.
  - If a real report path is available, also run `scripts/check_initial_release_gate.py` against that report before claiming completion.
- For detection/reporting pipeline changes:
  - Prefer verifying both unit tests and at least one real session/report artifact.
- Report whether validation covered only tests, only real artifacts, or both.

## 11) Project Structure Quick Map
- Reports: `workspace/projects/<target>/reports/`
- Sessions: `workspace/projects/<target>/sessions/`
- Validation and gate scripts: `scripts/`
- Reporting logic: `src/reporting/`
- Orchestration logic: `src/core/engine/`
- Detection / swarm logic: `src/core/agents/swarm/`

## 12) Artifact / Schema Safety Rules
- Do not remove, rename, or repurpose report/session schema fields without first searching for all readers.
- Prefer additive helpers, formatters, or inspectors over schema cleanup unless the task explicitly requires structural change.
- Do not treat report-only backfill as equivalent to raw session evidence unless both are clearly distinguished and verified.
- If report output and raw session findings appear inconsistent, inspect the source session before proposing logic changes.

## 13) CLI-First Ops Routing
- For `report` / `session` / `validate` operations, use `shigoku-ops` first.
- Preferred forms:
  - `.venv/bin/shigoku-ops ...`
  - `python3 scripts/shigoku_ops_cli.py ...` (fallback when command resolution is unavailable)
- Do not bypass this routing unless the task explicitly requires another entrypoint.

## 14) Documentation Single-Source Rules (SHIGOKU)
- SHIGOKU関連ドキュメントの正本は `docs/shigoku/` とする。
- 新規ドキュメントは必ず `docs/shigoku/` 配下へ作成し、既存更新も同配下を優先する。
- ドキュメントは用途別に配置する:
  - `specs/`, `roadmaps/`, `plans/`, `subtasks/`, `reports/`, `worklogs/`, `manuals/`, `registry/`
  - `archive/`, `misc/` は移行用ディレクトリであり、通常運用では新規格納しない
- `doc_type` の許可値は `spec|roadmap|plan|subtask_plan|work_report|work_log|manual` とする。
- `docs/shigoku/registry/task_registry.yaml` にタスクIDを登録する。
- タスク関連ドキュメントは YAML Front Matter に `task_id`, `doc_type`, `created_at`, `updated_at` を必須で含める（`YYYY-MM-DD`）。
- 作業報告書で未対応事項が出た場合は、構造化 `deferred_tasks` ブロックで残す。

## 15) Mandatory Task Ledger Workflow (Enforced)
- 実装/機能追加時は、必ず次の順序で実施する:
  1. 台帳確認 (`docs/shigoku/registry/task_registry.yaml`, `task_ledger.md`)
  2. 新タスクなら新しい `SGK-YYYY-NNNN` を採番し台帳へ追加（既存ID再利用禁止）
  3. `status` を記入（開始時 `active`、完了時 `done` など）
  4. タスク計画書 (`plan` or `subtask_plan`) を作成/更新
  5. 作業完了報告書 (`work_report`) を作成/更新
  6. 作業ログ (`work_log`) を作成/更新
- 主要ドキュメントは `parent_task_id` と `related_docs` を必須で設定する。
- 変更後は必ず `python3 scripts/validate_shigoku_docs.py` を実行し、0エラーであることを確認する。
- 変更後は必ず `python3 scripts/sync_shigoku_updated_at.py` を先に実行し、変更した Markdown の `updated_at` を当日付に揃えてから `python3 scripts/validate_shigoku_docs.py` を実行する。

## 16) External Tool Organization Rules (Enforced)
- 外部ツール（FOSSツールラッパー）の配置は統一的な構造に従うこと
- 新規外部ツールは `src/core/adapters/external/` 配下に `*_adapter.py` の命名規則で配置すること
- 既存ツールの移行は段階的に実施し、下位互換性を維持すること
- 外部ツール統合に関する計画書では、必ず本ルールをAGENTS.mdおよびWindsorfのRulesに反映させるプロセスを含めること
- ツール分類の重複を避け、機能別に整理すること（例: scanners, fuzzing, oob等）

## 17) タスク応じた個別ルールの動的ロード規律（強制実行）

コンテキストを節約するため、以下のトピックに関する作業を行う場合は、思考プロセスの最初（コードを触る前）に必ず指定されたルールファイルを `read` ツールで読み込み、その指示を完全に遵守せよ。

| 対象のトピック | 読み込むべきルールファイル |
|---|---|
| コード品質、エラーハンドリング、非同期処理、サブプロセス、シークレット管理 | `rules/codingrules.md` |
| レポートとセッションの整合性、Haddixレポート、ゲート判定のロジック | `rules/report-session-consistency.md` |
| レポートのフォーマット、検証ゲートの実装、品質ポリシー | `rules/reporting.md` |
| Ops CLI（shigoku-ops）のルーティング、各種コマンド操作 | `rules/cli-ops-routing.md` |
| SHIGOKUドキュメントの単体変更・微修正 | `rules/shigoku-docs.md` |
| タスクの追跡、タスクIDの採番、計画書や作業報告書の作成・更新 | `rules/task-ledger.md` と `rules/shigoku-docs.md` |
| Pythonのテスト実行方法、カバレッジの期待値 | `rules/python-tests.md` |

**実行ルール:**
- 該当するファイルが存在する場合は、推測で動かず必ず中身をロードすること。
- ユーザーへの最終報告時に、本タスクのために「どのルールファイルを参考にしたか」を必ず明記して報告せよ。

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

When the user types `/graphify`, invoke the `skill` tool with `skill: "graphify"` before doing anything else.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- Dirty graphify-out/ files are expected after hooks or incremental updates; dirty graph files are not a reason to skip graphify. Only skip graphify if the task is about stale or incorrect graph output, or the user explicitly says not to use it.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
