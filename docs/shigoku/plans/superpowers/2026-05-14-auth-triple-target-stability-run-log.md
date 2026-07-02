---
task_id: SGK-2026-0053
doc_type: plan
status: backlog
parent_task_id: null
related_docs: []
created_at: '2026-05-14'
updated_at: '2026-07-02'
---

# 2026-05-14 Auth Triple Target Stability Run Log

- Execution mode: inline (`writing-plans` -> `executing-plans`)
- Runtime root: `/home/bbb/Documents/App/Shigoku/tmp/bench_runtime/auth_triple_target_2026-05-14`
- Stop policy: auth failure or non-progress must stop immediately

## Completed Before Stop

- Preflight binaries: `python_ok`, `ops_ok`, `bench_script_ok`
- Reachability:
  - CRAPI: `200`
  - JuiceShop: `200`
  - DVWA: `302`

## Stop Event

- Target: `CRAPI preflight (Task 2 Step 1)`
- Script: `scripts/bench/run_scn01_07_p0_5runs.sh`
- Outcome:
  - `scan_exit=127`
  - `report_exit=0`
  - `consistency_exit=99`
  - `findings_exit=99`
  - `gate_exit=99`
- Fresh artifact generation: **none**

## Primary Error Evidence

- Scan log:
  - `tmp/bench_runtime/auth_triple_target_2026-05-14/workspace/projects/crapi_auth_preflight/reports/benchmark_scn01_07_P2/P2_run01_scan.log`
  - `bash: line 1: .venv/bin/python: No such file or directory`
- Report log:
  - `tmp/bench_runtime/auth_triple_target_2026-05-14/workspace/projects/crapi_auth_preflight/reports/benchmark_scn01_07_P2/P2_run01_report.log`
  - `No valid session found for project http://127.0.0.1:8888`

## Stop Reason

- Non-progress condition matched (runner failed before scan execution).
- Per user rule, execution stopped immediately and not continued to JuiceShop/DVWA preflight/main runs.

## Next Fix Candidate (Not Executed Yet)

- Use absolute Python path inside `SCAN_CMD`, e.g.:
  - `/home/bbb/Documents/App/Shigoku/.venv/bin/python -m src.main ...`
- Re-run CRAPI preflight only after command-path fix confirmation.

---

## Re-Run Attempt (Bearer-Only, Docker Command)

- Date: 2026-05-14
- Command shape:
  - `docker compose run --rm shigoku python3 -m src.main --target http://127.0.0.1:8888/ --skip-initial-recon --bearer-token <JWT>`
- Project key: `crapi_auth_preflight_bearer`

### Result

- Start failure (`scan_exit=127`) は解消。
- Bearer ヘッダー注入で recon は実行開始し、実際に auth header を使って tool 実行しているログを確認。
- ただし `Async execution timeout after 600s` -> `timeout_batch` -> `recon_master retry` の流れで非進捗と判断。
- report/session は生成されず、ユーザー指定ルールに従って即時停止。

### Evidence

- `tmp/bench_runtime/auth_triple_target_2026-05-14/workspace/projects/crapi_auth_preflight_bearer/reports/benchmark_scn01_07_P2/P2_run01_scan.log`
- Key lines:
  - `Injecting 1 auth headers into httpx`
  - `Authorization: Bearer ...`
  - `Async execution timeout after 600s (coro=ParallelOrchestrator.execute_parallel)`
  - `Batch execution failed (timeout_batch)`
  - `Retrying unfinished tasks sequentially`

### Security Note

- 実行ログ・プロセス一覧にBearerトークンが露出するため、トークン再発行を推奨。

---

## Re-Run Attempt 2 (Bearer-Only + Fast Guard)

- Date: 2026-05-14
- Project key: `crapi_auth_preflight_bearer2`
- Runner knobs:
  - `BENCH_FAST=1`
  - `RUN_TIMEOUT_SEC=900`
  - scan args: `--skip-initial-recon --recon-start-step 6 --recon-end-step 8 --bearer-token <JWT>`

### Result

- `scan_exit=124` (timeout)
- `report_exit=0`
- `consistency_exit=99`, `findings_exit=99`, `gate_exit=99`
- Runner message: `no fresh report/session generated; checks skipped`
- 判定: 非進捗（セッション/レポート新規生成なし）につき即停止

### Evidence

- Benchmark stdout summary:
  - `[WARN] P2_run01: no fresh report/session generated; checks skipped`
  - `[INFO] P2_run01: scan_exit=124, report_exit=0, consistency_exit=99, findings_exit=99, gate_exit=99`
- Scan log:
  - `tmp/bench_runtime/auth_triple_target_2026-05-14/workspace/projects/crapi_auth_preflight_bearer2/reports/benchmark_scn01_07_P2/P2_run01_scan.log`
  - observed near timeout: `Shutdown error: CancelledError()`

---

## Re-Run Attempt 3 (Post-Fix Evaluation)

- Date: 2026-05-14
- Project key: `crapi_auth_eval_fix_20260514`
- Command shape:
  - `docker compose run --rm shigoku python3 -m src.main --target http://127.0.0.1:8888/ --skip-initial-recon --bearer-token <JWT>`
- Bench mode:
  - `docker_scan_mode=1` (scan project dir switched to `workspace/projects/127.0.0.1:8888`)
  - `BENCH_FAST=1`
  - `RUN_TIMEOUT_SEC=1200` (explicit)

### Result

- Path/ownership mismatch fix is effective:
  - `report_path` now resolves to workspace report path (not empty)
  - report generation succeeded in docker context (`report_exit=0`)
- Run still timed out due explicit timeout and long-running scan:
  - `scan_exit=137` (timeout kill path)
  - `session_path` remained empty in benchmark meta (no fresh session delta)
  - benchmark printed `no fresh report/session generated; checks skipped`

### Evidence

- Meta:
  - `tmp/bench_runtime/auth_triple_target_2026-05-14/workspace/projects/crapi_auth_eval_fix_20260514/reports/benchmark_scn01_07_P2/P2_run01_meta.env`
  - `report_path=/home/bbb/Documents/App/Shigoku/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260514_025842.md`
  - `scan_exit=137`
- Report log:
  - `tmp/bench_runtime/auth_triple_target_2026-05-14/workspace/projects/crapi_auth_eval_fix_20260514/reports/benchmark_scn01_07_P2/P2_run01_report.log`
  - `Using latest VALID session ... session_20260514_011853.json`
  - `jHADDIX Style Report generated ... haddix_report_20260514_025842.md`

### Post-Run Gate Snapshot

- consistency: `consistent` (exit=0)
- gate: `fail` (exit=3)
- reason codes:
  - `confirmed_below_minimum`
  - `required_detection_class_below_minimum`
