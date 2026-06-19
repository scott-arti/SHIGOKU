---
task_id: SGK-2026-0052
doc_type: plan
doc_usage: implementation_plan
status: backlog
parent_task_id: null
related_docs: []
created_at: '2026-05-14'
updated_at: '2026-05-19'
---

# Auth Triple-Target Stability Execution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** CRAPI + Juice Shop + DVWA の3ターゲットで、認証付きSCN01-07安定性評価を実行し、認証エラーまたは進捗停止を検知したら即停止する。

**Architecture:** 既存の `scripts/bench/run_scn01_07_p0_5runs.sh` を単一の実行エントリにして、ターゲットごとに `TARGET_URL/PROJECT_KEY/RUN_COUNT/SCAN_CMD` を差し替えて走らせる。各run後は `shigoku-ops report consistency` と `shigoku-ops report gate` で判定し、auth failure（401/403固定）または artifact未生成で停止する。結果は実行ログに集約する。

**Tech Stack:** Bash, `.venv/bin/python`, `.venv/bin/shigoku-ops`, existing benchmark scripts

---

## File Structure

- Create: `docs/superpowers/plans/2026-05-14-auth-triple-target-stability-execution-plan.md` (この計画)
- Create: `tmp/bench_runtime/auth_triple_target_2026-05-14/` (実行時artifact)
- Create: `docs/superpowers/plans/2026-05-14-auth-triple-target-stability-run-log.md` (実行結果ログ)
- Read: `scripts/bench/run_scn01_07_p0_5runs.sh`
- Read: `scripts/shigoku_ops_cli.py`

### Task 1: Preflight and Credential Session Setup

**Files:**
- Modify: なし（シェル環境変数のみ）
- Read: `scripts/bench/run_scn01_07_p0_5runs.sh`
- Test: なし

- [ ] **Step 1: 実行環境と必須バイナリ確認**

```bash
cd /home/bbb/Documents/App/Shigoku
test -x .venv/bin/python && echo "python_ok"
test -x .venv/bin/shigoku-ops && echo "ops_ok"
test -f scripts/bench/run_scn01_07_p0_5runs.sh && echo "bench_script_ok"
```

Expected: `python_ok`, `ops_ok`, `bench_script_ok` が出力される。

- [ ] **Step 2: 認証情報を環境変数へロード（ファイル保存しない）**

```bash
export CRAPI_BEARER_TOKEN="${CRAPI_BEARER_TOKEN:?set CRAPI_BEARER_TOKEN in current shell first}"
export CRAPI_COOKIE="${CRAPI_COOKIE:-token=${CRAPI_BEARER_TOKEN}}"
export DVWA_COOKIE="${DVWA_COOKIE:?set DVWA_COOKIE in current shell first}"
echo "env_loaded and validated"
```

Expected: `env_loaded and validated` が出力される。

- [ ] **Step 3: 軽量なターゲット到達性確認**

```bash
curl -s -o /dev/null -w 'crapi:%{http_code}\n' http://127.0.0.1:8888/
curl -s -o /dev/null -w 'juiceshop:%{http_code}\n' http://127.0.0.1:3000/
curl -s -o /dev/null -w 'dvwa:%{http_code}\n' http://127.0.0.1:4280/
```

Expected: 3行出力され、`000` ではない。

---

### Task 2: Auth Preflight Runs (1 run each)

**Files:**
- Create: `tmp/bench_runtime/auth_triple_target_2026-05-14/` 配下 artifact
- Read: `scripts/bench/run_scn01_07_p0_5runs.sh`
- Test: ベンチ実行ログ

- [ ] **Step 1: CRAPI auth preflight (1 run)**

```bash
cd /home/bbb/Documents/App/Shigoku
TARGET_URL='http://127.0.0.1:8888' \
PROJECT_KEY='crapi_auth_preflight' \
RUNTIME_CWD='/home/bbb/Documents/App/Shigoku/tmp/bench_runtime/auth_triple_target_2026-05-14' \
RUN_COUNT=1 \
PROFILE_ID='P2' \
SCAN_CMD=".venv/bin/python -m src.main --target http://127.0.0.1:8888 --mode bugbounty --bearer-token ${CRAPI_BEARER_TOKEN} --cookie '${CRAPI_COOKIE}'" \
bash scripts/bench/run_scn01_07_p0_5runs.sh
```

Expected: script終了コード `0`。`[INFO] ===== P2_run01` が出て report/session が生成される。

- [ ] **Step 2: Juice Shop preflight (1 run)**

```bash
cd /home/bbb/Documents/App/Shigoku
TARGET_URL='http://127.0.0.1:3000' \
PROJECT_KEY='juiceshop_preflight' \
RUNTIME_CWD='/home/bbb/Documents/App/Shigoku/tmp/bench_runtime/auth_triple_target_2026-05-14' \
RUN_COUNT=1 \
PROFILE_ID='P2' \
SCAN_CMD=".venv/bin/python -m src.main --target http://127.0.0.1:3000 --mode bugbounty" \
bash scripts/bench/run_scn01_07_p0_5runs.sh
```

Expected: script終了コード `0`。report/session 生成。

- [ ] **Step 3: DVWA auth preflight (1 run)**

```bash
cd /home/bbb/Documents/App/Shigoku
TARGET_URL='http://127.0.0.1:4280' \
PROJECT_KEY='dvwa_auth_preflight' \
RUNTIME_CWD='/home/bbb/Documents/App/Shigoku/tmp/bench_runtime/auth_triple_target_2026-05-14' \
RUN_COUNT=1 \
PROFILE_ID='P2' \
SCAN_CMD=".venv/bin/python -m src.main --target http://127.0.0.1:4280 --mode bugbounty --cookie '${DVWA_COOKIE}'" \
bash scripts/bench/run_scn01_07_p0_5runs.sh
```

Expected: script終了コード `0`。report/session 生成。

- [ ] **Step 4: preflight停止条件チェック（即停止ルール）**

```bash
cd /home/bbb/Documents/App/Shigoku
rg -n "401|403|auth|unauthorized|forbidden|no fresh report/session generated" \
  tmp/bench_runtime/auth_triple_target_2026-05-14/workspace/projects/*/reports/benchmark_scn01_07_P2/*_scan.log \
  tmp/bench_runtime/auth_triple_target_2026-05-14/workspace/projects/*/reports/benchmark_scn01_07_P2/*_report.log
```

Expected: 認証失敗固定パターンが主原因ならここで実行停止して人間へ報告する。

---

### Task 3: Main Benchmark Runs (CRAPI=5, JuiceShop=2, DVWA=2)

**Files:**
- Create: 各 `PROJECT_KEY` の report/session artifact
- Read: `scripts/bench/run_scn01_07_p0_5runs.sh`
- Test: ベンチ実行ログ

- [ ] **Step 1: CRAPI 本評価 5 run**

```bash
cd /home/bbb/Documents/App/Shigoku
TARGET_URL='http://127.0.0.1:8888' \
PROJECT_KEY='crapi_auth_main' \
RUNTIME_CWD='/home/bbb/Documents/App/Shigoku/tmp/bench_runtime/auth_triple_target_2026-05-14' \
RUN_COUNT=5 \
PROFILE_ID='P2' \
SCAN_CMD=".venv/bin/python -m src.main --target http://127.0.0.1:8888 --mode bugbounty --bearer-token ${CRAPI_BEARER_TOKEN} --cookie '${CRAPI_COOKIE}'" \
bash scripts/bench/run_scn01_07_p0_5runs.sh
```

Expected: `P2_run01..05` が完走し、report/session が各run分ある。

- [ ] **Step 2: Juice Shop 本評価 2 run**

```bash
cd /home/bbb/Documents/App/Shigoku
TARGET_URL='http://127.0.0.1:3000' \
PROJECT_KEY='juiceshop_main' \
RUNTIME_CWD='/home/bbb/Documents/App/Shigoku/tmp/bench_runtime/auth_triple_target_2026-05-14' \
RUN_COUNT=2 \
PROFILE_ID='P2' \
SCAN_CMD=".venv/bin/python -m src.main --target http://127.0.0.1:3000 --mode bugbounty" \
bash scripts/bench/run_scn01_07_p0_5runs.sh
```

Expected: `P2_run01..02` 完走。

- [ ] **Step 3: DVWA 本評価 2 run**

```bash
cd /home/bbb/Documents/App/Shigoku
TARGET_URL='http://127.0.0.1:4280' \
PROJECT_KEY='dvwa_auth_main' \
RUNTIME_CWD='/home/bbb/Documents/App/Shigoku/tmp/bench_runtime/auth_triple_target_2026-05-14' \
RUN_COUNT=2 \
PROFILE_ID='P2' \
SCAN_CMD=".venv/bin/python -m src.main --target http://127.0.0.1:4280 --mode bugbounty --cookie '${DVWA_COOKIE}'" \
bash scripts/bench/run_scn01_07_p0_5runs.sh
```

Expected: `P2_run01..02` 完走。

---

### Task 4: Consistency/Gate Evaluation and Stop Rules

**Files:**
- Read: 各ターゲットの最新 `haddix_report_*.md`
- Read: `scripts/shigoku_ops_cli.py`
- Create: `docs/superpowers/plans/2026-05-14-auth-triple-target-stability-run-log.md`

- [ ] **Step 1: 各ターゲットで最新report抽出**

```bash
cd /home/bbb/Documents/App/Shigoku
CRAPI_RP="$(ls -1t tmp/bench_runtime/auth_triple_target_2026-05-14/workspace/projects/crapi_auth_main/reports/haddix_report_*.md | head -n 1)"
JUICE_RP="$(ls -1t tmp/bench_runtime/auth_triple_target_2026-05-14/workspace/projects/juiceshop_main/reports/haddix_report_*.md | head -n 1)"
DVWA_RP="$(ls -1t tmp/bench_runtime/auth_triple_target_2026-05-14/workspace/projects/dvwa_auth_main/reports/haddix_report_*.md | head -n 1)"
printf "CRAPI=%s\nJUICE=%s\nDVWA=%s\n" "$CRAPI_RP" "$JUICE_RP" "$DVWA_RP"
```

Expected: 3つとも空でないパスが表示される。

- [ ] **Step 2: consistency判定（3レポート）**

```bash
cd /home/bbb/Documents/App/Shigoku
.venv/bin/shigoku-ops --json report consistency --report "$CRAPI_RP"
.venv/bin/shigoku-ops --json report consistency --report "$JUICE_RP"
.venv/bin/shigoku-ops --json report consistency --report "$DVWA_RP"
```

Expected: `status=consistent` が返る。1つでも不整合なら停止して報告。

- [ ] **Step 3: gate判定（3レポート）**

```bash
cd /home/bbb/Documents/App/Shigoku
for RP in "$CRAPI_RP" "$JUICE_RP" "$DVWA_RP"; do
  .venv/bin/shigoku-ops --json report gate \
    --report "$RP" \
    --allowed-missing scn_08_oob_external_channel_flow,scn_10_semantic_business_logic,scn_12_advanced_ssrf_internal_topology \
    --required-confirmed-classes access_control,idor_bola,mass_assignment,endpoint_bfla \
    --required-class-confirmed-min 1 \
    --confirmed-min 3 \
    --candidate-max 2 \
    --confirmed-poc-missing-max 0 \
    --reason-code-missing-max 0
done
```

Expected: `status=pass` を確認。fail時は理由コード付きで停止報告。

- [ ] **Step 4: 実行ログ作成**

```markdown
# 2026-05-14 Auth Triple Target Stability Run Log

- Targets: CRAPI(5), JuiceShop(2), DVWA(2)
- Auth inputs:
  - CRAPI bearer: provided in session env
  - CRAPI cookie: provided in session env
  - DVWA cookie: provided in session env
- Stop conditions:
  - auth failure fixed (401/403)
  - missing report/session artifacts
  - consistency != consistent
- Final verdict:
  - CRAPI: pass / fail / blocked
  - JuiceShop: pass / fail / blocked
  - DVWA: pass / fail / blocked
```

Expected: `docs/superpowers/plans/2026-05-14-auth-triple-target-stability-run-log.md` が作成される。

---

### Task 5: Guardrail Confirmation (No Curve-Fit Change)

**Files:**
- Read: `src/`
- Test: 文字列検索のみ

- [ ] **Step 1: ターゲット固有分岐混入チェック**

```bash
cd /home/bbb/Documents/App/Shigoku
rg -n "if .*crapi|if .*juiceshop|if .*dvwa|127\\.0\\.0\\.1:8888|127\\.0\\.0\\.1:3000|127\\.0\\.0\\.1:4280" src || true
```

Expected: 既存以外の新規ターゲット固定分岐がない。

- [ ] **Step 2: コミット禁止確認（この実行ではコミットしない）**

```bash
cd /home/bbb/Documents/App/Shigoku
git status --short
```

Expected: 変更確認のみ。コミット/ブランチ操作は実施しない。
