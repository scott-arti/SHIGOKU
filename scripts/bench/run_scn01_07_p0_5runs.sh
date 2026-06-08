#!/usr/bin/env bash
set -euo pipefail

# SCN01-07 P0 baseline benchmark runner (5 runs)
# Usage:
#   bash scripts/bench/run_scn01_07_p0_5runs.sh
# Optional env:
#   TARGET_URL="http://127.0.0.1:8888"
#   RUN_COUNT=5
#   PROFILE_ID="P0"
#   SEED_SET_ID="scn01-07_seed_v1"
#   BENCH_FAST=1
#   BENCH_ULTRA=1
#   BENCH_ULTRA_MAX_DERIVED=2
#   BENCH_ULTRA_MAX_SESSION_TASKS=10
#   RUN_TIMEOUT_SEC=1200
#   SCAN_CMD="./.venv/bin/python -m src.main --target http://127.0.0.1:8888 --mode bugbounty"

REPO_ROOT="/home/bbb/Documents/App/Shigoku"
cd "${REPO_ROOT}"

PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"
if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "[ERROR] ${PYTHON_BIN} not found or not executable"
  exit 2
fi

TARGET_URL="${TARGET_URL:-http://127.0.0.1:8888}"
RUN_COUNT="${RUN_COUNT:-5}"
PROFILE_ID="${PROFILE_ID:-P0}"
SEED_SET_ID="${SEED_SET_ID:-scn01-07_seed_v1}"
PROJECT_KEY="${PROJECT_KEY:-127.0.0.1:8888}"
RUNTIME_CWD="${RUNTIME_CWD:-${REPO_ROOT}/tmp/bench_runtime}"
mkdir -p "${RUNTIME_CWD}"
BENCH_FAST="${BENCH_FAST:-0}"
BENCH_ULTRA="${BENCH_ULTRA:-0}"

RUN_TIMEOUT_SEC_ENV_SET=0
if [[ "${RUN_TIMEOUT_SEC+x}" == "x" ]]; then
  RUN_TIMEOUT_SEC_ENV_SET=1
fi
RUN_TIMEOUT_SEC="${RUN_TIMEOUT_SEC:-1200}"
RUN_TIMEOUT_KILL_AFTER_SEC="${RUN_TIMEOUT_KILL_AFTER_SEC:-30}"
BENCH_ULTRA_MAX_DERIVED="${BENCH_ULTRA_MAX_DERIVED:-2}"
BENCH_ULTRA_MAX_SESSION_TASKS="${BENCH_ULTRA_MAX_SESSION_TASKS:-10}"
AUTO_APPLY_SEED="${AUTO_APPLY_SEED:-1}"
SEED_DATE="${SEED_DATE:-$(date +%Y%m%d)}"

# Default scan command can be overridden by SCAN_CMD.
DEFAULT_SCAN_CMD="${PYTHON_BIN} -m src.main --target ${TARGET_URL} --mode bugbounty"
if [[ "${BENCH_FAST}" == "1" ]]; then
  # Fast bench mode:
  # - skip initial recon
  # - run only late recon steps for cached/short execution
  DEFAULT_SCAN_CMD="${DEFAULT_SCAN_CMD} --skip-initial-recon --recon-start-step 6 --recon-end-step 8"
fi
SCAN_CMD="${SCAN_CMD:-${DEFAULT_SCAN_CMD}}"

# Target project name normalization (same semantics as ProjectManager URL normalization).
TARGET_PROJECT_NAME="${TARGET_URL#http://}"
TARGET_PROJECT_NAME="${TARGET_PROJECT_NAME#https://}"
TARGET_PROJECT_NAME="${TARGET_PROJECT_NAME%/}"

# If SCAN_CMD runs inside docker-compose shigoku service, artifacts/sessions are emitted
# under repo-mounted workspace/projects/<target_project_name>.
IS_DOCKER_SCAN=0
if [[ "${SCAN_CMD}" == *"docker compose run"* && "${SCAN_CMD}" == *" shigoku "* ]]; then
  IS_DOCKER_SCAN=1
fi

if [[ "${IS_DOCKER_SCAN}" == "1" ]]; then
  PROJECT_DIR="${REPO_ROOT}/workspace/projects/${TARGET_PROJECT_NAME}"
else
  PROJECT_DIR="${RUNTIME_CWD}/projects/${PROJECT_KEY}"
fi

REPORTS_DIR="${PROJECT_DIR}/reports"
SESSIONS_DIR="${PROJECT_DIR}/sessions"

# Keep benchmark artifacts independent from scan output ownership/location.
ARTIFACT_DIR="${RUNTIME_CWD}/projects/${PROJECT_KEY}/reports/benchmark_scn01_07_${PROFILE_ID}"
mkdir -p "${ARTIFACT_DIR}"

# If artifact dir is not writable (e.g. previously created by root),
# fall back to a user-writable directory under repo tmp.
if [[ ! -w "${ARTIFACT_DIR}" ]]; then
  FALLBACK_DIR="${REPO_ROOT}/tmp/benchmark_scn01_07_${PROFILE_ID}_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "${FALLBACK_DIR}"
  echo "[WARN] artifact dir is not writable: ${ARTIFACT_DIR}"
  echo "[WARN] switching artifact dir to: ${FALLBACK_DIR}"
  ARTIFACT_DIR="${FALLBACK_DIR}"
fi

# Seed set bootstrap (v2):
# apply tagged seed URLs into the runtime project to keep SCN01-07 runs reproducible.
if [[ "${AUTO_APPLY_SEED}" == "1" && "${SEED_SET_ID}" == "scn01-07_seed_v2" ]]; then
  echo "[INFO] applying seed_set_v2 to runtime project (date=${SEED_DATE})"
  "${PYTHON_BIN}" "${REPO_ROOT}/scripts/bench/apply_seed_set_v2.py" \
    --project-dir "${PROJECT_DIR}" \
    --date "${SEED_DATE}" \
    > "${ARTIFACT_DIR}/seed_set_v2_apply.json"
fi

# In fast benchmark mode, lightweight thinking is usually a large latency amplifier.
# Keep this opt-in to avoid accidental long runs.
if [[ "${BENCH_FAST}" == "1" ]]; then
  LW_THINK_RAW="${SHIGOKU_DEEPSEEK_THINKING_ENABLED_FOR_LIGHTWEIGHT:-}"
  LW_THINK_LC="${LW_THINK_RAW,,}"
  if [[ "${LW_THINK_LC}" == "1" || "${LW_THINK_LC}" == "true" || "${LW_THINK_LC}" == "yes" ]]; then
    if [[ "${BENCH_ALLOW_LIGHTWEIGHT_THINKING:-0}" != "1" ]]; then
      export SHIGOKU_DEEPSEEK_THINKING_ENABLED_FOR_LIGHTWEIGHT=false
      echo "[WARN] BENCH_FAST: forcing SHIGOKU_DEEPSEEK_THINKING_ENABLED_FOR_LIGHTWEIGHT=false"
      echo "[WARN] set BENCH_ALLOW_LIGHTWEIGHT_THINKING=1 to opt-in (slower)"
    else
      echo "[WARN] BENCH_FAST with lightweight thinking enabled (opt-in) may increase runtime significantly"
    fi
  fi

  # Fast bench defaults (quality-first safe knobs).
  # All values are overrideable via explicit env vars.
  export SHIGOKU_PHASE2_ON_EMPTY_FORCE_DISABLE="${SHIGOKU_PHASE2_ON_EMPTY_FORCE_DISABLE:-1}"
  export SHIGOKU_RISK_PREDICTOR_DELAY_HIGH_ONLY="${SHIGOKU_RISK_PREDICTOR_DELAY_HIGH_ONLY:-1}"
  export SHIGOKU_PHASE1_TIMEOUT_RETRY_SAME_CAUSE_GUARD="${SHIGOKU_PHASE1_TIMEOUT_RETRY_SAME_CAUSE_GUARD:-1}"
  export SHIGOKU_PHASE1_TIMEOUT_RETRY_GUARD_MIN_PRIORITY="${SHIGOKU_PHASE1_TIMEOUT_RETRY_GUARD_MIN_PRIORITY:-70}"
  export SHIGOKU_INJECTION_BATCH_PARALLELISM="${SHIGOKU_INJECTION_BATCH_PARALLELISM:-2}"
fi

TIMEOUT_HAS_KILL_AFTER=0
if command -v timeout >/dev/null 2>&1; then
  if timeout --help 2>/dev/null | grep -q -- "--kill-after"; then
    TIMEOUT_HAS_KILL_AFTER=1
  fi
fi

USE_SCAN_TIMEOUT=1
if [[ "${RUN_TIMEOUT_SEC}" =~ ^[0-9]+$ ]] && [[ "${RUN_TIMEOUT_SEC}" -le 0 ]]; then
  USE_SCAN_TIMEOUT=0
fi
# Docker scan mode defaults to no outer timeout unless user explicitly set RUN_TIMEOUT_SEC.
# This aligns bench behavior with direct `docker compose run ... src.main` expectations.
if [[ "${IS_DOCKER_SCAN}" == "1" && "${RUN_TIMEOUT_SEC_ENV_SET}" == "0" ]]; then
  USE_SCAN_TIMEOUT=0
fi

# Snapshot effective LLM settings for this run (post-env + .env resolution).
set +e
LLM_CONFIG_SNAPSHOT="$(
  cd "${REPO_ROOT}" && PYTHONPATH="${REPO_ROOT}" "${PYTHON_BIN}" - <<'PY'
from src.core.config.settings import get_settings
from src.config import settings as legacy_settings
s = get_settings()
print(f"core_model={getattr(s, 'model', '')}")
print(f"core_model_output={getattr(s, 'model_output', '')}")
print(f"core_model_lightweight={getattr(s, 'model_lightweight', '')}")
print(f"core_thinking_output={getattr(s, 'deepseek_thinking_enabled_for_output', '')}")
print(f"core_thinking_lightweight={getattr(s, 'deepseek_thinking_enabled_for_lightweight', '')}")
print(f"legacy_model={getattr(legacy_settings, 'model', '')}")
print(f"legacy_model_output={getattr(legacy_settings, 'model_output', '')}")
print(f"legacy_model_lightweight={getattr(legacy_settings, 'model_lightweight', '')}")
print(f"legacy_thinking_output={getattr(legacy_settings, 'deepseek_thinking_enabled_for_output', '')}")
print(f"legacy_thinking_lightweight={getattr(legacy_settings, 'deepseek_thinking_enabled_for_lightweight', '')}")
PY
)"
SNAP_EXIT=$?
set -e
if [[ ${SNAP_EXIT} -eq 0 ]]; then
  echo "${LLM_CONFIG_SNAPSHOT}" | while IFS= read -r line; do
    [[ -n "${line}" ]] && echo "[INFO] llm_${line}"
  done
else
  echo "[WARN] failed to capture LLM config snapshot"
fi

echo "[INFO] target=${TARGET_URL}"
echo "[INFO] profile_id=${PROFILE_ID}, seed_set_id=${SEED_SET_ID}, run_count=${RUN_COUNT}"
echo "[INFO] scan_cmd=${SCAN_CMD}"
echo "[INFO] runtime_cwd=${RUNTIME_CWD}"
echo "[INFO] scan_project_dir=${PROJECT_DIR}"
echo "[INFO] scan_project_reports_dir=${REPORTS_DIR}"
echo "[INFO] scan_project_sessions_dir=${SESSIONS_DIR}"
echo "[INFO] docker_scan_mode=${IS_DOCKER_SCAN}"
echo "[INFO] bench_fast=${BENCH_FAST}, bench_ultra=${BENCH_ULTRA}, run_timeout_sec=${RUN_TIMEOUT_SEC}"
if [[ "${USE_SCAN_TIMEOUT}" == "0" ]]; then
  echo "[INFO] timeout_mode=disabled (RUN_TIMEOUT_SEC<=0)"
elif [[ "${TIMEOUT_HAS_KILL_AFTER}" == "1" ]]; then
  echo "[INFO] timeout_mode=hard_kill_after, run_timeout_kill_after_sec=${RUN_TIMEOUT_KILL_AFTER_SEC}"
else
  echo "[INFO] timeout_mode=term_only"
fi

# Ultra-fast knobs: aggressively reduce derived work and scenario backfill budgets.
# This is for throughput benchmarking, not full-quality coverage runs.
if [[ "${BENCH_ULTRA}" == "1" ]]; then
  export SHIGOKU_MAX_DERIVED_TASKS_PER_SESSION="${SHIGOKU_MAX_DERIVED_TASKS_PER_SESSION:-${BENCH_ULTRA_MAX_DERIVED}}"
  export SHIGOKU_MAX_SESSION_TASKS="${SHIGOKU_MAX_SESSION_TASKS:-${BENCH_ULTRA_MAX_SESSION_TASKS}}"
  export SHIGOKU_CSRF_TARGET_BUDGET="${SHIGOKU_CSRF_TARGET_BUDGET:-1}"
  export SHIGOKU_XSS_TARGET_BUDGET="${SHIGOKU_XSS_TARGET_BUDGET:-1}"
  export SHIGOKU_API_INJECTION_TARGET_BUDGET="${SHIGOKU_API_INJECTION_TARGET_BUDGET:-1}"
  export SHIGOKU_TAGGED_HISTORY_REPLAY_LIMIT="${SHIGOKU_TAGGED_HISTORY_REPLAY_LIMIT:-2}"
  export SHIGOKU_TAGGED_HISTORY_REPLAY_LIMIT_DENSE="${SHIGOKU_TAGGED_HISTORY_REPLAY_LIMIT_DENSE:-2}"
  export SHIGOKU_AUTHZ_HISTORY_REPLAY_LIMIT="${SHIGOKU_AUTHZ_HISTORY_REPLAY_LIMIT:-2}"
  export SHIGOKU_RECON_MASTER_TIMEOUT="${SHIGOKU_RECON_MASTER_TIMEOUT:-300}"
  export SHIGOKU_INJECTION_MANAGER_TIMEOUT="${SHIGOKU_INJECTION_MANAGER_TIMEOUT:-300}"
  # Keep batch short: reduce long-tail specialist tasks.
  export SHIGOKU_SINGLE_TASK_TIMEOUT="${SHIGOKU_SINGLE_TASK_TIMEOUT:-180}"
  export SHIGOKU_PARALLEL_BATCH_TIMEOUT="${SHIGOKU_PARALLEL_BATCH_TIMEOUT:-240}"
fi

# Profile-based tightening defaults (can be overridden by explicit env vars).
case "${PROFILE_ID}" in
  P1)
    export SHIGOKU_REPORT_HEURISTIC_MAX_CANDIDATES="${SHIGOKU_REPORT_HEURISTIC_MAX_CANDIDATES:-4}"
    export SHIGOKU_REPORT_HEURISTIC_APPEND_WHEN_CONFIRMED="${SHIGOKU_REPORT_HEURISTIC_APPEND_WHEN_CONFIRMED:-1}"
    export SHIGOKU_REPORT_HEURISTIC_PROMOTE_PRIVILEGE_PROBE_MIN="${SHIGOKU_REPORT_HEURISTIC_PROMOTE_PRIVILEGE_PROBE_MIN:-3}"
    export SHIGOKU_REPORT_HEURISTIC_PROMOTE_COMPLETED_PROBE_MIN="${SHIGOKU_REPORT_HEURISTIC_PROMOTE_COMPLETED_PROBE_MIN:-3}"
    ;;
  P2)
    export SHIGOKU_REPORT_HEURISTIC_MAX_CANDIDATES="${SHIGOKU_REPORT_HEURISTIC_MAX_CANDIDATES:-2}"
    export SHIGOKU_REPORT_HEURISTIC_APPEND_WHEN_CONFIRMED="${SHIGOKU_REPORT_HEURISTIC_APPEND_WHEN_CONFIRMED:-0}"
    export SHIGOKU_REPORT_HEURISTIC_PROMOTE_PRIVILEGE_PROBE_MIN="${SHIGOKU_REPORT_HEURISTIC_PROMOTE_PRIVILEGE_PROBE_MIN:-4}"
    export SHIGOKU_REPORT_HEURISTIC_PROMOTE_COMPLETED_PROBE_MIN="${SHIGOKU_REPORT_HEURISTIC_PROMOTE_COMPLETED_PROBE_MIN:-4}"
    ;;
esac

echo "[INFO] heuristic_max_candidates=${SHIGOKU_REPORT_HEURISTIC_MAX_CANDIDATES:-default}"
echo "[INFO] heuristic_append_when_confirmed=${SHIGOKU_REPORT_HEURISTIC_APPEND_WHEN_CONFIRMED:-default}"
echo "[INFO] heuristic_promote_privilege_probe_min=${SHIGOKU_REPORT_HEURISTIC_PROMOTE_PRIVILEGE_PROBE_MIN:-default}"
echo "[INFO] heuristic_promote_completed_probe_min=${SHIGOKU_REPORT_HEURISTIC_PROMOTE_COMPLETED_PROBE_MIN:-default}"
echo "[INFO] phase2_on_empty_force_disable=${SHIGOKU_PHASE2_ON_EMPTY_FORCE_DISABLE:-default}"
echo "[INFO] risk_predictor_delay_high_only=${SHIGOKU_RISK_PREDICTOR_DELAY_HIGH_ONLY:-default}"
echo "[INFO] phase1_timeout_retry_same_cause_guard=${SHIGOKU_PHASE1_TIMEOUT_RETRY_SAME_CAUSE_GUARD:-default}"
echo "[INFO] phase1_timeout_retry_guard_min_priority=${SHIGOKU_PHASE1_TIMEOUT_RETRY_GUARD_MIN_PRIORITY:-default}"
echo "[INFO] injection_batch_parallelism=${SHIGOKU_INJECTION_BATCH_PARALLELISM:-default}"

# Preflight: ensure required runtime env is present.
if [[ -z "${SHIGOKU_NEO4J_PASSWORD:-}" ]]; then
  echo "[ERROR] SHIGOKU_NEO4J_PASSWORD is not set."
  echo "[HINT] Do not run with plain sudo (it drops env)."
  echo "[HINT] Run as current user, or preserve env explicitly."
  exit 2
fi

for i in $(seq 1 "${RUN_COUNT}"); do
  RUN_ID="${PROFILE_ID}_run$(printf '%02d' "${i}")"
  STARTED_AT="$(date -Iseconds)"
  echo "[INFO] ===== ${RUN_ID} started_at=${STARTED_AT} ====="

  BEFORE_REPORT="$(ls -1t "${REPORTS_DIR}"/haddix_report_*.md 2>/dev/null | head -n 1 || true)"
  BEFORE_SESSION="$(ls -1t "${SESSIONS_DIR}"/session_*.json 2>/dev/null | head -n 1 || true)"

  # 1) scan execution
  set +e
  if [[ "${USE_SCAN_TIMEOUT}" == "0" ]]; then
    (cd "${RUNTIME_CWD}" && PYTHONPATH="${REPO_ROOT}" bash -lc "${SCAN_CMD}") > "${ARTIFACT_DIR}/${RUN_ID}_scan.log" 2>&1
  elif command -v timeout >/dev/null 2>&1; then
    if [[ "${TIMEOUT_HAS_KILL_AFTER}" == "1" ]]; then
      (
        cd "${RUNTIME_CWD}" && \
        PYTHONPATH="${REPO_ROOT}" timeout --signal=TERM --kill-after="${RUN_TIMEOUT_KILL_AFTER_SEC}s" "${RUN_TIMEOUT_SEC}s" bash -lc "${SCAN_CMD}"
      ) > "${ARTIFACT_DIR}/${RUN_ID}_scan.log" 2>&1
    else
      (cd "${RUNTIME_CWD}" && PYTHONPATH="${REPO_ROOT}" timeout "${RUN_TIMEOUT_SEC}" bash -lc "${SCAN_CMD}") > "${ARTIFACT_DIR}/${RUN_ID}_scan.log" 2>&1
    fi
  else
    (cd "${RUNTIME_CWD}" && PYTHONPATH="${REPO_ROOT}" bash -lc "${SCAN_CMD}") > "${ARTIFACT_DIR}/${RUN_ID}_scan.log" 2>&1
  fi
  SCAN_EXIT=$?
  set -e

  # 2) haddix report generation from latest valid session
  set +e
  if [[ "${IS_DOCKER_SCAN}" == "1" ]]; then
    (
      cd "${REPO_ROOT}" && \
      docker compose run --rm shigoku python3 -m src.main --report --format haddix --target "${TARGET_URL}"
    ) > "${ARTIFACT_DIR}/${RUN_ID}_report.log" 2>&1
  else
    (
      cd "${RUNTIME_CWD}" && \
      PYTHONPATH="${REPO_ROOT}" "${PYTHON_BIN}" -m src.main --report --format haddix --target "${TARGET_URL}"
    ) > "${ARTIFACT_DIR}/${RUN_ID}_report.log" 2>&1
  fi
  REPORT_EXIT=$?
  set -e

  # 3) pick latest report/session
  LATEST_REPORT="$(ls -1t "${REPORTS_DIR}"/haddix_report_*.md 2>/dev/null | head -n 1 || true)"
  LATEST_SESSION="$(ls -1t "${SESSIONS_DIR}"/session_*.json 2>/dev/null | head -n 1 || true)"
  if [[ "${LATEST_REPORT}" == "${BEFORE_REPORT}" ]]; then
    LATEST_REPORT=""
  fi
  if [[ "${LATEST_SESSION}" == "${BEFORE_SESSION}" ]]; then
    LATEST_SESSION=""
  fi

  CONSISTENCY_EXIT=99
  FINDINGS_EXIT=99
  GATE_EXIT=99

  # 4) mandatory consistency check
  if [[ -n "${LATEST_REPORT}" && -n "${LATEST_SESSION}" ]]; then
    set +e
    python3 "${REPO_ROOT}/scripts/verify_report_session_consistency.py" --report "${LATEST_REPORT}" \
      > "${ARTIFACT_DIR}/${RUN_ID}_consistency.json" 2>&1
    CONSISTENCY_EXIT=$?
    set -e

    # 5) findings inspection
    set +e
    python3 "${REPO_ROOT}/scripts/inspect_session_findings.py" --session "${LATEST_SESSION}" \
      > "${ARTIFACT_DIR}/${RUN_ID}_findings.json" 2>&1
    FINDINGS_EXIT=$?
    set -e

    # 6) gate observation
    set +e
    python3 "${REPO_ROOT}/scripts/check_initial_release_gate.py" \
      --report "${LATEST_REPORT}" \
      --allowed-missing scn_08_oob_external_channel_flow,scn_10_semantic_business_logic,scn_12_advanced_ssrf_internal_topology \
      --confirmed-min 3 \
      --candidate-max 2 \
      --confirmed-poc-missing-max 0 \
      --reason-code-missing-max 0 \
      --required-confirmed-classes access_control,idor_bola,mass_assignment,endpoint_bfla \
      --required-class-confirmed-min 1 \
      > "${ARTIFACT_DIR}/${RUN_ID}_gate.json" 2>&1
    GATE_EXIT=$?
    set -e
  else
    echo "[WARN] ${RUN_ID}: no fresh report/session generated; checks skipped" \
      | tee "${ARTIFACT_DIR}/${RUN_ID}_checks_skipped.log"
  fi

  ENDED_AT="$(date -Iseconds)"
  {
    echo "run_id=${RUN_ID}"
    echo "profile_id=${PROFILE_ID}"
    echo "seed_set_id=${SEED_SET_ID}"
    echo "started_at=${STARTED_AT}"
    echo "ended_at=${ENDED_AT}"
    echo "target_url=${TARGET_URL}"
    echo "scan_cmd=${SCAN_CMD}"
    echo "report_path=${LATEST_REPORT:-}"
    echo "session_path=${LATEST_SESSION:-}"
    echo "scan_exit=${SCAN_EXIT}"
    echo "report_exit=${REPORT_EXIT}"
    echo "consistency_exit=${CONSISTENCY_EXIT}"
    echo "findings_exit=${FINDINGS_EXIT}"
    echo "gate_exit=${GATE_EXIT}"
  } > "${ARTIFACT_DIR}/${RUN_ID}_meta.env"

  echo "[INFO] ${RUN_ID}: scan_exit=${SCAN_EXIT}, report_exit=${REPORT_EXIT}, consistency_exit=${CONSISTENCY_EXIT}, findings_exit=${FINDINGS_EXIT}, gate_exit=${GATE_EXIT}"
  echo "[INFO] ${RUN_ID}: report=$(basename "${LATEST_REPORT}"), session=$(basename "${LATEST_SESSION}")"
done

echo "[DONE] artifacts: ${ARTIFACT_DIR}"
