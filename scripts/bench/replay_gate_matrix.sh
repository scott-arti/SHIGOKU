#!/usr/bin/env bash
set -euo pipefail

# Re-evaluate gate thresholds on existing run artifacts without re-scanning.
# Usage:
#   bash scripts/bench/replay_gate_matrix.sh
# Optional env:
#   ARTIFACT_DIR=/abs/path/benchmark_scn01_07_P0
#   SOURCE_PREFIX=P0_run
#   RUN_IDS="01 02 03 04 05"
#   P1_CONFIRMED_MIN=3
#   P1_CANDIDATE_MAX=1
#   P2_CONFIRMED_MIN=4
#   P2_CANDIDATE_MAX=1

REPO_ROOT="/home/bbb/Documents/App/Shigoku"
cd "${REPO_ROOT}"

ARTIFACT_DIR="${ARTIFACT_DIR:-/home/bbb/Documents/App/Shigoku/tmp/bench_runtime/projects/127.0.0.1:8888/reports/benchmark_scn01_07_P0}"
SOURCE_PREFIX="${SOURCE_PREFIX:-P0_run}"
RUN_IDS="${RUN_IDS:-01 02 03 04 05}"

P1_CONFIRMED_MIN="${P1_CONFIRMED_MIN:-3}"
P1_CANDIDATE_MAX="${P1_CANDIDATE_MAX:-1}"
P2_CONFIRMED_MIN="${P2_CONFIRMED_MIN:-4}"
P2_CANDIDATE_MAX="${P2_CANDIDATE_MAX:-1}"

ALLOWED_MISSING="${ALLOWED_MISSING:-scn_08_oob_external_channel_flow,scn_10_semantic_business_logic,scn_12_advanced_ssrf_internal_topology}"
REQUIRED_CLASSES="${REQUIRED_CLASSES:-access_control,idor_bola,mass_assignment,endpoint_bfla}"

if [[ ! -d "${ARTIFACT_DIR}" ]]; then
  echo "[ERROR] artifact dir not found: ${ARTIFACT_DIR}"
  exit 2
fi

echo "[INFO] artifact_dir=${ARTIFACT_DIR}"
echo "[INFO] source_prefix=${SOURCE_PREFIX}, run_ids=${RUN_IDS}"
echo "[INFO] P1: confirmed_min=${P1_CONFIRMED_MIN}, candidate_max=${P1_CANDIDATE_MAX}"
echo "[INFO] P2: confirmed_min=${P2_CONFIRMED_MIN}, candidate_max=${P2_CANDIDATE_MAX}"

for i in ${RUN_IDS}; do
  META="${ARTIFACT_DIR}/${SOURCE_PREFIX}${i}_meta.env"
  if [[ ! -f "${META}" ]]; then
    echo "[WARN] meta not found: ${META}"
    continue
  fi

  RP="$(grep '^report_path=' "${META}" | cut -d= -f2- || true)"
  if [[ -z "${RP}" || ! -f "${RP}" ]]; then
    echo "[WARN] report_path missing/invalid in ${META}"
    continue
  fi

  echo "[INFO] ===== run${i} ====="
  python3 scripts/verify_report_session_consistency.py --report "${RP}" \
    > "${ARTIFACT_DIR}/P1_gate_run${i}_consistency.json"

  set +e
  python3 scripts/check_initial_release_gate.py \
    --report "${RP}" \
    --allowed-missing "${ALLOWED_MISSING}" \
    --confirmed-min "${P1_CONFIRMED_MIN}" \
    --candidate-max "${P1_CANDIDATE_MAX}" \
    --confirmed-poc-missing-max 0 \
    --reason-code-missing-max 0 \
    --required-confirmed-classes "${REQUIRED_CLASSES}" \
    --required-class-confirmed-min 1 \
    > "${ARTIFACT_DIR}/P1_gate_run${i}.json"
  P1_EXIT=$?
  set -e

  python3 scripts/verify_report_session_consistency.py --report "${RP}" \
    > "${ARTIFACT_DIR}/P2_gate_run${i}_consistency.json"

  set +e
  python3 scripts/check_initial_release_gate.py \
    --report "${RP}" \
    --allowed-missing "${ALLOWED_MISSING}" \
    --confirmed-min "${P2_CONFIRMED_MIN}" \
    --candidate-max "${P2_CANDIDATE_MAX}" \
    --confirmed-poc-missing-max 0 \
    --reason-code-missing-max 0 \
    --required-confirmed-classes "${REQUIRED_CLASSES}" \
    --required-class-confirmed-min 1 \
    > "${ARTIFACT_DIR}/P2_gate_run${i}.json"
  P2_EXIT=$?
  set -e
  echo "[INFO] run${i}: P1_gate_exit=${P1_EXIT}, P2_gate_exit=${P2_EXIT}"
done

ARTIFACT_DIR="${ARTIFACT_DIR}" python3 - <<'PY'
import json
from pathlib import Path
import os

adir = Path(os.environ.get('ARTIFACT_DIR', ''))
if not adir:
    raise SystemExit(0)

summary = {'P1': {'pass':0,'fail':0,'reason_codes':{}}, 'P2': {'pass':0,'fail':0,'reason_codes':{}}}
for profile in ('P1','P2'):
    for path in sorted(adir.glob(f'{profile}_gate_run*.json')):
        obj = json.loads(path.read_text(encoding='utf-8'))
        st = str(obj.get('status','')).lower()
        if st in ('pass','fail'):
            summary[profile][st] += 1
        for rc in obj.get('reason_codes',[]) or []:
            summary[profile]['reason_codes'][rc] = summary[profile]['reason_codes'].get(rc,0) + 1

out = adir / 'replay_gate_matrix_summary.json'
out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'Wrote summary: {out}')
print(json.dumps(summary, ensure_ascii=False, indent=2))
PY

echo "[DONE] replay complete: ${ARTIFACT_DIR}"
