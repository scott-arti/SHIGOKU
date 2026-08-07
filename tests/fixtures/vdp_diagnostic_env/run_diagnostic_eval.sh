#!/usr/bin/env bash
# SGK-2026-0425 M4 — generated opaque diagnostic evaluation orchestration.
#
#   bash tests/fixtures/vdp_diagnostic_env/run_diagnostic_eval.sh
#
# Flow: private dir -> fixture up (seeded, fault-injected) -> wait for the
# sealed manifest -> runtime run (REAL VDP adapter + generator) -> simulated
# full event list (M1 hooks pending) -> evaluator run (real analyzer) ->
# anonymized result lines. NO sealed content is ever written into the repo:
# manifest/labels/out live in a mktemp private dir (removed on exit).
#
# Params via env: DIAG_SEED (default 1), DIAG_FAULT_STAGE (default S00 =
# pass-through), DIAG_CASE_COUNT (default 3), DIAG_RUN_ID,
# DIAG_EVENTS_SOURCE (auto|simulated|runtime: which event list the evaluator
# evaluates; auto uses the genuine runtime events for S02/S03 faults, where
# the real pipeline exhibits the cut per case, and the simulated full list
# everywhere else).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-$REPO_ROOT/.venv/bin/python}"

DIAG_SEED="${DIAG_SEED:-1}"
DIAG_CASE_COUNT="${DIAG_CASE_COUNT:-3}"
DIAG_FAULT_STAGE="${DIAG_FAULT_STAGE:-S00}"
DIAG_RUN_ID="${DIAG_RUN_ID:-diag-run-$(date +%s)}"
DIAG_EVENTS_SOURCE="${DIAG_EVENTS_SOURCE:-auto}"

PRIV="$(mktemp -d)"
chmod 700 "$PRIV"
echo "diagnostic_private_dir:$PRIV"

export DIAG_SECRETS_DIR="$PRIV/secrets"
export DIAG_OUT_DIR="$PRIV/out"
mkdir -p "$DIAG_SECRETS_DIR" "$DIAG_OUT_DIR/eval"

cleanup() {
  docker compose down --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$PRIV"
}
trap cleanup EXIT

cd "$SCRIPT_DIR"

# --- clean slate: stop any leftover stack from a previous run --------------
docker compose down --remove-orphans >/dev/null 2>&1 || true

# --- start the fixture and wait for the sealed manifest --------------------
export DIAG_SEED DIAG_CASE_COUNT DIAG_FAULT_STAGE DIAG_RUN_ID
docker compose up -d --wait fixture-target
manifest_written=0
for _ in $(seq 1 120); do
  if [ -f "$DIAG_SECRETS_DIR/case_manifest.json" ]; then
    manifest_written=1
    break
  fi
  sleep 1
done
if [ "$manifest_written" != "1" ]; then
  echo "case manifest not written by the fixture" >&2
  docker compose logs fixture-target >&2 || true
  exit 1
fi
echo "case_manifest_written:1"

# --- runtime run (REAL ObservationAdapter + generate_hypotheses) ----------
docker compose run --rm runtime

# --- simulated full event list (M1 hooks pending): the event list the
# runtime WOULD produce when the funnel is cut at the injected stage -------
(
  cd "$REPO_ROOT"
  "$PYTHON_BIN" tests/fixtures/vdp_diagnostic_env/event_simulator.py \
    --manifest "$DIAG_SECRETS_DIR/case_manifest.json" \
    --labels "$DIAG_SECRETS_DIR/expected_path_labels.json" \
    --fault-stage "$DIAG_FAULT_STAGE" \
    --run-id "$DIAG_RUN_ID" \
    --out "$DIAG_OUT_DIR/runtime_events_simulated.jsonl"
)

# --- event source for the evaluator (CONTAINER paths: /out is the mount
# point of $DIAG_OUT_DIR inside the evaluator container) -------------------
case "$DIAG_EVENTS_SOURCE" in
  simulated)
    RUNTIME_EVENTS_PATH=/out/runtime_events_simulated.jsonl
    ;;
  runtime)
    RUNTIME_EVENTS_PATH=/out/runtime_events.jsonl
    ;;
  auto)
    case "$DIAG_FAULT_STAGE" in
      S02|S03)
        # genuine per-case events exhibit these cuts end to end
        RUNTIME_EVENTS_PATH=/out/runtime_events.jsonl
        ;;
      *)
        RUNTIME_EVENTS_PATH=/out/runtime_events_simulated.jsonl
        ;;
    esac
    ;;
  *)
    echo "invalid DIAG_EVENTS_SOURCE: $DIAG_EVENTS_SOURCE" >&2
    exit 1
    ;;
esac
export RUNTIME_EVENTS_PATH

# --- evaluator run (privileged reader, network_mode none) -----------------
docker compose run --rm evaluator

echo "diagnostic_eval_done:1"
