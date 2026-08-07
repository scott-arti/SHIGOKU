#!/usr/bin/env bash
# SGK-2026-0423 Lane P-2 — opaque holdout evaluation orchestration.
#
#   bash tests/fixtures/vdp_holdout_env/run_holdout_eval.sh
#
# Flow: private dirs -> fixture up -> wait for the hold out -> freeze
# iso-v2 thresholds (SAME VALUES as iso-v1) -> runtime run -> evaluator run
# -> anonymized result print. NO holdout content is ever written into the
# repo: secrets/logs live in ./_private_secrets + ./_private_logs (created
# here, removed on exit) and the session/thresholds/result live in a
# mktemp private dir (echoed for the operator).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-$REPO_ROOT/.venv/bin/python}"

PRIV="$(mktemp -d)"
chmod 700 "$PRIV"
echo "holdout_private_dir:$PRIV"

# Secrets/logs live OUTSIDE the repo under $PRIV (host private dirs).
SECRETS_DIR="$PRIV/secrets"
LOGS_DIR="$PRIV/logs"
mkdir -p "$SECRETS_DIR" "$LOGS_DIR"
export VDP_HOLDOUT_SECRETS_DIR="$SECRETS_DIR"
export VDP_HOLDOUT_LOGS_DIR="$LOGS_DIR"
cleanup() {
  rm -rf "$SECRETS_DIR" "$LOGS_DIR"
}
trap cleanup EXIT

export VDP_HOLDOUT_OUT_DIR="$PRIV/out"
mkdir -p "$VDP_HOLDOUT_OUT_DIR/eval"

cd "$SCRIPT_DIR"

# --- clean slate: stop any leftover stack from a previous run --------------
docker compose down --remove-orphans >/dev/null 2>&1 || true

# --- start the fixture and wait for the hold out -------------------------
docker compose up -d --wait fixture-target
holdout_written=0
for _ in $(seq 1 120); do
  if [ -f "$SECRETS_DIR/secret.json" ]; then
    holdout_written=1
    break
  fi
  sleep 1
done
if [ "$holdout_written" != "1" ]; then
  echo "holdout not written by the fixture" >&2
  docker compose logs fixture-target >&2 || true
  exit 1
fi
echo "holdout_written:1"

# --- export the account credentials from the hold out (host private
# secrets; the runtime receives them ONLY via env) -------------------------
(
  cd "$REPO_ROOT"
  "$PYTHON_BIN" - "$SECRETS_DIR/secret.json" "$PRIV/accounts.env" <<'PY'
import json
import sys

holdout = json.loads(open(sys.argv[1], encoding="utf-8").read())
accounts = holdout["accounts"]
lines = [
    f"VDP_ACCOUNT_A_ID=acct-a",
    f"VDP_ACCOUNT_A_SECRET={accounts['acct-a']}",
    f"VDP_ACCOUNT_B_ID=acct-b",
    f"VDP_ACCOUNT_B_SECRET={accounts['acct-b']}",
]
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    handle.write("\n".join(lines) + "\n")
PY
)
set -a
# shellcheck disable=SC1090
source "$PRIV/accounts.env"
set +a
echo "account_env_exported:1"

# --- freeze iso-v2 thresholds (SAME VALUES as iso-v1) ---------------------
(
  cd "$REPO_ROOT"
  "$PYTHON_BIN" - "$VDP_HOLDOUT_OUT_DIR/eval/thresholds_v1.json" <<'PY'
import json
import sys
from pathlib import Path

from src.reporting.vdp_dataset import ThresholdMetric, freeze_thresholds

out = Path(sys.argv[1])
thresholds = freeze_thresholds(
    eval_version="iso-v2",
    decided_at="2026-08-05T00:00:00Z",
    metrics=[
        ThresholdMetric(name="evidence_completeness", value=0.2,
                        formula="hypotheses_with_evidence / total_hypotheses",
                        target_set="hidden_holdout", direction="minimum"),
        ThresholdMetric(name="funnel:hypothesis_to_attempt", value=0.2,
                        formula="attempts / hypotheses",
                        target_set="hidden_holdout", direction="minimum"),
        ThresholdMetric(name="untested_rate", value=0.5,
                        formula="untested_verdicts / verdicts",
                        target_set="hidden_holdout", direction="maximum"),
        ThresholdMetric(name="false_promotion_rate", value=0.2,
                        formula="confirmed_without_gt_match / confirmed",
                        target_set="hidden_holdout", direction="maximum"),
        ThresholdMetric(name="recall", value=0.5,
                        formula="matched_ground_truth / ground_truth",
                        target_set="hidden_holdout", direction="minimum"),
        ThresholdMetric(name="budget_compliance", value=0.8,
                        formula="within-limit budget entries / eligible entries",
                        target_set="hidden_holdout", direction="minimum"),
    ],
)
out.write_text(json.dumps(thresholds.to_dict(), sort_keys=True, indent=2), encoding="utf-8")
print(f"thresholds_frozen:{out.name}")
PY
)

# --- runtime run (comparison confirmations happen here) -------------------
docker compose run --rm shigoku-runtime

# --- evaluator run (privileged reader, network_mode none) -----------------
docker compose run --rm holdout-evaluator

echo "holdout_eval_done:1"
