#!/usr/bin/env bash
# SGK-2026-0427 — M5 sealed-audit isolated instrumented run harness.
#
# Executes `python -m src.main --target http://localhost:3000` EXACTLY ONCE
# against the local disposable target container, with:
#   - vdp mode readonly_enforce / stage m3a + diagnostics enabled+required
#   - egress: internal network only; external traffic solely via an
#     allowlist proxy (approved LLM destinations only); everything else
#     denied at DNS/network/proxy level and logged
#   - host secrets: only user-provided env file keys are injected
#   - config/shigoku.yaml: snapshot(sha256) -> temp run settings -> restored
#     byte-exact to the pre-run working tree afterwards
#   - single-run guard: refuses to run twice per output dir (1 eval version
#     = 1 run)
#
# Usage:
#   M5_ENV_FILE=/tmp/opencode/m5-run.env \
#   bash tests/fixtures/vdp_juiceshop_sealed/run_m5_audit.sh
#
# Required env file (never echoed, sourced via docker --env-file):
#   DEEPSEEK_API_KEY=...
# Optional (forwarded from host env when set): OPENAI_API_KEY
#
# Outputs (M5_OUT, default /tmp/opencode/m5-out):
#   run_stdout.log  target_access.log  proxy_access.log  hashes.start/end
#   config.backup.yaml  first_failure_juiceshop_v1.json  external_audit_v2.json
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-$REPO_ROOT/.venv/bin/python}"
HOST_PYTHON="${HOST_PYTHON:-python3}"

M5_OUT="${M5_OUT:-/tmp/opencode/m5-out}"
M5_ENV_FILE="${M5_ENV_FILE:-/tmp/opencode/m5-run.env}"
M5_TIMEOUT="${M5_TIMEOUT:-3900}"
TARGET_CONTAINER="${M5_TARGET_CONTAINER:-juice-shop}"
TARGET_URL="${M5_TARGET_URL:-http://localhost:3000}"
RUNNER_IMAGE="${M5_RUNNER_IMAGE:-python:3.13-slim}"
PROXY_IMAGE="m5-proxy:latest"
NET_INT="sgk-m5-net"
NET_EGRESS="sgk-m5-egress"
MARKER="$M5_OUT/run_marker"
CONFIG="$REPO_ROOT/config/shigoku.yaml"

mkdir -p "$M5_OUT"

log() { echo "[m5-audit] $*"; }
die() { log "FATAL: $*"; exit 1; }

TARGET_ORIG_NETS=""
cleanup() {
    docker rm -f m5-proxy >/dev/null 2>&1 || true
    docker rm -f m5-runner >/dev/null 2>&1 || true
    if [ -n "$TARGET_ORIG_NETS" ]; then
        docker network disconnect "$NET_INT" "$TARGET_CONTAINER" >/dev/null 2>&1 || true
        for net in $TARGET_ORIG_NETS; do
            docker network connect "$net" "$TARGET_CONTAINER" >/dev/null 2>&1 || true
        done
    fi
    if [ -f "$M5_OUT/config.backup.yaml" ]; then
        cp "$M5_OUT/config.backup.yaml" "$CONFIG" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# --- single-run guard ----------------------------------------------------------
if [ -f "$MARKER" ]; then
    die "run marker exists ($MARKER) — refusing a second run for this eval version"
fi
if [ ! -f "$M5_ENV_FILE" ]; then
    die "env file missing: $M5_ENV_FILE (create with DEEPSEEK_API_KEY=... and chmod 600)"
fi
if ! docker ps --format '{{.Names}}' | grep -qx "$TARGET_CONTAINER"; then
    die "target container '$TARGET_CONTAINER' is not running"
fi

log "=== phase 0: preconditions ok (single run, env file, target running) ==="
log "target: $TARGET_URL  container: $TARGET_CONTAINER  out: $M5_OUT"
touch "$MARKER"

# --- phase 1: snapshot (config + runtime surface hashes) -----------------------
cp "$CONFIG" "$M5_OUT/config.backup.yaml"
sha256sum "$CONFIG" > "$M5_OUT/config.sha256"
snapshot_tree() {
    find "$REPO_ROOT/src" "$REPO_ROOT/config" "$REPO_ROOT/src/prompts" \
        -type f -not -path '*__pycache__*' -print0 2>/dev/null \
        | sort -z | xargs -0 sha256sum
}
snapshot_tree > "$M5_OUT/hashes.start"
log "phase 1: config snapshot + runtime surface hashes saved"

# --- phase 2: temporary run config (byte-precise edits) ------------------------
# App mode: bugbounty -> vulntest. In bugbounty mode the compiled guard is
# fail-closed WITHOUT a program bundle (policy_unavailable blocks every
# network request); no bundle exists for a local disposable target and we do
# NOT fabricate one (same discipline as the rejected progression-records
# forge). vulntest mode is the designed mode for non-program lab targets and
# keeps the VDP path fully active; scope enforcement is provided by the VDP
# admission/scope revalidation gates + the harness network isolation.
"$HOST_PYTHON" - "$CONFIG" <<'PY'
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as fh:
    text = fh.read()

old_mode = 'mode: bugbounty # bugbounty | vulntest | ctf'
new_mode = 'mode: vulntest # bugbounty | vulntest | ctf'
assert text.count(old_mode) == 1, "mode line anchor not unique"
text = text.replace(old_mode, new_mode)

old_vdp = 'vdp:\n  mode: "off"'
new_vdp = 'vdp:\n  mode: "readonly_enforce"\n  stage: "m3a"\n  capability_rules:\n    follow_up_probe: "allowed"'
assert text.count(old_vdp) == 1, "vdp block anchor not unique"
text = text.replace(old_vdp, new_vdp)

old_diag = 'diagnostics:\n  enabled: false\n  required: false'
new_diag = 'diagnostics:\n  enabled: true\n  required: true'
assert text.count(old_diag) == 1, "diagnostics block anchor not unique"
text = text.replace(old_diag, new_diag)

with open(path, "w", encoding="utf-8") as fh:
    fh.write(text)
print("temp run config applied (mode=vulntest, vdp readonly_enforce/m3a, diagnostics on/required)")
PY
log "phase 2: temp run config applied"

# --- phase 3: isolated networks ------------------------------------------------
docker network create --internal "$NET_INT" >/dev/null 2>&1 || true
docker network create "$NET_EGRESS" >/dev/null 2>&1 || true
log "phase 3: networks ready ($NET_INT internal, $NET_EGRESS egress)"

# --- phase 4: allowlist proxy ---------------------------------------------------
docker build -q -t "$PROXY_IMAGE" -f "$SCRIPT_DIR/proxy/Dockerfile.proxy" "$SCRIPT_DIR/proxy" >/dev/null
docker rm -f m5-proxy >/dev/null 2>&1 || true
docker run -d --name m5-proxy --network "$NET_INT" \
    -e "ALLOW_DEST=api.deepseek.com:443,api.openai.com:443" \
    -v "$M5_OUT:/var/log/m5proxy" \
    "$PROXY_IMAGE" >/dev/null
docker network connect "$NET_EGRESS" m5-proxy >/dev/null
log "phase 4: proxy started (allowlist: api.deepseek.com:443, api.openai.com:443)"

# --- phase 5: isolate the target container --------------------------------------
TARGET_ORIG_NETS="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$TARGET_CONTAINER")"
docker network connect "$NET_INT" "$TARGET_CONTAINER"
for net in $TARGET_ORIG_NETS; do
    if [ "$net" != "$NET_INT" ] && [ "$net" != "host" ] && [ "$net" != "none" ]; then
        docker network disconnect "$net" "$TARGET_CONTAINER" >/dev/null 2>&1 || true
    fi
done
log "phase 5: target isolated on internal network (original nets: $TARGET_ORIG_NETS)"

# --- phase 6: bring-up verification (no target traffic) -------------------------
TARGET_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET_INT\").IPAddress}}" "$TARGET_CONTAINER")"
log "phase 6: bring-up verification (target internal IP: $TARGET_IP)"

PROXY_TEST=$(cat <<'PY'
import socket, sys

def connect(host, port, payload):
    s = socket.create_connection(("m5-proxy", 3128), timeout=15)
    s.sendall(payload)
    s.settimeout(10)
    try:
        data = s.recv(1024)
    except OSError:
        data = b""
    s.close()
    return data

# DENY test: CONNECT to a non-allowlisted destination must be refused.
resp = connect("example.com", 443, b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
if b"200" in resp.split(b"\r\n", 1)[0]:
    sys.exit("DENY-FAILED")
print("deny-ok")

# ALLOW test: CONNECT to an approved LLM destination must be established.
resp = connect("api.deepseek.com", 443, b"CONNECT api.deepseek.com:443 HTTP/1.1\r\nHost: api.deepseek.com:443\r\n\r\n")
if b"200" not in resp.split(b"\r\n", 1)[0]:
    sys.exit("ALLOW-FAILED")
print("allow-ok")
PY
)
PROXY_TEST_RESULT="$(docker run --rm --network "$NET_INT" "$RUNNER_IMAGE" \
    python -c "$PROXY_TEST" 2>&1 || true)"
echo "$PROXY_TEST_RESULT"
echo "$PROXY_TEST_RESULT" | grep -q "deny-ok" || die "proxy DENY test failed"
echo "$PROXY_TEST_RESULT" | grep -q "allow-ok" || die "proxy ALLOW test failed"
log "6a/6b: proxy allowlist enforcement verified (deny + allow)"

# 6c. runner smoke: venv works and external DNS is unreachable in the shared netns
RUNNER_SMOKE="$(docker run -i --rm --network "container:$TARGET_CONTAINER" \
    -v "$REPO_ROOT:/home/bbb/Documents/App/Shigoku" \
    -v "/home/bbb/.local/share/uv:/home/bbb/.local/share/uv:ro" \
    -v "/home/bbb/go/bin:/home/bbb/go/bin:ro" \
    -v "/home/bbb/.local/bin:/home/bbb/.local/bin:ro" \
    "$RUNNER_IMAGE" /home/bbb/Documents/App/Shigoku/.venv/bin/python - <<'PY' 2>&1 || true
import socket
print("venv-ok")
try:
    socket.create_connection(("api.deepseek.com", 443), timeout=8)
    print("dns-gate-FAILED")
except OSError:
    print("dns-gate-ok")
PY
)"
echo "RUNNER_SMOKE=[$RUNNER_SMOKE]"
echo "$RUNNER_SMOKE" | grep -q "venv-ok" || die "runner smoke: venv broken"
echo "$RUNNER_SMOKE" | grep -q "dns-gate-ok" || die "runner smoke: external DNS reachable (isolation broken)"
log "6c: runner venv + DNS gate verified"

# --- phase 7: THE SINGLE INSTRUMENTED RUN ---------------------------------------
log "phase 7: instrumented run starting (single, timeout ${M5_TIMEOUT}s)"
cp "$SCRIPT_DIR/caido_stub.py" "$M5_OUT/caido_stub.py"
OPENAI_FWD=()
if [ -n "${OPENAI_API_KEY:-}" ]; then
    OPENAI_FWD=(-e OPENAI_API_KEY)
fi
set +e
timeout "$M5_TIMEOUT" docker run --rm --name m5-runner \
    --network "container:$TARGET_CONTAINER" \
    -v "$REPO_ROOT:/home/bbb/Documents/App/Shigoku" \
    -v "/home/bbb/.local/share/uv:/home/bbb/.local/share/uv:ro" \
    -v "/home/bbb/go/bin:/home/bbb/go/bin:ro" \
    -v "/home/bbb/.local/bin:/home/bbb/.local/bin:ro" \
    -v "/home/bbb/nuclei-templates:/home/bbb/nuclei-templates:ro" \
    -v "/home/bbb/nuclei-templates:/root/nuclei-templates:ro" \
    -v "/home/linuxbrew:/home/linuxbrew:ro" \
    -v "$M5_OUT:/m5out" \
    --env-file "$M5_ENV_FILE" \
    "${OPENAI_FWD[@]}" \
    -e "SHIGOKU_SKIP_ENTRY_GATE=1" \
    -e "HTTPS_PROXY=http://m5-proxy:3128" \
    -e "HTTP_PROXY=http://m5-proxy:3128" \
    -e "NO_PROXY=localhost,127.0.0.1" \
    -e "PATH=/home/bbb/.local/bin:/home/bbb/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    "$RUNNER_IMAGE" \
    /bin/sh -c 'python /m5out/caido_stub.py & STUB_PID=$!; sleep 1; /home/bbb/Documents/App/Shigoku/.venv/bin/python -m src.main --target "$0"; RC=$?; kill $STUB_PID 2>/dev/null; exit $RC' \
    "$TARGET_URL" \
    > "$M5_OUT/run_stdout.log" 2>&1
RUN_EXIT=$?
set -e
log "phase 7: run finished exit=$RUN_EXIT"

# --- phase 8: evidence + restore --------------------------------------------------
docker logs "$TARGET_CONTAINER" > "$M5_OUT/target_access.log" 2>&1 || true
docker logs m5-proxy > "$M5_OUT/proxy_access.log" 2>&1 || true
docker rm -f m5-proxy >/dev/null 2>&1 || true
if [ -n "$TARGET_ORIG_NETS" ]; then
    docker network disconnect "$NET_INT" "$TARGET_CONTAINER" >/dev/null 2>&1 || true
    for net in $TARGET_ORIG_NETS; do
        docker network connect "$net" "$TARGET_CONTAINER" >/dev/null 2>&1 || true
    done
fi
cp "$M5_OUT/config.backup.yaml" "$CONFIG"
snapshot_tree > "$M5_OUT/hashes.end"
log "phase 8: config restored + target network restored"
if cmp -s <(sha256sum "$CONFIG") "$M5_OUT/config.sha256"; then
    log "config/shigoku.yaml byte-identical to pre-run snapshot"
else
    log "WARN: config/shigoku.yaml differs from snapshot — investigate"
fi
if diff -q "$M5_OUT/hashes.start" "$M5_OUT/hashes.end" >/dev/null; then
    log "runtime surface (src/config/prompts) byte-identical pre/post run"
else
    log "WARN: runtime surface hashes changed during the run:"
    diff "$M5_OUT/hashes.start" "$M5_OUT/hashes.end" | head -20 || true
fi

# --- phase 9: evaluator post-binding ----------------------------------------------
SESSION="$(find "$REPO_ROOT/workspace/projects" -name 'session_*.json' -newer "$MARKER" -type f 2>/dev/null | head -1)"
if [ -n "$SESSION" ]; then
    log "session: $SESSION"
    "$PYTHON_BIN" "$SCRIPT_DIR/evaluate_m5.py" \
        --session "$SESSION" \
        --labels "$SCRIPT_DIR/labels/expected_path_cases_v1.json" \
        --output-dir "$M5_OUT" \
        --eval-version v1 --run-mode m3a-readonly \
        > "$M5_OUT/evaluate_stdout.log" 2>&1 || true
    log "evaluator outputs:"
    tail -5 "$M5_OUT/evaluate_stdout.log" 2>/dev/null || true
else
    log "WARN: no instrumented session found under workspace/projects"
fi

log "=== done: run exit=$RUN_EXIT — artifacts in $M5_OUT ==="
exit "$RUN_EXIT"
