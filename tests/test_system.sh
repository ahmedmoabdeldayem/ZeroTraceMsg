#!/usr/bin/env bash
# Binary-level system test — exercises the compiled msg_server and msg_client
# executables rather than the library code directly.
#
# What this covers that unit/integration tests do not:
#   - server/main.cpp argument parsing and Config::load() at process startup
#   - client/main.cpp argument validation and error output
#   - The full server process lifecycle (bind, listen, accept, shutdown)
#   - Config fallback when the file is missing or invalid

set -euo pipefail

SERVER=./build/msg_server
CLIENT=./build/msg_client
PASS=0
FAIL=0

check() {
    local desc="$1"; shift
    if "$@" 2>/dev/null; then
        echo "  PASS  $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  $desc"
        FAIL=$((FAIL + 1))
    fi
}

check_output() {
    local desc="$1"
    local pattern="$2"
    shift 2
    local out
    out=$("$@" 2>&1 || true)
    if echo "$out" | grep -q "$pattern"; then
        echo "  PASS  $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  $desc  (expected pattern: '$pattern')"
        echo "        got: $out"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== system tests ==="
echo ""

# ── binaries exist and are executable ─────────────────────────────────────────
check "msg_server binary exists"  test -x "$SERVER"
check "msg_client binary exists"  test -x "$CLIENT"

# ── client argument validation ────────────────────────────────────────────────
check_output "client with no args prints usage"      "Usage:" "$CLIENT"
check_output "client with one arg prints usage"      "Usage:" "$CLIENT" alice

# ── server starts with an explicit config file ────────────────────────────────
PORT=59980
CERT=/tmp/ztm_system.cert.pem
KEY=/tmp/ztm_system.key.pem
CONF=$(mktemp /tmp/ztm_system_XXXXXX.conf)
rm -f "$CERT" "$KEY"

# cert_path and key_path belong in [server], not [tls]
cat > "$CONF" <<EOF
[server]
port      = $PORT
cert_path = $CERT
key_path  = $KEY
EOF

"$SERVER" "$CONF" &
SRV_PID=$!
sleep 1

check "server process alive after start"  kill -0 "$SRV_PID"

# Check port is bound
check "server port $PORT is listening" \
    bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT && exec 3>&-"

check "server generated TLS cert"   test -f "$CERT"
check "server generated TLS key"    test -f "$KEY"

kill "$SRV_PID" 2>/dev/null || true
wait "$SRV_PID" 2>/dev/null || true

# ── server falls back to defaults when config is missing ──────────────────────
# Start in background, capture output, then kill before it blocks on accept().
"$SERVER" /tmp/ztm_no_such_config_xyz.conf >/tmp/ztm_srv_out.txt 2>&1 &
FALLBACK_PID=$!
sleep 0.3
kill "$FALLBACK_PID" 2>/dev/null || true
wait "$FALLBACK_PID" 2>/dev/null || true
if grep -q "Using default configuration" /tmp/ztm_srv_out.txt 2>/dev/null; then
    echo "  PASS  missing config triggers fallback message"
    PASS=$((PASS + 1))
else
    echo "  FAIL  missing config triggers fallback message"
    FAIL=$((FAIL + 1))
fi

# ── server prints error for invalid config values ─────────────────────────────
BAD_CONF=$(mktemp /tmp/ztm_bad_XXXXXX.conf)
printf '[server]\nport = 99999\n' > "$BAD_CONF"
"$SERVER" "$BAD_CONF" >/tmp/ztm_bad_out.txt 2>&1 &
BAD_PID=$!
sleep 0.3
kill "$BAD_PID" 2>/dev/null || true
wait "$BAD_PID" 2>/dev/null || true
if grep -q "Config error" /tmp/ztm_bad_out.txt 2>/dev/null; then
    echo "  PASS  invalid config triggers error message"
    PASS=$((PASS + 1))
else
    echo "  FAIL  invalid config triggers error message"
    FAIL=$((FAIL + 1))
fi

# ── cleanup ───────────────────────────────────────────────────────────────────
rm -f "$CONF" "$BAD_CONF" "$CERT" "$KEY"

echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "Results: $PASS passed, $FAIL failed"
    exit 0
else
    echo "Results: $PASS passed, $FAIL failed"
    exit 1
fi
