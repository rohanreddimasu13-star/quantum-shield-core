#!/usr/bin/env bash
# Disposable end-to-end test of the Docker Compose apply adapter.
# This uses a self-signed certificate and publishes only on an OS-assigned 127.0.0.1 port.
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
QS="$ROOT/target/debug/qsctl"
for tool in docker openssl curl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: required tool not found: $tool" >&2; exit 1; }
done
[ -x "$QS" ] || { echo "ERROR: build qsctl first: cargo build --bin qsctl" >&2; exit 1; }
docker compose version >/dev/null

STAMP="$(date +%s)"
TMP="$(mktemp -d "/tmp/qs-compose-local-${STAMP}.XXXXXX")"
COMPOSE="$TMP/compose.yaml"
CONFIG="$TMP/config.toml"
CERT="$TMP/cert.pem"
KEY="$TMP/key.pem"
LOG="$TMP/deploy.log"
DOMAIN="qs-local-test-${STAMP}.dev"
SERVICE=""
OVERLAY=""
BUILD_DIR=""

cleanup() {
  set +e
  if [ -n "$SERVICE" ] && [ -f "$COMPOSE" ] && [ -n "$OVERLAY" ] && [ -f "$OVERLAY" ]; then
    docker compose -f "$COMPOSE" -f "$OVERLAY" rm --stop --force "$SERVICE" >/dev/null 2>&1
  fi
  if [ -f "$COMPOSE" ]; then
    docker compose -f "$COMPOSE" down --remove-orphans >/dev/null 2>&1
  fi
  # Never remove parsed paths unless they are inside this test's temporary directory.
  case "$OVERLAY" in "$TMP"/*) [ ! -f "$OVERLAY" ] || rm -f -- "$OVERLAY" ;; esac
  case "$BUILD_DIR" in "$TMP"/*) [ ! -d "$BUILD_DIR" ] || rm -rf -- "$BUILD_DIR" ;; esac
  rm -rf -- "$TMP"
}
trap cleanup EXIT

cat > "$COMPOSE" <<'YAML'
services:
  web:
    image: hashicorp/http-echo:1.0.0
    command: ["-listen=:3000", "-text=Quantum Shield local Compose test"]
    expose:
      - "3000"
YAML

cat > "$CONFIG" <<TOML
schema_version = 1

[[sites]]
id = "qs-local-test"
domain = "$DOMAIN"
upstream = "http://web:3000"
TOML

openssl req -x509 -newkey ec \
  -pkeyopt ec_paramgen_curve:prime256v1 \
  -sha256 -days 1 -nodes \
  -keyout "$KEY" -out "$CERT" \
  -subj "/CN=$DOMAIN" \
  -addext "subjectAltName=DNS:$DOMAIN" >/dev/null 2>&1
chmod 600 "$KEY"

printf 'Starting disposable upstream service...\n'
docker compose -f "$COMPOSE" up -d web
printf 'Applying Quantum Shield in loopback-only test mode...\n'
set +e
"$QS" deploy-compose "$CONFIG" \
  --compose-file "$COMPOSE" --cert "$CERT" --key "$KEY" \
  --apply --local-test >"$LOG" 2>&1
DEPLOY_RC=$?
set -e
cat "$LOG"
OVERLAY="$(sed -n 's/^Generated overlay: //p' "$LOG" | tail -n 1)"
BUILD_DIR="$(sed -n 's/^Generated build : //p' "$LOG" | tail -n 1)"
SERVICE="$(sed -n 's/^Proxy service  : //p' "$LOG" | tail -n 1)"
[ "$DEPLOY_RC" -eq 0 ] || { echo "FAIL: deploy-compose returned $DEPLOY_RC" >&2; exit "$DEPLOY_RC"; }
PORT="$(sed -n 's#^Local test URL : https://[^:]*:\([0-9][0-9]*\)/$#\1#p' "$LOG" | tail -n 1)"
[[ "$PORT" =~ ^[0-9]+$ ]] || { echo "FAIL: could not read Docker-assigned loopback port from deploy log." >&2; exit 1; }
(( PORT > 0 && PORT <= 65535 )) || { echo "FAIL: invalid Docker-assigned port: $PORT" >&2; exit 1; }
echo "Using Docker-assigned loopback test port: $PORT"

printf 'Verifying the actual container log-rotation settings...\n'
CID="$(docker compose -f "$COMPOSE" -f "$OVERLAY" ps -q "$SERVICE")"
[ -n "$CID" ] || { echo "FAIL: could not find the running Quantum Shield container." >&2; exit 1; }
LOG_CONFIG="$(docker inspect --format '{{.HostConfig.LogConfig.Type}}|{{index .HostConfig.LogConfig.Config "max-size"}}|{{index .HostConfig.LogConfig.Config "max-file"}}' "$CID")"
[ "$LOG_CONFIG" = "json-file|10m|3" ] || {
  echo "FAIL: expected json-file|10m|3 logging settings, found: $LOG_CONFIG" >&2
  exit 1
}
echo "PASS: actual Docker container uses json-file max-size=10m and max-file=3."

printf 'Checking loopback HTTPS body...\n'
BODY="$(curl --noproxy '*' --insecure --silent --show-error --max-time 8 \
  --resolve "$DOMAIN:$PORT:127.0.0.1" "https://$DOMAIN:$PORT/")"
[ "$BODY" = "Quantum Shield local Compose test" ] || {
  echo "FAIL: unexpected response body: $BODY" >&2
  exit 1
}
echo "PASS: disposable Compose HTTPS route works on loopback only."

# QS_LIVE_WAF_ATTACK_TESTS
printf '\nRunning attack probes against the actual loopback HTTPS container...\n'

request_status() {
  curl --noproxy '*' --insecure --silent --show-error --max-time 8 \
    --resolve "$DOMAIN:$PORT:127.0.0.1" \
    --output /dev/null --write-out '%{http_code}' "$@"
}

expect_blocked() {
  label="$1"
  shift
  code="$(request_status "$@")"
  if [ "$code" = "403" ]; then
    printf 'PASS: %s blocked with HTTP 403.\n' "$label"
  else
    printf 'FAIL: %s returned HTTP %s; expected 403.\n' "$label" "$code" >&2
    exit 1
  fi
}

expect_allowed() {
  label="$1"
  shift
  code="$(request_status "$@")"
  if [ "$code" = "200" ]; then
    printf 'PASS: %s allowed with HTTP 200.\n' "$label"
  else
    printf 'FAIL: %s returned HTTP %s; expected 200.\n' "$label" "$code" >&2
    exit 1
  fi
}

expect_blocked "SQL injection query" \
  --get --data-urlencode "q=' OR 1=1--" \
  "https://$DOMAIN:$PORT/search"

expect_blocked "XSS query" \
  --get --data-urlencode 'q=<script>alert(1)</script>' \
  "https://$DOMAIN:$PORT/search"

expect_blocked "path traversal" \
  --path-as-is "https://$DOMAIN:$PORT/../../../../etc/passwd"

expect_blocked "SQL injection in JSON body" \
  --request POST \
  --header 'Content-Type: application/json' \
  --data-binary '{"query":"SELECT * FROM users WHERE id=1 OR 1=1"}' \
  "https://$DOMAIN:$PORT/search"

expect_allowed "benign product search" \
  --get --data-urlencode 'q=normal product search' \
  "https://$DOMAIN:$PORT/search"

echo "PASS: live WAF attack-probe suite completed."
echo "PASS: no public listener was requested; local certificate trust bypass was restricted to this test."
echo "Cleaning up the test-only containers and generated files."
