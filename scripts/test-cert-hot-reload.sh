#!/usr/bin/env bash
# Integration test: replace the cert/key files atomically and prove that the
# running Rustls server presents the new certificate without restarting.
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
QS="$ROOT/target/debug/qsctl"
UPSTREAM_BIN="$ROOT/target/debug/examples/test_upstream"
DOMAIN="app.example.com"
PORT="18489"
TMP="$(mktemp -d /tmp/qs-cert-reload.XXXXXX)"
UP_PID=""
QS_PID=""
QS_LOG="$TMP/qs.log"
UP_LOG="$TMP/upstream.log"

stop_test_child() {
  local pid="$1" attempt state
  [ -n "$pid" ] || return 0

  state="$(ps -o stat= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
  if [ -z "$state" ] || [[ "$state" == Z* ]]; then
    wait "$pid" 2>/dev/null || true
    return 0
  fi

  # INT permits graceful shutdown; TERM and KILL bound cleanup if needed.
  kill -INT "$pid" 2>/dev/null || true
  for attempt in {1..20}; do
    state="$(ps -o stat= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
    [ -z "$state" ] || [[ "$state" == Z* ]] && break
    sleep 0.1
  done

  state="$(ps -o stat= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
  if [ -n "$state" ] && [[ "$state" != Z* ]]; then
    kill -TERM "$pid" 2>/dev/null || true
    for attempt in {1..20}; do
      state="$(ps -o stat= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
      [ -z "$state" ] || [[ "$state" == Z* ]] && break
      sleep 0.1
    done
  fi

  state="$(ps -o stat= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
  if [ -n "$state" ] && [[ "$state" != Z* ]]; then
    kill -KILL "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
}

cleanup() {
  set +e
  stop_test_child "$QS_PID"
  QS_PID=""
  stop_test_child "$UP_PID"
  UP_PID=""
  if [ -s "$QS_LOG" ]; then echo "=== Quantum Shield log ==="; cat "$QS_LOG"; fi
  if [ -s "$UP_LOG" ]; then echo "=== Test upstream log ==="; cat "$UP_LOG"; fi
  rm -rf -- "$TMP"
}
trap cleanup EXIT

for tool in openssl curl ss timeout; do
  command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: required tool not found: $tool" >&2; exit 1; }
done
[ -x "$QS" ] || { echo "ERROR: build qsctl first: cargo build --bin qsctl" >&2; exit 1; }
if ss -ltn "sport = :$PORT" | grep -q LISTEN; then
  echo "ERROR: test port $PORT is already occupied; refusing to stop an unknown process." >&2
  exit 1
fi

if ! curl --noproxy '*' -fsS --max-time 2 http://127.0.0.1:3000/ 2>/dev/null | grep -Fqx 'Quantum Shield Rust test upstream'; then
  if ss -ltn 'sport = :3000' | grep -q LISTEN; then
    echo "ERROR: port 3000 is occupied but is not the expected Quantum Shield test upstream." >&2
    exit 1
  fi
  [ -x "$UPSTREAM_BIN" ] || { echo "ERROR: build the test upstream first: cargo build --example test_upstream" >&2; exit 1; }
  "$UPSTREAM_BIN" >"$UP_LOG" 2>&1 &
  UP_PID=$!
  READY=0
  for _ in $(seq 1 50); do
    if curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:3000/ 2>/dev/null | grep -Fqx 'Quantum Shield Rust test upstream'; then READY=1; break; fi
    sleep 0.1
  done
  [ "$READY" -eq 1 ] || { echo "ERROR: test upstream failed to start." >&2; exit 1; }
fi

make_cert() {
  local suffix="$1"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -sha256 -days 1 -nodes -keyout "$TMP/key-$suffix.pem" \
    -out "$TMP/cert-$suffix.pem" -subj "/CN=$DOMAIN" \
    -addext "subjectAltName=DNS:$DOMAIN" >/dev/null 2>&1
  chmod 600 "$TMP/key-$suffix.pem"
}
make_cert a
make_cert b
cp "$TMP/cert-a.pem" "$TMP/cert.pem"
cp "$TMP/key-a.pem" "$TMP/key.pem"
chmod 600 "$TMP/key.pem"

"$QS" serve-https "$ROOT/config.example.toml" \
  --listen "127.0.0.1:$PORT" --cert "$TMP/cert.pem" --key "$TMP/key.pem" \
  >"$QS_LOG" 2>&1 &
QS_PID=$!

request_body() {
  curl --noproxy '*' --insecure --silent --show-error --max-time 5 \
    --resolve "$DOMAIN:$PORT:127.0.0.1" "https://$DOMAIN:$PORT/"
}
fingerprint() {
  timeout 5 openssl s_client -connect "127.0.0.1:$PORT" -servername "$DOMAIN" \
    </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//'
}

READY=0
for _ in $(seq 1 50); do
  if request_body 2>/dev/null | grep -Fqx 'Quantum Shield Rust test upstream'; then READY=1; break; fi
  kill -0 "$QS_PID" 2>/dev/null || { echo "ERROR: HTTPS server exited before initial health check." >&2; exit 1; }
  sleep 0.1
done
[ "$READY" -eq 1 ] || { echo "ERROR: initial HTTPS health check failed." >&2; exit 1; }
FP_A="$(fingerprint)"
[ -n "$FP_A" ] || { echo "ERROR: could not read initial served certificate fingerprint." >&2; exit 1; }
echo "PASS: initial HTTPS request succeeded; cert fingerprint $FP_A"

# Atomic replacements emulate ACME/renewal tooling. The watcher sees parent
# directory events; an intermediate mismatched pair must not replace the good key.
cp "$TMP/cert-b.pem" "$TMP/cert.new"
chmod 600 "$TMP/cert.new"
mv -f "$TMP/cert.new" "$TMP/cert.pem"
cp "$TMP/key-b.pem" "$TMP/key.new"
chmod 600 "$TMP/key.new"
mv -f "$TMP/key.new" "$TMP/key.pem"

FP_B=""
for _ in $(seq 1 100); do
  FP_B="$(fingerprint || true)"
  if [ -n "$FP_B" ] && [ "$FP_B" != "$FP_A" ]; then break; fi
  sleep 0.1
done
[ -n "$FP_B" ] && [ "$FP_B" != "$FP_A" ] || {
  echo "FAIL: the running server did not present the replacement certificate." >&2
  exit 1
}
BODY="$(request_body)"
[ "$BODY" = "Quantum Shield Rust test upstream" ] || {
  echo "FAIL: HTTPS forwarding failed after certificate reload: $BODY" >&2
  exit 1
}
echo "PASS: certificate changed without restarting qsctl (new fingerprint $FP_B)."
echo "PASS: HTTPS forwarding still works after certificate reload."
echo "NOTE: this validates direct serve-https file watching. Docker single-file bind-mount replacements may need container recreation; ACME mode manages its certs in-process."
