#!/usr/bin/env bash
# Self-contained local HTTPS regression: starts and cleans up its own fixtures.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/lib/local-test-stack.sh"

qs_stack_init
PORT="${QS_TLS_TEST_PORT:-18443}"
HOST_HEADER="${QS_TEST_HOST:-app.example.com}"
EXPECTED="Quantum Shield Rust test upstream"
BASE_URL="${QS_TLS_TEST_URL:-https://127.0.0.1:$PORT/}"

if [[ "${QS_TEST_EXTERNAL_SERVER:-0}" != "1" ]]; then
    qs_stack_start_upstream
    qs_stack_start_https "$PORT"
    # Pin SNI and destination to the local listener despite the test Host header.
    BASE_URL="https://$HOST_HEADER:$PORT/"
    RESOLVE=(--resolve "$HOST_HEADER:$PORT:127.0.0.1")
else
    RESOLVE=()
fi

TMP_RESPONSE="$(mktemp "$QS_TMP/response.XXXXXX")"
echo "1/2 Checking local HTTPS and TLS 1.3..."
STATUS="$(curl --noproxy '*' --insecure --silent --show-error --fail --max-time 8 \
  --tlsv1.3 --tls-max 1.3 "${RESOLVE[@]}" \
  -o "$TMP_RESPONSE" -w '%{http_code}' \
  -H "Host: $HOST_HEADER" "$BASE_URL")"
[[ "$STATUS" == "200" ]] || {
  echo "FAIL: expected HTTP 200 over TLS 1.3, got $STATUS" >&2
  cat "$TMP_RESPONSE" >&2 || true
  exit 1
}
[[ "$(cat "$TMP_RESPONSE")" == "$EXPECTED" ]] || {
  echo "FAIL: HTTPS body differed from the test upstream." >&2
  cat "$TMP_RESPONSE" >&2 || true
  exit 1
}
echo "PASS: normal request returned the expected body over TLS 1.3."

echo "2/2 Checking repeated HTTPS requests..."
STATUS="$(curl --noproxy '*' --insecure --silent --show-error --fail --max-time 8 \
  --tlsv1.3 --tls-max 1.3 "${RESOLVE[@]}" \
  -o "$TMP_RESPONSE" -w '%{http_code}' \
  -H "Host: $HOST_HEADER" "$BASE_URL")"
[[ "$STATUS" == "200" ]]
echo "PASS: repeated TLS 1.3 request succeeded."
echo "NOTE: self-signed certificate verification is intentionally disabled for local testing."
echo "All local TLS smoke checks passed."
