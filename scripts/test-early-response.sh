#!/usr/bin/env bash
# Self-contained local HTTP regression: starts and cleans up its own fixtures.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/lib/local-test-stack.sh"

qs_stack_init
PORT="${QS_TEST_PORT:-18082}"
HOST_HEADER="${QS_TEST_HOST:-app.example.com}"
BASE_URL="${QS_TEST_URL:-http://127.0.0.1:$PORT/}"

if [[ "${QS_TEST_EXTERNAL_SERVER:-0}" != "1" ]]; then
    qs_stack_start_upstream
    qs_stack_start_http "$PORT"
fi

TMP_BODY="$(mktemp "$QS_TMP/upload.XXXXXX")"
TMP_RESPONSE="$(mktemp "$QS_TMP/response.XXXXXX")"

echo "1/2 Checking a normal local request..."
NORMAL_BODY="$(curl --noproxy '*' --silent --show-error --fail --max-time 5 \
  -H "Host: $HOST_HEADER" "$BASE_URL")"
[[ "$NORMAL_BODY" == "Quantum Shield Rust test upstream" ]] || {
  echo "FAIL: unexpected normal response body: $NORMAL_BODY" >&2
  exit 1
}
echo "PASS: normal request returned the expected upstream body."

echo "2/2 Sending a 17 MiB chunked upload to exercise early-response body limits..."
dd if=/dev/zero of="$TMP_BODY" bs=1M count=17 status=none
if ! HTTP_STATUS="$(curl --noproxy '*' --http1.1 --silent --show-error --max-time 60 \
  --output "$TMP_RESPONSE" --write-out '%{http_code}' \
  -H "Host: $HOST_HEADER" \
  -H 'Transfer-Encoding: chunked' \
  -H 'Content-Length:' \
  -H 'Expect:' \
  --data-binary "@$TMP_BODY" "$BASE_URL")"; then
  echo "FAIL: curl transport failed before a final HTTP status." >&2
  cat "$TMP_RESPONSE" >&2 || true
  exit 1
fi
if [[ "$HTTP_STATUS" != "413" ]]; then
  echo "FAIL: expected HTTP 413, got HTTP $HTTP_STATUS." >&2
  cat "$TMP_RESPONSE" >&2 || true
  exit 1
fi
echo "PASS: oversized chunked upload was rejected with HTTP 413."
echo "All early-response regression checks passed."
