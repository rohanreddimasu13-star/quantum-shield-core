#!/usr/bin/env bash
set -u

PORT="${QS_TEST_PORT:-18444}"
HOST="${QS_TEST_HOST:-app.example.com}"
BASE_URL="https://${HOST}:${PORT}/"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/qs-failsafe.XXXXXXXX")"
trap 'rm -rf -- "$TMP"' EXIT

PASS=0
FAIL=0
UNVERIFIED=0

pass() { echo "PASS: $*"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $*"; FAIL=$((FAIL + 1)); }
unverified() { echo "UNVERIFIED: $*"; UNVERIFIED=$((UNVERIFIED + 1)); }

echo "==========================================="
echo " Quantum Shield — Local Failsafe Validation"
echo "==========================================="
echo "Target: 127.0.0.1:$PORT"
echo "TLS hostname: $HOST"
echo "No external hosts are contacted."
echo "Oversize test is bounded; it does not upload 5 GB."
echo

for tool in curl openssl timeout grep; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: Required tool missing: $tool"
        exit 2
    fi
done

echo "=== PREFLIGHT: Self-contained local HTTPS test stack ==="
# QS_FAILSAFE_LOCAL_STACK: start only loopback test services owned by this script.
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/lib/local-test-stack.sh"
qs_stack_init

cleanup_failsafe() {
    qs_stack_cleanup
    rm -rf -- "$TMP"
}
trap cleanup_failsafe EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$HOST" != "$QS_DOMAIN" ]; then
    echo "ERROR: QS_TEST_HOST=$HOST does not match test config hostname $QS_DOMAIN."
    echo "Use the default app.example.com hostname for this fixture."
    exit 2
fi

qs_stack_start_upstream
qs_stack_start_https "$PORT"

echo "PASS: local HTTPS proxy ready on 127.0.0.1:$PORT."

echo
echo "=== PROOF 1: TLS 1.3 hybrid key exchange ==="
if timeout 7 openssl s_client \
    -connect "127.0.0.1:$PORT" \
    -servername "$HOST" \
    -tls1_3 \
    -groups X25519MLKEM768 \
    -brief </dev/null >"$TMP/tls.log" 2>&1; then
    if grep -qF 'X25519MLKEM768' "$TMP/tls.log"; then
        pass "Client output reports X25519MLKEM768."
    else
        unverified "Handshake completed, but OpenSSL did not expose the negotiated group."
        sed -n '1,35p' "$TMP/tls.log"
    fi
else
    unverified "Could not complete the forced-hybrid OpenSSL handshake."
    sed -n '1,35p' "$TMP/tls.log"
fi

echo
echo "=== PROOF 2: Oversized declared request ==="
# Send only 64 KiB. The header claims 5 GB; never stream /dev/zero indefinitely.
head -c 65536 /dev/zero >"$TMP/bounded-body.bin"

set +e
curl --noproxy '*' --http1.1 --insecure --silent --show-error \
    --max-time 6 --limit-rate 256k \
    --resolve "$HOST:$PORT:127.0.0.1" \
    --output "$TMP/oversize-response.txt" \
    --write-out '%{http_code}' \
    --request POST \
    --header "Host: $HOST" \
    --header 'Content-Length: 5000000000' \
    --header 'Expect:' \
    --data-binary "@$TMP/bounded-body.bin" \
    "$BASE_URL" >"$TMP/oversize-status.txt" 2>"$TMP/oversize-error.txt"
CURL_RC=$?
set -e 2>/dev/null || true

CODE="$(cat "$TMP/oversize-status.txt" 2>/dev/null || true)"
echo "HTTP status: ${CODE:-none}; curl exit code: $CURL_RC"

if [ "$CODE" = "413" ]; then
    pass "Proxy rejected the oversized declared request with HTTP 413."
else
    fail "Expected HTTP 413; got ${CODE:-no HTTP response}."
    cat "$TMP/oversize-error.txt"
fi

echo
echo "=== PROOF 3: Host-loop injection ==="
set +e
CODE="$(curl --noproxy '*' --insecure --silent --show-error \
    --max-time 5 \
    --resolve "$HOST:$PORT:127.0.0.1" \
    --output "$TMP/host-response.txt" \
    --write-out '%{http_code}' \
    --header 'Host: 127.0.0.1' \
    "$BASE_URL" 2>"$TMP/host-error.txt")"
CURL_RC=$?
set -u

echo "HTTP status: ${CODE:-none}; curl exit code: $CURL_RC"

case "$CODE" in
    400|403|421)
        if grep -Fqx 'Quantum Shield Rust test upstream' "$TMP/host-response.txt"; then
            fail "Host-mismatch request returned the upstream body."
        else
            pass "Host-mismatch request was rejected with HTTP $CODE and the upstream body was not returned."
        fi
        ;;
    *)
        fail "Expected HTTP 400, 403, or 421 for the loop-injection request."
        cat "$TMP/host-error.txt"
        ;;
esac

echo
echo "=== PROOF 4: GPTBot User-Agent handling ==="
set +e
CODE="$(curl --noproxy '*' --insecure --silent --show-error \
    --max-time 5 \
    --resolve "$HOST:$PORT:127.0.0.1" \
    --output "$TMP/gptbot-response.txt" \
    --write-out '%{http_code}' \
    --header 'User-Agent: Mozilla/5.0 GPTBot/1.0' \
    "$BASE_URL" 2>"$TMP/gptbot-error.txt")"
CURL_RC=$?
set -u

echo "HTTP status: ${CODE:-none}; curl exit code: $CURL_RC"

if [ "$CODE" = "403" ]; then
    pass "GPTBot request received HTTP 403."
else
    fail "GPTBot was not explicitly denied with HTTP 403."
    echo "This feature may not be implemented in the current proxy."
fi

echo
echo "==========================================="
echo " VALIDATION SUMMARY"
echo "==========================================="
echo "Passed:      $PASS"
echo "Failed:      $FAIL"
echo "Unverified:  $UNVERIFIED"
echo
echo "A pass covers only this local test configuration."
echo "It does not prove resistance to all DoS, SSRF, or scraping attacks."

[ "$FAIL" -eq 0 ] && [ "$UNVERIFIED" -eq 0 ]
